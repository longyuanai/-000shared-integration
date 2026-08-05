"""Execution of persisted scan jobs against product adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence

from shared_llm_core import CorrelationRule, Finding, FindingRegistry, FindingSource

from shared_integration.adapters import (
    ProductAdapter,
    ProductCLIError,
    ProductTimeoutError,
)
from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.jobs import JobStatus, SQLiteJobRepository


class JobCancelledError(RuntimeError):
    """Internal control flow for a requested job cancellation."""


class JobExecutor:
    """Run one persisted job with retry, cancellation, and tenant binding."""

    def __init__(
        self,
        *,
        repository: SQLiteJobRepository,
        registry: FindingRegistry,
        products: Mapping[FindingSource, ProductAdapter],
        correlations: Sequence[CorrelationRule] = (),
        max_attempts: int = 2,
        retry_backoff_seconds: float = 0.25,
        cancellation_poll_seconds: float = 0.1,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        self.repository = repository
        self.registry = registry
        self.products = dict(products)
        self.correlations = list(correlations)
        self.max_attempts = max_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self.cancellation_poll_seconds = cancellation_poll_seconds

    async def execute(self, job_id: str, tenant_id: str) -> None:
        job = self.repository.get(tenant_id, job_id)
        if job is None or job.status.terminal:
            return
        adapter = self.products.get(job.source)
        if adapter is None:
            self.repository.transition(
                tenant_id,
                job_id,
                JobStatus.FAILED,
                error_code="UNKNOWN_SOURCE",
                error_message=f"No adapter registered for {job.source.value}",
            )
            return

        for attempt in range(1, self.max_attempts + 1):
            current = self.repository.get(tenant_id, job_id)
            if current is None or current.cancel_requested or current.status is JobStatus.CANCELLED:
                if current is not None and current.status is not JobStatus.CANCELLED:
                    self.repository.transition(tenant_id, job_id, JobStatus.CANCELLED)
                return

            started = self.repository.mark_running(
                tenant_id,
                job_id,
                require_queued=attempt == 1,
            )
            if started is None:
                return
            token = bind_tenant(tenant_id)
            try:
                findings = await self._scan_with_cancellation(
                    adapter, current.payload, tenant_id, job_id
                )
                await self._store_results(tenant_id, job_id, findings)
                self.repository.transition(
                    tenant_id,
                    job_id,
                    JobStatus.SUCCEEDED,
                    result_count=len(findings),
                )
                return
            except JobCancelledError:
                self.repository.transition(tenant_id, job_id, JobStatus.CANCELLED)
                return
            except asyncio.CancelledError:
                current = self.repository.get(tenant_id, job_id)
                if current is not None and not current.status.terminal:
                    self.repository.transition(
                        tenant_id, job_id, JobStatus.CANCELLED
                    )
                raise
            except ProductCLIError as exc:
                if exc.retryable and attempt < self.max_attempts:
                    self.repository.append_event(
                        tenant_id,
                        job_id,
                        "retrying",
                        {
                            "attempt": attempt,
                            "next_attempt": attempt + 1,
                            "code": exc.code,
                        },
                    )
                    await asyncio.sleep(self.retry_backoff_seconds * attempt)
                    continue
                status = (
                    JobStatus.TIMED_OUT
                    if isinstance(exc, ProductTimeoutError)
                    else JobStatus.FAILED
                )
                self.repository.transition(
                    tenant_id,
                    job_id,
                    status,
                    error_code=exc.code,
                    error_message=str(exc),
                )
                return
            except Exception as exc:  # noqa: BLE001 - persist isolated worker failure
                self.repository.transition(
                    tenant_id,
                    job_id,
                    JobStatus.FAILED,
                    error_code="INTERNAL_ERROR",
                    error_message=str(exc),
                )
                return
            finally:
                reset_tenant(token)

    async def _scan_with_cancellation(
        self,
        adapter: ProductAdapter,
        payload: dict[str, object],
        tenant_id: str,
        job_id: str,
    ) -> list[Finding]:
        async def collect() -> list[Finding]:
            return [finding async for finding in adapter.scan(payload)]

        scan_task = asyncio.create_task(collect(), name=f"scan-{job_id}")
        try:
            while not scan_task.done():
                await asyncio.wait(
                    {scan_task},
                    timeout=self.cancellation_poll_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                current = self.repository.get(tenant_id, job_id)
                if current is None or not current.cancel_requested:
                    continue
                scan_task.cancel()
                try:
                    await scan_task
                except asyncio.CancelledError:
                    pass
                raise JobCancelledError(job_id)
            return await scan_task
        except asyncio.CancelledError:
            if not scan_task.done():
                scan_task.cancel()
                try:
                    await scan_task
                except asyncio.CancelledError:
                    pass
            raise

    async def _store_results(
        self,
        tenant_id: str,
        job_id: str,
        findings: list[Finding],
    ) -> None:
        existing = list(self.registry.findings)
        for finding in findings:
            await self.registry.add(finding)
            self.repository.append_event(
                tenant_id,
                job_id,
                "finding",
                finding.to_dict(),
            )
            for rule in self.correlations:
                for correlation in rule.correlate(finding, existing):
                    await self.registry.add_correlation(correlation)
                    self.repository.append_event(
                        tenant_id,
                        job_id,
                        "correlation",
                        {
                            "rule_id": correlation.rule_id,
                            "findings": list(correlation.findings),
                            "severity": correlation.severity.value,
                            "narrative": correlation.narrative,
                        },
                    )
            existing.append(finding)


__all__ = ["JobCancelledError", "JobExecutor"]
