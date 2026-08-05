"""Async job execution, retry, cancellation, and persistence tests."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from shared_llm_core import Finding, FindingRegistry, FindingSeverity, FindingSource

from shared_integration.adapters import AdapterCapabilities, ProductAdapter, ProductTimeoutError
from shared_integration.execution import JobExecutor
from shared_integration.jobs import JobStatus, SQLiteJobRepository


class FakeAdapter(ProductAdapter):
    source = FindingSource.SOC

    def __init__(self) -> None:
        self.calls = 0

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        self.calls += 1
        yield Finding(
            id="finding-1",
            source=self.source,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            title=payload["title"],
        )

    def health(self) -> dict[str, Any]:
        return {"status": "ok"}

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            source=self.source,
            product_id="fake",
            version="1",
            queue="fast",
            timeout_seconds=1,
            max_concurrency=1,
            max_input_bytes=1000,
            max_output_bytes=1000,
        )


class RetryAdapter(FakeAdapter):
    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        self.calls += 1
        if self.calls == 1:
            raise ProductTimeoutError("temporary timeout")
        if False:  # pragma: no cover - async generator typing
            yield
        yield Finding(
            id="finding-after-retry",
            source=self.source,
            severity=FindingSeverity.MEDIUM,
            confidence=0.8,
            title=payload["title"],
        )


class SlowAdapter(FakeAdapter):
    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        del payload
        self.calls += 1
        await asyncio.sleep(60)
        if False:  # pragma: no cover
            yield


def make_executor(
    tmp_path: Path, adapter: ProductAdapter
) -> tuple[SQLiteJobRepository, FindingRegistry, JobExecutor]:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    registry = FindingRegistry()
    executor = JobExecutor(
        repository=repository,
        registry=registry,
        products={FindingSource.SOC: adapter},
        max_attempts=2,
        retry_backoff_seconds=0,
        cancellation_poll_seconds=0.01,
    )
    return repository, registry, executor


async def test_executor_persists_findings_and_success(tmp_path: Path) -> None:
    repository, registry, executor = make_executor(tmp_path, FakeAdapter())
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"title": "Detected"},
    )
    await executor.execute(job.id, "tenant-a")

    completed = repository.get("tenant-a", job.id)
    assert completed is not None
    assert completed.status is JobStatus.SUCCEEDED
    assert completed.result_count == 1
    assert registry.findings[0].title == "Detected"
    assert "finding" in [
        event.kind for event in repository.list_events("tenant-a", job.id)
    ]
    repository.close()


async def test_executor_retries_retryable_timeout(tmp_path: Path) -> None:
    adapter = RetryAdapter()
    repository, _, executor = make_executor(tmp_path, adapter)
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"title": "Recovered"},
    )
    await executor.execute(job.id, "tenant-a")

    completed = repository.get("tenant-a", job.id)
    assert completed is not None
    assert completed.status is JobStatus.SUCCEEDED
    assert completed.attempt == 2
    assert adapter.calls == 2
    assert "retrying" in [
        event.kind for event in repository.list_events("tenant-a", job.id)
    ]
    repository.close()


async def test_executor_cancels_running_scan(tmp_path: Path) -> None:
    repository, _, executor = make_executor(tmp_path, SlowAdapter())
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={},
    )
    task = asyncio.create_task(executor.execute(job.id, "tenant-a"))
    while (current := repository.get("tenant-a", job.id)) is not None:
        if current.status is JobStatus.RUNNING:
            break
        await asyncio.sleep(0)
    repository.request_cancel("tenant-a", job.id)
    await asyncio.wait_for(task, timeout=1)

    cancelled = repository.get("tenant-a", job.id)
    assert cancelled is not None
    assert cancelled.status is JobStatus.CANCELLED
    repository.close()
