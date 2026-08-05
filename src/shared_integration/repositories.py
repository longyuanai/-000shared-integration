"""Persistence contracts shared by SQLite and SQLAlchemy backends."""

from __future__ import annotations

from typing import Any, Protocol

from shared_llm_core import FindingSource

from shared_integration.jobs import JobEvent, JobRecord, JobStatus


class JobRepository(Protocol):
    """Tenant-scoped durable job operations required by API and workers."""

    def create(
        self,
        *,
        tenant_id: str,
        source: FindingSource,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> tuple[JobRecord, bool]: ...

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None: ...

    def list_jobs(
        self,
        tenant_id: str,
        *,
        status: JobStatus | None = None,
        source: FindingSource | None = None,
        limit: int = 50,
    ) -> list[JobRecord]: ...

    def find_by_idempotency_key(
        self, tenant_id: str, idempotency_key: str
    ) -> JobRecord | None: ...

    def mark_running(
        self,
        tenant_id: str,
        job_id: str,
        *,
        require_queued: bool = True,
    ) -> JobRecord | None: ...

    def transition(
        self,
        tenant_id: str,
        job_id: str,
        status: JobStatus,
        *,
        result_count: int | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> JobRecord: ...

    def append_event(
        self,
        tenant_id: str,
        job_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> JobEvent: ...

    def list_events(
        self,
        tenant_id: str,
        job_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> list[JobEvent]: ...

    def set_dispatch_id(
        self, tenant_id: str, job_id: str, dispatch_id: str
    ) -> None: ...

    def request_cancel(self, tenant_id: str, job_id: str) -> JobRecord: ...

    def ping(self) -> bool: ...

    def close(self) -> None: ...


__all__ = ["JobRepository"]
