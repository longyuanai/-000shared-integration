"""Relational Job repository contract and tenant isolation tests."""

from __future__ import annotations

from pathlib import Path

from shared_llm_core import FindingSource
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from shared_integration.db_models import AuditEventRow
from shared_integration.jobs import JobStatus
from shared_integration.sql_jobs import SQLAlchemyJobRepository


def _repository(path: Path) -> SQLAlchemyJobRepository:
    return SQLAlchemyJobRepository(
        f"sqlite+pysqlite:///{path.as_posix()}",
        create_schema=True,
    )


def test_relational_job_repository_is_idempotent_and_tenant_scoped(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "jobs.db")
    first, created = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"events": []},
        idempotency_key="request-1",
    )
    replay, replay_created = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"events": ["ignored"]},
        idempotency_key="request-1",
    )
    other, other_created = repository.create(
        tenant_id="tenant-b",
        source=FindingSource.SOC,
        payload={},
        idempotency_key="request-1",
    )

    assert created is True
    assert replay_created is False
    assert replay.id == first.id
    assert replay.payload == {"events": []}
    assert other_created is True
    assert other.id != first.id
    assert repository.get("tenant-b", first.id) is None
    repository.close()


def test_relational_job_claim_cancel_events_and_audit_survive_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.db"
    repository = _repository(database)
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.CODE,
        payload={},
    )

    claimed = repository.mark_running("tenant-a", job.id)
    duplicate = repository.mark_running("tenant-a", job.id)
    assert claimed is not None
    assert claimed.attempt == 1
    assert duplicate is None

    requested = repository.request_cancel("tenant-a", job.id)
    assert requested.status is JobStatus.RUNNING
    assert requested.cancel_requested is True
    finished = repository.transition("tenant-a", job.id, JobStatus.CANCELLED)
    assert finished.status is JobStatus.CANCELLED
    repository.close()

    reopened = _repository(database)
    restored = reopened.get("tenant-a", job.id)
    assert restored is not None
    assert restored.status is JobStatus.CANCELLED
    assert restored.attempt == 1
    assert [
        event.kind for event in reopened.list_events("tenant-a", job.id)
    ] == ["status", "status", "cancel_requested", "status"]
    with Session(reopened.engine) as session:
        audit_count = session.scalar(
            select(func.count()).select_from(AuditEventRow)
        )
    assert audit_count == 3
    reopened.close()


def test_relational_queued_cancellation_cannot_be_claimed(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "jobs.db")
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.FIRMWARE,
        payload={},
    )
    cancelled = repository.request_cancel("tenant-a", job.id)

    assert cancelled.status is JobStatus.CANCELLED
    assert repository.mark_running("tenant-a", job.id) is None
    assert repository.get("tenant-a", job.id).attempt == 0  # type: ignore[union-attr]
    repository.close()


def test_relational_job_listing_filters_and_isolates_tenants(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "jobs.db")
    soc, _ = repository.create(
        tenant_id="tenant-a", source=FindingSource.SOC, payload={}
    )
    code, _ = repository.create(
        tenant_id="tenant-a", source=FindingSource.CODE, payload={}
    )
    repository.create(tenant_id="tenant-b", source=FindingSource.SOC, payload={})
    repository.transition("tenant-a", code.id, JobStatus.SUCCEEDED)

    assert {job.id for job in repository.list_jobs("tenant-a")} == {
        soc.id,
        code.id,
    }
    assert [
        job.id
        for job in repository.list_jobs(
            "tenant-a", status=JobStatus.SUCCEEDED
        )
    ] == [code.id]
    assert [
        job.id
        for job in repository.list_jobs("tenant-a", source=FindingSource.SOC)
    ] == [soc.id]
    repository.close()
