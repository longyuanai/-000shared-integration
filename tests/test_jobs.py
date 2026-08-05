"""Persisted v1 job repository tests."""

from __future__ import annotations

from pathlib import Path

from shared_llm_core import FindingSource

from shared_integration.jobs import JobStatus, SQLiteJobRepository


def test_job_creation_is_idempotent_per_tenant(tmp_path: Path) -> None:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    first, created = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"host": "one"},
        idempotency_key="same-request",
    )
    repeated, repeated_created = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={"host": "two"},
        idempotency_key="same-request",
    )
    other, other_created = repository.create(
        tenant_id="tenant-b",
        source=FindingSource.SOC,
        payload={"host": "three"},
        idempotency_key="same-request",
    )

    assert created is True
    assert repeated_created is False
    assert repeated.id == first.id
    assert repeated.payload == {"host": "one"}
    assert other_created is True
    assert other.id != first.id
    repository.close()


def test_job_events_and_status_survive_restart(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    first = SQLiteJobRepository(database)
    job, _ = first.create(
        tenant_id="tenant-a",
        source=FindingSource.CODE,
        payload={},
    )
    first.mark_running("tenant-a", job.id)
    first.append_event("tenant-a", job.id, "progress", {"percent": 50})
    first.transition(
        "tenant-a", job.id, JobStatus.SUCCEEDED, result_count=2
    )
    first.close()

    second = SQLiteJobRepository(database)
    restored = second.get("tenant-a", job.id)
    assert restored is not None
    assert restored.status is JobStatus.SUCCEEDED
    assert restored.result_count == 2
    assert [event.kind for event in second.list_events("tenant-a", job.id)] == [
        "status",
        "status",
        "progress",
        "status",
    ]
    assert second.get("tenant-b", job.id) is None
    second.close()


def test_cancel_queued_job_is_terminal(tmp_path: Path) -> None:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.FIRMWARE,
        payload={},
    )
    cancelled = repository.request_cancel("tenant-a", job.id)
    assert cancelled.status is JobStatus.CANCELLED
    assert cancelled.cancel_requested is True
    repository.close()


def test_only_one_worker_can_claim_a_queued_job(tmp_path: Path) -> None:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.SOC,
        payload={},
    )

    first_claim = repository.mark_running("tenant-a", job.id)
    duplicate_claim = repository.mark_running("tenant-a", job.id)

    assert first_claim is not None
    assert first_claim.attempt == 1
    assert duplicate_claim is None
    assert repository.get("tenant-a", job.id) == first_claim
    repository.close()
