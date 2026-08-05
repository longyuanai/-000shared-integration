"""Celery routing contract tests without requiring a live broker."""

from __future__ import annotations

from pathlib import Path

import pytest
from shared_llm_core import FindingSource

from shared_integration import dispatch
from shared_integration.dispatch import CeleryJobDispatcher
from shared_integration.jobs import SQLiteJobRepository


def test_celery_dispatch_uses_adapter_queue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.REVERSE,
        payload={},
    )
    calls: list[tuple[str, list[str], str]] = []

    class Result:
        id = "celery-task-1"

    def fake_send_task(name: str, *, args: list[str], queue: str) -> Result:
        calls.append((name, args, queue))
        return Result()

    monkeypatch.setattr(dispatch.celery_app, "send_task", fake_send_task)
    task_id = CeleryJobDispatcher().submit(job, queue="sandbox")

    assert task_id == "celery-task-1"
    assert calls == [
        (
            "shared_integration.execute_job",
            [job.id, "tenant-a"],
            "sandbox",
        )
    ]
    repository.close()


def test_celery_cancel_revokes_queued_task(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository = SQLiteJobRepository(tmp_path / "jobs.sqlite3")
    job, _ = repository.create(
        tenant_id="tenant-a",
        source=FindingSource.CODE,
        payload={},
    )
    repository.set_dispatch_id("tenant-a", job.id, "celery-task-2")
    dispatched = repository.get("tenant-a", job.id)
    assert dispatched is not None
    calls: list[tuple[str, bool]] = []

    def fake_revoke(task_id: str, *, terminate: bool) -> None:
        calls.append((task_id, terminate))

    monkeypatch.setattr(dispatch.celery_app.control, "revoke", fake_revoke)
    CeleryJobDispatcher().cancel(dispatched)

    assert calls == [("celery-task-2", False)]
    repository.close()
