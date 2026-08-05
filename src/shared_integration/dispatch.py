"""Job dispatch implementations for local and Celery execution."""

from __future__ import annotations

import asyncio
import uuid
from typing import Protocol

from shared_integration.celery_app import celery_app
from shared_integration.execution import JobExecutor
from shared_integration.jobs import JobRecord


class JobDispatcher(Protocol):
    def submit(self, job: JobRecord, *, queue: str) -> str: ...

    def cancel(self, job: JobRecord) -> None: ...

    def ready(self) -> bool: ...


class InlineJobDispatcher:
    """Run jobs in this process for local development and deterministic tests."""

    def __init__(self, executor: JobExecutor) -> None:
        self.executor = executor
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def submit(self, job: JobRecord, *, queue: str) -> str:
        del queue
        dispatch_id = f"inline_{uuid.uuid4().hex}"
        task = asyncio.get_running_loop().create_task(
            self.executor.execute(job.id, job.tenant_id),
            name=dispatch_id,
        )
        self._tasks[dispatch_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(dispatch_id, None))
        return dispatch_id

    def cancel(self, job: JobRecord) -> None:
        # The executor polls the durable cancel flag and then cancels the child
        # subprocess. Cancelling the executor task itself would skip persistence.
        del job

    def ready(self) -> bool:
        return True


class CeleryJobDispatcher:
    """Publish persisted jobs to a Valkey/Redis-backed Celery queue."""

    def submit(self, job: JobRecord, *, queue: str) -> str:
        result = celery_app.send_task(
            "shared_integration.execute_job",
            args=[job.id, job.tenant_id],
            queue=queue,
        )
        return str(result.id)

    def cancel(self, job: JobRecord) -> None:
        if job.dispatch_id:
            celery_app.control.revoke(job.dispatch_id, terminate=False)

    def ready(self) -> bool:
        try:
            with celery_app.connection_for_read() as connection:
                connection.ensure_connection(max_retries=0)
            return True
        except Exception:  # noqa: BLE001 - readiness reports broker outage
            return False


__all__ = ["CeleryJobDispatcher", "InlineJobDispatcher", "JobDispatcher"]
