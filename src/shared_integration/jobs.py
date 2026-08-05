"""Tenant-scoped asynchronous scan jobs and their SQLite repository."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from shared_llm_core import FindingSource


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"

    @property
    def terminal(self) -> bool:
        return self in {
            JobStatus.SUCCEEDED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.TIMED_OUT,
        }


@dataclass(frozen=True)
class JobRecord:
    id: str
    tenant_id: str
    source: FindingSource
    payload: dict[str, Any]
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    idempotency_key: str | None = None
    dispatch_id: str | None = None
    attempt: int = 0
    cancel_requested: bool = False
    result_count: int = 0
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "source": self.source.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "attempt": self.attempt,
            "cancel_requested": self.cancel_requested,
            "result_count": self.result_count,
            "error": (
                {"code": self.error_code, "message": self.error_message}
                if self.error_code
                else None
            ),
        }


@dataclass(frozen=True)
class JobEvent:
    sequence: int
    job_id: str
    tenant_id: str
    kind: str
    payload: dict[str, Any]
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "job_id": self.job_id,
            "kind": self.kind,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }


class SQLiteJobRepository:
    """Small v1 job repository used before the PostgreSQL M2 migration."""

    def __init__(self, path: str | Path) -> None:
        database = str(path)
        if database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self.path = database
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(database, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                job_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                idempotency_key TEXT,
                dispatch_id TEXT,
                attempt INTEGER NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                result_count INTEGER NOT NULL DEFAULT 0,
                error_code TEXT,
                error_message TEXT,
                UNIQUE (tenant_id, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_status_created
                ON scan_jobs (tenant_id, status, created_at DESC);

            CREATE TABLE IF NOT EXISTS scan_job_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (tenant_id, job_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_job_events_tenant_job_sequence
                ON scan_job_events (tenant_id, job_id, sequence);
            """
        )
        self._connection.commit()

    def create(
        self,
        *,
        tenant_id: str,
        source: FindingSource,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> tuple[JobRecord, bool]:
        """Create a queued job or return the tenant's idempotent match."""
        if idempotency_key is not None:
            existing = self.find_by_idempotency_key(tenant_id, idempotency_key)
            if existing is not None:
                return existing, False

        now = _utcnow()
        job_id = f"job_{uuid.uuid4().hex}"
        with self._lock:
            try:
                self._connection.execute(
                    """
                    INSERT INTO scan_jobs (
                        job_id, tenant_id, source, payload, status, created_at,
                        updated_at, idempotency_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        tenant_id,
                        source.value,
                        _json(payload),
                        JobStatus.QUEUED.value,
                        now.isoformat(),
                        now.isoformat(),
                        idempotency_key,
                    ),
                )
                self._append_event_locked(
                    tenant_id,
                    job_id,
                    "status",
                    {"status": JobStatus.QUEUED.value},
                    now,
                )
                self._connection.commit()
            except sqlite3.IntegrityError:
                self._connection.rollback()
                if idempotency_key is None:
                    raise
                existing = self.find_by_idempotency_key(tenant_id, idempotency_key)
                if existing is None:
                    raise
                return existing, False
        created = self.get(tenant_id, job_id)
        if created is None:  # pragma: no cover - defensive database invariant
            raise RuntimeError("created job could not be reloaded")
        return created, True

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM scan_jobs WHERE tenant_id = ? AND job_id = ?",
                (tenant_id, job_id),
            ).fetchone()
        return _job_from_row(row) if row is not None else None

    def find_by_idempotency_key(
        self, tenant_id: str, idempotency_key: str
    ) -> JobRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM scan_jobs
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (tenant_id, idempotency_key),
            ).fetchone()
        return _job_from_row(row) if row is not None else None

    def mark_running(
        self,
        tenant_id: str,
        job_id: str,
        *,
        require_queued: bool = True,
    ) -> JobRecord | None:
        now = _utcnow()
        expected_status = (
            JobStatus.QUEUED if require_queued else JobStatus.RUNNING
        )
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE scan_jobs
                SET status = ?, attempt = attempt + 1, updated_at = ?,
                    error_code = NULL, error_message = NULL
                WHERE tenant_id = ? AND job_id = ? AND status = ?
                    AND cancel_requested = 0
                """,
                (
                    JobStatus.RUNNING.value,
                    now.isoformat(),
                    tenant_id,
                    job_id,
                    expected_status.value,
                ),
            )
            if cursor.rowcount != 1:
                self._connection.commit()
                return None
            self._append_event_locked(
                tenant_id,
                job_id,
                "status",
                {"status": JobStatus.RUNNING.value},
                now,
            )
            self._connection.commit()
        return self._required(tenant_id, job_id)

    def transition(
        self,
        tenant_id: str,
        job_id: str,
        status: JobStatus,
        *,
        result_count: int | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> JobRecord:
        now = _utcnow()
        with self._lock:
            current = self._required_locked(tenant_id, job_id)
            count = current.result_count if result_count is None else result_count
            self._connection.execute(
                """
                UPDATE scan_jobs
                SET status = ?, updated_at = ?, result_count = ?,
                    error_code = ?, error_message = ?
                WHERE tenant_id = ? AND job_id = ?
                """,
                (
                    status.value,
                    now.isoformat(),
                    count,
                    error_code,
                    error_message,
                    tenant_id,
                    job_id,
                ),
            )
            event_payload: dict[str, Any] = {"status": status.value}
            if error_code:
                event_payload["error"] = {
                    "code": error_code,
                    "message": error_message,
                }
            self._append_event_locked(tenant_id, job_id, "status", event_payload, now)
            self._connection.commit()
        return self._required(tenant_id, job_id)

    def append_event(
        self,
        tenant_id: str,
        job_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> JobEvent:
        with self._lock:
            self._required_locked(tenant_id, job_id)
            event = self._append_event_locked(
                tenant_id, job_id, kind, payload, _utcnow()
            )
            self._connection.commit()
        return event

    def list_events(
        self,
        tenant_id: str,
        job_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> list[JobEvent]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT tenant_id, job_id, sequence, kind, payload, created_at
                FROM scan_job_events
                WHERE tenant_id = ? AND job_id = ? AND sequence > ?
                ORDER BY sequence ASC
                LIMIT ?
                """,
                (tenant_id, job_id, after_sequence, limit),
            ).fetchall()
        return [_event_from_row(row) for row in rows]

    def set_dispatch_id(self, tenant_id: str, job_id: str, dispatch_id: str) -> None:
        with self._lock:
            self._connection.execute(
                """
                UPDATE scan_jobs SET dispatch_id = ?, updated_at = ?
                WHERE tenant_id = ? AND job_id = ?
                """,
                (dispatch_id, _utcnow().isoformat(), tenant_id, job_id),
            )
            self._connection.commit()

    def request_cancel(self, tenant_id: str, job_id: str) -> JobRecord:
        now = _utcnow()
        with self._lock:
            current = self._required_locked(tenant_id, job_id)
            if current.status.terminal:
                return current
            next_status = (
                JobStatus.CANCELLED
                if current.status is JobStatus.QUEUED
                else current.status
            )
            self._connection.execute(
                """
                UPDATE scan_jobs
                SET cancel_requested = 1, status = ?, updated_at = ?
                WHERE tenant_id = ? AND job_id = ?
                """,
                (next_status.value, now.isoformat(), tenant_id, job_id),
            )
            self._append_event_locked(
                tenant_id,
                job_id,
                "cancel_requested",
                {"status": next_status.value},
                now,
            )
            self._connection.commit()
        return self._required(tenant_id, job_id)

    def ping(self) -> bool:
        with self._lock:
            return self._connection.execute("SELECT 1").fetchone()[0] == 1

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _required(self, tenant_id: str, job_id: str) -> JobRecord:
        with self._lock:
            return self._required_locked(tenant_id, job_id)

    def _required_locked(self, tenant_id: str, job_id: str) -> JobRecord:
        row = self._connection.execute(
            "SELECT * FROM scan_jobs WHERE tenant_id = ? AND job_id = ?",
            (tenant_id, job_id),
        ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return _job_from_row(row)

    def _append_event_locked(
        self,
        tenant_id: str,
        job_id: str,
        kind: str,
        payload: dict[str, Any],
        created_at: datetime,
    ) -> JobEvent:
        row = self._connection.execute(
            """
            SELECT COALESCE(MAX(sequence), 0) + 1
            FROM scan_job_events WHERE tenant_id = ? AND job_id = ?
            """,
            (tenant_id, job_id),
        ).fetchone()
        sequence = int(row[0])
        self._connection.execute(
            """
            INSERT INTO scan_job_events (
                tenant_id, job_id, sequence, kind, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                job_id,
                sequence,
                kind,
                _json(payload),
                created_at.isoformat(),
            ),
        )
        return JobEvent(
            sequence=sequence,
            job_id=job_id,
            tenant_id=tenant_id,
            kind=kind,
            payload=payload,
            created_at=created_at,
        )


def _job_from_row(row: sqlite3.Row) -> JobRecord:
    return JobRecord(
        id=row["job_id"],
        tenant_id=row["tenant_id"],
        source=FindingSource(row["source"]),
        payload=json.loads(row["payload"]),
        status=JobStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        idempotency_key=row["idempotency_key"],
        dispatch_id=row["dispatch_id"],
        attempt=int(row["attempt"]),
        cancel_requested=bool(row["cancel_requested"]),
        result_count=int(row["result_count"]),
        error_code=row["error_code"],
        error_message=row["error_message"],
    )


def _event_from_row(row: sqlite3.Row) -> JobEvent:
    return JobEvent(
        sequence=int(row["sequence"]),
        job_id=row["job_id"],
        tenant_id=row["tenant_id"],
        kind=row["kind"],
        payload=json.loads(row["payload"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = ["JobEvent", "JobRecord", "JobStatus", "SQLiteJobRepository"]
