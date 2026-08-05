"""SQLAlchemy/PostgreSQL implementation of the tenant-scoped Job repository."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from shared_llm_core import FindingSource
from sqlalchemy import Engine, create_engine, event, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from shared_integration.db_models import (
    AuditEventRow,
    Base,
    JobEventRow,
    JobRow,
    TenantRow,
)
from shared_integration.jobs import JobEvent, JobRecord, JobStatus

_QUEUES = {
    FindingSource.SOC: "fast",
    FindingSource.VULN: "analysis",
    FindingSource.LAB: "sandbox",
    FindingSource.CODE: "analysis",
    FindingSource.REVERSE: "sandbox",
    FindingSource.FIRMWARE: "sandbox",
    FindingSource.EXTERNAL: "analysis",
}


def create_database_engine(database_url: str) -> Engine:
    """Build an engine with safe SQLite test settings and pool liveness checks."""
    options: dict[str, Any] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            options["poolclass"] = StaticPool
    engine = create_engine(database_url, **options)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


class SQLAlchemyJobRepository:
    """Process-safe Job repository for PostgreSQL and SQLite-backed tests."""

    def __init__(
        self,
        database_url: str,
        *,
        create_schema: bool = False,
        engine: Engine | None = None,
    ) -> None:
        self.engine = engine or create_database_engine(database_url)
        self._owns_engine = engine is None
        if create_schema:
            Base.metadata.create_all(self.engine)
        self._sessions = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=Session,
        )

    def create(
        self,
        *,
        tenant_id: str,
        source: FindingSource,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> tuple[JobRecord, bool]:
        if idempotency_key is not None:
            existing = self.find_by_idempotency_key(tenant_id, idempotency_key)
            if existing is not None:
                return existing, False

        now = _utcnow()
        job_id = f"job_{uuid.uuid4().hex}"
        try:
            with self._sessions.begin() as session:
                _ensure_tenant(session, tenant_id, now)
                row = JobRow(
                    id=job_id,
                    tenant_id=tenant_id,
                    source=source.value,
                    status=JobStatus.QUEUED.value,
                    queue=_QUEUES[source],
                    input_payload=dict(payload),
                    idempotency_key=idempotency_key,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
                session.flush()
                _append_event(
                    session,
                    tenant_id,
                    job_id,
                    "status",
                    {"status": JobStatus.QUEUED.value},
                    now,
                )
                _audit(
                    session,
                    tenant_id,
                    "job.created",
                    "job",
                    job_id,
                    {"source": source.value, "queue": row.queue},
                    now,
                )
        except IntegrityError:
            if idempotency_key is None:
                raise
            existing = self.find_by_idempotency_key(tenant_id, idempotency_key)
            if existing is None:
                raise
            return existing, False
        created = self.get(tenant_id, job_id)
        if created is None:  # pragma: no cover - transaction invariant
            raise RuntimeError("created job could not be reloaded")
        return created, True

    def get(self, tenant_id: str, job_id: str) -> JobRecord | None:
        with self._sessions() as session:
            row = session.scalar(
                select(JobRow).where(
                    JobRow.tenant_id == tenant_id,
                    JobRow.id == job_id,
                )
            )
            return _job_from_row(row) if row is not None else None

    def list_jobs(
        self,
        tenant_id: str,
        *,
        status: JobStatus | None = None,
        source: FindingSource | None = None,
        limit: int = 50,
    ) -> list[JobRecord]:
        statement = select(JobRow).where(JobRow.tenant_id == tenant_id)
        if status is not None:
            statement = statement.where(JobRow.status == status.value)
        if source is not None:
            statement = statement.where(JobRow.source == source.value)
        with self._sessions() as session:
            rows = session.scalars(
                statement.order_by(JobRow.created_at.desc(), JobRow.id.desc()).limit(
                    max(1, min(limit, 200))
                )
            ).all()
            return [_job_from_row(row) for row in rows]

    def find_by_idempotency_key(
        self, tenant_id: str, idempotency_key: str
    ) -> JobRecord | None:
        with self._sessions() as session:
            row = session.scalar(
                select(JobRow).where(
                    JobRow.tenant_id == tenant_id,
                    JobRow.idempotency_key == idempotency_key,
                )
            )
            return _job_from_row(row) if row is not None else None

    def mark_running(
        self,
        tenant_id: str,
        job_id: str,
        *,
        require_queued: bool = True,
    ) -> JobRecord | None:
        now = _utcnow()
        expected = JobStatus.QUEUED if require_queued else JobStatus.RUNNING
        with self._sessions.begin() as session:
            result = session.execute(
                update(JobRow)
                .where(
                    JobRow.tenant_id == tenant_id,
                    JobRow.id == job_id,
                    JobRow.status == expected.value,
                    JobRow.cancel_requested.is_(False),
                )
                .values(
                    status=JobStatus.RUNNING.value,
                    attempt=JobRow.attempt + 1,
                    updated_at=now,
                    error_code=None,
                    error_message=None,
                )
            )
            if result.rowcount != 1:
                return None
            _append_event(
                session,
                tenant_id,
                job_id,
                "status",
                {"status": JobStatus.RUNNING.value},
                now,
            )
        return self.get(tenant_id, job_id)

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
        with self._sessions.begin() as session:
            row = _required_row(session, tenant_id, job_id, lock=True)
            row.status = status.value
            row.updated_at = now
            if result_count is not None:
                row.result_count = result_count
            row.error_code = error_code
            row.error_message = error_message
            payload: dict[str, Any] = {"status": status.value}
            if error_code:
                payload["error"] = {"code": error_code, "message": error_message}
            _append_event(session, tenant_id, job_id, "status", payload, now)
            _audit(
                session,
                tenant_id,
                "job.status_changed",
                "job",
                job_id,
                payload,
                now,
            )
        return self._required(tenant_id, job_id)

    def append_event(
        self,
        tenant_id: str,
        job_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> JobEvent:
        with self._sessions.begin() as session:
            _required_row(session, tenant_id, job_id, lock=True)
            event_row = _append_event(
                session, tenant_id, job_id, kind, payload, _utcnow()
            )
            session.flush()
            return _event_from_row(event_row)

    def list_events(
        self,
        tenant_id: str,
        job_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> list[JobEvent]:
        with self._sessions() as session:
            rows = session.scalars(
                select(JobEventRow)
                .where(
                    JobEventRow.tenant_id == tenant_id,
                    JobEventRow.job_id == job_id,
                    JobEventRow.sequence > after_sequence,
                )
                .order_by(JobEventRow.sequence.asc())
                .limit(limit)
            ).all()
            return [_event_from_row(row) for row in rows]

    def set_dispatch_id(self, tenant_id: str, job_id: str, dispatch_id: str) -> None:
        with self._sessions.begin() as session:
            session.execute(
                update(JobRow)
                .where(JobRow.tenant_id == tenant_id, JobRow.id == job_id)
                .values(dispatch_id=dispatch_id, updated_at=_utcnow())
            )

    def request_cancel(self, tenant_id: str, job_id: str) -> JobRecord:
        now = _utcnow()
        with self._sessions.begin() as session:
            row = _required_row(session, tenant_id, job_id, lock=True)
            current = JobStatus(row.status)
            if current.terminal:
                return _job_from_row(row)
            next_status = (
                JobStatus.CANCELLED if current is JobStatus.QUEUED else current
            )
            row.cancel_requested = True
            row.status = next_status.value
            row.updated_at = now
            payload = {"status": next_status.value}
            _append_event(
                session, tenant_id, job_id, "cancel_requested", payload, now
            )
            _audit(
                session,
                tenant_id,
                "job.cancel_requested",
                "job",
                job_id,
                payload,
                now,
            )
        return self._required(tenant_id, job_id)

    def ping(self) -> bool:
        try:
            with self.engine.connect() as connection:
                return connection.scalar(text("SELECT 1")) == 1
        except Exception:  # noqa: BLE001 - readiness must degrade
            return False

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    def _required(self, tenant_id: str, job_id: str) -> JobRecord:
        job = self.get(tenant_id, job_id)
        if job is None:
            raise KeyError(job_id)
        return job


def _ensure_tenant(session: Session, tenant_id: str, now: datetime) -> None:
    if session.get(TenantRow, tenant_id) is None:
        session.add(
            TenantRow(
                id=tenant_id,
                slug=tenant_id,
                name=tenant_id,
                status="active",
                retention_days=90,
                created_at=now,
                updated_at=now,
            )
        )
        session.flush()


def _required_row(
    session: Session, tenant_id: str, job_id: str, *, lock: bool = False
) -> JobRow:
    statement = select(JobRow).where(
        JobRow.tenant_id == tenant_id,
        JobRow.id == job_id,
    )
    if lock:
        statement = statement.with_for_update()
    row = session.scalar(statement)
    if row is None:
        raise KeyError(job_id)
    return row


def _append_event(
    session: Session,
    tenant_id: str,
    job_id: str,
    kind: str,
    payload: dict[str, Any],
    created_at: datetime,
) -> JobEventRow:
    sequence = session.scalar(
        select(func.coalesce(func.max(JobEventRow.sequence), 0) + 1).where(
            JobEventRow.tenant_id == tenant_id,
            JobEventRow.job_id == job_id,
        )
    )
    row = JobEventRow(
        tenant_id=tenant_id,
        job_id=job_id,
        sequence=int(sequence or 1),
        kind=kind,
        payload=dict(payload),
        created_at=created_at,
    )
    session.add(row)
    return row


def _audit(
    session: Session,
    tenant_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict[str, Any],
    created_at: datetime,
) -> None:
    session.add(
        AuditEventRow(
            id=f"audit_{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            actor="system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=None,
            outcome="success",
            details=dict(details),
            created_at=created_at,
        )
    )


def _job_from_row(row: JobRow) -> JobRecord:
    return JobRecord(
        id=row.id,
        tenant_id=row.tenant_id,
        source=FindingSource(row.source),
        payload=dict(row.input_payload),
        status=JobStatus(row.status),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
        idempotency_key=row.idempotency_key,
        dispatch_id=row.dispatch_id,
        attempt=row.attempt,
        cancel_requested=row.cancel_requested,
        result_count=row.result_count,
        error_code=row.error_code,
        error_message=row.error_message,
    )


def _event_from_row(row: JobEventRow) -> JobEvent:
    return JobEvent(
        sequence=row.sequence,
        job_id=row.job_id,
        tenant_id=row.tenant_id,
        kind=row.kind,
        payload=dict(row.payload),
        created_at=_as_utc(row.created_at),
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


__all__ = ["SQLAlchemyJobRepository", "create_database_engine"]
