"""Tenant-isolated SQLAlchemy Finding lifecycle, deduplication, and paging."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from shared_llm_core import (
    Correlation,
    Finding,
    FindingRegistry,
    FindingSeverity,
    FindingSource,
)
from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from shared_integration.auth import current_tenant
from shared_integration.db_models import (
    AuditEventRow,
    Base,
    CorrelationFindingRow,
    CorrelationRow,
    FindingRow,
    TenantRow,
)
from shared_integration.sql_jobs import create_database_engine

FindingStreamItem = tuple[str, Finding] | tuple[str, Correlation]
_UNSET = object()


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True)
class FindingLifecycleRecord:
    finding: Finding
    fingerprint: str
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    job_id: str | None
    assigned_to: str | None
    cursor: str

    def to_dict(self) -> dict[str, Any]:
        result = self.finding.to_dict()
        result.update(
            {
                "fingerprint": self.fingerprint,
                "status": self.status.value,
                "first_seen": self.first_seen.isoformat(),
                "last_seen": self.last_seen.isoformat(),
                "occurrences": self.occurrences,
                "job_id": self.job_id,
                "assigned_to": self.assigned_to,
            }
        )
        return result


class SQLAlchemyTenantFindingRegistry(FindingRegistry):
    """FindingRegistry compatible facade backed by the M2 relational schema."""

    def __init__(
        self,
        database_url: str,
        *,
        create_schema: bool = False,
        engine: Engine | None = None,
    ) -> None:
        super().__init__()
        self.engine = engine or create_database_engine(database_url)
        self._owns_engine = engine is None
        if create_schema:
            Base.metadata.create_all(self.engine)
        self._sessions = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=Session,
        )
        self._tenant_subscribers: dict[
            str, list[asyncio.Queue[FindingStreamItem]]
        ] = {}

    @property
    def findings(self) -> tuple[Finding, ...]:
        tenant_id = current_tenant()
        with self._sessions() as session:
            rows = session.scalars(
                select(FindingRow)
                .where(FindingRow.tenant_id == tenant_id)
                .order_by(FindingRow.row_id.asc())
            ).all()
            return tuple(_finding_from_row(row) for row in rows)

    @property
    def correlations(self) -> tuple[Correlation, ...]:
        tenant_id = current_tenant()
        with self._sessions() as session:
            rows = session.scalars(
                select(CorrelationRow)
                .where(CorrelationRow.tenant_id == tenant_id)
                .order_by(CorrelationRow.created_at.asc())
            ).all()
            if not rows:
                return ()
            links = session.scalars(
                select(CorrelationFindingRow).where(
                    CorrelationFindingRow.tenant_id == tenant_id
                )
            ).all()
            finding_ids: dict[str, list[str]] = {}
            for link in links:
                finding_ids.setdefault(link.correlation_id, []).append(link.finding_id)
            return tuple(
                Correlation(
                    rule_id=row.rule_id,
                    findings=tuple(finding_ids.get(row.id, ())),
                    severity=FindingSeverity(row.severity),
                    narrative=row.narrative,
                )
                for row in rows
            )

    async def add(self, finding: Finding) -> None:
        await self.add_for_job(finding, job_id=None)

    async def add_for_job(self, finding: Finding, *, job_id: str | None) -> None:
        tenant_id = current_tenant()
        stored = self._store_finding(tenant_id, finding, job_id=job_id)
        for queue in self._tenant_subscribers.get(tenant_id, ()):
            if not queue.full():
                queue.put_nowait(("finding", stored))

    async def add_correlation(self, correlation: Correlation) -> None:
        tenant_id = current_tenant()
        now = _utcnow()
        correlation_id = f"corr_{uuid.uuid4().hex}"
        with self._sessions.begin() as session:
            _ensure_tenant(session, tenant_id, now)
            session.add(
                CorrelationRow(
                    id=correlation_id,
                    tenant_id=tenant_id,
                    rule_id=correlation.rule_id,
                    rule_version="1",
                    severity=correlation.severity.value,
                    narrative=correlation.narrative,
                    created_at=now,
                )
            )
            session.flush()
            session.add_all(
                CorrelationFindingRow(
                    tenant_id=tenant_id,
                    correlation_id=correlation_id,
                    finding_id=finding_id,
                )
                for finding_id in correlation.findings
            )
        for queue in self._tenant_subscribers.get(tenant_id, ()):
            if not queue.full():
                queue.put_nowait(("correlation", correlation))

    def add_sync(self, finding: Finding) -> None:
        self._store_finding(current_tenant(), finding, job_id=None)

    def query(
        self,
        *,
        source: FindingSource | None = None,
        severity: FindingSeverity | None = None,
        host: str | None = None,
        cve: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        tenant_id = current_tenant()
        statement = select(FindingRow).where(FindingRow.tenant_id == tenant_id)
        if source is not None:
            statement = statement.where(FindingRow.source == source.value)
        if severity is not None:
            statement = statement.where(FindingRow.severity == severity.value)
        if host is not None:
            statement = statement.where(FindingRow.asset == host)
        if cve is not None:
            statement = statement.where(FindingRow.cve == cve)
        if since is not None:
            statement = statement.where(FindingRow.last_seen >= since)
        with self._sessions() as session:
            rows = session.scalars(
                statement.order_by(FindingRow.last_seen.desc()).limit(limit)
            ).all()
            return [_finding_from_row(row) for row in rows]

    async def subscribe(self) -> AsyncIterator[FindingStreamItem]:
        tenant_id = current_tenant()
        queue: asyncio.Queue[FindingStreamItem] = asyncio.Queue(maxsize=1000)
        subscribers = self._tenant_subscribers.setdefault(tenant_id, [])
        subscribers.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            subscribers.remove(queue)
            if not subscribers:
                self._tenant_subscribers.pop(tenant_id, None)

    def list_page(
        self,
        tenant_id: str,
        *,
        cursor: str | None = None,
        limit: int = 100,
        source: FindingSource | None = None,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
    ) -> tuple[list[FindingLifecycleRecord], str | None]:
        statement = select(FindingRow).where(FindingRow.tenant_id == tenant_id)
        if cursor is not None:
            statement = statement.where(FindingRow.row_id < _decode_cursor(cursor))
        if source is not None:
            statement = statement.where(FindingRow.source == source.value)
        if severity is not None:
            statement = statement.where(FindingRow.severity == severity.value)
        if status is not None:
            statement = statement.where(FindingRow.status == status.value)
        with self._sessions() as session:
            rows = session.scalars(
                statement.order_by(FindingRow.row_id.desc()).limit(limit + 1)
            ).all()
            has_more = len(rows) > limit
            page = rows[:limit]
            records = [_record_from_row(row) for row in page]
            next_cursor = (
                _encode_cursor(page[-1].row_id) if has_more and page else None
            )
            return records, next_cursor

    def update_lifecycle(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        status: FindingStatus | None = None,
        assigned_to: str | None | object = _UNSET,
        actor: str = "system",
    ) -> FindingLifecycleRecord | None:
        now = _utcnow()
        with self._sessions.begin() as session:
            row = session.scalar(
                select(FindingRow)
                .where(
                    FindingRow.tenant_id == tenant_id,
                    FindingRow.finding_id == finding_id,
                )
                .with_for_update()
            )
            if row is None:
                return None
            changes: dict[str, Any] = {}
            if status is not None and status.value != row.status:
                changes["status"] = {"from": row.status, "to": status.value}
                row.status = status.value
            if assigned_to is not _UNSET and assigned_to != row.assigned_to:
                changes["assigned_to"] = {
                    "from": row.assigned_to,
                    "to": assigned_to,
                }
                row.assigned_to = assigned_to  # type: ignore[assignment]
            row.updated_at = now
            session.add(
                AuditEventRow(
                    id=f"audit_{uuid.uuid4().hex}",
                    tenant_id=tenant_id,
                    actor=actor,
                    action="finding.updated",
                    resource_type="finding",
                    resource_id=finding_id,
                    request_id=None,
                    outcome="success",
                    details=changes,
                    created_at=now,
                )
            )
            session.flush()
            return _record_from_row(row)

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    def _store_finding(
        self, tenant_id: str, finding: Finding, *, job_id: str | None
    ) -> Finding:
        fingerprint = finding_fingerprint(finding)
        seen_at = _as_utc(finding.ts) if finding.ts is not None else _utcnow()
        now = _utcnow()
        try:
            with self._sessions.begin() as session:
                _ensure_tenant(session, tenant_id, now)
                row = session.scalar(
                    select(FindingRow)
                    .where(
                        FindingRow.tenant_id == tenant_id,
                        FindingRow.fingerprint == fingerprint,
                    )
                    .with_for_update()
                )
                if row is None:
                    row = FindingRow(
                        tenant_id=tenant_id,
                        finding_id=finding.id,
                        fingerprint=fingerprint,
                        source=finding.source.value,
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        status=FindingStatus.OPEN.value,
                        asset=finding.host,
                        cve=finding.cve,
                        title=finding.title,
                        description=finding.description,
                        first_seen=seen_at,
                        last_seen=seen_at,
                        occurrences=1,
                        job_id=job_id,
                        assigned_to=None,
                        payload=finding.to_dict(),
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                else:
                    existing = _finding_from_row(row)
                    merged = _merge_findings(existing, finding)
                    row.severity = merged.severity.value
                    row.confidence = merged.confidence
                    row.description = merged.description
                    row.last_seen = max(_as_utc(row.last_seen), seen_at)
                    row.first_seen = min(_as_utc(row.first_seen), seen_at)
                    row.occurrences += 1
                    row.job_id = job_id or row.job_id
                    row.payload = merged.to_dict()
                    row.updated_at = now
                session.flush()
                return _finding_from_row(row)
        except IntegrityError:
            # A concurrent insert won the tenant/fingerprint unique constraint.
            with self._sessions.begin() as session:
                row = session.scalar(
                    select(FindingRow)
                    .where(
                        FindingRow.tenant_id == tenant_id,
                        FindingRow.fingerprint == fingerprint,
                    )
                    .with_for_update()
                )
                if row is None:
                    raise
                merged = _merge_findings(_finding_from_row(row), finding)
                row.occurrences += 1
                row.last_seen = max(_as_utc(row.last_seen), seen_at)
                row.payload = merged.to_dict()
                row.updated_at = now
                session.flush()
                return _finding_from_row(row)


def finding_fingerprint(finding: Finding) -> str:
    """Return a stable tenant-local identity independent of product UUIDs."""
    metadata = finding.metadata if isinstance(finding.metadata, Mapping) else {}
    locators = {
        key: metadata[key]
        for key in (
            "asset",
            "component",
            "file",
            "line",
            "path",
            "rule_id",
            "symbol",
        )
        if key in metadata
    }
    identity = {
        "source": finding.source.value,
        "title": finding.title.strip().casefold(),
        "host": (finding.host or "").strip().casefold(),
        "cve": (finding.cve or "").strip().upper(),
        "locators": locators,
    }
    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _merge_findings(existing: Finding, incoming: Finding) -> Finding:
    severity_rank = {
        FindingSeverity.INFO: 0,
        FindingSeverity.LOW: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.HIGH: 3,
        FindingSeverity.CRITICAL: 4,
    }
    severity = max(
        (existing.severity, incoming.severity), key=severity_rank.__getitem__
    )
    return replace(
        incoming,
        id=existing.id,
        severity=severity,
        confidence=max(existing.confidence, incoming.confidence),
        evidence=tuple(dict.fromkeys((*existing.evidence, *incoming.evidence))),
        related=tuple(dict.fromkeys((*existing.related, *incoming.related))),
        tags=existing.tags | incoming.tags,
    )


def _finding_from_row(row: FindingRow) -> Finding:
    return Finding.from_dict(dict(row.payload))


def _record_from_row(row: FindingRow) -> FindingLifecycleRecord:
    return FindingLifecycleRecord(
        finding=_finding_from_row(row),
        fingerprint=row.fingerprint,
        status=FindingStatus(row.status),
        first_seen=_as_utc(row.first_seen),
        last_seen=_as_utc(row.last_seen),
        occurrences=row.occurrences,
        job_id=row.job_id,
        assigned_to=row.assigned_to,
        cursor=_encode_cursor(row.row_id),
    )


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


def _encode_cursor(row_id: int) -> str:
    return base64.urlsafe_b64encode(str(row_id).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> int:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = int(base64.urlsafe_b64decode(padded).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid finding cursor") from exc
    if value < 1:
        raise ValueError("invalid finding cursor")
    return value


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


__all__ = [
    "FindingLifecycleRecord",
    "FindingStatus",
    "SQLAlchemyTenantFindingRegistry",
    "finding_fingerprint",
]
