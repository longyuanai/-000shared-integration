"""One-time, repeatable migration from the legacy SQLite gateway database."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shared_llm_core import Finding, FindingSource
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from shared_integration.db_models import (
    AuditEventRow,
    CorrelationFindingRow,
    CorrelationRow,
    FindingRow,
    JobEventRow,
    JobRow,
    TenantRow,
)
from shared_integration.finding_lifecycle import FindingStatus, finding_fingerprint
from shared_integration.sql_jobs import create_database_engine

_QUEUES = {
    FindingSource.SOC: "fast",
    FindingSource.VULN: "analysis",
    FindingSource.LAB: "sandbox",
    FindingSource.CODE: "analysis",
    FindingSource.REVERSE: "sandbox",
    FindingSource.FIRMWARE: "sandbox",
    FindingSource.EXTERNAL: "analysis",
}
_LEGACY_TABLES = frozenset({"scan_jobs", "scan_job_events", "findings", "correlations"})


@dataclass(frozen=True)
class MigrationCounts:
    tenants: int = 0
    jobs: int = 0
    job_events: int = 0
    findings: int = 0
    correlations: int = 0


@dataclass(frozen=True)
class MigrationReport:
    dry_run: bool
    source: MigrationCounts
    imported: MigrationCounts
    skipped: MigrationCounts

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LegacySQLiteMigrator:
    """Copy legacy rows transactionally while making reruns no-ops."""

    def __init__(
        self,
        source_path: str | Path,
        database_url: str,
        *,
        engine: Engine | None = None,
    ) -> None:
        self.source_path = Path(source_path).resolve()
        if not self.source_path.is_file():
            raise FileNotFoundError(self.source_path)
        self.engine = engine or create_database_engine(database_url)
        self._owns_engine = engine is None
        self._sessions = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=Session,
        )

    def run(self, *, apply: bool = False) -> MigrationReport:
        with self._source_connection() as source:
            tables = _source_tables(source)
            if not tables & _LEGACY_TABLES:
                raise ValueError("source does not contain a legacy gateway schema")
            source_rows = _read_source(source, tables)
        source_counts = _count_source(source_rows)
        if not apply:
            return MigrationReport(
                dry_run=True,
                source=source_counts,
                imported=MigrationCounts(),
                skipped=MigrationCounts(),
            )

        imported = _MutableCounts()
        skipped = _MutableCounts()
        now = _utcnow()
        with self._sessions.begin() as session:
            tenant_ids = _tenant_ids(source_rows)
            for tenant_id in tenant_ids:
                if session.get(TenantRow, tenant_id) is None:
                    session.add(
                        TenantRow(
                            id=tenant_id,
                            slug=_legacy_slug(tenant_id),
                            name=f"Imported tenant {tenant_id}",
                            status="active",
                            retention_days=90,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                    imported.tenants += 1
                else:
                    skipped.tenants += 1
            session.flush()
            _import_jobs(session, source_rows["scan_jobs"], imported, skipped)
            _import_job_events(
                session, source_rows["scan_job_events"], imported, skipped
            )
            finding_ids = _import_findings(
                session, source_rows["findings"], imported, skipped, now
            )
            _import_correlations(
                session,
                source_rows["correlations"],
                finding_ids,
                imported,
                skipped,
                now,
            )
            for tenant_id in tenant_ids:
                _migration_audit(
                    session,
                    tenant_id,
                    self.source_path,
                    source_counts,
                    imported.freeze(),
                    now,
                )
        return MigrationReport(
            dry_run=False,
            source=source_counts,
            imported=imported.freeze(),
            skipped=skipped.freeze(),
        )

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    def _source_connection(self) -> sqlite3.Connection:
        uri_path = self.source_path.as_posix()
        connection = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection


@dataclass
class _MutableCounts:
    tenants: int = 0
    jobs: int = 0
    job_events: int = 0
    findings: int = 0
    correlations: int = 0

    def freeze(self) -> MigrationCounts:
        return MigrationCounts(**asdict(self))


def _source_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def _read_source(
    connection: sqlite3.Connection, tables: set[str]
) -> dict[str, list[sqlite3.Row]]:
    result: dict[str, list[sqlite3.Row]] = {}
    ordering = {
        "scan_jobs": "created_at, job_id",
        "scan_job_events": "tenant_id, job_id, sequence",
        "findings": "seq",
        "correlations": "seq",
    }
    for table in _LEGACY_TABLES:
        result[table] = (
            list(connection.execute(f"SELECT * FROM {table} ORDER BY {ordering[table]}"))
            if table in tables
            else []
        )
    return result


def _count_source(rows: dict[str, list[sqlite3.Row]]) -> MigrationCounts:
    return MigrationCounts(
        tenants=len(_tenant_ids(rows)),
        jobs=len(rows["scan_jobs"]),
        job_events=len(rows["scan_job_events"]),
        findings=len(rows["findings"]),
        correlations=len(rows["correlations"]),
    )


def _tenant_ids(rows: dict[str, list[sqlite3.Row]]) -> list[str]:
    values = {
        str(row["tenant_id"])
        for table_rows in rows.values()
        for row in table_rows
        if "tenant_id" in row.keys()
    }
    return sorted(values)


def _import_jobs(
    session: Session,
    rows: list[sqlite3.Row],
    imported: _MutableCounts,
    skipped: _MutableCounts,
) -> None:
    for row in rows:
        existing = session.get(JobRow, row["job_id"])
        if existing is not None:
            if existing.tenant_id != row["tenant_id"]:
                raise ValueError(
                    f"job ID collision across tenants: {row['job_id']}"
                )
            skipped.jobs += 1
            continue
        source = FindingSource(row["source"])
        session.add(
            JobRow(
                id=row["job_id"],
                tenant_id=row["tenant_id"],
                source=source.value,
                status=row["status"],
                queue=_QUEUES[source],
                input_payload=_json_object(row["payload"], "job payload"),
                progress=1.0 if row["status"] == "succeeded" else 0.0,
                timeout_at=None,
                created_by="legacy-sqlite-migration",
                idempotency_key=row["idempotency_key"],
                dispatch_id=row["dispatch_id"],
                attempt=int(row["attempt"]),
                cancel_requested=bool(row["cancel_requested"]),
                result_count=int(row["result_count"]),
                error_code=row["error_code"],
                error_message=row["error_message"],
                created_at=_parse_datetime(row["created_at"]),
                updated_at=_parse_datetime(row["updated_at"]),
            )
        )
        imported.jobs += 1
    session.flush()


def _import_job_events(
    session: Session,
    rows: list[sqlite3.Row],
    imported: _MutableCounts,
    skipped: _MutableCounts,
) -> None:
    for row in rows:
        key = (row["tenant_id"], row["job_id"], int(row["sequence"]))
        exists = session.scalar(
            select(JobEventRow.row_id).where(
                JobEventRow.tenant_id == key[0],
                JobEventRow.job_id == key[1],
                JobEventRow.sequence == key[2],
            )
        )
        if exists is not None:
            skipped.job_events += 1
            continue
        if session.get(JobRow, row["job_id"]) is None:
            raise ValueError(f"job event references missing job: {row['job_id']}")
        session.add(
            JobEventRow(
                tenant_id=key[0],
                job_id=key[1],
                sequence=key[2],
                kind=row["kind"],
                payload=_json_object(row["payload"], "job event payload"),
                created_at=_parse_datetime(row["created_at"]),
            )
        )
        imported.job_events += 1
    session.flush()


def _import_findings(
    session: Session,
    rows: list[sqlite3.Row],
    imported: _MutableCounts,
    skipped: _MutableCounts,
    now: datetime,
) -> dict[tuple[str, str], str]:
    finding_ids: dict[tuple[str, str], str] = {}
    for row in rows:
        tenant_id = str(row["tenant_id"])
        finding = Finding.from_dict(_json_object(row["payload"], "finding payload"))
        fingerprint = finding_fingerprint(finding)
        existing = session.scalar(
            select(FindingRow).where(
                FindingRow.tenant_id == tenant_id,
                FindingRow.fingerprint == fingerprint,
            )
        )
        if existing is not None:
            finding_ids[(tenant_id, finding.id)] = existing.finding_id
            skipped.findings += 1
            continue
        id_collision = session.scalar(
            select(FindingRow).where(
                FindingRow.tenant_id == tenant_id,
                FindingRow.finding_id == finding.id,
            )
        )
        if id_collision is not None:
            raise ValueError(
                f"finding ID has a different fingerprint: {tenant_id}/{finding.id}"
            )
        seen_at = _parse_finding_timestamp(finding, now)
        session.add(
            FindingRow(
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
                job_id=None,
                assigned_to=None,
                payload=finding.to_dict(),
                created_at=now,
                updated_at=now,
            )
        )
        finding_ids[(tenant_id, finding.id)] = finding.id
        imported.findings += 1
    session.flush()
    return finding_ids


def _import_correlations(
    session: Session,
    rows: list[sqlite3.Row],
    finding_ids: dict[tuple[str, str], str],
    imported: _MutableCounts,
    skipped: _MutableCounts,
    now: datetime,
) -> None:
    for row in rows:
        tenant_id = str(row["tenant_id"])
        payload = _json_object(row["payload"], "correlation payload")
        correlation_id = _legacy_correlation_id(tenant_id, int(row["seq"]), payload)
        if session.get(CorrelationRow, correlation_id) is not None:
            skipped.correlations += 1
            continue
        source_finding_ids = payload.get("findings", [])
        if not isinstance(source_finding_ids, list):
            raise ValueError("correlation findings must be a list")
        mapped_ids = [
            finding_ids.get((tenant_id, str(finding_id)), str(finding_id))
            for finding_id in source_finding_ids
        ]
        session.add(
            CorrelationRow(
                id=correlation_id,
                tenant_id=tenant_id,
                rule_id=str(payload["rule_id"]),
                rule_version="legacy",
                severity=str(payload["severity"]),
                narrative=str(payload["narrative"]),
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
            for finding_id in dict.fromkeys(mapped_ids)
        )
        imported.correlations += 1
    session.flush()


def _migration_audit(
    session: Session,
    tenant_id: str,
    source_path: Path,
    source_counts: MigrationCounts,
    imported: MigrationCounts,
    now: datetime,
) -> None:
    source_key = hashlib.sha256(str(source_path).encode("utf-8")).hexdigest()[:16]
    audit_id = f"audit_migration_{source_key}_{_short_hash(tenant_id)}"
    if session.get(AuditEventRow, audit_id) is not None:
        return
    session.add(
        AuditEventRow(
            id=audit_id,
            tenant_id=tenant_id,
            actor="legacy-sqlite-migration",
            action="migration.legacy_sqlite",
            resource_type="tenant",
            resource_id=tenant_id,
            outcome="success",
            details={
                "source": asdict(source_counts),
                "imported": asdict(imported),
            },
            created_at=now,
        )
    )


def _legacy_slug(tenant_id: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", tenant_id.casefold()).strip("-") or "tenant"
    return f"legacy-{base[:96]}-{_short_hash(tenant_id)}"


def _legacy_correlation_id(
    tenant_id: str, sequence: int, payload: dict[str, Any]
) -> str:
    canonical = json.dumps(
        {"tenant": tenant_id, "sequence": sequence, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"corr_legacy_{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _json_object(payload: str, label: str) -> dict[str, Any]:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _parse_finding_timestamp(finding: Finding, fallback: datetime) -> datetime:
    if finding.ts is None:
        return fallback
    return (
        finding.ts.replace(tzinfo=UTC)
        if finding.ts.tzinfo is None
        else finding.ts.astimezone(UTC)
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "LegacySQLiteMigrator",
    "MigrationCounts",
    "MigrationReport",
]
