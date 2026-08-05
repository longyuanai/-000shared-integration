"""Legacy SQLite to relational M2 migration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from shared_llm_core import Correlation, Finding, FindingSeverity, FindingSource
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.db_models import (
    AuditEventRow,
    Base,
    CorrelationFindingRow,
    CorrelationRow,
    FindingRow,
    JobEventRow,
    JobRow,
    TenantRow,
)
from shared_integration.jobs import JobStatus, SQLiteJobRepository
from shared_integration.migration_tools import LegacySQLiteMigrator, MigrationCounts
from shared_integration.persistence import SQLiteTenantFindingRegistry
from shared_integration.sql_jobs import create_database_engine


async def _legacy_database(path: Path) -> str:
    jobs = SQLiteJobRepository(path)
    job, _ = jobs.create(
        tenant_id="tenant-a",
        source=FindingSource.CODE,
        payload={"repository": "legacy"},
        idempotency_key="legacy-request",
    )
    jobs.mark_running("tenant-a", job.id)
    jobs.transition("tenant-a", job.id, JobStatus.SUCCEEDED, result_count=1)
    jobs.close()

    registry = SQLiteTenantFindingRegistry(path)
    token = bind_tenant("tenant-a")
    try:
        await registry.add(
            Finding(
                id="finding-legacy",
                source=FindingSource.CODE,
                severity=FindingSeverity.HIGH,
                confidence=0.91,
                title="Legacy SQL injection",
                host="api-01",
            )
        )
        await registry.add_correlation(
            Correlation(
                rule_id="legacy-rule",
                findings=("finding-legacy",),
                severity=FindingSeverity.HIGH,
                narrative="Legacy correlation",
            )
        )
    finally:
        reset_tenant(token)
        registry.close()
    return job.id


def _count(engine: Engine, model: type) -> int:
    with Session(engine) as session:
        return int(session.scalar(select(func.count()).select_from(model)) or 0)


async def test_dry_run_does_not_write_and_apply_is_repeatable(tmp_path: Path) -> None:
    source = tmp_path / "legacy.sqlite3"
    job_id = await _legacy_database(source)
    target_url = f"sqlite:///{tmp_path / 'target.sqlite3'}"
    engine = create_database_engine(target_url)
    Base.metadata.create_all(engine)
    migrator = LegacySQLiteMigrator(source, target_url, engine=engine)

    dry_run = migrator.run()
    assert dry_run.dry_run is True
    assert dry_run.source == MigrationCounts(
        tenants=1,
        jobs=1,
        job_events=3,
        findings=1,
        correlations=1,
    )
    assert _count(engine, TenantRow) == 0

    first = migrator.run(apply=True)
    assert first.dry_run is False
    assert first.imported == dry_run.source
    assert first.skipped == MigrationCounts()
    assert _count(engine, TenantRow) == 1
    assert _count(engine, JobRow) == 1
    assert _count(engine, JobEventRow) == 3
    assert _count(engine, FindingRow) == 1
    assert _count(engine, CorrelationRow) == 1
    assert _count(engine, CorrelationFindingRow) == 1
    assert _count(engine, AuditEventRow) == 1

    with Session(engine) as session:
        job = session.get(JobRow, job_id)
        assert job is not None
        assert job.status == "succeeded"
        assert job.result_count == 1
        finding = session.scalar(select(FindingRow))
        assert finding is not None
        assert finding.finding_id == "finding-legacy"
        assert finding.occurrences == 1
        link = session.scalar(select(CorrelationFindingRow))
        assert link is not None
        assert link.finding_id == "finding-legacy"

    repeated = migrator.run(apply=True)
    assert repeated.imported == MigrationCounts()
    assert repeated.skipped == dry_run.source
    assert _count(engine, AuditEventRow) == 1
    assert _count(engine, FindingRow) == 1
    with Session(engine) as session:
        finding = session.scalar(select(FindingRow))
        assert finding is not None
        assert finding.occurrences == 1

    migrator.close()
    engine.dispose()


async def test_fingerprint_dedup_maps_correlation_to_existing_finding(
    tmp_path: Path,
) -> None:
    source = tmp_path / "legacy.sqlite3"
    await _legacy_database(source)
    target_url = f"sqlite:///{tmp_path / 'target.sqlite3'}"
    engine = create_database_engine(target_url)
    Base.metadata.create_all(engine)
    migrator = LegacySQLiteMigrator(source, target_url, engine=engine)
    now = datetime.now(UTC)

    from shared_integration.finding_lifecycle import finding_fingerprint

    equivalent = Finding(
        id="existing-finding",
        source=FindingSource.CODE,
        severity=FindingSeverity.HIGH,
        confidence=0.99,
        title="Legacy SQL injection",
        host="api-01",
    )
    with Session(engine) as session, session.begin():
        session.add(
            TenantRow(
                id="tenant-a",
                slug="tenant-a",
                name="Existing Tenant",
                status="active",
                retention_days=90,
                created_at=now,
                updated_at=now,
            )
        )
        session.flush()
        session.add(
            FindingRow(
                tenant_id="tenant-a",
                finding_id=equivalent.id,
                fingerprint=finding_fingerprint(equivalent),
                source=equivalent.source.value,
                severity=equivalent.severity.value,
                confidence=equivalent.confidence,
                status="open",
                asset=equivalent.host,
                title=equivalent.title,
                description="",
                first_seen=now,
                last_seen=now,
                occurrences=1,
                payload=equivalent.to_dict(),
                created_at=now,
                updated_at=now,
            )
        )

    report = migrator.run(apply=True)
    assert report.skipped.findings == 1
    assert _count(engine, FindingRow) == 1
    with Session(engine) as session:
        link = session.scalar(select(CorrelationFindingRow))
        assert link is not None
        assert link.finding_id == "existing-finding"

    engine.dispose()
