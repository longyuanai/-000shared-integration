"""Opt-in concurrency checks against a real migrated PostgreSQL database."""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from shared_llm_core import Finding, FindingSeverity, FindingSource
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.db_models import FindingRow, TenantRow
from shared_integration.finding_lifecycle import SQLAlchemyTenantFindingRegistry
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.jobs import JobStatus, SQLiteJobRepository
from shared_integration.migration_tools import LegacySQLiteMigrator, MigrationCounts
from shared_integration.persistence import SQLiteTenantFindingRegistry
from shared_integration.sql_jobs import SQLAlchemyJobRepository, create_database_engine


def _postgres_url() -> str:
    value = os.getenv("INTEGRATION_TEST_POSTGRES_URL", "").strip()
    if not value:
        pytest.skip("INTEGRATION_TEST_POSTGRES_URL is not configured")
    if not value.startswith("postgresql"):
        pytest.fail("INTEGRATION_TEST_POSTGRES_URL must point to PostgreSQL")
    return value


def test_postgres_concurrent_idempotency_claim_and_finding_dedup() -> None:
    database_url = _postgres_url()
    suffix = uuid.uuid4().hex[:12]
    tenant_a = f"concurrency-a-{suffix}"
    tenant_b = f"concurrency-b-{suffix}"
    engine = create_database_engine(database_url)
    identity = SQLAlchemyIdentityRepository(database_url)
    jobs = SQLAlchemyJobRepository(database_url)
    findings = SQLAlchemyTenantFindingRegistry(database_url)

    def clean() -> None:
        with Session(engine) as session, session.begin():
            session.execute(
                delete(TenantRow).where(TenantRow.id.in_([tenant_a, tenant_b]))
            )

    clean()
    try:
        identity.create_tenant(
            tenant_id=tenant_a,
            slug=tenant_a,
            name="Concurrency Tenant A",
        )
        identity.create_tenant(
            tenant_id=tenant_b,
            slug=tenant_b,
            name="Concurrency Tenant B",
        )
        issued = identity.issue_api_key(tenant_id=tenant_a, role="analyst")
        with ThreadPoolExecutor(max_workers=12) as pool:
            principals = list(
                pool.map(identity.authenticate_api_key, [issued.token] * 24)
            )
        assert all(principal is not None for principal in principals)
        assert {principal.tenant_id for principal in principals if principal} == {
            tenant_a
        }

        def create_idempotent(index: int) -> tuple[str, bool]:
            job, created = jobs.create(
                tenant_id=tenant_a,
                source=FindingSource.CODE,
                payload={"caller": index},
                idempotency_key="same-concurrent-request",
            )
            return job.id, created

        with ThreadPoolExecutor(max_workers=12) as pool:
            created_jobs = list(pool.map(create_idempotent, range(24)))
        assert len({job_id for job_id, _ in created_jobs}) == 1
        assert sum(created for _, created in created_jobs) == 1
        job_id = created_jobs[0][0]

        with ThreadPoolExecutor(max_workers=12) as pool:
            claims = list(
                pool.map(
                    lambda _: jobs.mark_running(tenant_a, job_id),
                    range(24),
                )
            )
        successful_claims = [claim for claim in claims if claim is not None]
        assert len(successful_claims) == 1
        assert successful_claims[0].attempt == 1

        other_job, other_created = jobs.create(
            tenant_id=tenant_b,
            source=FindingSource.CODE,
            payload={"tenant": "b"},
            idempotency_key="same-concurrent-request",
        )
        assert other_created is True
        assert other_job.id != job_id

        def add_finding(index: int, tenant_id: str = tenant_a) -> None:
            tenant_token = bind_tenant(tenant_id)
            try:
                findings.add_sync(
                    Finding(
                        id=f"finding-{tenant_id}-{index}",
                        source=FindingSource.CODE,
                        severity=(
                            FindingSeverity.CRITICAL
                            if index == 23
                            else FindingSeverity.HIGH
                        ),
                        confidence=0.5 + index / 100,
                        title="Concurrent SQL injection",
                        host="api-01",
                        evidence=(f"evidence-{index}",),
                    )
                )
            finally:
                reset_tenant(tenant_token)

        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(add_finding, range(24)))
        add_finding(0, tenant_b)

        with Session(engine) as session:
            tenant_a_rows = session.scalars(
                select(FindingRow).where(FindingRow.tenant_id == tenant_a)
            ).all()
            assert len(tenant_a_rows) == 1
            assert tenant_a_rows[0].occurrences == 24
            assert tenant_a_rows[0].severity == FindingSeverity.CRITICAL.value
            assert len(tenant_a_rows[0].payload["evidence"]) == 24
            tenant_b_count = session.scalar(
                select(func.count())
                .select_from(FindingRow)
                .where(FindingRow.tenant_id == tenant_b)
            )
            assert tenant_b_count == 1
    finally:
        clean()
        findings.close()
        jobs.close()
        identity.close()
        engine.dispose()


async def test_legacy_sqlite_import_into_postgres_is_repeatable(
    tmp_path: Path,
) -> None:
    database_url = _postgres_url()
    suffix = uuid.uuid4().hex[:12]
    tenant_id = f"migration-{suffix}"
    source_path = tmp_path / "legacy.sqlite3"
    legacy_jobs = SQLiteJobRepository(source_path)
    job, _ = legacy_jobs.create(
        tenant_id=tenant_id,
        source=FindingSource.SOC,
        payload={"host": "legacy-api"},
    )
    legacy_jobs.mark_running(tenant_id, job.id)
    legacy_jobs.transition(tenant_id, job.id, JobStatus.SUCCEEDED, result_count=1)
    legacy_jobs.close()
    legacy_findings = SQLiteTenantFindingRegistry(source_path)
    tenant_token = bind_tenant(tenant_id)
    try:
        await legacy_findings.add(
            Finding(
                id="legacy-postgres-finding",
                source=FindingSource.SOC,
                severity=FindingSeverity.HIGH,
                confidence=0.9,
                title="Legacy PostgreSQL migration",
                host="legacy-api",
            )
        )
    finally:
        reset_tenant(tenant_token)
        legacy_findings.close()

    engine = create_database_engine(database_url)
    migrator = LegacySQLiteMigrator(source_path, database_url)
    try:
        dry_run = migrator.run()
        assert dry_run.source == MigrationCounts(
            tenants=1,
            jobs=1,
            job_events=3,
            findings=1,
        )
        applied = migrator.run(apply=True)
        assert applied.imported == dry_run.source
        repeated = migrator.run(apply=True)
        assert repeated.imported == MigrationCounts()
        assert repeated.skipped == dry_run.source
        with Session(engine) as session:
            finding = session.scalar(
                select(FindingRow).where(FindingRow.tenant_id == tenant_id)
            )
            assert finding is not None
            assert finding.occurrences == 1
    finally:
        with Session(engine) as session, session.begin():
            session.execute(delete(TenantRow).where(TenantRow.id == tenant_id))
        migrator.close()
        engine.dispose()
