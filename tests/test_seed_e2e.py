"""Regression checks for deterministic E2E seed identifiers."""

from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from shared_integration.db_models import FindingRow, JobRow
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.scripts.seed_e2e import (
    SEED_FINDINGS,
    _seed_fingerprint,
    seed,
)
from shared_integration.sql_jobs import create_database_engine


def test_seed_fingerprints_fit_persistence_contract() -> None:
    fingerprints = {
        _seed_fingerprint("e2e", finding) for finding in SEED_FINDINGS
    }

    assert len(fingerprints) == len(SEED_FINDINGS)
    assert all(value.startswith("e2e:") for value in fingerprints)
    assert all(len(value) == 64 for value in fingerprints)


def test_seed_is_repeatable_against_current_schema(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'seed.sqlite3'}"
    identity = SQLAlchemyIdentityRepository(database_url, create_schema=True)
    identity.create_tenant(tenant_id="e2e", slug="e2e", name="E2E")
    monkeypatch.setenv("INTEGRATION_DATABASE_URL", database_url)

    try:
        assert seed("e2e", reset=True) == {"findings": 7, "jobs": 3}
        assert seed("e2e", reset=True) == {"findings": 7, "jobs": 3}

        engine = create_database_engine(database_url)
        try:
            with Session(engine) as session:
                assert session.scalar(select(func.count()).select_from(FindingRow)) == 7
                assert session.scalar(select(func.count()).select_from(JobRow)) == 3
        finally:
            engine.dispose()
    finally:
        identity.close()
