"""Alembic M2 schema upgrade and rollback tests."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_m2_migration_upgrades_and_downgrades(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    database = tmp_path / "migration.db"
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))
    config.set_main_option(
        "sqlalchemy.url", f"sqlite+pysqlite:///{database.as_posix()}"
    )

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite+pysqlite:///{database.as_posix()}")
    expected = {
        "alembic_version",
        "api_keys",
        "audit_events",
        "correlation_findings",
        "correlations",
        "findings",
        "identity_clients",
        "job_events",
        "jobs",
        "memberships",
        "tenants",
        "users",
        "user_sessions",
    }
    assert expected.issubset(set(inspect(engine).get_table_names()))
    assert {column["name"] for column in inspect(engine).get_columns("findings")} >= {
        "tenant_id",
        "fingerprint",
        "status",
        "first_seen",
        "last_seen",
        "occurrences",
    }
    assert "status" in {
        column["name"] for column in inspect(engine).get_columns("memberships")
    }
    assert {
        "key_prefix",
        "secret_hash",
        "allowed_issuers",
        "rotated_from_id",
        "last_used_at",
        "revoked_at",
    }.issubset(
        {
            column["name"]
            for column in inspect(engine).get_columns("identity_clients")
        }
    )
    assert {
        "token_hash",
        "user_id",
        "tenant_id",
        "identity_client_id",
        "expires_at",
        "last_seen_at",
        "revoked_at",
    }.issubset(
        {
            column["name"] for column in inspect(engine).get_columns("user_sessions")
        }
    )
    engine.dispose()
    command.check(config)

    command.downgrade(config, "base")
    engine = create_engine(f"sqlite+pysqlite:///{database.as_posix()}")
    remaining = set(inspect(engine).get_table_names())
    assert not (expected - {"alembic_version"}) & remaining
    engine.dispose()
