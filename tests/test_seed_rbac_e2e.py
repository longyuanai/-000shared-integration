"""Tests for isolated real-browser RBAC fixture management."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from shared_integration.db_models import (
    IdentityClientRow,
    MembershipRow,
    TenantRow,
    UserRow,
)
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.scripts.seed_rbac_e2e import (
    ISSUER,
    _subject,
    cleanup,
    expire_sessions,
    provision,
    set_membership_status,
    snapshot,
)


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    value = f"sqlite+pysqlite:///{tmp_path / 'rbac-e2e.sqlite3'}"
    repository = SQLAlchemyIdentityRepository(value, create_schema=True)
    repository.close()
    return value


def test_provision_creates_tagged_tenants_roles_and_hashed_client(
    database_url: str,
) -> None:
    fixture = provision("round-1", database_url=database_url)

    assert fixture["tenant_a"] == "e2e-rbac-round-1-a"
    assert fixture["tenant_b"] == "e2e-rbac-round-1-b"
    assert set(fixture["identities"]) == {
        "viewer",
        "analyst",
        "admin",
        "cross",
        "revoked",
        "expiring",
        "logout",
        "refresh",
        "no-member",
    }
    assert snapshot("round-1", database_url=database_url) == {
        "tenants": 2,
        "users": 9,
        "clients": 1,
        "sessions": 0,
        "findings": 2,
        "jobs": 2,
    }
    repository = SQLAlchemyIdentityRepository(database_url)
    try:
        with Session(repository.engine) as session:
            client = session.scalar(select(IdentityClientRow))
            assert client is not None
            assert client.secret_hash.startswith("scrypt$")
            assert fixture["bridge_token"] not in client.secret_hash
            assert fixture["bridge_token"].partition(".")[2] not in client.secret_hash
    finally:
        repository.close()


def test_membership_and_expiry_controls_are_limited_to_fixture_personas(
    database_url: str,
) -> None:
    fixture = provision("controls", database_url=database_url)
    repository = SQLAlchemyIdentityRepository(database_url)
    try:
        user = repository.upsert_user(
            issuer=ISSUER,
            subject=_subject("controls", "expiring"),
        )
        session = repository.issue_user_session(
            identity_client_id=fixture["identity_client_id"],
            tenant_id=fixture["tenant_a"],
            user_id=user.id,
        )
        assert repository.authenticate_user_session(session.token) is not None
        result = expire_sessions(
            "controls", "expiring", database_url=database_url
        )
        assert result["expired_sessions"] == 1
        assert repository.authenticate_user_session(session.token) is None

        set_membership_status(
            "controls", "revoked", "suspended", database_url=database_url
        )
        with Session(repository.engine) as sql_session:
            revoked_user_id = sql_session.scalar(
                select(MembershipRow.user_id)
                .join(UserRow, UserRow.id == MembershipRow.user_id)
                .where(
                    MembershipRow.tenant_id == fixture["tenant_a"],
                    MembershipRow.status == "suspended",
                    UserRow.subject == _subject("controls", "revoked"),
                )
            )
        assert revoked_user_id is not None
    finally:
        repository.close()


def test_cleanup_preserves_unlabelled_data_and_removes_all_fixture_rows(
    database_url: str,
) -> None:
    unrelated = SQLAlchemyIdentityRepository(database_url)
    unrelated.create_tenant(
        tenant_id="keep-tenant",
        slug="keep-tenant",
        name="Keep Tenant",
    )
    fixture = provision("cleanup", database_url=database_url)
    user = unrelated.upsert_user(issuer=ISSUER, subject=_subject("cleanup", "viewer"))
    unrelated.issue_user_session(
        identity_client_id=fixture["identity_client_id"],
        tenant_id=fixture["tenant_a"],
        user_id=user.id,
    )
    unrelated.close()

    removed = cleanup("cleanup", database_url=database_url)

    assert removed["sessions"] == 1
    assert all(value == 0 for value in snapshot("cleanup", database_url=database_url).values())
    repository = SQLAlchemyIdentityRepository(database_url)
    try:
        with Session(repository.engine) as session:
            assert session.get(TenantRow, "keep-tenant") is not None
    finally:
        repository.close()


@pytest.mark.parametrize("run_id", ["", "bad space", "a" * 33])
def test_run_id_rejects_unscoped_labels(database_url: str, run_id: str) -> None:
    with pytest.raises(ValueError, match="run-id"):
        provision(run_id, database_url=database_url)
