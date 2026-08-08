"""Identity bridge credentials and short-lived user session tests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from shared_integration.db_models import (
    AuditEventRow,
    IdentityClientRow,
    UserSessionRow,
)
from shared_integration.identity import SQLAlchemyIdentityRepository

ISSUER = "https://identity.example.test"


@pytest.fixture
def identity(tmp_path: Path) -> SQLAlchemyIdentityRepository:
    repository = SQLAlchemyIdentityRepository(
        f"sqlite:///{tmp_path / 'identity-sessions.sqlite3'}",
        create_schema=True,
    )
    yield repository
    repository.close()


def _provision(
    identity: SQLAlchemyIdentityRepository,
) -> tuple[str, str, str]:
    identity.create_tenant(
        tenant_id="tenant-a",
        slug="tenant-a",
        name="Tenant A",
    )
    user = identity.upsert_user(
        issuer=ISSUER,
        subject="subject-a",
        email="analyst@example.test",
    )
    identity.set_membership(
        tenant_id="tenant-a",
        user_id=user.id,
        role="analyst",
    )
    client = identity.issue_identity_client(
        name="Dashboard BFF",
        allowed_issuers=[ISSUER],
    )
    return user.id, client.record.id, client.token


def test_identity_client_secret_is_hashed_and_list_is_metadata_only(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    issued = identity.issue_identity_client(
        name=" Dashboard BFF ",
        allowed_issuers=[ISSUER, ISSUER],
    )

    with Session(identity.engine) as session:
        row = session.get(IdentityClientRow, issued.record.id)
        assert row is not None
        assert row.secret_hash.startswith("scrypt$")
        assert issued.token not in row.secret_hash
        assert issued.token.partition(".")[2] not in row.secret_hash

    records = identity.list_identity_clients()
    assert len(records) == 1
    assert records[0].name == "Dashboard BFF"
    assert records[0].key_prefix.startswith("igb_")
    assert records[0].allowed_issuers == (ISSUER,)
    assert not hasattr(records[0], "secret_hash")
    assert issued.token not in repr(records[0])


def test_identity_client_auth_requires_exact_allowed_issuer(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    issued = identity.issue_identity_client(
        name="Dashboard BFF",
        allowed_issuers=[ISSUER, "https://second.example.test"],
    )

    principal = identity.authenticate_identity_client(
        issued.token,
        issuer=ISSUER,
    )
    assert principal is not None
    assert principal.identity_client_id == issued.record.id
    assert principal.scopes == ("auth:exchange",)
    assert (
        identity.authenticate_identity_client(
            issued.token,
            issuer="https://unknown.example.test",
        )
        is None
    )
    assert identity.authenticate_identity_client("not-a-key", issuer=ISSUER) is None
    with Session(identity.engine) as session:
        row = session.get(IdentityClientRow, issued.record.id)
        assert row is not None
        assert row.last_used_at is not None


def test_identity_client_rotation_keeps_dual_key_window_until_revoke(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    previous = identity.issue_identity_client(
        name="Dashboard BFF",
        allowed_issuers=[ISSUER],
    )
    current = identity.rotate_identity_client(previous.record.id)

    assert current.record.id != previous.record.id
    assert current.record.rotated_from_id == previous.record.id
    assert identity.authenticate_identity_client(previous.token, issuer=ISSUER)
    assert identity.authenticate_identity_client(current.token, issuer=ISSUER)
    assert identity.revoke_identity_client(previous.record.id) is True
    assert identity.revoke_identity_client(previous.record.id) is True
    assert identity.authenticate_identity_client(previous.token, issuer=ISSUER) is None
    assert identity.authenticate_identity_client(current.token, issuer=ISSUER)
    with pytest.raises(ValueError, match="revoked"):
        identity.rotate_identity_client(previous.record.id)


def test_identity_client_validation_rejects_unsafe_metadata(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    with pytest.raises(ValueError, match="name"):
        identity.issue_identity_client(name=" ", allowed_issuers=[ISSUER])
    with pytest.raises(ValueError, match="at least one issuer"):
        identity.issue_identity_client(name="BFF", allowed_issuers=[])
    with pytest.raises(ValueError, match="at most 16"):
        identity.issue_identity_client(
            name="BFF",
            allowed_issuers=[f"https://issuer-{index}.test" for index in range(17)],
        )


def test_user_session_stores_sha256_only_and_authenticates(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    user_id, client_id, _ = _provision(identity)
    issued = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )

    with Session(identity.engine) as session:
        row = session.get(UserSessionRow, issued.id)
        assert row is not None
        assert row.token_hash == hashlib.sha256(issued.token.encode()).hexdigest()
        assert issued.token not in row.token_hash

    principal = identity.authenticate_user_session(issued.token)
    assert principal is not None
    assert principal.tenant_id == "tenant-a"
    assert principal.user_id == user_id
    assert principal.role == "analyst"
    assert principal.identity_client_id == client_id
    assert identity.authenticate_user_session(f"{issued.token}x") is None

    with Session(identity.engine) as session:
        row = session.get(UserSessionRow, issued.id)
        assert row is not None
        assert row.last_seen_at is not None
        actions = session.scalars(
            select(AuditEventRow.action).where(
                AuditEventRow.tenant_id == "tenant-a"
            )
        ).all()
        assert "user_session.issued" in actions


def test_user_session_ttl_is_bounded(identity: SQLAlchemyIdentityRepository) -> None:
    user_id, client_id, _ = _provision(identity)
    before = datetime.now(UTC)
    issued = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )
    assert before + timedelta(seconds=295) <= issued.expires_at
    assert issued.expires_at <= datetime.now(UTC) + timedelta(seconds=305)

    for invalid in (0, 901, True):
        with pytest.raises(ValueError, match="ttl_seconds"):
            identity.issue_user_session(
                identity_client_id=client_id,
                tenant_id="tenant-a",
                user_id=user_id,
                ttl_seconds=invalid,  # type: ignore[arg-type]
            )


def test_user_session_rechecks_role_and_membership_status(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    user_id, client_id, _ = _provision(identity)
    issued = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )
    assert identity.authenticate_user_session(issued.token).role == "analyst"  # type: ignore[union-attr]

    identity.set_membership(
        tenant_id="tenant-a",
        user_id=user_id,
        role="admin",
    )
    assert identity.authenticate_user_session(issued.token).role == "admin"  # type: ignore[union-attr]
    identity.set_membership_status(
        tenant_id="tenant-a",
        user_id=user_id,
        status="suspended",
    )
    assert identity.authenticate_user_session(issued.token) is None
    with pytest.raises(ValueError, match="active membership"):
        identity.issue_user_session(
            identity_client_id=client_id,
            tenant_id="tenant-a",
            user_id=user_id,
        )


def test_user_session_rechecks_tenant_and_identity_client(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    user_id, client_id, _ = _provision(identity)
    issued = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )
    identity.set_tenant_status("tenant-a", "suspended")
    assert identity.authenticate_user_session(issued.token) is None
    identity.set_tenant_status("tenant-a", "active")
    assert identity.authenticate_user_session(issued.token) is not None
    identity.revoke_identity_client(client_id)
    assert identity.authenticate_user_session(issued.token) is None


def test_user_session_revoke_is_tenant_scoped_and_idempotent(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    user_id, client_id, _ = _provision(identity)
    issued = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )

    assert identity.revoke_user_session("tenant-b", issued.id) is False
    assert identity.revoke_user_session("tenant-a", issued.id, actor="admin") is True
    assert identity.revoke_user_session("tenant-a", issued.id, actor="admin") is True
    assert identity.authenticate_user_session(issued.token) is None
    with Session(identity.engine) as session:
        revoke_count = session.scalar(
            select(func.count())
            .select_from(AuditEventRow)
            .where(AuditEventRow.action == "user_session.revoked")
        )
        assert revoke_count == 1


def test_expired_session_cleanup_preserves_audit_events(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    user_id, client_id, _ = _provision(identity)
    expired = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )
    active = identity.issue_user_session(
        identity_client_id=client_id,
        tenant_id="tenant-a",
        user_id=user_id,
    )
    with identity.engine.begin() as connection:
        connection.execute(
            update(UserSessionRow)
            .where(UserSessionRow.id == expired.id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )

    assert identity.cleanup_expired_user_sessions() == 1
    with Session(identity.engine) as session:
        assert session.get(UserSessionRow, expired.id) is None
        assert session.get(UserSessionRow, active.id) is not None
        audit_count = session.scalar(
            select(func.count())
            .select_from(AuditEventRow)
            .where(AuditEventRow.action == "user_session.issued")
        )
        assert audit_count == 2
