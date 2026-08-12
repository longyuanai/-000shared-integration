"""Persistent identity and database-backed RBAC tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from shared_llm_core import Finding, FindingSeverity, FindingSource
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.db_models import ApiKeyRow, AuditEventRow
from shared_integration.gateway import build_app
from shared_integration.identity import SQLAlchemyIdentityRepository


@pytest.fixture
def identity(tmp_path: Path) -> SQLAlchemyIdentityRepository:
    repository = SQLAlchemyIdentityRepository(
        f"sqlite:///{tmp_path / 'identity.sqlite3'}",
        create_schema=True,
    )
    yield repository
    repository.close()


def test_api_key_is_hashed_authenticated_and_revocable(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    identity.create_tenant(
        tenant_id="tenant-a",
        slug="tenant-a",
        name="Tenant A",
    )
    issued = identity.issue_api_key(
        tenant_id="tenant-a",
        role="analyst",
        scopes=["scan:read", "scan:write", "scan:read"],
        actor="bootstrap",
    )

    with Session(identity.engine) as session:
        row = session.get(ApiKeyRow, issued.id)
        assert row is not None
        assert row.secret_hash.startswith("scrypt$")
        assert issued.token not in row.secret_hash
        assert issued.token.partition(".")[2] not in row.secret_hash
        actions = list(
            session.scalars(
                select(AuditEventRow.action).where(
                    AuditEventRow.tenant_id == "tenant-a"
                )
            )
        )
        assert actions == ["tenant.created", "api_key.issued"]

    principal = identity.authenticate_api_key(issued.token)
    assert principal is not None
    assert principal.tenant_id == "tenant-a"
    assert principal.role == "analyst"
    assert principal.scopes == ("scan:read", "scan:write")
    assert identity.authenticate_api_key(f"{issued.token}wrong") is None

    assert identity.revoke_api_key("tenant-b", issued.id) is False
    assert identity.revoke_api_key("tenant-a", issued.id, actor="admin") is True
    assert identity.revoke_api_key("tenant-a", issued.id, actor="admin") is True
    assert identity.authenticate_api_key(issued.token) is None

    with Session(identity.engine) as session:
        revoke_events = session.scalars(
            select(AuditEventRow).where(AuditEventRow.action == "api_key.revoked")
        ).all()
        assert len(revoke_events) == 1


def test_api_key_expiry_and_tenant_status_are_enforced(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    identity.create_tenant(
        tenant_id="tenant-a",
        slug="tenant-a",
        name="Tenant A",
    )
    issued = identity.issue_api_key(
        tenant_id="tenant-a",
        role="viewer",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    assert identity.authenticate_api_key(issued.token) is not None

    with identity.engine.begin() as connection:
        connection.execute(
            update(ApiKeyRow)
            .where(ApiKeyRow.id == issued.id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    assert identity.authenticate_api_key(issued.token) is None

    fresh = identity.issue_api_key(tenant_id="tenant-a", role="viewer")
    identity.set_tenant_status("tenant-a", "suspended", actor="admin")
    assert identity.authenticate_api_key(fresh.token) is None
    with pytest.raises(ValueError, match="active tenants"):
        identity.issue_api_key(tenant_id="tenant-a", role="admin")


def test_list_api_keys_is_tenant_scoped(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    for tenant_id in ("tenant-a", "tenant-b"):
        identity.create_tenant(
            tenant_id=tenant_id,
            slug=tenant_id,
            name=tenant_id.title(),
        )
    first = identity.issue_api_key(
        tenant_id="tenant-a",
        role="viewer",
        scopes=["gateway:read"],
    )
    second = identity.issue_api_key(tenant_id="tenant-b", role="admin")

    tenant_a = identity.list_api_keys("tenant-a")
    tenant_b = identity.list_api_keys("tenant-b")

    assert [record.id for record in tenant_a] == [first.id]
    assert [record.id for record in tenant_b] == [second.id]
    assert tenant_a[0].key_prefix == first.token.partition(".")[0]
    assert not hasattr(tenant_a[0], "secret_hash")


def test_users_and_memberships_are_tenant_scoped(
    identity: SQLAlchemyIdentityRepository,
) -> None:
    for tenant_id in ("tenant-a", "tenant-b"):
        identity.create_tenant(
            tenant_id=tenant_id,
            slug=tenant_id,
            name=tenant_id.title(),
        )
    user = identity.upsert_user(
        issuer="https://id.example.test",
        subject="subject-1",
        email="analyst@example.test",
        display_name="Analyst",
    )
    updated = identity.upsert_user(
        issuer="https://id.example.test",
        subject="subject-1",
        email="new@example.test",
    )
    assert updated.id == user.id
    assert updated.email == "new@example.test"

    identity.set_membership(
        tenant_id="tenant-a",
        user_id=user.id,
        role="admin",
        actor="bootstrap",
    )
    assert identity.get_membership("tenant-a", user.id).role == "admin"  # type: ignore[union-attr]
    assert identity.get_membership("tenant-b", user.id) is None


async def _request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    token: str | None = None,
    **kwargs: object,
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, headers=headers, **kwargs)


async def test_database_api_keys_drive_http_rbac_and_tenant_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("INTEGRATION_AUTH_BACKEND", "database")
    monkeypatch.setenv("INTEGRATION_AUTH_REQUIRED", "true")
    monkeypatch.setenv("INTEGRATION_AUTO_CREATE_SCHEMA", "true")
    database_url = f"sqlite:///{tmp_path / 'gateway.sqlite3'}"
    app = build_app(tmp_path, database_url=database_url)
    identity: SQLAlchemyIdentityRepository = app.state.identity_repository
    identity.create_tenant(tenant_id="tenant-a", slug="tenant-a", name="Tenant A")
    identity.create_tenant(tenant_id="tenant-b", slug="tenant-b", name="Tenant B")
    viewer = identity.issue_api_key(tenant_id="tenant-a", role="viewer")
    analyst = identity.issue_api_key(tenant_id="tenant-a", role="analyst")
    scoped_scan = identity.issue_api_key(
        tenant_id="tenant-a", role="analyst", scopes=["scan:write"]
    )
    scoped_read = identity.issue_api_key(
        tenant_id="tenant-a", role="analyst", scopes=["gateway:read"]
    )
    other = identity.issue_api_key(tenant_id="tenant-b", role="viewer")

    tenant_token = bind_tenant("tenant-a")
    try:
        await app.state.registry.add(
            Finding(
                id="tenant-a-only",
                source=FindingSource.SOC,
                severity=FindingSeverity.HIGH,
                confidence=0.9,
                title="Tenant A only",
            )
        )
    finally:
        reset_tenant(tenant_token)

    try:
        assert (await _request(app, "GET", "/livez")).status_code == 200
        assert (await _request(app, "GET", "/v0.5/findings")).status_code == 401
        viewer_findings = await _request(
            app, "GET", "/v0.5/findings", token=viewer.token
        )
        other_findings = await _request(
            app, "GET", "/v0.5/findings", token=other.token
        )
        assert viewer_findings.json()["count"] == 1
        assert other_findings.json()["count"] == 0
        assert (
            await _request(
                app,
                "POST",
                "/v0.5/unknown/scan",
                token=viewer.token,
                json={},
            )
        ).status_code == 403
        assert (
            await _request(
                app,
                "POST",
                "/v0.5/unknown/scan",
                token=analyst.token,
                json={},
            )
        ).status_code == 404
        assert (
            await _request(
                app,
                "GET",
                "/v0.5/findings",
                token=scoped_scan.token,
            )
        ).status_code == 403
        assert (
            await _request(
                app,
                "POST",
                "/v0.5/unknown/scan",
                token=scoped_scan.token,
                json={},
            )
        ).status_code == 404
        assert (
            await _request(
                app,
                "POST",
                "/v0.5/unknown/scan",
                token=scoped_read.token,
                json={},
            )
        ).status_code == 403
    finally:
        app.state.identity_repository.close()
        app.state.job_repository.close()
        app.state.registry.close()
