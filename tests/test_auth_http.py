"""HTTP identity exchange, user-session RBAC, and compatibility tests."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from shared_integration.auth import ExchangeRateLimiter
from shared_integration.db_models import AuditEventRow, UserSessionRow
from shared_integration.gateway import build_app
from shared_integration.identity import SQLAlchemyIdentityRepository

ISSUER = "https://identity.example.test"


@dataclass
class AuthHTTPFixture:
    app: FastAPI
    identity: SQLAlchemyIdentityRepository
    bridge_token: str
    bridge_id: str
    subjects: dict[str, str]


async def request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    token: str | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(
            method,
            path,
            headers=request_headers,
            **kwargs,
        )


def exchange_body(subject: str, *, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {
        "issuer": ISSUER,
        "subject": subject,
        "email": f"{subject}@example.test",
        "display_name": subject.title(),
        "requested_tenant_id": tenant_id,
    }


async def exchange(
    fixture: AuthHTTPFixture,
    subject: str,
    *,
    tenant_id: str = "tenant-a",
    bridge_token: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return await request(
        fixture.app,
        "POST",
        "/v1/auth/exchange",
        token=bridge_token or fixture.bridge_token,
        headers=headers,
        json=exchange_body(subject, tenant_id=tenant_id),
    )


@pytest.fixture
def auth_http(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[AuthHTTPFixture]:
    monkeypatch.setenv("INTEGRATION_AUTH_BACKEND", "database")
    monkeypatch.setenv("INTEGRATION_AUTH_REQUIRED", "true")
    monkeypatch.setenv("INTEGRATION_AUTO_CREATE_SCHEMA", "true")
    monkeypatch.setenv("INTEGRATION_AUTH_EXCHANGE_RATE_LIMIT", "100")
    monkeypatch.delenv("INTEGRATION_AUTH_TOKENS", raising=False)
    database_url = f"sqlite:///{tmp_path / 'auth-http.sqlite3'}"
    app = build_app(tmp_path, database_url=database_url)
    identity: SQLAlchemyIdentityRepository = app.state.identity_repository
    identity.create_tenant(tenant_id="tenant-a", slug="tenant-a", name="Tenant A")
    identity.create_tenant(tenant_id="tenant-b", slug="tenant-b", name="Tenant B")
    subjects = {
        "viewer": "viewer-subject",
        "analyst": "analyst-subject",
        "admin": "admin-subject",
        "no_member": "no-member-subject",
    }
    for role in ("viewer", "analyst", "admin"):
        user = identity.upsert_user(issuer=ISSUER, subject=subjects[role])
        identity.set_membership(
            tenant_id="tenant-a",
            user_id=user.id,
            role=role,
            actor="fixture",
        )
    identity.upsert_user(issuer=ISSUER, subject=subjects["no_member"])
    bridge = identity.issue_identity_client(
        name="Web BFF",
        allowed_issuers=[ISSUER],
    )
    fixture = AuthHTTPFixture(
        app=app,
        identity=identity,
        bridge_token=bridge.token,
        bridge_id=bridge.record.id,
        subjects=subjects,
    )
    yield fixture
    app.state.identity_repository.close()
    app.state.job_repository.close()
    app.state.registry.close()


async def test_valid_exchange_returns_short_user_session(
    auth_http: AuthHTTPFixture,
) -> None:
    response = await exchange(auth_http, auth_http.subjects["viewer"])

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["session_token"].startswith("igs_")
    assert response.json()["role"] == "viewer"
    assert response.json()["tenant_id"] == "tenant-a"
    assert auth_http.bridge_token not in response.text


async def test_exchange_propagates_request_id_into_audit(
    auth_http: AuthHTTPFixture,
) -> None:
    request_id = "req-http-audit-001"
    response = await exchange(
        auth_http,
        auth_http.subjects["analyst"],
        headers={"X-Request-ID": request_id},
    )

    assert response.headers["x-request-id"] == request_id
    with Session(auth_http.identity.engine) as session:
        event = session.scalar(
            select(AuditEventRow)
            .where(AuditEventRow.action == "user_session.issued")
            .order_by(AuditEventRow.created_at.desc())
        )
        assert event is not None
        assert event.request_id == request_id
        assert event.details["user_id"] == response.json()["user_id"]
        assert event.details["identity_client_id"] == auth_http.bridge_id
        assert "token" not in str(event.details).lower()


async def test_unknown_issuer_returns_generic_401(auth_http: AuthHTTPFixture) -> None:
    body = exchange_body(auth_http.subjects["viewer"])
    body["issuer"] = "https://unknown.example.test"
    response = await request(
        auth_http.app,
        "POST",
        "/v1/auth/exchange",
        token=auth_http.bridge_token,
        json=body,
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"
    assert body["issuer"] not in response.text
    assert auth_http.bridge_token not in response.text
    with Session(auth_http.identity.engine) as session:
        event = session.scalar(
            select(AuditEventRow)
            .where(AuditEventRow.action == "auth.exchange")
            .order_by(AuditEventRow.created_at.desc())
        )
        assert event is not None
        assert event.outcome == "failure"
        assert event.request_id == response.headers["x-request-id"]
        assert event.actor.endswith(auth_http.bridge_token.partition(".")[0])
        assert auth_http.bridge_token not in str(event.details)


async def test_wrong_bridge_secret_returns_generic_401(
    auth_http: AuthHTTPFixture,
) -> None:
    response = await exchange(
        auth_http,
        auth_http.subjects["viewer"],
        bridge_token=f"{auth_http.bridge_token}wrong",
    )
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Authentication failed"


async def test_revoked_bridge_client_is_rejected(auth_http: AuthHTTPFixture) -> None:
    auth_http.identity.revoke_identity_client(auth_http.bridge_id)
    response = await exchange(auth_http, auth_http.subjects["viewer"])
    assert response.status_code == 401


async def test_exchange_requires_active_membership(auth_http: AuthHTTPFixture) -> None:
    response = await exchange(auth_http, auth_http.subjects["no_member"])
    assert response.status_code == 403
    assert response.json()["error"]["message"] == "Access denied"


async def test_exchange_rejects_disabled_tenant(auth_http: AuthHTTPFixture) -> None:
    auth_http.identity.set_tenant_status("tenant-a", "disabled")
    response = await exchange(auth_http, auth_http.subjects["viewer"])
    assert response.status_code == 403


async def test_exchange_rejects_client_role_and_scopes(
    auth_http: AuthHTTPFixture,
) -> None:
    body: dict[str, Any] = exchange_body(auth_http.subjects["viewer"])
    body.update({"role": "admin", "scopes": ["gateway:*"]})
    response = await request(
        auth_http.app,
        "POST",
        "/v1/auth/exchange",
        token=auth_http.bridge_token,
        json=body,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "gateway:*" not in response.text


async def test_viewer_session_is_read_only(auth_http: AuthHTTPFixture) -> None:
    session_token = (await exchange(auth_http, auth_http.subjects["viewer"])).json()[
        "session_token"
    ]
    readable = await request(
        auth_http.app, "GET", "/v0.5/findings", token=session_token
    )
    denied = await request(
        auth_http.app,
        "POST",
        "/v0.5/unknown/scan",
        token=session_token,
        json={},
    )
    assert readable.status_code == 200
    assert denied.status_code == 403


async def test_analyst_session_can_write_but_not_admin(
    auth_http: AuthHTTPFixture,
) -> None:
    session_token = (await exchange(auth_http, auth_http.subjects["analyst"])).json()[
        "session_token"
    ]
    allowed = await request(
        auth_http.app,
        "POST",
        "/v0.5/unknown/scan",
        token=session_token,
        json={},
    )
    denied = await request(
        auth_http.app, "GET", "/v1/admin/health", token=session_token
    )
    assert allowed.status_code == 404
    assert denied.status_code == 403


async def test_admin_session_can_reach_admin_route(auth_http: AuthHTTPFixture) -> None:
    session_token = (await exchange(auth_http, auth_http.subjects["admin"])).json()[
        "session_token"
    ]
    response = await request(
        auth_http.app, "GET", "/v1/admin/health", token=session_token
    )
    assert response.status_code == 200


async def test_cross_tenant_exchange_is_denied(auth_http: AuthHTTPFixture) -> None:
    response = await exchange(
        auth_http,
        auth_http.subjects["viewer"],
        tenant_id="tenant-b",
    )
    assert response.status_code == 403


async def test_expired_session_is_unauthorized(auth_http: AuthHTTPFixture) -> None:
    issued = (await exchange(auth_http, auth_http.subjects["viewer"])).json()
    with auth_http.identity.engine.begin() as connection:
        connection.execute(
            update(UserSessionRow)
            .where(UserSessionRow.token_hash.is_not(None))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    response = await request(
        auth_http.app,
        "GET",
        "/v0.5/findings",
        token=issued["session_token"],
    )
    assert response.status_code == 401


async def test_user_session_can_revoke_itself(auth_http: AuthHTTPFixture) -> None:
    session_token = (await exchange(auth_http, auth_http.subjects["viewer"])).json()[
        "session_token"
    ]
    revoked = await request(
        auth_http.app,
        "POST",
        "/v1/auth/session/revoke",
        token=session_token,
    )
    after = await request(
        auth_http.app, "GET", "/v0.5/findings", token=session_token
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True}
    assert after.status_code == 401
    assert session_token not in revoked.text


async def test_bridge_can_only_revoke_its_own_sessions(
    auth_http: AuthHTTPFixture,
) -> None:
    session_token = (await exchange(auth_http, auth_http.subjects["viewer"])).json()[
        "session_token"
    ]
    other_bridge = auth_http.identity.issue_identity_client(
        name="Other BFF",
        allowed_issuers=[ISSUER],
    )
    denied = await request(
        auth_http.app,
        "POST",
        "/v1/auth/session/revoke",
        token=other_bridge.token,
        json={"session_token": session_token},
    )
    revoked = await request(
        auth_http.app,
        "POST",
        "/v1/auth/session/revoke",
        token=auth_http.bridge_token,
        json={"session_token": session_token},
    )
    assert denied.status_code == 401
    assert revoked.status_code == 200


async def test_role_change_applies_on_the_next_request(
    auth_http: AuthHTTPFixture,
) -> None:
    exchange_response = await exchange(auth_http, auth_http.subjects["viewer"])
    session_token = exchange_response.json()["session_token"]
    before = await request(
        auth_http.app,
        "POST",
        "/v0.5/unknown/scan",
        token=session_token,
        json={},
    )
    auth_http.identity.set_membership(
        tenant_id="tenant-a",
        user_id=exchange_response.json()["user_id"],
        role="analyst",
        actor="admin",
    )
    after = await request(
        auth_http.app,
        "POST",
        "/v0.5/unknown/scan",
        token=session_token,
        json={},
    )
    assert before.status_code == 403
    assert after.status_code == 404


async def test_membership_suspension_invalidates_session(
    auth_http: AuthHTTPFixture,
) -> None:
    exchange_response = await exchange(auth_http, auth_http.subjects["viewer"])
    auth_http.identity.set_membership_status(
        tenant_id="tenant-a",
        user_id=exchange_response.json()["user_id"],
        status="suspended",
        actor="admin",
    )
    response = await request(
        auth_http.app,
        "GET",
        "/v0.5/findings",
        token=exchange_response.json()["session_token"],
    )
    assert response.status_code == 401


async def test_existing_machine_api_key_remains_compatible(
    auth_http: AuthHTTPFixture,
) -> None:
    machine = auth_http.identity.issue_api_key(
        tenant_id="tenant-a",
        role="analyst",
        scopes=["scan:write"],
    )
    response = await request(
        auth_http.app,
        "POST",
        "/v0.5/unknown/scan",
        token=machine.token,
        json={},
    )
    assert response.status_code == 404


async def test_public_path_and_generic_auth_error_have_request_ids(
    auth_http: AuthHTTPFixture,
) -> None:
    public = await request(auth_http.app, "GET", "/livez")
    denied = await request(
        auth_http.app,
        "GET",
        "/v0.5/findings",
        token="igs_not-a-valid-session",
    )
    assert public.status_code == 200
    assert public.headers["x-request-id"].startswith("req_")
    assert denied.status_code == 401
    assert denied.json()["error"]["request_id"] == denied.headers["x-request-id"]
    assert "igs_not-a-valid-session" not in denied.text


async def test_exchange_rate_limit_uses_secret_free_key(
    auth_http: AuthHTTPFixture,
) -> None:
    auth_http.app.state.exchange_rate_limiter.max_attempts = 1
    first = await exchange(
        auth_http,
        auth_http.subjects["viewer"],
        bridge_token="invalid-bridge-token",
    )
    second = await exchange(
        auth_http,
        auth_http.subjects["viewer"],
        bridge_token="another-invalid-token",
    )
    assert first.status_code == 401
    assert second.status_code == 429
    assert int(second.headers["retry-after"]) >= 1
    assert "invalid-bridge-token" not in second.text


def test_auth_openapi_distinguishes_401_and_403(auth_http: AuthHTTPFixture) -> None:
    paths = auth_http.app.openapi()["paths"]
    exchange_responses = paths["/v1/auth/exchange"]["post"]["responses"]
    revoke_responses = paths["/v1/auth/session/revoke"]["post"]["responses"]
    assert {"401", "403", "429"}.issubset(exchange_responses)
    assert {"401", "403"}.issubset(revoke_responses)


def test_exchange_rate_limiter_bounds_client_keys() -> None:
    limiter = ExchangeRateLimiter(
        max_attempts=1,
        window_seconds=60,
        max_keys=2,
        clock=lambda: 100.0,
    )
    assert limiter.check("client-a") == (True, 0)
    assert limiter.check("client-b") == (True, 0)
    assert limiter.check("client-c")[0] is False
    assert len(limiter._attempts) == 2  # noqa: SLF001 - resource-bound invariant
