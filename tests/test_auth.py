"""Authentication, RBAC, and HTTP tenant-isolation tests."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from shared_llm_core import Finding, FindingSeverity, FindingSource

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.gateway import build_app
from shared_integration.persistence import SQLiteTenantFindingRegistry

VIEWER_TOKEN = "viewer-token-at-least-16"
ANALYST_TOKEN = "analyst-token-at-least-16"
OTHER_TOKEN = "other-tenant-token-16"


async def request(
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


@pytest.fixture
def secured_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[FastAPI]:
    principals = {
        VIEWER_TOKEN: {"tenant": "tenant-a", "role": "viewer"},
        ANALYST_TOKEN: {"tenant": "tenant-a", "role": "analyst"},
        OTHER_TOKEN: {"tenant": "tenant-b", "role": "viewer"},
    }
    monkeypatch.setenv("INTEGRATION_AUTH_TOKENS", json.dumps(principals))
    monkeypatch.setenv("INTEGRATION_AUTH_REQUIRED", "true")
    app = build_app(tmp_path, database_path=tmp_path / "gateway.sqlite3")
    yield app
    app.state.job_repository.close()
    app.state.registry.close()


async def test_health_is_public_for_platform_probes(secured_app: FastAPI) -> None:
    response = await request(secured_app, "GET", "/v0.5/health")
    assert response.status_code == 200


async def test_protected_route_requires_bearer(secured_app: FastAPI) -> None:
    response = await request(secured_app, "GET", "/v0.5/findings")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_viewer_is_read_only(secured_app: FastAPI) -> None:
    response = await request(
        secured_app,
        "POST",
        "/v0.5/unknown/scan",
        token=VIEWER_TOKEN,
        json={},
    )
    assert response.status_code == 403


async def test_analyst_can_reach_scan_route(secured_app: FastAPI) -> None:
    response = await request(
        secured_app,
        "POST",
        "/v0.5/unknown/scan",
        token=ANALYST_TOKEN,
        json={},
    )
    assert response.status_code == 404


async def test_http_queries_are_tenant_isolated(
    secured_app: FastAPI,
) -> None:
    registry: SQLiteTenantFindingRegistry = secured_app.state.registry
    tenant = bind_tenant("tenant-a")
    try:
        await registry.add(
            Finding(
                id="tenant-a-finding",
                source=FindingSource.SOC,
                severity=FindingSeverity.HIGH,
                confidence=0.9,
                title="Tenant A only",
            )
        )
    finally:
        reset_tenant(tenant)

    tenant_a = await request(
        secured_app,
        "GET",
        "/v0.5/findings",
        token=VIEWER_TOKEN,
    )
    tenant_b = await request(
        secured_app,
        "GET",
        "/v0.5/findings",
        token=OTHER_TOKEN,
    )
    assert tenant_a.json()["count"] == 1
    assert tenant_b.json()["count"] == 0
