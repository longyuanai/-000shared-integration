"""v1 Finding lifecycle API tests against the relational backend."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from shared_llm_core import Finding, FindingSeverity, FindingSource

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.finding_lifecycle import SQLAlchemyTenantFindingRegistry
from shared_integration.gateway import build_app
from shared_integration.sql_jobs import SQLAlchemyJobRepository


@pytest.mark.asyncio
async def test_finding_list_patch_rbac_and_tenant_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tokens = {
        "analyst-a-token-at-least-32-bytes": {
            "tenant": "tenant-a",
            "role": "analyst",
        },
        "viewer-a-token-at-least-32-bytes-xx": {
            "tenant": "tenant-a",
            "role": "viewer",
        },
        "analyst-b-token-at-least-32-bytes": {
            "tenant": "tenant-b",
            "role": "analyst",
        },
    }
    monkeypatch.setenv("INTEGRATION_AUTH_TOKENS", json.dumps(tokens))
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'api.db').as_posix()}"
    registry = SQLAlchemyTenantFindingRegistry(database_url, create_schema=True)
    jobs = SQLAlchemyJobRepository(database_url, create_schema=True)
    token = bind_tenant("tenant-a")
    try:
        await registry.add(
            Finding(
                id="finding-api",
                source=FindingSource.SOC,
                severity=FindingSeverity.HIGH,
                confidence=0.8,
                title="API finding",
                host="host-a",
            )
        )
    finally:
        reset_tenant(token)

    app = build_app(registry=registry, job_repository=jobs)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        analyst_a = {
            "Authorization": "Bearer analyst-a-token-at-least-32-bytes"
        }
        listed = await client.get("/v1/findings?limit=1", headers=analyst_a)
        assert listed.status_code == 200
        assert listed.json()["count"] == 1
        assert listed.json()["items"][0]["occurrences"] == 1

        updated = await client.patch(
            "/v1/findings/finding-api",
            headers=analyst_a,
            json={
                "status": "confirmed",
                "assigned_to": "analyst@example.test",
            },
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == "confirmed"
        assert updated.json()["assigned_to"] == "analyst@example.test"

        viewer_update = await client.patch(
            "/v1/findings/finding-api",
            headers={
                "Authorization": "Bearer viewer-a-token-at-least-32-bytes-xx"
            },
            json={"status": "resolved"},
        )
        assert viewer_update.status_code == 403

        tenant_b = {
            "Authorization": "Bearer analyst-b-token-at-least-32-bytes"
        }
        isolated = await client.get("/v1/findings", headers=tenant_b)
        assert isolated.status_code == 200
        assert isolated.json()["items"] == []
        cross_tenant_patch = await client.patch(
            "/v1/findings/finding-api",
            headers=tenant_b,
            json={"status": "resolved"},
        )
        assert cross_tenant_patch.status_code == 404

        invalid_cursor = await client.get(
            "/v1/findings?cursor=invalid", headers=analyst_a
        )
        assert invalid_cursor.status_code == 400
        assert invalid_cursor.json()["error"]["code"] == "INVALID_CURSOR"

    jobs.close()
    registry.close()
