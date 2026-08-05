"""Job-oriented v1 API tests."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from shared_integration.gateway import build_app
from shared_integration.jobs import JobRecord

ANALYST_TOKEN = "analyst-token-at-least-16"
VIEWER_TOKEN = "viewer-token-at-least-16"
ADMIN_TOKEN = "admin-token-at-least-16"
OTHER_TOKEN = "other-token-at-least-16"


class RecordingDispatcher:
    def __init__(self) -> None:
        self.submissions: list[tuple[str, str]] = []
        self.cancellations: list[str] = []

    def submit(self, job: JobRecord, *, queue: str) -> str:
        self.submissions.append((job.id, queue))
        return f"dispatch-{job.id}"

    def cancel(self, job: JobRecord) -> None:
        self.cancellations.append(job.id)

    def ready(self) -> bool:
        return True


async def request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    token: str | None = None,
    **kwargs: Any,
) -> httpx.Response:
    headers = dict(kwargs.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, headers=headers, **kwargs)


@pytest.fixture
def v1_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[FastAPI, RecordingDispatcher]]:
    principals = {
        ANALYST_TOKEN: {"tenant": "tenant-a", "role": "analyst"},
        VIEWER_TOKEN: {"tenant": "tenant-a", "role": "viewer"},
        ADMIN_TOKEN: {"tenant": "tenant-a", "role": "admin"},
        OTHER_TOKEN: {"tenant": "tenant-b", "role": "viewer"},
    }
    monkeypatch.setenv("INTEGRATION_AUTH_TOKENS", json.dumps(principals))
    monkeypatch.setenv("INTEGRATION_AUTH_REQUIRED", "true")
    dispatcher = RecordingDispatcher()
    app = build_app(
        tmp_path,
        database_path=tmp_path / "gateway.sqlite3",
        dispatcher=dispatcher,
    )
    yield app, dispatcher
    app.state.job_repository.close()
    app.state.registry.close()


async def test_livez_is_public(v1_app: tuple[FastAPI, RecordingDispatcher]) -> None:
    app, _ = v1_app
    response = await request(app, "GET", "/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_create_scan_is_idempotent_and_uses_adapter_queue(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, dispatcher = v1_app
    headers = {"Idempotency-Key": "upload-123"}
    body = {"source": "001", "payload": {"host": "host-a"}}
    first = await request(
        app, "POST", "/v1/scans", token=ANALYST_TOKEN, headers=headers, json=body
    )
    repeated = await request(
        app, "POST", "/v1/scans", token=ANALYST_TOKEN, headers=headers, json=body
    )

    assert first.status_code == 202
    assert repeated.status_code == 200
    assert first.json()["id"] == repeated.json()["id"]
    assert dispatcher.submissions == [(first.json()["id"], "fast")]


async def test_job_queries_are_tenant_isolated(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, _ = v1_app
    created = await request(
        app,
        "POST",
        "/v1/scans",
        token=ANALYST_TOKEN,
        json={"source": "002", "payload": {}},
    )
    job_id = created.json()["id"]
    same_tenant = await request(
        app, "GET", f"/v1/scans/{job_id}", token=VIEWER_TOKEN
    )
    other_tenant = await request(
        app, "GET", f"/v1/scans/{job_id}", token=OTHER_TOKEN
    )
    assert same_tenant.status_code == 200
    assert other_tenant.status_code == 404


async def test_viewer_cannot_create_or_cancel(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, _ = v1_app
    create = await request(
        app,
        "POST",
        "/v1/scans",
        token=VIEWER_TOKEN,
        json={"source": "001", "payload": {}},
    )
    assert create.status_code == 403


async def test_analyst_cannot_read_admin_health(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, _ = v1_app
    analyst = await request(
        app, "GET", "/v1/admin/health", token=ANALYST_TOKEN
    )
    admin = await request(app, "GET", "/v1/admin/health", token=ADMIN_TOKEN)
    assert analyst.status_code == 403
    assert admin.status_code == 200


async def test_cancelled_job_events_are_streamed(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, dispatcher = v1_app
    created = await request(
        app,
        "POST",
        "/v1/scans",
        token=ANALYST_TOKEN,
        json={"source": "004", "payload": {}},
    )
    job_id = created.json()["id"]
    cancelled = await request(
        app, "POST", f"/v1/scans/{job_id}/cancel", token=ANALYST_TOKEN
    )
    events = await request(
        app, "GET", f"/v1/scans/{job_id}/events", token=VIEWER_TOKEN
    )

    assert cancelled.json()["status"] == "cancelled"
    assert dispatcher.cancellations == [job_id]
    assert "event: status" in events.text
    assert "event: cancel_requested" in events.text


async def test_capabilities_list_all_products(
    v1_app: tuple[FastAPI, RecordingDispatcher],
) -> None:
    app, _ = v1_app
    response = await request(app, "GET", "/v1/adapters", token=VIEWER_TOKEN)
    assert response.status_code == 200
    assert response.json()["count"] == 6
    assert {item["queue"] for item in response.json()["adapters"]} == {
        "fast",
        "analysis",
        "sandbox",
    }
