from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from shared_integration import tracing
from shared_integration.adapters import SOCAdapter, base
from shared_integration.gateway import build_app, build_gateway


class RecordingSpan:
    def __init__(self, attributes: dict[str, object]) -> None:
        self.attributes = attributes

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value


def _capture_spans(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, RecordingSpan]]:
    captured: list[tuple[str, RecordingSpan]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object] | None = None,
    ) -> Iterator[RecordingSpan]:
        active = RecordingSpan(dict(attributes or {}))
        captured.append((name, active))
        yield active

    monkeypatch.setattr(tracing, "span", recording_span)
    return captured


async def _request(
    application: FastAPI,
    method: str,
    path: str,
    **kwargs: Any,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


async def test_request_span_created(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured = _capture_spans(monkeypatch)
    monkeypatch.setattr(tracing, "current_trace_id", lambda: None)
    application = build_app(tmp_path)

    response = await _request(application, "GET", "/v0.5/health")

    assert response.status_code == 200
    assert [name for name, _active in captured] == ["gateway.request"]
    attributes = captured[0][1].attributes
    assert attributes["gateway.status"] == "ok"
    assert attributes["http.response.status_code"] == 200
    assert isinstance(attributes["gateway.latency_ms"], int)


async def test_traceparent_propagated_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    calls: list[dict[str, Any]] = []

    class FakeProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b'{"findings":[]}', b""

    async def fake_create_subprocess_exec(*_args: Any, **kwargs: Any) -> FakeProcess:
        calls.append(kwargs)
        return FakeProcess()

    monkeypatch.setattr(base.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(base, "trace_context_environment", lambda: {"traceparent": expected})

    adapter = SOCAdapter(tmp_path)
    assert [finding async for finding in adapter.scan({"target_type": "event"})] == []
    assert calls[0]["env"]["traceparent"] == expected


async def test_span_contains_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured = _capture_spans(monkeypatch)
    monkeypatch.setattr(tracing, "current_trace_id", lambda: None)
    application = build_app(tmp_path)
    secret = "secret-session-token-must-not-appear"

    response = await _request(
        application,
        "GET",
        "/v0.5/health",
        headers={"Authorization": f"Bearer {secret}", "X-Request-ID": "request-safe"},
    )

    assert response.status_code == 200
    serialized = json.dumps(captured[0][1].attributes, sort_keys=True)
    assert secret not in serialized
    assert all(
        forbidden not in key.lower()
        for key in captured[0][1].attributes
        for forbidden in ("authorization", "credential", "api_key", "session", "token")
    )


async def test_disabled_tracing_does_not_change_responses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("SHARED_LLM_OTEL_ENABLED", raising=False)
    untraced = build_gateway(tmp_path).app
    traced = build_app(tmp_path)

    before = await _request(untraced, "GET", "/v0.5/findings")
    after = await _request(traced, "GET", "/v0.5/findings")

    assert before.status_code == after.status_code == 200
    assert before.content == after.content == b'{"count":0,"findings":[]}'


async def test_request_id_and_trace_id_are_associated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured = _capture_spans(monkeypatch)
    trace_id = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(tracing, "current_trace_id", lambda: trace_id)
    application = build_app(tmp_path)

    response = await _request(
        application,
        "GET",
        "/v0.5/health",
        headers={"X-Request-ID": "request-correlation"},
    )

    assert response.status_code == 200
    attributes = captured[0][1].attributes
    assert attributes["gateway.request_id"] == "request-correlation"
    assert attributes["gateway.trace_id"] == trace_id
    assert attributes["gateway.request_id"] != attributes["gateway.trace_id"]


async def test_product_and_job_ids_are_bounded_attributes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured = _capture_spans(monkeypatch)
    monkeypatch.setattr(tracing, "current_trace_id", lambda: None)
    application = build_app(tmp_path)
    job_id = "job_0123456789abcdef0123456789abcdef"

    await _request(application, "GET", "/v0.5/001/scan")
    await _request(application, "GET", f"/v1/scans/{job_id}")

    assert captured[0][1].attributes["gateway.product_id"] == "001"
    assert captured[1][1].attributes["gateway.job_id"] == job_id
