"""IntegrationGateway composition and HTTP tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from shared_llm_core import FindingRegistry, FindingSource, IntegrationGateway

from shared_integration import gateway as gateway_module
from shared_integration.gateway import build_gateway, suite_root


async def request(
    gateway: IntegrationGateway,
    method: str,
    path: str,
    **kwargs: Any,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_suite_root_is_product_parent() -> None:
    expected = Path(__file__).resolve().parents[2]
    assert suite_root() == expected


def test_build_gateway_returns_core_gateway(tmp_path: Path) -> None:
    assert isinstance(build_gateway(tmp_path), IntegrationGateway)


def test_build_gateway_registers_six_products(tmp_path: Path) -> None:
    gateway = build_gateway(tmp_path)
    assert set(gateway._products) == {  # noqa: SLF001 - composition contract test
        FindingSource.SOC,
        FindingSource.VULN,
        FindingSource.LAB,
        FindingSource.CODE,
        FindingSource.REVERSE,
        FindingSource.FIRMWARE,
    }


def test_build_gateway_uses_flat_code_audit_checkout(tmp_path: Path) -> None:
    gateway = build_gateway(tmp_path)

    code_adapter = gateway._products[FindingSource.CODE]  # noqa: SLF001
    assert code_adapter._cli == (tmp_path / "004AI-Code-Audit").resolve()  # noqa: SLF001


def test_build_gateway_uses_finding_registry(tmp_path: Path) -> None:
    assert isinstance(build_gateway(tmp_path).registry, FindingRegistry)


def test_build_gateway_installs_correlation_rule(tmp_path: Path) -> None:
    gateway = build_gateway(tmp_path)
    assert gateway._correlations[0].id == "integ-same-host-multi-source"  # noqa: SLF001


async def test_health_returns_ok() -> None:
    response = await request(build_gateway(), "GET", "/v0.5/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_health_lists_all_six_products() -> None:
    response = await request(build_gateway(), "GET", "/v0.5/health")
    assert set(response.json()["products"]) == {"001", "002", "003", "004", "005", "006"}


async def test_findings_initially_empty() -> None:
    response = await request(build_gateway(), "GET", "/v0.5/findings")
    assert response.status_code == 200
    assert response.json() == {"count": 0, "findings": []}


async def test_unknown_scan_source_returns_404() -> None:
    response = await request(
        build_gateway(),
        "POST",
        "/v0.5/unknown/scan",
        json={"host": "127.0.0.1"},
    )
    assert response.status_code == 404


def test_module_exposes_fastapi_app() -> None:
    paths = {route.path for route in gateway_module.app.routes}
    assert "/v0.5/health" in paths
    assert "/v0.5/{source}/scan" in paths
    assert "/v0.5/stream" in paths
    assert "/v1/scans" in paths
    assert "/v1/adapters" in paths
    assert "/livez" in paths


def test_main_runs_on_port_8080(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}

    def fake_run(app: FastAPI, host: str, port: int) -> None:
        called.update(app=app, host=host, port=port)

    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setattr(gateway_module.uvicorn, "run", fake_run)
    gateway_module.main()
    assert called == {
        "app": gateway_module.app,
        "host": "0.0.0.0",
        "port": 8080,
    }
