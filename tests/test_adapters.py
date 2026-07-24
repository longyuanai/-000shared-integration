"""Product adapter tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from shared_llm_core import FindingSource
from shared_integration.adapters import (
    CodeAdapter,
    FirmwareAdapter,
    LabAdapter,
    ReverseAdapter,
    SOCAdapter,
    VulnAdapter,
)
from shared_integration.adapters import base


class FakeProcess:
    def __init__(self, output: dict[str, Any], returncode: int = 0) -> None:
        self._stdout = json.dumps(output).encode()
        self._stderr = b"failure"
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


def install_fake_process(
    monkeypatch: pytest.MonkeyPatch,
    output: dict[str, Any],
) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    async def fake_create_subprocess_exec(*args: Any, **kwargs: Any) -> FakeProcess:
        calls.append((*args, kwargs))
        return FakeProcess(output)

    monkeypatch.setattr(base.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    return calls


async def collect(adapter: base.ProductAdapter) -> list[Any]:
    return [finding async for finding in adapter.scan({"host": "10.0.0.1"})]


def test_soc_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert SOCAdapter(tmp_path).health()["status"] == "ok"


async def test_soc_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "SOC alert", "severity": "high", "host": "host-a"}]},
    )
    findings = await collect(SOCAdapter(tmp_path))
    assert findings[0].source is FindingSource.SOC
    assert findings[0].title == "SOC alert"


async def test_soc_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(SOCAdapter(tmp_path)) == []


async def test_soc_adapter_uses_current_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = install_fake_process(monkeypatch, {"findings": []})
    await collect(SOCAdapter(tmp_path))
    assert calls[0][0] == sys.executable


def test_vuln_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert VulnAdapter(tmp_path).health()["status"] == "ok"


async def test_vuln_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "Vulnerability", "severity": "critical"}]},
    )
    findings = await collect(VulnAdapter(tmp_path))
    assert findings[0].source is FindingSource.VULN
    assert findings[0].title == "Vulnerability"


async def test_vuln_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(VulnAdapter(tmp_path)) == []


def test_vuln_adapter_source(tmp_path: Path) -> None:
    assert VulnAdapter(tmp_path).source is FindingSource.VULN


def test_lab_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert LabAdapter(tmp_path).health()["status"] == "ok"


async def test_lab_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "Lab exploit", "severity": "medium"}]},
    )
    findings = await collect(LabAdapter(tmp_path))
    assert findings[0].source is FindingSource.LAB
    assert findings[0].title == "Lab exploit"


async def test_lab_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(LabAdapter(tmp_path)) == []


def test_lab_adapter_source(tmp_path: Path) -> None:
    assert LabAdapter(tmp_path).source is FindingSource.LAB


def test_code_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert CodeAdapter(tmp_path).health()["status"] == "ok"


async def test_code_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "Code injection", "severity": "high"}]},
    )
    findings = await collect(CodeAdapter(tmp_path))
    assert findings[0].source is FindingSource.CODE
    assert findings[0].title == "Code injection"


async def test_code_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(CodeAdapter(tmp_path)) == []


def test_code_adapter_source(tmp_path: Path) -> None:
    assert CodeAdapter(tmp_path).source is FindingSource.CODE


def test_reverse_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert ReverseAdapter(tmp_path).health()["status"] == "ok"


async def test_reverse_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "Packed binary", "severity": "low"}]},
    )
    findings = await collect(ReverseAdapter(tmp_path))
    assert findings[0].source is FindingSource.REVERSE
    assert findings[0].title == "Packed binary"


async def test_reverse_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(ReverseAdapter(tmp_path)) == []


def test_reverse_adapter_source(tmp_path: Path) -> None:
    assert ReverseAdapter(tmp_path).source is FindingSource.REVERSE


def test_firmware_adapter_health_returns_ok(tmp_path: Path) -> None:
    assert FirmwareAdapter(tmp_path).health()["status"] == "ok"


async def test_firmware_adapter_scan_parses_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(
        monkeypatch,
        {"findings": [{"title": "Outdated component", "severity": "critical"}]},
    )
    findings = await collect(FirmwareAdapter(tmp_path))
    assert findings[0].source is FindingSource.FIRMWARE
    assert findings[0].title == "Outdated component"


async def test_firmware_adapter_scan_empty_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": []})
    assert await collect(FirmwareAdapter(tmp_path)) == []


def test_firmware_adapter_source(tmp_path: Path) -> None:
    assert FirmwareAdapter(tmp_path).source is FindingSource.FIRMWARE
