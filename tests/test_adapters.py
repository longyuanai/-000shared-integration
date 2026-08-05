"""Product adapter tests."""

from __future__ import annotations

import asyncio
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
    ProductOutputLimitError,
    ProductTimeoutError,
    ReverseAdapter,
    SOCAdapter,
    VulnAdapter,
    base,
)


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


def test_missing_adapter_directory_is_degraded(tmp_path: Path) -> None:
    health = SOCAdapter(tmp_path / "missing").health()
    assert health["status"] == "degraded"
    assert "path" not in health


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


async def test_payload_is_not_exposed_in_process_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = install_fake_process(monkeypatch, {"findings": []})
    await collect(SOCAdapter(tmp_path))
    flattened = " ".join(str(value) for value in calls[0][:-1])
    assert '"host":"10.0.0.1"' not in flattened
    assert "shared_integration.adapters.worker" in flattened


async def test_adapter_enforces_output_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    install_fake_process(monkeypatch, {"findings": [{"title": "too large"}]})
    adapter = SOCAdapter(tmp_path, max_output_bytes=5)
    with pytest.raises(ProductOutputLimitError):
        await collect(adapter)


async def test_adapter_terminates_timed_out_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class SlowProcess:
        returncode: int | None = None
        terminated = False

        async def communicate(self) -> tuple[bytes, bytes]:
            await asyncio.sleep(60)
            return b"{}", b""

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

        async def wait(self) -> int:
            return self.returncode or 0

    process = SlowProcess()

    async def fake_create_subprocess_exec(*args: Any, **kwargs: Any) -> SlowProcess:
        del args, kwargs
        return process

    monkeypatch.setattr(base.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    with pytest.raises(ProductTimeoutError):
        await collect(SOCAdapter(tmp_path, timeout_seconds=0.01))
    assert process.terminated is True


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
