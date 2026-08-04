"""FastAPI entrypoint for the longyuanai integration gateway."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from shared_llm_core import FindingRegistry, FindingSource, IntegrationGateway

from shared_integration.adapters import (
    CodeAdapter,
    FirmwareAdapter,
    LabAdapter,
    ReverseAdapter,
    SOCAdapter,
    VulnAdapter,
)
from shared_integration.correlations import SameHostMultiSourceRule


def suite_root() -> Path:
    """Return the directory containing all longyuanai product repositories."""
    return Path(__file__).resolve().parents[3]


def build_gateway(root: Path | None = None) -> IntegrationGateway:
    """Compose all six subprocess adapters behind the v0.5 core gateway."""
    products_root = (root or suite_root()).resolve()
    products = {
        FindingSource.SOC: SOCAdapter(products_root / "001AI-SOC-Agent"),
        FindingSource.VULN: VulnAdapter(products_root / "002AI-Vulnerability-Agent"),
        FindingSource.LAB: LabAdapter(products_root / "003AI Agent安全靶场"),
        FindingSource.CODE: CodeAdapter(
            products_root / "004AI-Code-Audit" / "004AI-CodeGuard-upgrade"
        ),
        FindingSource.REVERSE: ReverseAdapter(
            products_root / "005AI-Reverse-Agent"
        ),
        FindingSource.FIRMWARE: FirmwareAdapter(
            products_root / "006AI-Firmware-Security-Agent"
        ),
    }
    return IntegrationGateway(
        products=products,
        registry=FindingRegistry(),
        correlations=[SameHostMultiSourceRule()],
    )


app: FastAPI = build_gateway().app


def main() -> None:
    """Run the gateway on the contract's default address."""
    build_gateway().run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
