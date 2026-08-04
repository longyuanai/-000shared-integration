"""SQLite registry persistence and tenant isolation tests."""

from __future__ import annotations

from pathlib import Path

from shared_llm_core import Correlation, Finding, FindingSeverity, FindingSource

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.persistence import SQLiteTenantFindingRegistry


def finding(identifier: str) -> Finding:
    return Finding(
        id=identifier,
        source=FindingSource.CODE,
        severity=FindingSeverity.HIGH,
        confidence=0.91,
        title=f"Finding {identifier}",
        host="api-01",
    )


async def test_findings_survive_registry_restart(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite3"
    first = SQLiteTenantFindingRegistry(database)
    tenant = bind_tenant("tenant-a")
    try:
        await first.add(finding("persisted"))
    finally:
        reset_tenant(tenant)
        first.close()

    second = SQLiteTenantFindingRegistry(database)
    tenant = bind_tenant("tenant-a")
    try:
        assert [item.id for item in second.query()] == ["persisted"]
    finally:
        reset_tenant(tenant)
        second.close()


async def test_findings_and_correlations_are_tenant_isolated(tmp_path: Path) -> None:
    registry = SQLiteTenantFindingRegistry(tmp_path / "gateway.sqlite3")
    tenant_a = bind_tenant("tenant-a")
    try:
        await registry.add(finding("a"))
        await registry.add_correlation(
            Correlation(
                rule_id="test",
                findings=("a",),
                severity=FindingSeverity.HIGH,
                narrative="Tenant A correlation",
            )
        )
    finally:
        reset_tenant(tenant_a)

    tenant_b = bind_tenant("tenant-b")
    try:
        assert registry.query() == []
        assert registry.correlations == ()
        await registry.add(finding("b"))
    finally:
        reset_tenant(tenant_b)

    tenant_a = bind_tenant("tenant-a")
    try:
        assert [item.id for item in registry.query()] == ["a"]
        assert len(registry.correlations) == 1
    finally:
        reset_tenant(tenant_a)
        registry.close()
