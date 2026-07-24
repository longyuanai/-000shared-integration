"""FindingRegistry integration tests."""

from __future__ import annotations

from shared_llm_core import (
    Finding,
    FindingRegistry as CoreFindingRegistry,
    FindingSeverity,
    FindingSource,
)
from shared_integration.registry import FindingRegistry


def make_finding(
    identifier: str,
    *,
    source: FindingSource = FindingSource.SOC,
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    host: str = "host-a",
) -> Finding:
    return Finding(
        id=identifier,
        source=source,
        severity=severity,
        confidence=0.8,
        title=f"Finding {identifier}",
        host=host,
    )


def test_registry_import_from_shared_llm_core() -> None:
    assert FindingRegistry is CoreFindingRegistry


async def test_registry_add_and_query() -> None:
    registry = FindingRegistry()
    finding = make_finding("finding-1")
    await registry.add(finding)
    assert registry.query() == [finding]


async def test_registry_query_by_source() -> None:
    registry = FindingRegistry()
    soc = make_finding("soc", source=FindingSource.SOC)
    vuln = make_finding("vuln", source=FindingSource.VULN)
    await registry.add(soc)
    await registry.add(vuln)
    assert registry.query(source=FindingSource.VULN) == [vuln]


async def test_registry_query_by_severity() -> None:
    registry = FindingRegistry()
    low = make_finding("low", severity=FindingSeverity.LOW)
    critical = make_finding("critical", severity=FindingSeverity.CRITICAL)
    await registry.add(low)
    await registry.add(critical)
    assert registry.query(severity=FindingSeverity.CRITICAL) == [critical]


async def test_registry_max_size_eviction() -> None:
    registry = FindingRegistry(max_size=2)
    first = make_finding("first")
    second = make_finding("second")
    third = make_finding("third")
    await registry.add(first)
    await registry.add(second)
    await registry.add(third)
    assert registry.query(limit=10) == [third, second]


async def test_registry_query_by_host() -> None:
    registry = FindingRegistry()
    expected = make_finding("target", host="10.0.0.8")
    await registry.add(make_finding("other", host="10.0.0.9"))
    await registry.add(expected)
    assert registry.query(host="10.0.0.8") == [expected]
