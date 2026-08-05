"""Finding fingerprint, lifecycle, paging, and tenant isolation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from shared_llm_core import Finding, FindingSeverity, FindingSource
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from shared_integration.auth import bind_tenant, reset_tenant
from shared_integration.db_models import AuditEventRow
from shared_integration.finding_lifecycle import (
    FindingStatus,
    SQLAlchemyTenantFindingRegistry,
    finding_fingerprint,
)


def _registry(path: Path) -> SQLAlchemyTenantFindingRegistry:
    return SQLAlchemyTenantFindingRegistry(
        f"sqlite+pysqlite:///{path.as_posix()}",
        create_schema=True,
    )


def _finding(
    finding_id: str,
    *,
    title: str = "Repeated issue",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    confidence: float = 0.6,
    seen_at: datetime | None = None,
    evidence: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        id=finding_id,
        source=FindingSource.CODE,
        severity=severity,
        confidence=confidence,
        title=title,
        description="description",
        host="asset-a",
        cve="CVE-2026-0001",
        ts=seen_at or datetime(2026, 8, 5, tzinfo=UTC),
        evidence=evidence,
        metadata={"path": "src/app.py", "line": 42},
    )


@pytest.mark.asyncio
async def test_duplicate_finding_merges_within_tenant_only(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "findings.db")
    first = _finding("finding-1", evidence=("first",))
    repeated = _finding(
        "finding-2",
        severity=FindingSeverity.HIGH,
        confidence=0.9,
        seen_at=first.ts + timedelta(hours=1),  # type: ignore[operator]
        evidence=("second",),
    )

    token = bind_tenant("tenant-a")
    try:
        await registry.add_for_job(first, job_id="job-1")
        await registry.add_for_job(repeated, job_id="job-2")
        records, cursor = registry.list_page("tenant-a")
    finally:
        reset_tenant(token)

    assert cursor is None
    assert len(records) == 1
    record = records[0]
    assert record.finding.id == "finding-1"
    assert record.finding.severity is FindingSeverity.HIGH
    assert record.finding.confidence == 0.9
    assert record.finding.evidence == ("first", "second")
    assert record.occurrences == 2
    assert record.job_id == "job-2"
    assert record.fingerprint == finding_fingerprint(first)

    other_token = bind_tenant("tenant-b")
    try:
        await registry.add(first)
        other_records, _ = registry.list_page("tenant-b")
    finally:
        reset_tenant(other_token)
    assert len(other_records) == 1
    assert other_records[0].occurrences == 1
    registry.close()


@pytest.mark.asyncio
async def test_finding_cursor_filters_and_lifecycle_audit(tmp_path: Path) -> None:
    registry = _registry(tmp_path / "findings.db")
    token = bind_tenant("tenant-a")
    try:
        for index in range(3):
            await registry.add(
                _finding(
                    f"finding-{index}",
                    title=f"Issue {index}",
                )
            )
    finally:
        reset_tenant(token)

    first_page, cursor = registry.list_page("tenant-a", limit=2)
    assert len(first_page) == 2
    assert cursor is not None
    second_page, next_cursor = registry.list_page(
        "tenant-a", cursor=cursor, limit=2
    )
    assert len(second_page) == 1
    assert next_cursor is None
    assert {item.finding.id for item in [*first_page, *second_page]} == {
        "finding-0",
        "finding-1",
        "finding-2",
    }

    finding_id = first_page[0].finding.id
    updated = registry.update_lifecycle(
        "tenant-a",
        finding_id,
        status=FindingStatus.CONFIRMED,
        assigned_to="analyst@example.test",
        actor="user-1",
    )
    assert updated is not None
    assert updated.status is FindingStatus.CONFIRMED
    assert updated.assigned_to == "analyst@example.test"
    status_only = registry.update_lifecycle(
        "tenant-a", finding_id, status=FindingStatus.RESOLVED
    )
    assert status_only is not None
    assert status_only.assigned_to == "analyst@example.test"
    filtered, _ = registry.list_page(
        "tenant-a", status=FindingStatus.RESOLVED
    )
    assert [item.finding.id for item in filtered] == [finding_id]
    assert registry.update_lifecycle("tenant-b", finding_id) is None
    with Session(registry.engine) as session:
        audit_count = session.scalar(
            select(func.count()).select_from(AuditEventRow)
        )
    assert audit_count == 2

    with pytest.raises(ValueError, match="cursor"):
        registry.list_page("tenant-a", cursor="not-a-cursor")
    registry.close()
