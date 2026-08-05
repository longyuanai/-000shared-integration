"""Cross-product correlation rule tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from shared_llm_core import Finding, FindingSeverity, FindingSource

from shared_integration.correlations import SameHostMultiSourceRule

NOW = datetime(2026, 7, 24, 12, tzinfo=UTC)


def make_finding(
    identifier: str,
    *,
    source: FindingSource,
    host: str | None = "server-1",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    ts: datetime | None = NOW,
) -> Finding:
    return Finding(
        id=identifier,
        source=source,
        severity=severity,
        confidence=0.9,
        title=f"Finding {identifier}",
        host=host,
        ts=ts,
    )


def test_same_host_correlation_triggers() -> None:
    existing = make_finding("soc", source=FindingSource.SOC)
    new = make_finding("vuln", source=FindingSource.VULN)
    correlations = SameHostMultiSourceRule().correlate(new, [existing])
    assert len(correlations) == 1
    assert correlations[0].findings == ("vuln", "soc")


def test_same_source_no_correlation() -> None:
    existing = make_finding("soc-1", source=FindingSource.SOC)
    new = make_finding("soc-2", source=FindingSource.SOC)
    assert SameHostMultiSourceRule().correlate(new, [existing]) == []


def test_different_hosts_no_correlation() -> None:
    existing = make_finding("soc", source=FindingSource.SOC, host="server-1")
    new = make_finding("vuln", source=FindingSource.VULN, host="server-2")
    assert SameHostMultiSourceRule().correlate(new, [existing]) == []


def test_window_exceeded_no_correlation() -> None:
    existing = make_finding("soc", source=FindingSource.SOC, ts=NOW - timedelta(days=30))
    new = make_finding("vuln", source=FindingSource.VULN)
    assert SameHostMultiSourceRule().correlate(new, [existing]) == []


def test_no_host_no_correlation() -> None:
    existing = make_finding("soc", source=FindingSource.SOC)
    new = make_finding("vuln", source=FindingSource.VULN, host=None)
    assert SameHostMultiSourceRule().correlate(new, [existing]) == []


def test_correlation_severity_is_max() -> None:
    existing = make_finding(
        "soc",
        source=FindingSource.SOC,
        severity=FindingSeverity.CRITICAL,
    )
    new = make_finding(
        "vuln",
        source=FindingSource.VULN,
        severity=FindingSeverity.LOW,
    )
    correlation = SameHostMultiSourceRule().correlate(new, [existing])[0]
    assert correlation.severity is FindingSeverity.CRITICAL


def test_missing_timestamp_is_treated_as_related() -> None:
    existing = make_finding("soc", source=FindingSource.SOC, ts=None)
    new = make_finding("vuln", source=FindingSource.VULN)
    assert len(SameHostMultiSourceRule().correlate(new, [existing])) == 1


def test_multiple_sources_form_one_correlation() -> None:
    soc = make_finding("soc", source=FindingSource.SOC)
    code = make_finding("code", source=FindingSource.CODE)
    new = make_finding("vuln", source=FindingSource.VULN)
    correlation = SameHostMultiSourceRule().correlate(new, [soc, code])[0]
    assert correlation.findings == ("vuln", "soc", "code")


def test_negative_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        SameHostMultiSourceRule(window=timedelta(seconds=-1))
