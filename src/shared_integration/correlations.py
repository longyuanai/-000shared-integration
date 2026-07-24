"""Cross-product Finding correlation rules."""

from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from shared_llm_core import (
    Correlation,
    CorrelationRule,
    Finding,
    FindingSeverity,
)

_SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


class SameHostMultiSourceRule(CorrelationRule):
    """Correlate findings on one host from different products within 24 hours."""

    id = "integ-same-host-multi-source"

    def __init__(self, window: timedelta = timedelta(hours=24)) -> None:
        if window < timedelta(0):
            raise ValueError("window must be non-negative")
        self._window = window

    def correlate(
        self,
        new_finding: Finding,
        existing: Sequence[Finding],
    ) -> list[Correlation]:
        if not new_finding.host:
            return []

        related = [
            finding
            for finding in existing
            if finding.id != new_finding.id
            and finding.host == new_finding.host
            and finding.source != new_finding.source
            and _within_window(new_finding, finding, self._window)
        ]
        if not related:
            return []

        sources = ", ".join(
            [new_finding.source.value, *(finding.source.value for finding in related)]
        )
        return [
            Correlation(
                rule_id=self.id,
                findings=(new_finding.id, *(finding.id for finding in related)),
                severity=_max_severity([new_finding, *related]),
                narrative=f"Multi-source findings on {new_finding.host}: {sources}",
            )
        ]


def _within_window(a: Finding, b: Finding, window: timedelta) -> bool:
    if a.ts is None or b.ts is None:
        return True
    return abs((a.ts - b.ts).total_seconds()) <= window.total_seconds()


def _max_severity(findings: Sequence[Finding]) -> FindingSeverity:
    if not findings:
        raise ValueError("findings must not be empty")
    return max(findings, key=lambda finding: _SEVERITY_RANK[finding.severity]).severity


__all__ = ["SameHostMultiSourceRule"]
