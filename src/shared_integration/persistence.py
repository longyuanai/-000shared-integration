"""SQLite-backed, tenant-isolated Finding registry."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

from shared_llm_core import (
    Correlation,
    Finding,
    FindingRegistry,
    FindingSeverity,
    FindingSource,
)

from shared_integration.auth import current_tenant

FindingStreamItem = tuple[str, Finding] | tuple[str, Correlation]


class SQLiteTenantFindingRegistry(FindingRegistry):
    """Persist Findings and correlations while isolating every tenant."""

    def __init__(self, path: str | Path, *, max_size: int = 100_000) -> None:
        super().__init__(max_size=max_size)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._max_size = max_size
        self._db_lock = threading.RLock()
        self._tenant_subscribers: dict[
            str, list[asyncio.Queue[FindingStreamItem]]
        ] = {}
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE (tenant_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_tenant_seq
                ON findings (tenant_id, seq DESC);
            CREATE TABLE IF NOT EXISTS correlations (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_correlations_tenant_seq
                ON correlations (tenant_id, seq DESC);
            """
        )
        self._connection.commit()

    @property
    def findings(self) -> tuple[Finding, ...]:
        tenant = current_tenant()
        with self._db_lock:
            rows = self._connection.execute(
                "SELECT payload FROM findings WHERE tenant_id = ? ORDER BY seq ASC",
                (tenant,),
            ).fetchall()
        return tuple(Finding.from_dict(json.loads(row[0])) for row in rows)

    @property
    def correlations(self) -> tuple[Correlation, ...]:
        tenant = current_tenant()
        with self._db_lock:
            rows = self._connection.execute(
                "SELECT payload FROM correlations WHERE tenant_id = ? ORDER BY seq ASC",
                (tenant,),
            ).fetchall()
        return tuple(_correlation_from_json(row[0]) for row in rows)

    async def add(self, finding: Finding) -> None:
        tenant = current_tenant()
        self._store_finding(tenant, finding)
        for queue in self._tenant_subscribers.get(tenant, ()):
            if not queue.full():
                queue.put_nowait(("finding", finding))

    async def add_correlation(self, correlation: Correlation) -> None:
        tenant = current_tenant()
        with self._db_lock:
            self._connection.execute(
                "INSERT INTO correlations (tenant_id, payload) VALUES (?, ?)",
                (tenant, _correlation_to_json(correlation)),
            )
            self._prune("correlations", tenant)
            self._connection.commit()
        for queue in self._tenant_subscribers.get(tenant, ()):
            if not queue.full():
                queue.put_nowait(("correlation", correlation))

    def add_sync(self, finding: Finding) -> None:
        self._store_finding(current_tenant(), finding)

    def query(
        self,
        *,
        source: FindingSource | None = None,
        severity: FindingSeverity | None = None,
        host: str | None = None,
        cve: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        tenant = current_tenant()
        with self._db_lock:
            rows = self._connection.execute(
                "SELECT payload FROM findings WHERE tenant_id = ? ORDER BY seq DESC",
                (tenant,),
            ).fetchall()
        results: list[Finding] = []
        for row in rows:
            finding = Finding.from_dict(json.loads(row[0]))
            if source is not None and finding.source != source:
                continue
            if severity is not None and finding.severity != severity:
                continue
            if host is not None and finding.host != host:
                continue
            if cve is not None and finding.cve != cve:
                continue
            if since is not None and finding.ts is not None and finding.ts < since:
                continue
            results.append(finding)
            if len(results) >= limit:
                break
        return results

    async def subscribe(self) -> AsyncIterator[FindingStreamItem]:
        tenant = current_tenant()
        queue: asyncio.Queue[FindingStreamItem] = asyncio.Queue(maxsize=1000)
        subscribers = self._tenant_subscribers.setdefault(tenant, [])
        subscribers.append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            subscribers.remove(queue)
            if not subscribers:
                self._tenant_subscribers.pop(tenant, None)

    def close(self) -> None:
        with self._db_lock:
            self._connection.close()

    def _store_finding(self, tenant: str, finding: Finding) -> None:
        payload = json.dumps(finding.to_dict(), separators=(",", ":"))
        with self._db_lock:
            self._connection.execute(
                """
                INSERT INTO findings (tenant_id, finding_id, payload)
                VALUES (?, ?, ?)
                ON CONFLICT (tenant_id, finding_id)
                DO UPDATE SET payload = excluded.payload
                """,
                (tenant, finding.id, payload),
            )
            self._prune("findings", tenant)
            self._connection.commit()

    def _prune(self, table: str, tenant: str) -> None:
        self._connection.execute(
            f"""
            DELETE FROM {table}
            WHERE tenant_id = ?
              AND seq NOT IN (
                SELECT seq FROM {table}
                WHERE tenant_id = ?
                ORDER BY seq DESC
                LIMIT ?
              )
            """,
            (tenant, tenant, self._max_size),
        )


def _correlation_to_json(correlation: Correlation) -> str:
    return json.dumps(
        {
            "rule_id": correlation.rule_id,
            "findings": list(correlation.findings),
            "severity": correlation.severity.value,
            "narrative": correlation.narrative,
        },
        separators=(",", ":"),
    )


def _correlation_from_json(payload: str) -> Correlation:
    value = json.loads(payload)
    return Correlation(
        rule_id=value["rule_id"],
        findings=tuple(value["findings"]),
        severity=FindingSeverity(value["severity"]),
        narrative=value["narrative"],
    )


__all__ = ["SQLiteTenantFindingRegistry"]
