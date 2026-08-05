"""Seed deterministic Finding and Job rows for the web-ui e2e live-mode tests.

Run inside the gateway container with the same DATABASE_URL the gateway uses:

    docker compose exec -T gateway python -m shared_integration.scripts.seed_e2e --tenant e2e

Idempotent: deletes prior seed rows for the given tenant by fingerprint/job_id prefix
before re-inserting, so reruns don't accumulate junk.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from typing import Any

# Bootstrap path so this script works as `python -m shared_integration.scripts.seed_e2e`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PACKAGE_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_SRC_ROOT = os.path.dirname(_PACKAGE_ROOT)
for candidate in (_SRC_ROOT, _PACKAGE_ROOT):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from sqlalchemy import delete  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from shared_integration.db_models import (  # noqa: E402
    FindingRow,
    JobEventRow,
    JobRow,
)
from shared_integration.sql_jobs import create_database_engine  # noqa: E402


SEED_FINDINGS: list[dict[str, Any]] = [
    {
        "source": "006",
        "severity": "critical",
        "confidence": 0.98,
        "title": "OpenSSL 组件命中已知在野利用漏洞",
        "asset": "edge-gateway-07",
        "cve": "CVE-2024-3094",
        "occurrences": 3,
        "status": "open",
        "minutes_ago": 4,
    },
    {
        "source": "001",
        "severity": "high",
        "confidence": 0.94,
        "title": "同一来源 IP 触发凭据填充关联规则",
        "asset": "auth-prod-02",
        "occurrences": 8,
        "status": "confirmed",
        "assigned_to": "SOC Team",
        "minutes_ago": 12,
    },
    {
        "source": "004",
        "severity": "high",
        "confidence": 0.91,
        "title": "未净化用户输入进入系统命令执行",
        "asset": "payments-api",
        "occurrences": 1,
        "status": "open",
        "minutes_ago": 22,
    },
    {
        "source": "003",
        "severity": "medium",
        "confidence": 0.88,
        "title": "间接提示注入绕过工具调用边界",
        "asset": "research-agent",
        "occurrences": 2,
        "status": "open",
        "minutes_ago": 31,
    },
    {
        "source": "002",
        "severity": "medium",
        "confidence": 0.86,
        "title": "外网资产存在高 EPSS 漏洞组合",
        "asset": "vpn.example.internal",
        "cve": "CVE-2023-23397",
        "occurrences": 2,
        "status": "accepted_risk",
        "minutes_ago": 47,
    },
    {
        "source": "005",
        "severity": "low",
        "confidence": 0.79,
        "title": "可疑样本包含动态解析 API 行为",
        "asset": "sample-98af.exe",
        "occurrences": 1,
        "status": "resolved",
        "minutes_ago": 71,
    },
    {
        "source": "001",
        "severity": "info",
        "confidence": 0.65,
        "title": "扫描器版本升级提示",
        "asset": "scheduler",
        "occurrences": 1,
        "status": "open",
        "minutes_ago": 95,
    },
]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _fingerprint(tenant_id: str, finding: dict[str, Any]) -> str:
    raw = json.dumps(
        {
            "tenant": tenant_id,
            "source": finding["source"],
            "title": finding["title"],
            "asset": finding.get("asset"),
            "cve": finding.get("cve"),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def seed(tenant_id: str, reset: bool) -> dict[str, int]:
    database_url = os.environ.get("INTEGRATION_DATABASE_URL")
    if not database_url:
        raise SystemExit("INTEGRATION_DATABASE_URL not set")
    engine = create_database_engine(database_url)
    factory = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    counts = {"findings": 0, "jobs": 0}
    with factory() as session:
        if reset:
            session.execute(
                delete(FindingRow).where(
                    FindingRow.tenant_id == tenant_id,
                    FindingRow.fingerprint.like("e2e:%"),
                )
            )
            session.execute(
                delete(JobEventRow).where(
                    JobEventRow.tenant_id == tenant_id,
                    JobEventRow.job_id.like("e2e-job-%"),
                )
            )
            session.execute(
                delete(JobRow).where(
                    JobRow.tenant_id == tenant_id,
                    JobRow.id.like("e2e-job-%"),
                )
            )

        now = _now()
        for entry in SEED_FINDINGS:
            fingerprint = "e2e:" + _fingerprint(tenant_id, entry)
            payload = {
                "seeded_by": "seed_e2e",
                "asset": entry.get("asset"),
                "cve": entry.get("cve"),
                "assigned_to": entry.get("assigned_to"),
            }
            session.execute(
                FindingRow.__table__.insert().values(
                    tenant_id=tenant_id,
                    finding_id=f"e2e-{fingerprint[:16]}",
                    fingerprint=fingerprint,
                    source=entry["source"],
                    severity=entry["severity"],
                    confidence=entry["confidence"],
                    status=entry["status"],
                    asset=entry.get("asset"),
                    cve=entry.get("cve"),
                    title=entry["title"],
                    description="",
                    first_seen=now - dt.timedelta(minutes=entry["minutes_ago"] + 5),
                    last_seen=now - dt.timedelta(minutes=entry["minutes_ago"]),
                    occurrences=entry["occurrences"],
                    job_id=None,
                    assigned_to=entry.get("assigned_to"),
                    payload=payload,
                    created_at=now,
                    updated_at=now,
                )
            )
            counts["findings"] += 1

        for job_index, status in enumerate(("running", "succeeded", "failed")):
            job_id = f"e2e-job-{job_index:03d}"
            session.execute(
                JobRow.__table__.insert().values(
                    id=job_id,
                    tenant_id=tenant_id,
                    source=("004", "001", "006")[job_index],
                    status=status,
                    payload={"seeded_by": "seed_e2e"},
                    attempt=1,
                    cancel_requested=False,
                    result_count=(2, 1, 0)[job_index],
                    error=(
                        None
                        if status != "failed"
                        else {"code": "ADAPTER_TIMEOUT", "message": "分析超过时间限制"}
                    ),
                    created_at=now - dt.timedelta(minutes=20 + job_index * 15),
                    updated_at=now - dt.timedelta(minutes=15 + job_index * 15),
                )
            )
            counts["jobs"] += 1

        session.commit()
    engine.dispose()
    return counts


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Seed e2e fixtures")
    parser.add_argument("--tenant", default="e2e")
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help="Append instead of resetting prior e2e rows.",
    )
    args = parser.parse_args(argv)
    counts = seed(args.tenant, reset=not args.no_reset)
    print(json.dumps({"tenant": args.tenant, "counts": counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))