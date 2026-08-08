"""Provision and clean isolated multi-tenant RBAC browser fixtures.

This module is intentionally test-only. Run it inside the E2E gateway container so
the bridge secret is emitted only to the local test orchestrator:

    python -m shared_integration.scripts.seed_rbac_e2e provision --run-id RUN_ID
    python -m shared_integration.scripts.seed_rbac_e2e membership \
        --run-id RUN_ID --persona revoked --status suspended
    python -m shared_integration.scripts.seed_rbac_e2e expire \
        --run-id RUN_ID --persona expiring
    python -m shared_integration.scripts.seed_rbac_e2e cleanup --run-id RUN_ID

Every mutation is constrained to deterministic ``e2e-rbac`` identifiers derived
from ``run-id``. No unlabelled tenant, user, client, session, job, or finding is
selected for deletion.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from typing import Any, Final

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from shared_integration.db_models import (
    ApiKeyRow,
    AuditEventRow,
    CorrelationFindingRow,
    CorrelationRow,
    FindingRow,
    IdentityClientRow,
    JobEventRow,
    JobRow,
    MembershipRow,
    TenantRow,
    UserRow,
    UserSessionRow,
)
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.sql_jobs import create_database_engine

ISSUER: Final = "https://chatgpt.com/"
_RUN_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_PERSONAS: Final[dict[str, tuple[str, str | None]]] = {
    "viewer": ("viewer", "a"),
    "analyst": ("analyst", "a"),
    "admin": ("admin", "a"),
    "cross": ("viewer", "b"),
    "revoked": ("viewer", "a"),
    "expiring": ("analyst", "a"),
    "logout": ("analyst", "a"),
    "refresh": ("viewer", "a"),
    "no-member": ("viewer", None),
}


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _database_url() -> str:
    value = os.getenv("INTEGRATION_DATABASE_URL", "").strip()
    if not value:
        raise SystemExit("INTEGRATION_DATABASE_URL not set")
    return value


def _normalize_run_id(value: str) -> str:
    normalized = value.strip().lower()
    if not _RUN_ID.fullmatch(normalized):
        raise ValueError(
            "run-id must contain 1 to 32 lowercase letters, digits, or internal hyphens"
        )
    return normalized


def _tenant_id(run_id: str, suffix: str) -> str:
    return f"e2e-rbac-{run_id}-{suffix}"


def _subject(run_id: str, persona: str) -> str:
    return f"e2e-rbac:{run_id}:{persona}"


def _client_name(run_id: str) -> str:
    return f"[e2e-rbac:{run_id}] Dashboard BFF"


def _factory(database_url: str) -> tuple[Any, sessionmaker[Session]]:
    engine = create_database_engine(database_url)
    return engine, sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def provision(run_id: str, *, database_url: str | None = None) -> dict[str, Any]:
    run_id = _normalize_run_id(run_id)
    url = database_url or _database_url()
    cleanup(run_id, database_url=url)
    repository = SQLAlchemyIdentityRepository(url)
    tenant_a = _tenant_id(run_id, "a")
    tenant_b = _tenant_id(run_id, "b")
    try:
        repository.create_tenant(
            tenant_id=tenant_a,
            slug=tenant_a,
            name=f"E2E RBAC {run_id} Tenant A",
            actor="e2e-rbac-fixture",
        )
        repository.create_tenant(
            tenant_id=tenant_b,
            slug=tenant_b,
            name=f"E2E RBAC {run_id} Tenant B",
            actor="e2e-rbac-fixture",
        )
        identities: dict[str, dict[str, str]] = {}
        for persona, (role, tenant_suffix) in _PERSONAS.items():
            user = repository.upsert_user(
                issuer=ISSUER,
                subject=_subject(run_id, persona),
                email=f"{persona}.{run_id}@e2e.invalid",
                display_name=f"E2E {persona}",
            )
            if tenant_suffix is not None:
                repository.set_membership(
                    tenant_id=tenant_a if tenant_suffix == "a" else tenant_b,
                    user_id=user.id,
                    role=role,
                    actor="e2e-rbac-fixture",
                )
            identities[persona] = {
                "subject": user.subject,
                "email": user.email or "",
                "display_name": user.display_name or "",
            }
        issued_client = repository.issue_identity_client(
            name=_client_name(run_id),
            allowed_issuers=[ISSUER],
        )
        resources = _seed_resources(url, run_id, tenant_a, tenant_b)
        return {
            "run_id": run_id,
            "issuer": ISSUER,
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "identity_client_id": issued_client.record.id,
            "bridge_token": issued_client.token,
            "identities": identities,
            **resources,
        }
    except Exception:
        cleanup(run_id, database_url=url)
        raise
    finally:
        repository.close()


def _seed_resources(
    database_url: str,
    run_id: str,
    tenant_a: str,
    tenant_b: str,
) -> dict[str, str]:
    engine, factory = _factory(database_url)
    now = _utcnow()
    try:
        with factory.begin() as session:
            result: dict[str, str] = {}
            for suffix, tenant_id in (("a", tenant_a), ("b", tenant_b)):
                finding_id = f"e2e-rbac-{run_id}-{suffix}-finding"
                job_id = "job_" + hashlib.sha256(
                    f"e2e-rbac:{run_id}:{suffix}:job".encode()
                ).hexdigest()[:32]
                title = f"E2E RBAC {run_id.upper()} TENANT {suffix.upper()}"
                asset = f"{suffix}-asset.e2e.invalid"
                fingerprint = "e2e:" + hashlib.sha256(
                    f"{tenant_id}:{finding_id}".encode()
                ).hexdigest()[:60]
                session.add(
                    FindingRow(
                        tenant_id=tenant_id,
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        source="001",
                        severity="high",
                        confidence=0.99,
                        status="open",
                        asset=asset,
                        title=title,
                        description="isolated browser RBAC fixture",
                        first_seen=now,
                        last_seen=now,
                        occurrences=1,
                        payload={
                            "id": finding_id,
                            "source": "001",
                            "severity": "high",
                            "confidence": 0.99,
                            "title": title,
                            "description": "isolated browser RBAC fixture",
                            "host": asset,
                            "cve": None,
                            "ts": now.isoformat(),
                            "evidence": [],
                            "related": [],
                            "tags": ["e2e-rbac"],
                            "metadata": {"fixture": "e2e-rbac", "run_id": run_id},
                        },
                        created_at=now,
                        updated_at=now,
                    )
                )
                session.add(
                    JobRow(
                        id=job_id,
                        tenant_id=tenant_id,
                        source="001",
                        status="succeeded",
                        queue="fast",
                        input_payload={"fixture": "e2e-rbac", "run_id": run_id},
                        progress=1.0,
                        attempt=1,
                        cancel_requested=False,
                        result_count=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
                result[f"tenant_{suffix}_finding_title"] = title
                result[f"tenant_{suffix}_job_id"] = job_id
            return result
    finally:
        engine.dispose()


def set_membership_status(
    run_id: str,
    persona: str,
    status: str,
    *,
    database_url: str | None = None,
) -> dict[str, str]:
    run_id = _normalize_run_id(run_id)
    if persona not in _PERSONAS or _PERSONAS[persona][1] is None:
        raise ValueError("persona must identify a fixture member")
    if status not in {"active", "suspended"}:
        raise ValueError("status must be active or suspended")
    tenant_suffix = _PERSONAS[persona][1]
    repository = SQLAlchemyIdentityRepository(database_url or _database_url())
    try:
        with Session(repository.engine) as session:
            user_id = session.scalar(
                select(UserRow.id).where(
                    UserRow.issuer == ISSUER,
                    UserRow.subject == _subject(run_id, persona),
                )
            )
        if not user_id or tenant_suffix is None:
            raise KeyError("fixture persona not found")
        tenant_id = _tenant_id(run_id, tenant_suffix)
        repository.set_membership_status(
            tenant_id=tenant_id,
            user_id=user_id,
            status=status,
            actor="e2e-rbac-fixture",
        )
        return {"run_id": run_id, "persona": persona, "status": status}
    finally:
        repository.close()


def expire_sessions(
    run_id: str,
    persona: str,
    *,
    database_url: str | None = None,
) -> dict[str, Any]:
    run_id = _normalize_run_id(run_id)
    tenant_suffix = _PERSONAS.get(persona, ("", None))[1]
    if tenant_suffix is None:
        raise ValueError("persona must identify a fixture member")
    engine, factory = _factory(database_url or _database_url())
    try:
        with factory.begin() as session:
            user_id = session.scalar(
                select(UserRow.id).where(
                    UserRow.issuer == ISSUER,
                    UserRow.subject == _subject(run_id, persona),
                )
            )
            if not user_id:
                raise KeyError("fixture persona not found")
            result = session.execute(
                update(UserSessionRow)
                .where(
                    UserSessionRow.tenant_id == _tenant_id(run_id, tenant_suffix),
                    UserSessionRow.user_id == user_id,
                )
                .values(expires_at=_utcnow() - dt.timedelta(seconds=1))
            )
            return {
                "run_id": run_id,
                "persona": persona,
                "expired_sessions": int(result.rowcount or 0),
            }
    finally:
        engine.dispose()


def snapshot(run_id: str, *, database_url: str | None = None) -> dict[str, int]:
    run_id = _normalize_run_id(run_id)
    tenant_ids = (_tenant_id(run_id, "a"), _tenant_id(run_id, "b"))
    subject_prefix = f"e2e-rbac:{run_id}:"
    engine, factory = _factory(database_url or _database_url())
    try:
        with factory() as session:
            user_ids = select(UserRow.id).where(
                UserRow.issuer == ISSUER,
                UserRow.subject.like(f"{subject_prefix}%"),
            )
            client_ids = select(IdentityClientRow.id).where(
                IdentityClientRow.name == _client_name(run_id)
            )
            return {
                "tenants": int(
                    session.scalar(
                        select(func.count()).select_from(TenantRow).where(
                            TenantRow.id.in_(tenant_ids)
                        )
                    )
                    or 0
                ),
                "users": int(
                    session.scalar(
                        select(func.count()).select_from(UserRow).where(
                            UserRow.id.in_(user_ids)
                        )
                    )
                    or 0
                ),
                "clients": int(
                    session.scalar(
                        select(func.count()).select_from(IdentityClientRow).where(
                            IdentityClientRow.id.in_(client_ids)
                        )
                    )
                    or 0
                ),
                "sessions": int(
                    session.scalar(
                        select(func.count()).select_from(UserSessionRow).where(
                            or_(
                                UserSessionRow.tenant_id.in_(tenant_ids),
                                UserSessionRow.user_id.in_(user_ids),
                                UserSessionRow.identity_client_id.in_(client_ids),
                            )
                        )
                    )
                    or 0
                ),
                "findings": int(
                    session.scalar(
                        select(func.count()).select_from(FindingRow).where(
                            FindingRow.tenant_id.in_(tenant_ids)
                        )
                    )
                    or 0
                ),
                "jobs": int(
                    session.scalar(
                        select(func.count()).select_from(JobRow).where(
                            JobRow.tenant_id.in_(tenant_ids)
                        )
                    )
                    or 0
                ),
            }
    finally:
        engine.dispose()


def cleanup(run_id: str, *, database_url: str | None = None) -> dict[str, int]:
    run_id = _normalize_run_id(run_id)
    url = database_url or _database_url()
    before = snapshot(run_id, database_url=url)
    tenant_ids = (_tenant_id(run_id, "a"), _tenant_id(run_id, "b"))
    subject_prefix = f"e2e-rbac:{run_id}:"
    engine, factory = _factory(url)
    try:
        with factory.begin() as session:
            user_ids = select(UserRow.id).where(
                UserRow.issuer == ISSUER,
                UserRow.subject.like(f"{subject_prefix}%"),
            )
            client_ids = select(IdentityClientRow.id).where(
                IdentityClientRow.name == _client_name(run_id)
            )
            session.execute(
                delete(CorrelationFindingRow).where(
                    CorrelationFindingRow.tenant_id.in_(tenant_ids)
                )
            )
            for model in (
                CorrelationRow,
                FindingRow,
                JobEventRow,
                JobRow,
                AuditEventRow,
                ApiKeyRow,
                MembershipRow,
            ):
                session.execute(delete(model).where(model.tenant_id.in_(tenant_ids)))
            session.execute(
                delete(UserSessionRow).where(
                    or_(
                        UserSessionRow.tenant_id.in_(tenant_ids),
                        UserSessionRow.user_id.in_(user_ids),
                        UserSessionRow.identity_client_id.in_(client_ids),
                    )
                )
            )
            session.execute(delete(TenantRow).where(TenantRow.id.in_(tenant_ids)))
            session.execute(
                delete(IdentityClientRow).where(
                    IdentityClientRow.name == _client_name(run_id)
                )
            )
            session.execute(
                delete(UserRow).where(
                    UserRow.issuer == ISSUER,
                    UserRow.subject.like(f"{subject_prefix}%"),
                )
            )
    finally:
        engine.dispose()
    remaining = snapshot(run_id, database_url=url)
    if any(remaining.values()):
        raise RuntimeError(f"fixture cleanup incomplete: {remaining}")
    return before


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage isolated RBAC E2E fixtures")
    parser.add_argument(
        "action",
        choices=("provision", "membership", "expire", "snapshot", "cleanup"),
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--persona", choices=tuple(_PERSONAS))
    parser.add_argument("--status", choices=("active", "suspended"))
    args = parser.parse_args(argv)
    if args.action == "provision":
        result = provision(args.run_id)
    elif args.action == "membership":
        if not args.persona or not args.status:
            parser.error("membership requires --persona and --status")
        result = set_membership_status(args.run_id, args.persona, args.status)
    elif args.action == "expire":
        if not args.persona:
            parser.error("expire requires --persona")
        result = expire_sessions(args.run_id, args.persona)
    elif args.action == "snapshot":
        result = snapshot(args.run_id)
    else:
        result = cleanup(args.run_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
