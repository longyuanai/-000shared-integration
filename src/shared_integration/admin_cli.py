"""Operational CLI for identity bootstrap and legacy data migration."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from shared_integration.identity import ROLES, SQLAlchemyIdentityRepository
from shared_integration.migration_tools import LegacySQLiteMigrator


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    arguments = parser.parse_args(argv)
    database_url = os.getenv("INTEGRATION_DATABASE_URL", "").strip()
    if not database_url:
        parser.error("INTEGRATION_DATABASE_URL must be set")

    if arguments.command == "migrate-sqlite":
        migrator = LegacySQLiteMigrator(arguments.source, database_url)
        try:
            report = migrator.run(apply=arguments.apply)
        finally:
            migrator.close()
        _print(report.to_dict())
        return

    repository = SQLAlchemyIdentityRepository(database_url)
    try:
        if arguments.command == "tenant-create":
            record = repository.create_tenant(
                tenant_id=arguments.tenant,
                slug=arguments.slug,
                name=arguments.name,
                retention_days=arguments.retention_days,
                actor=arguments.actor,
            )
            _print(
                {
                    "id": record.id,
                    "slug": record.slug,
                    "name": record.name,
                    "status": record.status,
                    "retention_days": record.retention_days,
                }
            )
        elif arguments.command == "tenant-status":
            record = repository.set_tenant_status(
                arguments.tenant,
                arguments.status,
                actor=arguments.actor,
            )
            _print({"id": record.id, "status": record.status})
        elif arguments.command == "user-upsert":
            record = repository.upsert_user(
                issuer=arguments.issuer,
                subject=arguments.subject,
                email=arguments.email,
                display_name=arguments.display_name,
            )
            _print(
                {
                    "id": record.id,
                    "issuer": record.issuer,
                    "subject": record.subject,
                    "email": record.email,
                    "display_name": record.display_name,
                }
            )
        elif arguments.command == "membership-set":
            record = repository.set_membership(
                tenant_id=arguments.tenant,
                user_id=arguments.user,
                role=arguments.role,
                actor=arguments.actor,
            )
            _print(
                {
                    "tenant_id": record.tenant_id,
                    "user_id": record.user_id,
                    "role": record.role,
                }
            )
        elif arguments.command == "api-key-issue":
            issued = repository.issue_api_key(
                tenant_id=arguments.tenant,
                role=arguments.role,
                scopes=arguments.scope,
                expires_at=_parse_expiry(arguments.expires_at),
                actor=arguments.actor,
            )
            _print(
                {
                    "id": issued.id,
                    "tenant_id": issued.tenant_id,
                    "role": issued.role,
                    "scopes": list(issued.scopes),
                    "expires_at": (
                        issued.expires_at.isoformat() if issued.expires_at else None
                    ),
                    "token": issued.token,
                    "warning": "store this token now; it cannot be recovered",
                }
            )
        elif arguments.command == "api-key-revoke":
            revoked = repository.revoke_api_key(
                arguments.tenant,
                arguments.api_key,
                actor=arguments.actor,
            )
            _print({"id": arguments.api_key, "revoked": revoked})
        else:  # pragma: no cover - argparse enforces the command set
            parser.error(f"unsupported command: {arguments.command}")
    finally:
        repository.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shared-integration-admin",
        description="Bootstrap persistent identity and migrate legacy SQLite data.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    tenant_create = commands.add_parser("tenant-create")
    tenant_create.add_argument("--tenant", required=True)
    tenant_create.add_argument("--slug", required=True)
    tenant_create.add_argument("--name", required=True)
    tenant_create.add_argument("--retention-days", type=int, default=90)
    _actor_argument(tenant_create)

    tenant_status = commands.add_parser("tenant-status")
    tenant_status.add_argument("--tenant", required=True)
    tenant_status.add_argument(
        "--status", choices=("active", "suspended", "disabled"), required=True
    )
    _actor_argument(tenant_status)

    user_upsert = commands.add_parser("user-upsert")
    user_upsert.add_argument("--issuer", required=True)
    user_upsert.add_argument("--subject", required=True)
    user_upsert.add_argument("--email")
    user_upsert.add_argument("--display-name")

    membership_set = commands.add_parser("membership-set")
    membership_set.add_argument("--tenant", required=True)
    membership_set.add_argument("--user", required=True)
    membership_set.add_argument("--role", choices=sorted(ROLES), required=True)
    _actor_argument(membership_set)

    key_issue = commands.add_parser("api-key-issue")
    key_issue.add_argument("--tenant", required=True)
    key_issue.add_argument("--role", choices=sorted(ROLES), required=True)
    key_issue.add_argument("--scope", action="append", default=[])
    key_issue.add_argument(
        "--expires-at",
        help="ISO-8601 timestamp with timezone, for example 2027-01-01T00:00:00Z",
    )
    _actor_argument(key_issue)

    key_revoke = commands.add_parser("api-key-revoke")
    key_revoke.add_argument("--tenant", required=True)
    key_revoke.add_argument("--api-key", required=True)
    _actor_argument(key_revoke)

    migrate = commands.add_parser("migrate-sqlite")
    migrate.add_argument("source", help="path to the legacy SQLite database")
    migrate.add_argument(
        "--apply",
        action="store_true",
        help="write to the target; without this flag the command is a dry run",
    )
    return parser


def _actor_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor", default="integration-admin-cli")


def _parse_expiry(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("--expires-at must include a timezone")
    return parsed


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
