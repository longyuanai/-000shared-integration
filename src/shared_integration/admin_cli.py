"""Operational CLI for identity bootstrap and legacy data migration."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from shared_integration.identity import (
    ROLES,
    ApiKeyRecord,
    IdentityClientRecord,
    SQLAlchemyIdentityRepository,
)
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
        elif arguments.command == "api-key-list":
            _print(
                {
                    "api_keys": [
                        _api_key_payload(record)
                        for record in repository.list_api_keys(
                            arguments.tenant,
                            include_revoked=arguments.include_revoked,
                        )
                    ]
                }
            )
        elif arguments.command == "identity-client-create":
            issued = repository.issue_identity_client(
                name=arguments.name,
                allowed_issuers=arguments.issuer,
            )
            _print(
                {
                    **_identity_client_payload(issued.record),
                    "token": issued.token,
                    "warning": "store this token now; it cannot be recovered",
                }
            )
        elif arguments.command == "identity-client-list":
            _print(
                {
                    "identity_clients": [
                        _identity_client_payload(record)
                        for record in repository.list_identity_clients()
                    ]
                }
            )
        elif arguments.command == "identity-client-rotate":
            issued = repository.rotate_identity_client(arguments.identity_client)
            _print(
                {
                    **_identity_client_payload(issued.record),
                    "token": issued.token,
                    "warning": (
                        "store this token now; verify it before revoking the previous client"
                    ),
                }
            )
        elif arguments.command == "identity-client-revoke":
            revoked = repository.revoke_identity_client(arguments.identity_client)
            _print({"id": arguments.identity_client, "revoked": revoked})
        elif arguments.command == "user-session-revoke":
            revoked = repository.revoke_user_session(
                arguments.tenant,
                arguments.session,
                actor=arguments.actor,
            )
            _print({"id": arguments.session, "revoked": revoked})
        elif arguments.command == "user-session-cleanup":
            deleted = repository.cleanup_expired_user_sessions(
                before=_parse_timestamp(arguments.before, option="--before")
                if arguments.before
                else None
            )
            _print({"deleted": deleted})
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

    key_list = commands.add_parser("api-key-list")
    key_list.add_argument("--tenant", required=True)
    key_list.add_argument("--include-revoked", action="store_true")

    client_create = commands.add_parser("identity-client-create")
    client_create.add_argument("--name", required=True)
    client_create.add_argument("--issuer", action="append", required=True)

    commands.add_parser("identity-client-list")

    client_rotate = commands.add_parser("identity-client-rotate")
    client_rotate.add_argument("--identity-client", required=True)

    client_revoke = commands.add_parser("identity-client-revoke")
    client_revoke.add_argument("--identity-client", required=True)

    session_revoke = commands.add_parser("user-session-revoke")
    session_revoke.add_argument("--tenant", required=True)
    session_revoke.add_argument("--session", required=True)
    _actor_argument(session_revoke)

    session_cleanup = commands.add_parser("user-session-cleanup")
    session_cleanup.add_argument(
        "--before",
        help="delete sessions expiring at or before this ISO-8601 timestamp",
    )

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
    return _parse_timestamp(value, option="--expires-at")


def _parse_timestamp(value: str, *, option: str) -> datetime:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{option} must include a timezone")
    return parsed


def _identity_client_payload(record: IdentityClientRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "name": record.name,
        "key_prefix": record.key_prefix,
        "allowed_issuers": list(record.allowed_issuers),
        "active": record.active,
        "rotated_from_id": record.rotated_from_id,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "last_used_at": (
            record.last_used_at.isoformat() if record.last_used_at else None
        ),
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
    }


def _api_key_payload(record: ApiKeyRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "key_prefix": record.key_prefix,
        "role": record.role,
        "scopes": list(record.scopes),
        "created_at": record.created_at.isoformat(),
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
    }


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
