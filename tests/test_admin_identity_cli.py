"""Admin CLI coverage for identity bridge credential lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import update

from shared_integration import admin_cli
from shared_integration.db_models import UserSessionRow
from shared_integration.identity import SQLAlchemyIdentityRepository


def test_identity_client_cli_create_list_rotate_and_revoke(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_url = f"sqlite:///{tmp_path / 'admin-cli.sqlite3'}"
    repository = SQLAlchemyIdentityRepository(database_url, create_schema=True)
    repository.close()
    monkeypatch.setenv("INTEGRATION_DATABASE_URL", database_url)

    admin_cli.main(
        [
            "identity-client-create",
            "--name",
            "Dashboard BFF",
            "--issuer",
            "https://identity.example.test",
        ]
    )
    created = json.loads(capsys.readouterr().out)
    assert created["token"].startswith("igb_")
    assert created["key_prefix"].startswith("igb_")
    assert created["active"] is True
    previous_id = created["id"]
    previous_token = created["token"]

    admin_cli.main(["identity-client-list"])
    listed_text = capsys.readouterr().out
    listed = json.loads(listed_text)
    assert previous_token not in listed_text
    assert listed["identity_clients"][0]["id"] == previous_id
    assert "secret_hash" not in listed["identity_clients"][0]

    admin_cli.main(
        ["identity-client-rotate", "--identity-client", previous_id]
    )
    rotated = json.loads(capsys.readouterr().out)
    assert rotated["id"] != previous_id
    assert rotated["rotated_from_id"] == previous_id
    assert rotated["token"] != previous_token

    admin_cli.main(
        ["identity-client-revoke", "--identity-client", previous_id]
    )
    revoked = json.loads(capsys.readouterr().out)
    assert revoked == {"id": previous_id, "revoked": True}

    admin_cli.main(["identity-client-list"])
    final_list = json.loads(capsys.readouterr().out)["identity_clients"]
    by_id = {entry["id"]: entry for entry in final_list}
    assert by_id[previous_id]["active"] is False
    assert by_id[rotated["id"]]["active"] is True


def test_user_session_cli_revoke_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_url = f"sqlite:///{tmp_path / 'session-cli.sqlite3'}"
    repository = SQLAlchemyIdentityRepository(database_url, create_schema=True)
    repository.create_tenant(
        tenant_id="tenant-a",
        slug="tenant-a",
        name="Tenant A",
    )
    user = repository.upsert_user(
        issuer="https://identity.example.test",
        subject="subject-a",
    )
    repository.set_membership(
        tenant_id="tenant-a",
        user_id=user.id,
        role="analyst",
    )
    client = repository.issue_identity_client(
        name="Dashboard BFF",
        allowed_issuers=["https://identity.example.test"],
    )
    revoked_session = repository.issue_user_session(
        identity_client_id=client.record.id,
        tenant_id="tenant-a",
        user_id=user.id,
    )
    expired_session = repository.issue_user_session(
        identity_client_id=client.record.id,
        tenant_id="tenant-a",
        user_id=user.id,
    )
    with repository.engine.begin() as connection:
        connection.execute(
            update(UserSessionRow)
            .where(UserSessionRow.id == expired_session.id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    repository.close()
    monkeypatch.setenv("INTEGRATION_DATABASE_URL", database_url)

    admin_cli.main(
        [
            "user-session-revoke",
            "--tenant",
            "tenant-a",
            "--session",
            revoked_session.id,
        ]
    )
    revoked = json.loads(capsys.readouterr().out)
    assert revoked == {"id": revoked_session.id, "revoked": True}

    admin_cli.main(
        [
            "user-session-cleanup",
            "--before",
            datetime.now(UTC).isoformat(),
        ]
    )
    cleaned = json.loads(capsys.readouterr().out)
    assert cleaned == {"deleted": 1}

    repository = SQLAlchemyIdentityRepository(database_url)
    try:
        assert repository.authenticate_user_session(revoked_session.token) is None
        assert repository.authenticate_user_session(expired_session.token) is None
    finally:
        repository.close()
