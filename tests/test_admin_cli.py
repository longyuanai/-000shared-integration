"""Admin CLI coverage for secret-free API-key inventory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared_integration import admin_cli
from shared_integration.identity import SQLAlchemyIdentityRepository


def _database(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    database_url = f"sqlite:///{tmp_path / 'admin-api-keys.sqlite3'}"
    repository = SQLAlchemyIdentityRepository(database_url, create_schema=True)
    repository.create_tenant(
        tenant_id="tenant-a",
        slug="tenant-a",
        name="Tenant A",
    )
    repository.close()
    monkeypatch.setenv("INTEGRATION_DATABASE_URL", database_url)
    return database_url


def _issue(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    admin_cli.main(
        [
            "api-key-issue",
            "--tenant",
            "tenant-a",
            "--role",
            "viewer",
            "--scope",
            "gateway:read",
        ]
    )
    return json.loads(capsys.readouterr().out)


def test_api_key_list_returns_issued_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _database(monkeypatch, tmp_path)
    issued = _issue(capsys)

    admin_cli.main(["api-key-list", "--tenant", "tenant-a"])
    listed = json.loads(capsys.readouterr().out)["api_keys"]

    assert listed[0]["id"] == issued["id"]
    assert listed[0]["key_prefix"] == str(issued["token"]).partition(".")[0]
    assert listed[0]["role"] == "viewer"
    assert listed[0]["scopes"] == ["gateway:read"]


def test_api_key_list_hides_secret_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _database(monkeypatch, tmp_path)
    issued = _issue(capsys)
    token = str(issued["token"])

    admin_cli.main(["api-key-list", "--tenant", "tenant-a"])
    output = capsys.readouterr().out

    assert "secret_hash" not in output
    assert token not in output
    assert token.partition(".")[2] not in output


def test_api_key_list_excludes_revoked_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _database(monkeypatch, tmp_path)
    issued = _issue(capsys)
    admin_cli.main(
        [
            "api-key-revoke",
            "--tenant",
            "tenant-a",
            "--api-key",
            str(issued["id"]),
        ]
    )
    capsys.readouterr()

    admin_cli.main(["api-key-list", "--tenant", "tenant-a"])
    assert json.loads(capsys.readouterr().out) == {"api_keys": []}

    admin_cli.main(
        ["api-key-list", "--tenant", "tenant-a", "--include-revoked"]
    )
    listed = json.loads(capsys.readouterr().out)["api_keys"]
    assert listed[0]["id"] == issued["id"]
    assert listed[0]["revoked_at"] is not None
