from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_installs_code_audit_from_canonical_suite_path() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY [\"004AI-Code-Audit/\", \"/suite/004AI-Code-Audit/\"]" in dockerfile
    assert "test -f /suite/004AI-Code-Audit/004AI-CodeGuard-upgrade/pyproject.toml" in dockerfile
    assert "    /suite/004AI-Code-Audit \\\n" in dockerfile
    assert "    /suite/004AI-Code-Audit/004AI-CodeGuard-upgrade \\\n" not in dockerfile
