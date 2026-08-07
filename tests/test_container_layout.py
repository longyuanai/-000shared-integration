from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_installs_code_audit_from_canonical_suite_path() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM ${PYTHON_BASE_IMAGE} AS source" in dockerfile
    assert "FROM source AS runtime" in dockerfile
    assert "COPY [\"004AI-Code-Audit/\", \"/suite/004AI-Code-Audit/\"]" in dockerfile
    assert "test -f /suite/004AI-Code-Audit/004AI-CodeGuard-upgrade/pyproject.toml" in dockerfile
    assert "    /suite/004AI-Code-Audit \\\n" in dockerfile
    assert "    /suite/004AI-Code-Audit/004AI-CodeGuard-upgrade \\\n" not in dockerfile


def test_docker_context_excludes_sensitive_and_local_artifacts() -> None:
    patterns = {
        line.strip()
        for line in (ROOT / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert {
        "**/.git",
        "**/.git/**",
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/*.key",
        "**/node_modules",
        "**/playwright-report",
        "**/test-results",
        "**/*.trace",
        "**/*.sqlite3",
    } <= patterns
