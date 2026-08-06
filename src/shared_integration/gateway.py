"""FastAPI entrypoint for the longyuanai integration gateway."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from shared_llm_core import FindingRegistry, FindingSource, IntegrationGateway

from shared_integration.adapters import (
    CodeAdapter,
    FirmwareAdapter,
    LabAdapter,
    ReverseAdapter,
    SOCAdapter,
    VulnAdapter,
)
from shared_integration.api_v1 import install_v1_routes
from shared_integration.auth import TenantRBACMiddleware, load_principals
from shared_integration.correlations import SameHostMultiSourceRule
from shared_integration.dispatch import (
    CeleryJobDispatcher,
    InlineJobDispatcher,
    JobDispatcher,
)
from shared_integration.execution import JobExecutor
from shared_integration.finding_lifecycle import SQLAlchemyTenantFindingRegistry
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.jobs import SQLiteJobRepository
from shared_integration.persistence import SQLiteTenantFindingRegistry
from shared_integration.repositories import JobRepository
from shared_integration.sql_jobs import SQLAlchemyJobRepository


def suite_root() -> Path:
    """Return the directory containing all longyuanai product repositories."""
    configured = os.getenv("INTEGRATION_SUITE_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[3]


def build_gateway(
    root: Path | None = None,
    *,
    registry: FindingRegistry | None = None,
    database_path: str | Path | None = None,
    database_url: str | None = None,
) -> IntegrationGateway:
    """Compose all six subprocess adapters behind the v0.5 core gateway."""
    products_root = (root or suite_root()).resolve()
    configured_database = database_path or os.getenv("INTEGRATION_DB_PATH")
    configured_database_url = database_url or os.getenv("INTEGRATION_DATABASE_URL")
    finding_registry = registry
    if finding_registry is None and configured_database_url:
        finding_registry = SQLAlchemyTenantFindingRegistry(
            configured_database_url,
            create_schema=_auto_create_schema(),
        )
    elif finding_registry is None and configured_database:
        finding_registry = SQLiteTenantFindingRegistry(configured_database)
    products = {
        FindingSource.SOC: SOCAdapter(products_root / "001AI-SOC-Agent"),
        FindingSource.VULN: VulnAdapter(products_root / "002AI-Vulnerability-Agent"),
        FindingSource.LAB: LabAdapter(products_root / "003AI Agent安全靶场"),
        FindingSource.CODE: CodeAdapter(products_root / "004AI-Code-Audit"),
        FindingSource.REVERSE: ReverseAdapter(
            products_root / "005AI-Reverse-Agent"
        ),
        FindingSource.FIRMWARE: FirmwareAdapter(
            products_root / "006AI-Firmware-Security-Agent"
        ),
    }
    return IntegrationGateway(
        products=products,
        registry=finding_registry or FindingRegistry(),
        correlations=[SameHostMultiSourceRule()],
    )


def build_app(
    root: Path | None = None,
    *,
    registry: FindingRegistry | None = None,
    database_path: str | Path | None = None,
    database_url: str | None = None,
    job_repository: JobRepository | None = None,
    dispatcher: JobDispatcher | None = None,
    identity_repository: SQLAlchemyIdentityRepository | None = None,
) -> FastAPI:
    """Build the HTTP app with tenant and RBAC middleware."""
    gateway = build_gateway(
        root,
        registry=registry,
        database_path=database_path,
        database_url=database_url,
    )
    configured_database = database_path or os.getenv("INTEGRATION_DB_PATH")
    configured_database_url = database_url or os.getenv("INTEGRATION_DATABASE_URL")
    if job_repository is not None:
        jobs = job_repository
    elif configured_database_url:
        jobs = SQLAlchemyJobRepository(
            configured_database_url,
            create_schema=_auto_create_schema(),
        )
    else:
        jobs = SQLiteJobRepository(configured_database or ":memory:")
    executor = JobExecutor(
        repository=jobs,
        registry=gateway.registry,
        products=gateway._products,  # noqa: SLF001 - integration composition boundary
        correlations=gateway._correlations,  # noqa: SLF001
        max_attempts=int(os.getenv("INTEGRATION_JOB_MAX_ATTEMPTS", "2")),
    )
    if dispatcher is None:
        job_mode = os.getenv("INTEGRATION_JOB_MODE", "inline").strip().lower()
        if job_mode == "inline":
            dispatcher = InlineJobDispatcher(executor)
        elif job_mode == "celery":
            dispatcher = CeleryJobDispatcher()
        else:
            raise RuntimeError("INTEGRATION_JOB_MODE must be 'inline' or 'celery'")
    application = gateway.app
    application.state.gateway = gateway
    application.state.registry = gateway.registry
    application.state.job_repository = jobs
    application.state.job_dispatcher = dispatcher
    application.state.job_executor = executor
    install_v1_routes(
        application,
        gateway=gateway,
        repository=jobs,
        dispatcher=dispatcher,
    )
    auth_backend = os.getenv("INTEGRATION_AUTH_BACKEND", "static").strip().lower()
    if auth_backend not in {"static", "database", "hybrid"}:
        raise RuntimeError(
            "INTEGRATION_AUTH_BACKEND must be 'static', 'database', or 'hybrid'"
        )
    if auth_backend in {"database", "hybrid"}:
        if identity_repository is None and not configured_database_url:
            raise RuntimeError(
                "database authentication requires INTEGRATION_DATABASE_URL"
            )
        identity_repository = identity_repository or SQLAlchemyIdentityRepository(
            configured_database_url or "", create_schema=_auto_create_schema()
        )
    principals = (
        load_principals(require_when_enabled=auth_backend == "static")
        if auth_backend in {"static", "hybrid"}
        else {}
    )
    application.state.identity_repository = identity_repository
    application.add_middleware(
        TenantRBACMiddleware,
        principals=principals,
        authenticator=(
            identity_repository.authenticate_api_key
            if identity_repository is not None
            else None
        ),
    )
    return application


def _auto_create_schema() -> bool:
    return os.getenv("INTEGRATION_AUTO_CREATE_SCHEMA", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


app: FastAPI = build_app()


def main() -> None:
    """Run the gateway on the contract's default address."""
    uvicorn.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8080")),
    )


if __name__ == "__main__":
    main()
