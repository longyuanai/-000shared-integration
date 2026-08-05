"""Celery task entrypoints."""

from __future__ import annotations

import asyncio
import os

from shared_integration.celery_app import celery_app
from shared_integration.execution import JobExecutor
from shared_integration.gateway import build_gateway
from shared_integration.jobs import SQLiteJobRepository
from shared_integration.sql_jobs import SQLAlchemyJobRepository


@celery_app.task(name="shared_integration.execute_job", acks_late=True)
def execute_job(job_id: str, tenant_id: str) -> None:
    database_url = os.getenv("INTEGRATION_DATABASE_URL")
    database = os.getenv("INTEGRATION_DB_PATH")
    if not database_url and not database:
        raise RuntimeError(
            "INTEGRATION_DATABASE_URL or INTEGRATION_DB_PATH is required for workers"
        )

    repository = (
        SQLAlchemyJobRepository(database_url)
        if database_url
        else SQLiteJobRepository(database or ":memory:")
    )
    gateway = build_gateway(database_path=database, database_url=database_url)
    executor = JobExecutor(
        repository=repository,
        registry=gateway.registry,
        products=gateway._products,  # noqa: SLF001 - integration composition boundary
        correlations=gateway._correlations,  # noqa: SLF001
        max_attempts=int(os.getenv("INTEGRATION_JOB_MAX_ATTEMPTS", "2")),
    )
    try:
        asyncio.run(executor.execute(job_id, tenant_id))
    finally:
        repository.close()
        close = getattr(gateway.registry, "close", None)
        if close is not None:
            close()


__all__ = ["execute_job"]
