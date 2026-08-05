"""Version 1 job-oriented HTTP API."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from shared_llm_core import FindingSource, IntegrationGateway

from shared_integration.dispatch import JobDispatcher
from shared_integration.jobs import JobRecord, JobStatus, SQLiteJobRepository


class ScanCreateRequest(BaseModel):
    source: FindingSource
    payload: dict[str, Any] = Field(default_factory=dict)


def install_v1_routes(
    application: FastAPI,
    *,
    gateway: IntegrationGateway,
    repository: SQLiteJobRepository,
    dispatcher: JobDispatcher,
) -> None:
    """Install job, capability, readiness, and event endpoints."""

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):  # type: ignore[no-untyped-def]
        if not request.url.path.startswith("/v1"):
            return await request_validation_exception_handler(request, exc)
        return _error(
            422,
            "VALIDATION_ERROR",
            "Request validation failed",
            request_id=request.headers.get("x-request-id"),
            details=exc.errors(),
        )

    @application.get("/livez")
    async def livez() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz")
    async def readyz() -> JSONResponse:
        products = {
            source.value: adapter.health()
            for source, adapter in gateway._products.items()  # noqa: SLF001
        }
        ready = (
            repository.ping()
            and dispatcher.ready()
            and all(item["status"] == "ok" for item in products.values())
        )
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "degraded"},
        )

    @application.get("/v1/adapters")
    async def list_adapters() -> dict[str, Any]:
        adapters = [
            adapter.capabilities().to_dict()
            for _, adapter in sorted(
                gateway._products.items(),  # noqa: SLF001
                key=lambda item: item[0].value,
            )
        ]
        return {"count": len(adapters), "adapters": adapters}

    @application.post("/v1/scans")
    async def create_scan(request: Request, body: ScanCreateRequest) -> JSONResponse:
        tenant_id = request.state.tenant_id
        idempotency_key = request.headers.get("idempotency-key")
        if idempotency_key is not None and not (1 <= len(idempotency_key) <= 128):
            return _error(
                400,
                "INVALID_IDEMPOTENCY_KEY",
                "Idempotency-Key must contain 1 to 128 characters",
                request_id=request.headers.get("x-request-id"),
            )
        adapter = gateway._products.get(body.source)  # noqa: SLF001
        if adapter is None:
            return _error(
                404,
                "UNKNOWN_SOURCE",
                f"No adapter registered for {body.source.value}",
                request_id=request.headers.get("x-request-id"),
            )

        job, created = repository.create(
            tenant_id=tenant_id,
            source=body.source,
            payload=body.payload,
            idempotency_key=idempotency_key,
        )
        if created:
            try:
                dispatch_id = dispatcher.submit(
                    job, queue=adapter.capabilities().queue
                )
                repository.set_dispatch_id(tenant_id, job.id, dispatch_id)
                job = _required(repository, tenant_id, job.id)
            except Exception as exc:  # noqa: BLE001 - return durable dispatch failure
                job = repository.transition(
                    tenant_id,
                    job.id,
                    status=JobStatus.FAILED,
                    error_code="DISPATCH_FAILED",
                    error_message=str(exc),
                )
                return _error(
                    503,
                    "DISPATCH_FAILED",
                    "The scan could not be queued",
                    request_id=request.headers.get("x-request-id"),
                    job_id=job.id,
                    retryable=True,
                )

        return JSONResponse(
            status_code=202 if created else 200,
            content=job.to_dict(),
            headers={"Location": f"/v1/scans/{job.id}"},
        )

    @application.get("/v1/scans/{job_id}")
    async def get_scan(request: Request, job_id: str) -> JSONResponse:
        job = repository.get(request.state.tenant_id, job_id)
        if job is None:
            return _error(
                404,
                "JOB_NOT_FOUND",
                "Scan job not found",
                request_id=request.headers.get("x-request-id"),
                job_id=job_id,
            )
        return JSONResponse(content=job.to_dict())

    @application.post("/v1/scans/{job_id}/cancel")
    async def cancel_scan(request: Request, job_id: str) -> JSONResponse:
        tenant_id = request.state.tenant_id
        current = repository.get(tenant_id, job_id)
        if current is None:
            return _error(
                404,
                "JOB_NOT_FOUND",
                "Scan job not found",
                request_id=request.headers.get("x-request-id"),
                job_id=job_id,
            )
        job = repository.request_cancel(tenant_id, job_id)
        dispatcher.cancel(current)
        return JSONResponse(content=job.to_dict())

    @application.get("/v1/scans/{job_id}/events", response_model=None)
    async def scan_events(
        request: Request,
        job_id: str,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> StreamingResponse | JSONResponse:
        tenant_id = request.state.tenant_id
        if repository.get(tenant_id, job_id) is None:
            return _error(
                404,
                "JOB_NOT_FOUND",
                "Scan job not found",
                request_id=request.headers.get("x-request-id"),
                job_id=job_id,
            )
        try:
            after = max(0, int(last_event_id or "0"))
        except ValueError:
            return _error(
                400,
                "INVALID_EVENT_ID",
                "Last-Event-ID must be an integer",
                request_id=request.headers.get("x-request-id"),
                job_id=job_id,
            )

        async def event_stream():  # type: ignore[no-untyped-def]
            sequence = after
            idle_ticks = 0
            while True:
                events = repository.list_events(
                    tenant_id, job_id, after_sequence=sequence
                )
                for event in events:
                    sequence = event.sequence
                    data = json.dumps(event.to_dict(), ensure_ascii=False)
                    yield f"id: {sequence}\nevent: {event.kind}\ndata: {data}\n\n"
                job = repository.get(tenant_id, job_id)
                if job is None or (job.status.terminal and not events):
                    return
                idle_ticks = 0 if events else idle_ticks + 1
                if idle_ticks >= 60:
                    idle_ticks = 0
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0.25)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-transform"},
        )

    @application.get("/v1/admin/health")
    async def admin_health() -> dict[str, Any]:
        return {
            "status": "ok" if repository.ping() else "degraded",
            "dispatcher_ready": dispatcher.ready(),
            "products": {
                source.value: {
                    "health": adapter.health(),
                    "capabilities": adapter.capabilities().to_dict(),
                }
                for source, adapter in gateway._products.items()  # noqa: SLF001
            },
        }


def _required(
    repository: SQLiteJobRepository, tenant_id: str, job_id: str
) -> JobRecord:
    job = repository.get(tenant_id, job_id)
    if job is None:  # pragma: no cover - repository invariant after create
        raise RuntimeError("scan job disappeared")
    return job


def _error(
    status_code: int,
    code: str,
    message: str,
    *,
    request_id: str | None = None,
    job_id: str | None = None,
    retryable: bool = False,
    details: Any | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "retryable": retryable,
    }
    if request_id:
        error["request_id"] = request_id
    if job_id:
        error["job_id"] = job_id
    if details is not None:
        error["details"] = details
    return JSONResponse(status_code=status_code, content={"error": error})


__all__ = ["ScanCreateRequest", "install_v1_routes"]
