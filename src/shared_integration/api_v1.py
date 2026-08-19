"""Version 1 job-oriented HTTP API."""

from __future__ import annotations

import asyncio
import hmac
import json
from typing import Annotated, Any

from fastapi import FastAPI, Header, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from shared_llm_core import FindingSeverity, FindingSource, IntegrationGateway

from shared_integration.auth import ExchangeRateLimiter
from shared_integration.dispatch import JobDispatcher
from shared_integration.finding_lifecycle import FindingStatus
from shared_integration.identity import SQLAlchemyIdentityRepository
from shared_integration.jobs import JobRecord, JobStatus
from shared_integration.repositories import JobRepository
from shared_integration.tracing import set_gateway_job_id, set_gateway_product_id


class ScanCreateRequest(BaseModel):
    source: FindingSource
    payload: dict[str, Any] = Field(default_factory=dict)


class FindingUpdateRequest(BaseModel):
    status: FindingStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=255)


class IdentityExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)
    display_name: str | None = Field(default=None, max_length=255)
    requested_tenant_id: str = Field(min_length=1, max_length=128)


class SessionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_token: str | None = Field(default=None, min_length=40, max_length=80)


def install_v1_routes(
    application: FastAPI,
    *,
    gateway: IntegrationGateway,
    repository: JobRepository,
    dispatcher: JobDispatcher,
    identity_repository: SQLAlchemyIdentityRepository | None = None,
    exchange_rate_limiter: ExchangeRateLimiter | None = None,
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
            request_id=_request_id(request),
        )

    limiter = exchange_rate_limiter or ExchangeRateLimiter()

    @application.post(
        "/v1/auth/exchange",
        responses={
            401: {"description": "Identity bridge authentication failed"},
            403: {"description": "Tenant membership is not active"},
            429: {"description": "Identity exchange rate limit exceeded"},
        },
    )
    async def exchange_identity(
        request: Request,
        body: IdentityExchangeRequest,
    ) -> JSONResponse:
        request_id = _request_id(request)
        token = _bearer_token(request)
        allowed, retry_after = limiter.check(_exchange_rate_key(request, token))
        if not allowed:
            _record_exchange_failure(
                identity_repository,
                tenant_id=body.requested_tenant_id,
                actor=f"identity_client:{_safe_bridge_prefix(token)}",
                reason="rate_limited",
                request_id=request_id,
            )
            return _error(
                429,
                "RATE_LIMITED",
                "Too many authentication attempts",
                request_id=request_id,
                headers={"Retry-After": str(retry_after)},
            )
        if identity_repository is None:
            return _error(
                503,
                "AUTH_SERVICE_UNAVAILABLE",
                "Authentication service unavailable",
                request_id=request_id,
                retryable=True,
            )
        client = identity_repository.authenticate_identity_client(
            token or "",
            issuer=body.issuer,
        )
        if client is None:
            _record_exchange_failure(
                identity_repository,
                tenant_id=body.requested_tenant_id,
                actor=f"identity_client:{_safe_bridge_prefix(token)}",
                reason="authentication_failed",
                request_id=request_id,
            )
            return _error(
                401,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
                request_id=request_id,
                headers={"WWW-Authenticate": "Bearer"},
            )
        actor = f"identity_client:{client.identity_client_id}"
        try:
            user = identity_repository.upsert_user(
                issuer=body.issuer,
                subject=body.subject,
                email=body.email,
                display_name=body.display_name,
            )
        except ValueError:
            return _error(
                422,
                "VALIDATION_ERROR",
                "Request validation failed",
                request_id=request_id,
            )
        try:
            issued = identity_repository.issue_user_session(
                identity_client_id=client.identity_client_id,
                tenant_id=body.requested_tenant_id,
                user_id=user.id,
                actor=actor,
                request_id=request_id,
            )
        except (KeyError, ValueError):
            _record_exchange_failure(
                identity_repository,
                tenant_id=body.requested_tenant_id,
                actor=actor,
                reason="access_denied",
                request_id=request_id,
            )
            return _error(
                403,
                "ACCESS_DENIED",
                "Access denied",
                request_id=request_id,
            )
        principal = identity_repository.authenticate_user_session(issued.token)
        if principal is None:  # membership/client changed during the exchange
            identity_repository.revoke_user_session(
                issued.tenant_id,
                issued.id,
                actor=actor,
                request_id=request_id,
            )
            return _error(
                403,
                "ACCESS_DENIED",
                "Access denied",
                request_id=request_id,
            )
        return JSONResponse(
            content={
                "session_token": issued.token,
                "token_type": "Bearer",
                "expires_at": issued.expires_at.isoformat(),
                "tenant_id": issued.tenant_id,
                "user_id": issued.user_id,
                "role": principal.role,
            },
            headers={"Cache-Control": "no-store"},
        )

    @application.post(
        "/v1/auth/session/revoke",
        responses={
            401: {"description": "Session or identity bridge authentication failed"},
            403: {"description": "The authenticated session cannot revoke the target"},
        },
    )
    async def revoke_session(
        request: Request,
        body: SessionRevokeRequest | None = None,
    ) -> JSONResponse:
        request_id = _request_id(request)
        token = _bearer_token(request)
        if identity_repository is None:
            return _error(
                503,
                "AUTH_SERVICE_UNAVAILABLE",
                "Authentication service unavailable",
                request_id=request_id,
                retryable=True,
            )
        session_principal = identity_repository.authenticate_user_session(token or "")
        if session_principal is not None:
            if body is not None and body.session_token is not None and not hmac.compare_digest(
                body.session_token, token or ""
            ):
                return _error(
                    403,
                    "ACCESS_DENIED",
                    "Access denied",
                    request_id=request_id,
                )
            actor = (
                f"user:{session_principal.user_id};"
                f"session:{session_principal.session_id};"
                f"client:{session_principal.identity_client_id}"
            )
            identity_repository.revoke_user_session(
                session_principal.tenant_id,
                session_principal.session_id,
                actor=actor,
                request_id=request_id,
            )
            return JSONResponse(
                content={"revoked": True},
                headers={"Cache-Control": "no-store"},
            )

        bridge = identity_repository.authenticate_identity_client(token or "")
        target = (
            identity_repository.authenticate_user_session(body.session_token)
            if bridge is not None and body is not None and body.session_token is not None
            else None
        )
        if (
            bridge is None
            or target is None
            or target.identity_client_id != bridge.identity_client_id
        ):
            return _error(
                401,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
                request_id=request_id,
                headers={"WWW-Authenticate": "Bearer"},
            )
        identity_repository.revoke_user_session(
            target.tenant_id,
            target.session_id,
            actor=f"identity_client:{bridge.identity_client_id}",
            request_id=request_id,
        )
        return JSONResponse(
            content={"revoked": True},
            headers={"Cache-Control": "no-store"},
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
                request_id=_request_id(request),
            )
        adapter = gateway._products.get(body.source)  # noqa: SLF001
        if adapter is None:
            return _error(
                404,
                "UNKNOWN_SOURCE",
                f"No adapter registered for {body.source.value}",
                request_id=_request_id(request),
            )

        job, created = repository.create(
            tenant_id=tenant_id,
            source=body.source,
            payload=body.payload,
            idempotency_key=idempotency_key,
        )
        set_gateway_job_id(job.id)
        set_gateway_product_id(body.source.value)
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
                    request_id=_request_id(request),
                    job_id=job.id,
                    retryable=True,
                )

        return JSONResponse(
            status_code=202 if created else 200,
            content=job.to_dict(),
            headers={"Location": f"/v1/scans/{job.id}"},
        )

    @application.get("/v1/scans")
    async def list_scans(
        request: Request,
        status: Annotated[JobStatus | None, Query()] = None,
        source: Annotated[FindingSource | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        jobs = repository.list_jobs(
            request.state.tenant_id,
            status=status,
            source=source,
            limit=limit,
        )
        return {"count": len(jobs), "jobs": [job.to_dict() for job in jobs]}

    @application.get("/v1/scans/{job_id}")
    async def get_scan(request: Request, job_id: str) -> JSONResponse:
        job = repository.get(request.state.tenant_id, job_id)
        if job is None:
            return _error(
                404,
                "JOB_NOT_FOUND",
                "Scan job not found",
                request_id=_request_id(request),
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
                request_id=_request_id(request),
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
                request_id=_request_id(request),
                job_id=job_id,
            )
        try:
            after = max(0, int(last_event_id or "0"))
        except ValueError:
            return _error(
                400,
                "INVALID_EVENT_ID",
                "Last-Event-ID must be an integer",
                request_id=_request_id(request),
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

    @application.get("/v1/findings")
    async def list_findings(
        request: Request,
        cursor: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        source: FindingSource | None = None,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
    ) -> JSONResponse:
        list_page = getattr(gateway.registry, "list_page", None)
        if list_page is None:
            return _error(
                503,
                "LIFECYCLE_STORE_UNAVAILABLE",
                "Finding lifecycle storage requires INTEGRATION_DATABASE_URL",
                request_id=_request_id(request),
            )
        try:
            records, next_cursor = list_page(
                request.state.tenant_id,
                cursor=cursor,
                limit=limit,
                source=source,
                severity=severity,
                status=status,
            )
        except ValueError:
            return _error(
                400,
                "INVALID_CURSOR",
                "The finding cursor is invalid",
                request_id=_request_id(request),
            )
        return JSONResponse(
            content={
                "count": len(records),
                "items": [record.to_dict() for record in records],
                "next_cursor": next_cursor,
            }
        )

    @application.patch("/v1/findings/{finding_id}")
    async def update_finding(
        request: Request,
        finding_id: str,
        body: FindingUpdateRequest,
    ) -> JSONResponse:
        update_lifecycle = getattr(gateway.registry, "update_lifecycle", None)
        if update_lifecycle is None:
            return _error(
                503,
                "LIFECYCLE_STORE_UNAVAILABLE",
                "Finding lifecycle storage requires INTEGRATION_DATABASE_URL",
                request_id=_request_id(request),
            )
        if not body.model_fields_set:
            return _error(
                400,
                "EMPTY_UPDATE",
                "At least one lifecycle field must be provided",
                request_id=_request_id(request),
            )
        changes: dict[str, Any] = {
            "actor": f"role:{request.state.role}",
        }
        if "status" in body.model_fields_set:
            changes["status"] = body.status
        if "assigned_to" in body.model_fields_set:
            changes["assigned_to"] = body.assigned_to
        record = update_lifecycle(
            request.state.tenant_id,
            finding_id,
            **changes,
        )
        if record is None:
            return _error(
                404,
                "FINDING_NOT_FOUND",
                "Finding not found",
                request_id=_request_id(request),
            )
        return JSONResponse(content=record.to_dict())

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


def _bearer_token(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "")) or "request-unknown"


def _safe_bridge_prefix(token: str | None) -> str:
    if not token:
        return "unknown"
    prefix, separator, _ = token.partition(".")
    hexadecimal = set("0123456789abcdef")
    if (
        separator
        and prefix.startswith("igb_")
        and len(prefix) == 28
        and all(char in hexadecimal for char in prefix[4:])
    ):
        return prefix
    return "unknown"


def _exchange_rate_key(request: Request, token: str | None) -> str:
    client_host = request.client.host if request.client is not None else "unknown"
    return f"{client_host}:{_safe_bridge_prefix(token)}"


def _record_exchange_failure(
    identity_repository: SQLAlchemyIdentityRepository | None,
    *,
    tenant_id: str,
    actor: str,
    reason: str,
    request_id: str,
) -> None:
    if identity_repository is None:
        return
    identity_repository.record_auth_event(
        tenant_id=tenant_id,
        actor=actor,
        action="auth.exchange",
        outcome="failure",
        request_id=request_id,
        details={"reason": reason},
    )


def _required(repository: JobRepository, tenant_id: str, job_id: str) -> JobRecord:
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
    headers: dict[str, str] | None = None,
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
    return JSONResponse(
        status_code=status_code,
        content={"error": error},
        headers=headers,
    )


__all__ = [
    "FindingUpdateRequest",
    "IdentityExchangeRequest",
    "ScanCreateRequest",
    "SessionRevokeRequest",
    "install_v1_routes",
]
