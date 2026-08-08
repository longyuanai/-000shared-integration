"""Tenant identity and role-based access control for the gateway."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import time
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

_tenant_id: ContextVar[str] = ContextVar("integration_tenant_id", default="default")
_ROLES = {"viewer", "analyst", "admin"}
_PUBLIC_PATHS = {"/livez", "/v0.5/health"}
_ROUTE_AUTH_PATHS = {"/v1/auth/exchange", "/v1/auth/session/revoke"}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: str
    scopes: frozenset[str] | None = None
    auth_type: str = "machine"
    user_id: str | None = None
    session_id: str | None = None
    identity_client_id: str | None = None
    api_key_id: str | None = None


class PrincipalAuthenticator(Protocol):
    """Resolve a bearer token to a tenant principal."""

    def __call__(self, token: str) -> Principal | None: ...


class ExchangeRateLimiter:
    """Bound identity exchanges by a non-secret client/IP key."""

    def __init__(
        self,
        *,
        max_attempts: int = 20,
        window_seconds: int = 60,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1 or window_seconds < 1 or max_keys < 2:
            raise ValueError("exchange rate limits must be positive")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._attempts: dict[str, deque[float]] = {"overflow": deque()}
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Record an attempt and return ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._attempts and len(self._attempts) >= self.max_keys:
                stale_keys = [
                    stored_key
                    for stored_key, stored_attempts in self._attempts.items()
                    if stored_key != "overflow"
                    and (not stored_attempts or stored_attempts[-1] <= cutoff)
                ]
                for stored_key in stale_keys:
                    self._attempts.pop(stored_key, None)
                if len(self._attempts) >= self.max_keys:
                    key = "overflow"
            attempts = self._attempts.setdefault(key, deque())
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= self.max_attempts:
                retry_after = max(1, int(self.window_seconds - (now - attempts[0])))
                return False, retry_after
            attempts.append(now)
            return True, 0


def load_exchange_rate_limiter() -> ExchangeRateLimiter:
    """Build the exchange limiter from bounded integer environment values."""
    return ExchangeRateLimiter(
        max_attempts=_positive_int_env("INTEGRATION_AUTH_EXCHANGE_RATE_LIMIT", 20),
        window_seconds=_positive_int_env(
            "INTEGRATION_AUTH_EXCHANGE_RATE_WINDOW_SECONDS", 60
        ),
    )


def current_tenant() -> str:
    """Return the tenant bound to the current request or worker context."""
    return _tenant_id.get()


def bind_tenant(tenant_id: str) -> Token[str]:
    """Bind a tenant until the returned token is reset."""
    return _tenant_id.set(tenant_id)


def reset_tenant(token: Token[str]) -> None:
    _tenant_id.reset(token)


def load_principals(*, require_when_enabled: bool = True) -> dict[str, Principal]:
    """Load bearer-token principals from ``INTEGRATION_AUTH_TOKENS`` JSON."""
    raw = os.getenv("INTEGRATION_AUTH_TOKENS", "").strip()
    required = os.getenv("INTEGRATION_AUTH_REQUIRED", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if not raw:
        if required and require_when_enabled:
            raise RuntimeError(
                "INTEGRATION_AUTH_REQUIRED is enabled but INTEGRATION_AUTH_TOKENS is empty"
            )
        return {}

    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("INTEGRATION_AUTH_TOKENS must be a JSON object")

    principals: dict[str, Principal] = {}
    for bearer, value in payload.items():
        if not isinstance(bearer, str) or len(bearer) < 16:
            raise ValueError("every gateway bearer token must contain at least 16 characters")
        if not isinstance(value, dict):
            raise ValueError("every gateway token entry must be an object")
        tenant_id = value.get("tenant")
        role = value.get("role")
        if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 128:
            raise ValueError("gateway tenant IDs must contain 1 to 128 characters")
        if role not in _ROLES:
            raise ValueError(f"gateway role must be one of {sorted(_ROLES)}")
        principals[bearer] = Principal(tenant_id=tenant_id, role=role)
    return principals


class TenantRBACMiddleware:
    """Authenticate bearer tokens and bind tenant context for the full response."""

    def __init__(
        self,
        app: Any,
        principals: dict[str, Principal],
        authenticator: PrincipalAuthenticator | None = None,
    ) -> None:
        self.app = app
        self.principals = principals
        self.authenticator = authenticator

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _request_id(scope)
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_request_id(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        path = scope.get("path", "")
        if path in _PUBLIC_PATHS:
            await self._call_as(
                Principal("_system", "viewer", auth_type="public"),
                scope,
                receive,
                send_with_request_id,
            )
            return

        if path in _ROUTE_AUTH_PATHS:
            await self._call_as(
                Principal("_auth", "viewer", auth_type="route"),
                scope,
                receive,
                send_with_request_id,
            )
            return

        if not self.principals and self.authenticator is None:
            await self._call_as(
                Principal("default", "admin"),
                scope,
                receive,
                send_with_request_id,
            )
            return

        principal = self._authenticate(scope)
        if principal is None:
            await _auth_error(
                401,
                "AUTHENTICATION_REQUIRED",
                "Authentication required",
                request_id,
                authenticate=True,
            )(scope, receive, send_with_request_id)
            return

        method = scope.get("method", "GET").upper()
        if path.startswith("/v1/admin/") and principal.role != "admin":
            await _auth_error(
                403, "ACCESS_DENIED", "Access denied", request_id
            )(scope, receive, send_with_request_id)
            return
        if method not in {"GET", "HEAD", "OPTIONS"} and principal.role == "viewer":
            await _auth_error(
                403, "ACCESS_DENIED", "Access denied", request_id
            )(scope, receive, send_with_request_id)
            return
        if not _scope_allows(principal, method, path):
            await _auth_error(
                403, "ACCESS_DENIED", "Access denied", request_id
            )(scope, receive, send_with_request_id)
            return

        await self._call_as(principal, scope, receive, send_with_request_id)

    def _authenticate(self, scope: dict[str, Any]) -> Principal | None:
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        scheme, _, token = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        for configured, principal in self.principals.items():
            if hmac.compare_digest(token, configured):
                return principal
        if self.authenticator is not None:
            authenticated = self.authenticator(token)
            if authenticated is not None:
                raw_scopes = getattr(authenticated, "scopes", None)
                return Principal(
                    tenant_id=authenticated.tenant_id,
                    role=authenticated.role,
                    scopes=(frozenset(raw_scopes) if raw_scopes is not None else None),
                    auth_type=(
                        "user" if getattr(authenticated, "session_id", None) else "machine"
                    ),
                    user_id=getattr(authenticated, "user_id", None),
                    session_id=getattr(authenticated, "session_id", None),
                    identity_client_id=getattr(
                        authenticated, "identity_client_id", None
                    ),
                    api_key_id=getattr(authenticated, "api_key_id", None),
                )
        return None

    async def _call_as(
        self,
        principal: Principal,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        scope.setdefault("state", {})
        scope["state"]["tenant_id"] = principal.tenant_id
        scope["state"]["role"] = principal.role
        scope["state"]["principal"] = principal
        scope["state"]["auth_type"] = principal.auth_type
        scope["state"]["user_id"] = principal.user_id
        scope["state"]["session_id"] = principal.session_id
        scope["state"]["identity_client_id"] = principal.identity_client_id
        scope["state"]["api_key_id"] = principal.api_key_id
        token = bind_tenant(principal.tenant_id)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_tenant(token)


def _scope_allows(principal: Principal, method: str, path: str) -> bool:
    scopes = principal.scopes
    if scopes is None or not scopes or "gateway:*" in scopes:
        return True
    if path.startswith("/v1/admin/"):
        return "gateway:admin" in scopes
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "gateway:read" in scopes
    if path.startswith("/v1/scans") or (
        path.startswith("/v0.5/") and path.endswith("/scan")
    ):
        return "scan:write" in scopes
    if path.startswith("/v1/findings/") and method == "PATCH":
        return "finding:write" in scopes
    return "gateway:write" in scopes


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _request_id(scope: dict[str, Any]) -> str:
    for raw_key, raw_value in scope.get("headers", []):
        if raw_key.decode("latin-1").lower() != "x-request-id":
            continue
        candidate = raw_value.decode("latin-1").strip()
        if 1 <= len(candidate) <= 128 and all(32 < ord(char) < 127 for char in candidate):
            return candidate
    return f"req_{secrets.token_hex(12)}"


def _auth_error(
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    *,
    authenticate: bool = False,
) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if authenticate else None
    return JSONResponse(
        {"error": {"code": code, "message": message, "request_id": request_id}},
        status_code=status_code,
        headers=headers,
    )


__all__ = [
    "Principal",
    "PrincipalAuthenticator",
    "ExchangeRateLimiter",
    "TenantRBACMiddleware",
    "bind_tenant",
    "current_tenant",
    "load_principals",
    "load_exchange_rate_limiter",
    "reset_tenant",
]
