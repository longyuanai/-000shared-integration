"""Tenant identity and role-based access control for the gateway."""

from __future__ import annotations

import hmac
import json
import os
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Protocol

from starlette.responses import JSONResponse

_tenant_id: ContextVar[str] = ContextVar("integration_tenant_id", default="default")
_ROLES = {"viewer", "analyst", "admin"}
_PUBLIC_PATHS = {"/livez", "/v0.5/health"}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: str
    scopes: frozenset[str] | None = None


class PrincipalAuthenticator(Protocol):
    """Resolve a bearer token to a tenant principal."""

    def __call__(self, token: str) -> Principal | None: ...


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

        path = scope.get("path", "")
        if path in _PUBLIC_PATHS:
            await self._call_as(Principal("_system", "viewer"), scope, receive, send)
            return

        if not self.principals and self.authenticator is None:
            await self._call_as(Principal("default", "admin"), scope, receive, send)
            return

        principal = self._authenticate(scope)
        if principal is None:
            await JSONResponse(
                {"detail": "missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        if path.startswith("/v1/admin/") and principal.role != "admin":
            await JSONResponse(
                {"detail": "admin role is required"},
                status_code=403,
            )(scope, receive, send)
            return
        if method not in {"GET", "HEAD", "OPTIONS"} and principal.role == "viewer":
            await JSONResponse(
                {"detail": "viewer role is read-only"},
                status_code=403,
            )(scope, receive, send)
            return
        if not _scope_allows(principal, method, path):
            await JSONResponse(
                {"detail": "API key scope does not allow this operation"},
                status_code=403,
            )(scope, receive, send)
            return

        await self._call_as(principal, scope, receive, send)

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
                return Principal(
                    tenant_id=authenticated.tenant_id,
                    role=authenticated.role,
                    scopes=frozenset(getattr(authenticated, "scopes", ())),
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


__all__ = [
    "Principal",
    "PrincipalAuthenticator",
    "TenantRBACMiddleware",
    "bind_tenant",
    "current_tenant",
    "load_principals",
    "reset_tenant",
]
