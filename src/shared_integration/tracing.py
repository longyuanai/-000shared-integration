"""Gateway tracing middleware and request-span correlation helpers."""

from __future__ import annotations

import re
import time
from contextvars import ContextVar
from typing import Any

from shared_llm_core.telemetry import current_trace_id, span

_ACTIVE_REQUEST_SPAN: ContextVar[Any | None] = ContextVar(
    "integration_active_request_span",
    default=None,
)
_PRODUCT_SCAN_PATH = re.compile(r"^/v0\.5/(?P<product>00[1-6])/scan$")
_JOB_PATH = re.compile(r"^/v1/scans/(?P<job>job_[0-9a-f]{32})(?:/.*)?$")


def set_gateway_job_id(job_id: str) -> None:
    active_span = _ACTIVE_REQUEST_SPAN.get()
    if active_span is not None and re.fullmatch(r"job_[0-9a-f]{32}", job_id):
        active_span.set_attribute("gateway.job_id", job_id)


def set_gateway_product_id(product_id: str) -> None:
    active_span = _ACTIVE_REQUEST_SPAN.get()
    if active_span is not None and product_id in {"001", "002", "003", "004", "005", "006"}:
        active_span.set_attribute("gateway.product_id", product_id)


class GatewayTracingMiddleware:
    """Trace HTTP request lifecycle without inspecting request or response bodies."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        state = scope.setdefault("state", {})
        request_id = str(state.get("request_id", "request-unknown"))
        attributes: dict[str, object] = {
            "gateway.request_id": request_id,
            "http.request.method": str(scope.get("method", "GET")),
        }
        product_match = _PRODUCT_SCAN_PATH.fullmatch(path)
        if product_match is not None:
            attributes["gateway.product_id"] = product_match.group("product")
        job_match = _JOB_PATH.fullmatch(path)
        if job_match is not None:
            attributes["gateway.job_id"] = job_match.group("job")

        with span("gateway.request", attributes=attributes) as request_span:
            trace_id = current_trace_id()
            if trace_id is not None:
                request_span.set_attribute("gateway.trace_id", trace_id)
            token = _ACTIVE_REQUEST_SPAN.set(request_span)
            started = time.perf_counter()
            status_code = 500

            async def traced_send(message: dict[str, Any]) -> None:
                nonlocal status_code
                if message["type"] == "http.response.start":
                    status_code = int(message["status"])
                await send(message)

            try:
                await self.app(scope, receive, traced_send)
            except BaseException:
                request_span.set_attribute("gateway.status", "error")
                raise
            else:
                request_span.set_attribute(
                    "gateway.status",
                    "ok" if status_code < 500 else "error",
                )
            finally:
                request_span.set_attribute("http.response.status_code", status_code)
                request_span.set_attribute(
                    "gateway.latency_ms",
                    int((time.perf_counter() - started) * 1000),
                )
                _ACTIVE_REQUEST_SPAN.reset(token)


__all__ = [
    "GatewayTracingMiddleware",
    "set_gateway_job_id",
    "set_gateway_product_id",
]
