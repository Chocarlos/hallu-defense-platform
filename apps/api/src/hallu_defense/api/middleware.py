from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from hallu_defense.api.dependencies import audit_ledger, metrics_collector, telemetry
from hallu_defense.api.errors import error_content
from hallu_defense.services.trace import new_trace_id, reset_trace_id, set_trace_id

TRACE_ID_RE = re.compile(r"^tr_[a-zA-Z0-9_-]{8,80}$")


async def trace_and_audit_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    trace_id = _incoming_or_new_trace_id(request)
    token = set_trace_id(trace_id)
    started_at = time.perf_counter()
    status_code = 500
    response: Response

    with telemetry.request_span(method=request.method, path=request.url.path, trace_id=trace_id) as span:
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            telemetry.record_exception(span, exc)
            response = JSONResponse(
                status_code=500,
                content=error_content(
                    error="internal_server_error",
                    message="Unexpected server error.",
                    details={"exception_type": type(exc).__name__},
                ),
            )
            status_code = 500
        finally:
            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 3)
            route_path = _metric_path(request)
            telemetry.finish_request_span(
                span,
                route_path=route_path,
                status_code=status_code,
                duration_ms=elapsed_ms,
            )
            audit_ledger.append_event(
                trace_id=trace_id,
                tenant_id=_audit_tenant_id(request),
                event_type="http_request",
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                outcome="success" if status_code < 400 else "error",
                metadata={"duration_ms": elapsed_ms},
            )
            metrics_collector.record_http_request(
                method=request.method,
                path=route_path,
                status_code=status_code,
                duration_seconds=elapsed_ms / 1000,
            )
            reset_trace_id(token)

    response.headers["x-trace-id"] = trace_id
    return response


def _incoming_or_new_trace_id(request: Request) -> str:
    incoming = request.headers.get("x-trace-id")
    if incoming is not None and TRACE_ID_RE.match(incoming):
        return incoming
    return new_trace_id()


def _audit_tenant_id(request: Request) -> str:
    authenticated_tenant_id = getattr(request.state, "authenticated_tenant_id", None)
    if isinstance(authenticated_tenant_id, str) and authenticated_tenant_id:
        return authenticated_tenant_id
    return request.headers.get("x-tenant-id") or "local-dev"


def _metric_path(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return route_path
    return request.url.path
