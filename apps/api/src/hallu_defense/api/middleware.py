from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hallu_defense.api.dependencies import (
    audit_ledger,
    get_settings,
    metrics_collector,
    telemetry,
)
from hallu_defense.api.errors import error_content
from hallu_defense.services.trace import (
    current_trace_id,
    new_trace_id,
    reset_trace_id,
    set_trace_id,
)
from hallu_defense.services.metrics import normalize_http_method

TRACE_ID_RE = re.compile(r"^tr_[a-zA-Z0-9_-]{8,80}$")
PROBE_PATHS = frozenset({"/health", "/ready"})
UNAUTHENTICATED_AUDIT_TENANT_ID = "__unauthenticated__"
UNMATCHED_METRIC_PATH = "__unmatched__"
INVALID_CONTENT_LENGTH_MESSAGE = "Request Content-Length header is invalid."
INVALID_REQUEST_FRAMING_MESSAGE = "Request framing headers are invalid."
REQUEST_BODY_TOO_LARGE_MESSAGE = "Request body exceeds the configured size limit."
REQUEST_BODY_TIMEOUT_MESSAGE = "Request body was not received within the configured deadline."
MAX_REQUEST_BODY_MESSAGES = 4_096
LOGGER = logging.getLogger(__name__)


class _InvalidContentLength(ValueError):
    pass


class _RequestBodyTooLarge(RuntimeError):
    pass


class RequestBodyLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        body_timeout_seconds: float = 15.0,
        cors_allow_origins: tuple[str, ...] = (),
    ) -> None:
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        if body_timeout_seconds <= 0:
            raise ValueError("body_timeout_seconds must be positive")
        self._app = app
        self._max_body_bytes = max_body_bytes
        self._body_timeout_seconds = body_timeout_seconds
        self._cors_allow_origins = frozenset(cors_allow_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        try:
            _validate_transfer_encoding(scope)
            declared_length = _declared_content_length(scope, self._max_body_bytes)
        except _InvalidRequestFraming:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=400,
                error="invalid_request_framing",
                message=INVALID_REQUEST_FRAMING_MESSAGE,
            )
            return
        except _InvalidContentLength:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=400,
                error="invalid_content_length",
                message=INVALID_CONTENT_LENGTH_MESSAGE,
            )
            return
        if declared_length is not None and declared_length > self._max_body_bytes:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=413,
                error="request_body_too_large",
                message=REQUEST_BODY_TOO_LARGE_MESSAGE,
            )
            return

        try:
            async with asyncio.timeout(self._body_timeout_seconds):
                buffered_messages = await self._buffer_bounded_request(
                    receive,
                    declared_length=declared_length,
                )
        except TimeoutError:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=408,
                error="request_body_timeout",
                message=REQUEST_BODY_TIMEOUT_MESSAGE,
                details={
                    "request_body_timeout_seconds": self._body_timeout_seconds,
                },
            )
            return
        except _InvalidRequestFraming:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=400,
                error="invalid_request_framing",
                message=INVALID_REQUEST_FRAMING_MESSAGE,
            )
            return
        except _InvalidContentLength:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=400,
                error="invalid_content_length",
                message=INVALID_CONTENT_LENGTH_MESSAGE,
            )
            return
        except _RequestBodyTooLarge:
            await self._send_rejection(
                scope,
                receive,
                send,
                status_code=413,
                error="request_body_too_large",
                message=REQUEST_BODY_TOO_LARGE_MESSAGE,
            )
            return

        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(buffered_messages):
                message = buffered_messages[message_index]
                message_index += 1
                return message
            return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, send)

    async def _buffer_bounded_request(
        self,
        receive: Receive,
        *,
        declared_length: int | None,
    ) -> tuple[Message, ...]:
        body = bytearray()
        body_messages = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                if body:
                    return (
                        {
                            "type": "http.request",
                            "body": bytes(body),
                            "more_body": True,
                        },
                        message,
                    )
                return (message,)
            if message["type"] != "http.request":
                raise _InvalidRequestFraming
            body_messages += 1
            if body_messages > MAX_REQUEST_BODY_MESSAGES:
                raise _InvalidRequestFraming
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self._max_body_bytes:
                raise _RequestBodyTooLarge
            body.extend(chunk)
            if not message.get("more_body", False):
                if declared_length is not None and len(body) != declared_length:
                    raise _InvalidContentLength
                return (
                    {
                        "type": "http.request",
                        "body": bytes(body),
                        "more_body": False,
                    },
                )

    async def _send_rejection(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        error: str,
        message: str,
        details: dict[str, object] | None = None,
    ) -> None:
        headers = {
            "x-trace-id": current_trace_id(),
            **self._cors_rejection_headers(scope),
        }
        if scope.get("http_version") in {"1.0", "1.1"}:
            headers["connection"] = "close"
        response = JSONResponse(
            status_code=status_code,
            content=error_content(
                error=error,
                message=message,
                details=(
                    {"max_request_body_bytes": self._max_body_bytes}
                    if details is None
                    else details
                ),
            ),
            headers=headers,
        )
        await response(scope, receive, send)

    def _cors_rejection_headers(self, scope: Scope) -> dict[str, str]:
        origins = [
            value.decode("latin-1")
            for name, value in scope.get("headers", [])
            if name.lower() == b"origin"
        ]
        if len(origins) != 1 or origins[0] not in self._cors_allow_origins:
            return {}
        return {
            "access-control-allow-origin": origins[0],
            "access-control-allow-credentials": "true",
            "vary": "Origin",
        }


async def trace_and_audit_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    trace_id = _incoming_or_new_trace_id(request)
    token = set_trace_id(trace_id)
    started_at = time.perf_counter()
    status_code = 500
    response: Response

    method = normalize_http_method(request.method)
    with telemetry.request_span(method=method, trace_id=trace_id) as span:
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
            try:
                audit_ledger.append_event(
                    trace_id=trace_id,
                    tenant_id=_audit_tenant_id(request),
                    event_type="http_request",
                    method=method,
                    path=route_path,
                    status_code=status_code,
                    outcome="success" if status_code < 400 else "error",
                    metadata={"duration_ms": elapsed_ms},
                )
            except Exception as exc:
                if route_path not in PROBE_PATHS:
                    raise
                LOGGER.warning(
                    "Probe audit event could not be persisted.",
                    extra={
                        "probe_path": route_path,
                        "error_type": type(exc).__name__,
                    },
                )
            metrics_collector.record_http_request(
                method=method,
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
    if not get_settings().auth_required:
        return request.headers.get("x-tenant-id") or "local-dev"
    return UNAUTHENTICATED_AUDIT_TENANT_ID


def _metric_path(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return route_path
    return UNMATCHED_METRIC_PATH


class _InvalidRequestFraming(ValueError):
    pass


def _validate_transfer_encoding(scope: Scope) -> None:
    transfer_encodings = [
        value
        for name, value in scope.get("headers", [])
        if name.lower() == b"transfer-encoding"
    ]
    if not transfer_encodings:
        return
    if scope.get("http_version") != "1.1":
        raise _InvalidRequestFraming
    has_content_length = any(
        name.lower() == b"content-length" for name, _value in scope.get("headers", [])
    )
    if has_content_length or len(transfer_encodings) != 1:
        raise _InvalidRequestFraming
    if transfer_encodings[0].strip(b" \t").lower() != b"chunked":
        raise _InvalidRequestFraming


def _declared_content_length(scope: Scope, max_body_bytes: int) -> int | None:
    raw_values = [
        value
        for name, value in scope.get("headers", [])
        if name.lower() == b"content-length"
    ]
    if not raw_values:
        return None

    normalized_values: list[bytes] = []
    for raw_value in raw_values:
        for candidate in raw_value.split(b","):
            value = candidate.strip(b" \t")
            if not value or any(byte < ord("0") or byte > ord("9") for byte in value):
                raise _InvalidContentLength
            normalized_values.append(value.lstrip(b"0") or b"0")
    if any(value != normalized_values[0] for value in normalized_values[1:]):
        raise _InvalidContentLength

    normalized = normalized_values[0]
    maximum = str(max_body_bytes).encode("ascii")
    if len(normalized) > len(maximum) or (
        len(normalized) == len(maximum) and normalized > maximum
    ):
        return max_body_bytes + 1
    return int(normalized)
