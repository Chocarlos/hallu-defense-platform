from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Scope

from hallu_defense.api import dependencies
from hallu_defense.api import middleware as api_middleware
from hallu_defense.api.middleware import (
    MAX_REQUEST_BODY_MESSAGES,
    RequestBodyLimitMiddleware,
    UNAUTHENTICATED_AUDIT_TENANT_ID,
    UNMATCHED_METRIC_PATH,
    trace_and_audit_middleware,
)
from hallu_defense.config import (
    AUTH_CLAIMS_MODE_OIDC_JWT,
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS,
    MAX_REQUEST_BODY_BYTES_UPPER_BOUND,
    REQUEST_BODY_TIMEOUT_SECONDS_UPPER_BOUND,
    RequestBodyConfigurationError,
    Settings,
    load_settings,
)
from hallu_defense.main import app
from hallu_defense.services.audit import AuditLedger
from test_oidc_jwt import _write_jwks


def test_declared_oversize_is_rejected_without_reading_or_calling_downstream() -> None:
    downstream_calls = 0
    receive_calls = 0

    async def downstream(_scope: Scope, _receive: Any, _send: Any) -> None:
        nonlocal downstream_calls
        downstream_calls += 1

    async def scenario() -> list[Message]:
        nonlocal receive_calls

        async def receive() -> Message:
            nonlocal receive_calls
            receive_calls += 1
            raise AssertionError("declared oversize body must not be read")

        return await _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            headers=[(b"content-length", b"5")],
            receive=receive,
        )

    sent = asyncio.run(scenario())

    assert downstream_calls == 0
    assert receive_calls == 0
    assert _response_start(sent)["status"] == 413
    assert _headers(sent)[b"connection"] == b"close"
    payload = _response_json(sent)
    assert payload["error"] == "request_body_too_large"
    assert payload["details"] == {"max_request_body_bytes": 4}
    assert isinstance(payload["trace_id"], str)
    assert payload["trace_id"].startswith("tr_")


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"")],
        [(b"content-length", b"abc")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"1,2")],
        [(b"content-length", b"1"), (b"content-length", b"2")],
    ],
)
def test_malformed_or_conflicting_content_length_is_rejected(
    headers: list[tuple[bytes, bytes]],
) -> None:
    downstream_calls = 0

    async def downstream(_scope: Scope, _receive: Any, _send: Any) -> None:
        nonlocal downstream_calls
        downstream_calls += 1

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            headers=headers,
        )
    )

    assert downstream_calls == 0
    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_content_length"


@pytest.mark.parametrize(
    "headers",
    [
        [
            (b"transfer-encoding", b"chunked"),
            (b"content-length", b"1"),
        ],
        [(b"transfer-encoding", b"gzip")],
        [(b"transfer-encoding", b"chunked, chunked")],
        [
            (b"transfer-encoding", b"chunked"),
            (b"transfer-encoding", b"chunked"),
        ],
    ],
)
def test_ambiguous_or_invalid_transfer_encoding_is_rejected(
    headers: list[tuple[bytes, bytes]],
) -> None:
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=4),
            headers=headers,
        )
    )

    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_request_framing"


def test_identical_content_lengths_and_exact_boundary_are_accepted() -> None:
    received_body = bytearray()

    async def downstream(_scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            received_body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cd", "more_body": False},
    ]
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            headers=[
                (b"content-length", b"0004"),
                (b"content-length", b"4, 04"),
            ],
            messages=messages,
        )
    )

    assert bytes(received_body) == b"abcd"
    assert _response_start(sent)["status"] == 204


@pytest.mark.parametrize(
    ("declared_length", "body"),
    [(b"2", b"abc"), (b"4", b"abc")],
)
def test_content_length_must_equal_actual_body_within_cap(
    declared_length: bytes,
    body: bytes,
) -> None:
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=8),
            headers=[(b"content-length", declared_length)],
            messages=[{"type": "http.request", "body": body, "more_body": False}],
        )
    )

    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_content_length"


def test_http_disconnect_is_replayed_without_consuming_another_message() -> None:
    input_messages: list[Message] = [
        {"type": "http.request", "body": b"partial", "more_body": True},
        {"type": "http.disconnect"},
    ]
    receive_calls = 0
    replayed: list[Message] = []

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        return input_messages.pop(0)

    async def downstream(_scope: Scope, receive: Any, send: Any) -> None:
        replayed.extend([await receive(), await receive()])
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=8),
            receive=receive,
        )
    )

    assert receive_calls == 2
    assert replayed == [
        {"type": "http.request", "body": b"partial", "more_body": True},
        {"type": "http.disconnect"},
    ]
    assert _response_start(sent)["status"] == 204


def test_many_tiny_chunks_are_replayed_as_one_bounded_message() -> None:
    empty_chunks_remaining = 2_000
    one_byte_chunks_remaining = 1_000
    downstream_messages: list[Message] = []

    async def receive() -> Message:
        nonlocal empty_chunks_remaining, one_byte_chunks_remaining
        if empty_chunks_remaining:
            empty_chunks_remaining -= 1
            return {"type": "http.request", "body": b"", "more_body": True}
        one_byte_chunks_remaining -= 1
        return {
            "type": "http.request",
            "body": b"x",
            "more_body": one_byte_chunks_remaining > 0,
        }

    async def downstream(_scope: Scope, receive: Any, send: Any) -> None:
        downstream_messages.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=1_000),
            receive=receive,
        )
    )

    assert _response_start(sent)["status"] == 204
    assert empty_chunks_remaining == 0
    assert one_byte_chunks_remaining == 0
    assert downstream_messages == [
        {"type": "http.request", "body": b"x" * 1_000, "more_body": False}
    ]


def test_body_message_limit_rejects_fragmentation_without_downstream() -> None:
    receive_calls = 0

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"", "more_body": True}

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=4),
            receive=receive,
        )
    )

    assert receive_calls == MAX_REQUEST_BODY_MESSAGES + 1
    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_request_framing"


def test_body_message_limit_boundary_is_accepted_and_collapsed() -> None:
    receive_calls = 0
    downstream_messages: list[Message] = []

    async def receive() -> Message:
        nonlocal receive_calls
        receive_calls += 1
        if receive_calls < MAX_REQUEST_BODY_MESSAGES:
            return {"type": "http.request", "body": b"", "more_body": True}
        return {"type": "http.request", "body": b"ok", "more_body": False}

    async def downstream(_scope: Scope, receive: Any, send: Any) -> None:
        downstream_messages.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            receive=receive,
        )
    )

    assert receive_calls == MAX_REQUEST_BODY_MESSAGES
    assert downstream_messages == [
        {"type": "http.request", "body": b"ok", "more_body": False}
    ]
    assert _response_start(sent)["status"] == 204


def test_unexpected_asgi_message_fails_closed() -> None:
    async def receive() -> Message:
        return {"type": "websocket.receive", "bytes": b"unexpected"}  # type: ignore[typeddict-item]

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=4),
            receive=receive,
        )
    )

    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_request_framing"


def test_blocked_body_receive_times_out_with_safe_408() -> None:
    async def scenario() -> list[Message]:
        never = asyncio.Event()

        async def receive() -> Message:
            await never.wait()
            raise AssertionError("unreachable")

        return await _invoke(
            RequestBodyLimitMiddleware(
                _never_called,
                max_body_bytes=4,
                body_timeout_seconds=0.01,
            ),
            receive=receive,
        )

    sent = asyncio.run(scenario())

    assert _response_start(sent)["status"] == 408
    assert _headers(sent)[b"connection"] == b"close"
    assert _response_json(sent) == {
        "trace_id": _headers(sent)[b"x-trace-id"].decode("ascii"),
        "error": "request_body_timeout",
        "message": "Request body was not received within the configured deadline.",
        "details": {"request_body_timeout_seconds": 0.01},
    }


def test_external_body_receive_cancellation_is_not_converted_to_408() -> None:
    async def receive() -> Message:
        raise asyncio.CancelledError

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError):
            await _invoke(
                RequestBodyLimitMiddleware(
                    _never_called,
                    max_body_bytes=4,
                    body_timeout_seconds=1,
                ),
                receive=receive,
            )

    asyncio.run(scenario())


@pytest.mark.parametrize("declared_length", [None, b"2"])
def test_streamed_or_underdeclared_body_is_rejected_at_first_excess_chunk(
    declared_length: bytes | None,
) -> None:
    messages = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cde", "more_body": True},
        {"type": "http.request", "body": b"must-not-be-read", "more_body": False},
    ]
    receive_calls = 0

    async def downstream(_scope: Scope, receive: Any, _send: Any) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                return

    async def scenario() -> list[Message]:
        nonlocal receive_calls
        pending = list(messages)

        async def receive() -> Message:
            nonlocal receive_calls
            receive_calls += 1
            return pending.pop(0)

        headers = (
            [] if declared_length is None else [(b"content-length", declared_length)]
        )
        sent = await _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            headers=headers,
            receive=receive,
        )
        assert len(pending) == 1
        return sent

    sent = asyncio.run(scenario())

    assert receive_calls == 2
    assert _response_start(sent)["status"] == 413


def test_canonical_chunked_body_is_counted_without_content_length() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cde", "more_body": False},
    ]

    async def downstream(_scope: Scope, receive: Any, _send: Any) -> None:
        while (await receive()).get("more_body", False):
            pass

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            headers=[(b"transfer-encoding", b"Chunked")],
            messages=messages,
        )
    )

    assert _response_start(sent)["status"] == 413


def test_http2_rejects_transfer_encoding_even_when_chunked() -> None:
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=4),
            headers=[(b"transfer-encoding", b"chunked")],
            http_version="2",
        )
    )

    assert _response_start(sent)["status"] == 400
    assert _response_json(sent)["error"] == "invalid_request_framing"


def test_streamed_oversize_is_rejected_before_downstream_can_start_response() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cde", "more_body": False},
    ]
    downstream_calls = 0

    async def downstream(_scope: Scope, _receive: Any, _send: Any) -> None:
        nonlocal downstream_calls
        downstream_calls += 1

    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(downstream, max_body_bytes=4),
            messages=messages,
        )
    )

    assert downstream_calls == 0
    assert [message["type"] for message in sent].count("http.response.start") == 1
    assert _response_start(sent)["status"] == 413


def test_valid_cors_preflight_reaches_cors_after_body_validation() -> None:
    origin = "https://console.example"
    cors = CORSMiddleware(
        _never_called,
        allow_origins=[origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    middleware = RequestBodyLimitMiddleware(
        cors,
        max_body_bytes=4,
        cors_allow_origins=(origin,),
    )

    sent = asyncio.run(
        _invoke(
            middleware,
            method="OPTIONS",
            headers=[
                (b"origin", origin.encode("ascii")),
                (b"access-control-request-method", b"POST"),
            ],
        )
    )

    assert _response_start(sent)["status"] == 200
    headers = _headers(sent)
    assert headers[b"access-control-allow-origin"] == origin.encode("ascii")
    assert headers[b"access-control-allow-credentials"] == b"true"


def test_declared_oversize_cors_preflight_is_rejected_before_cors() -> None:
    origin = "https://console.example"
    receive_calls = 0
    cors = CORSMiddleware(
        _never_called,
        allow_origins=[origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    middleware = RequestBodyLimitMiddleware(
        cors,
        max_body_bytes=4,
        cors_allow_origins=(origin,),
    )

    async def scenario() -> list[Message]:
        nonlocal receive_calls

        async def receive() -> Message:
            nonlocal receive_calls
            receive_calls += 1
            raise AssertionError("declared oversize preflight body must not be read")

        return await _invoke(
            middleware,
            method="OPTIONS",
            headers=[
                (b"origin", origin.encode("ascii")),
                (b"access-control-request-method", b"POST"),
                (b"content-length", b"5"),
            ],
            receive=receive,
        )

    sent = asyncio.run(scenario())

    assert receive_calls == 0
    assert _response_start(sent)["status"] == 413
    headers = _headers(sent)
    assert headers[b"connection"] == b"close"
    assert headers[b"access-control-allow-origin"] == origin.encode("ascii")
    assert headers[b"access-control-allow-credentials"] == b"true"


def test_streamed_oversize_cors_preflight_is_rejected_before_cors() -> None:
    origin = "https://console.example"
    messages: list[Message] = [
        {"type": "http.request", "body": b"ab", "more_body": True},
        {"type": "http.request", "body": b"cde", "more_body": True},
        {"type": "http.request", "body": b"must-not-be-read", "more_body": False},
    ]
    receive_calls = 0
    cors = CORSMiddleware(
        _never_called,
        allow_origins=[origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    middleware = RequestBodyLimitMiddleware(
        cors,
        max_body_bytes=4,
        cors_allow_origins=(origin,),
    )

    async def scenario() -> list[Message]:
        nonlocal receive_calls
        pending = list(messages)

        async def receive() -> Message:
            nonlocal receive_calls
            receive_calls += 1
            return pending.pop(0)

        sent = await _invoke(
            middleware,
            method="OPTIONS",
            headers=[
                (b"origin", origin.encode("ascii")),
                (b"access-control-request-method", b"POST"),
                (b"transfer-encoding", b"chunked"),
            ],
            receive=receive,
        )
        assert len(pending) == 1
        return sent

    sent = asyncio.run(scenario())

    assert receive_calls == 2
    assert _response_start(sent)["status"] == 413
    headers = _headers(sent)
    assert headers[b"connection"] == b"close"
    assert headers[b"access-control-allow-origin"] == origin.encode("ascii")


@pytest.mark.parametrize(
    "origin_headers",
    [
        [(b"origin", b"https://attacker.example")],
        [
            (b"origin", b"https://console.example"),
            (b"origin", b"https://attacker.example"),
        ],
    ],
)
def test_body_rejection_never_reflects_disallowed_or_duplicate_origin(
    origin_headers: list[tuple[bytes, bytes]],
) -> None:
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(
                _never_called,
                max_body_bytes=4,
                cors_allow_origins=("https://console.example",),
            ),
            method="OPTIONS",
            headers=[*origin_headers, (b"content-length", b"5")],
        )
    )

    assert _response_start(sent)["status"] == 413
    assert b"access-control-allow-origin" not in _headers(sent)


def test_http2_rejection_does_not_emit_connection_header() -> None:
    sent = asyncio.run(
        _invoke(
            RequestBodyLimitMiddleware(_never_called, max_body_bytes=1),
            headers=[(b"content-length", b"2")],
            http_version="2",
        )
    )

    assert _response_start(sent)["status"] == 413
    assert b"connection" not in _headers(sent)


def test_default_and_env_request_body_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES", raising=False)
    monkeypatch.delenv("HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS", raising=False)
    assert load_settings().max_request_body_bytes == DEFAULT_MAX_REQUEST_BODY_BYTES
    assert (
        load_settings().request_body_timeout_seconds
        == DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS
    )

    monkeypatch.setenv("HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES", "2048")
    monkeypatch.setenv("HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS", "30")
    settings = load_settings()
    assert settings.max_request_body_bytes == 2048
    assert settings.request_body_timeout_seconds == 30


@pytest.mark.parametrize("value", ["0", str(MAX_REQUEST_BODY_BYTES_UPPER_BOUND + 1)])
def test_request_body_limit_outside_supported_range_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES", value)

    with pytest.raises(RequestBodyConfigurationError, match="between 1 and"):
        load_settings()


@pytest.mark.parametrize(
    "value",
    ["0", str(REQUEST_BODY_TIMEOUT_SECONDS_UPPER_BOUND + 1)],
)
def test_request_body_timeout_outside_supported_range_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS", value)

    with pytest.raises(RequestBodyConfigurationError, match="TIMEOUT_SECONDS"):
        load_settings()


def test_body_timeout_is_traced_and_audited_by_outer_middleware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=False,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1_000,
    )
    ledger = AuditLedger()
    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(api_middleware, "audit_ledger", ledger)

    test_app = FastAPI()
    test_app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=4,
        body_timeout_seconds=0.01,
    )
    test_app.middleware("http")(trace_and_audit_middleware)

    @test_app.post("/slow")
    async def slow_route() -> dict[str, bool]:
        return {"unexpected": True}

    trace_id = "tr_slow_body_audit"

    async def scenario() -> list[Message]:
        never = asyncio.Event()

        async def receive() -> Message:
            await never.wait()
            raise AssertionError("unreachable")

        sent: list[Message] = []

        async def send(message: Message) -> None:
            sent.append(message)

        scope = _http_scope(
            method="POST",
            headers=[(b"x-trace-id", trace_id.encode("ascii"))],
            path="/slow",
        )
        await test_app(scope, receive, send)
        return sent

    sent = asyncio.run(scenario())

    assert _response_start(sent)["status"] == 408
    assert _headers(sent)[b"x-trace-id"] == trace_id.encode("ascii")
    events = ledger.export_events(tenant_id="local-dev", trace_id=trace_id)
    assert len(events) == 1
    assert events[0].status_code == 408
    assert events[0].path == UNMATCHED_METRIC_PATH


def test_oversize_authenticated_route_is_traced_audited_and_cors_wrapped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_path=_write_jwks(tmp_path),
    )
    ledger = AuditLedger()
    metric_records: list[tuple[str, str, int]] = []

    class RecordingMetrics:
        def record_http_request(
            self,
            *,
            method: str,
            path: str,
            status_code: int,
            duration_seconds: float,
        ) -> None:
            del duration_seconds
            metric_records.append((method, path, status_code))

    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(api_middleware, "audit_ledger", ledger)
    monkeypatch.setattr(api_middleware, "metrics_collector", RecordingMetrics())
    trace_id = "tr_oversize_pre_auth_audit"
    sentinel = "SENTINEL_SECRET_PATH_MUST_NOT_ESCAPE"
    request_path = f"/attacker/token/{sentinel}"
    api_middleware.telemetry.clear_finished_spans()

    response = TestClient(app).post(
        request_path,
        content=b"x" * (DEFAULT_MAX_REQUEST_BODY_BYTES + 1),
        headers={
            "content-type": "application/json",
            "origin": "http://localhost:3000",
            "x-tenant-id": "tenant-b",
            "x-trace-id": trace_id,
        },
    )

    assert response.status_code == 413
    assert response.headers["x-trace-id"] == trace_id
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert response.json() == {
        "trace_id": trace_id,
        "error": "request_body_too_large",
        "message": "Request body exceeds the configured size limit.",
        "details": {"max_request_body_bytes": DEFAULT_MAX_REQUEST_BODY_BYTES},
    }
    assert ledger.export_events(tenant_id="tenant-b") == []
    events = ledger.export_events(
        tenant_id=UNAUTHENTICATED_AUDIT_TENANT_ID,
        trace_id=trace_id,
    )
    assert len(events) == 1
    assert events[0].status_code == 413
    assert events[0].path == UNMATCHED_METRIC_PATH
    assert metric_records == [("POST", UNMATCHED_METRIC_PATH, 413)]
    spans = [
        span
        for span in api_middleware.telemetry.finished_spans()
        if span.attributes.get("app.trace_id") == trace_id
    ]
    assert len(spans) == 1
    assert spans[0].attributes["http.route"] == UNMATCHED_METRIC_PATH
    assert "url.path" not in spans[0].attributes
    exported = repr(
        {
            "audit": events,
            "span_attributes": dict(spans[0].attributes),
            "span_events": spans[0].events,
            "span_status": spans[0].status,
            "logs": caplog.messages,
        }
    )
    assert sentinel not in exported


def test_oversize_local_route_preserves_header_tenant_audit_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=False,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
    )
    ledger = AuditLedger()
    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(api_middleware, "audit_ledger", ledger)
    trace_id = "tr_oversize_local_audit"

    response = TestClient(app).post(
        "/verification/run",
        content=b"x" * (DEFAULT_MAX_REQUEST_BODY_BYTES + 1),
        headers={"x-tenant-id": "tenant-local", "x-trace-id": trace_id},
    )

    assert response.status_code == 413
    events = ledger.export_events(tenant_id="tenant-local", trace_id=trace_id)
    assert len(events) == 1
    assert events[0].status_code == 413


async def _never_called(_scope: Scope, _receive: Any, _send: Any) -> None:
    raise AssertionError("downstream must not be called")


async def _invoke(
    app_to_invoke: ASGIApp,
    *,
    headers: Sequence[tuple[bytes, bytes]] = (),
    messages: list[Message] | None = None,
    receive: Any | None = None,
    http_version: str = "1.1",
    method: str = "POST",
) -> list[Message]:
    pending = list(
        messages
        if messages is not None
        else [{"type": "http.request", "body": b"", "more_body": False}]
    )

    async def default_receive() -> Message:
        return pending.pop(0)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    scope = _http_scope(headers=headers, http_version=http_version, method=method)
    await app_to_invoke(scope, receive or default_receive, send)
    return sent


def _http_scope(
    *,
    headers: Sequence[tuple[bytes, bytes]],
    http_version: str = "1.1",
    method: str = "POST",
    path: str = "/test",
) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": http_version,
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": list(headers),
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "state": {},
    }


def _response_start(messages: list[Message]) -> Message:
    return next(message for message in messages if message["type"] == "http.response.start")


def _headers(messages: list[Message]) -> dict[bytes, bytes]:
    return dict(_response_start(messages).get("headers", []))


def _response_json(messages: list[Message]) -> dict[str, object]:
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    parsed = json.loads(body)
    assert isinstance(parsed, dict)
    return parsed
