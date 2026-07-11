from __future__ import annotations

import json
from pathlib import Path

import pytest
from opentelemetry.trace import StatusCode

from hallu_defense.config import Settings
from hallu_defense.services.telemetry import (
    MAX_EXCEPTION_TYPE_LENGTH,
    SAFE_ERROR_STATUS_DESCRIPTION,
    TelemetryService,
)


def test_exception_telemetry_never_exports_message_cause_or_stacktrace(
    tmp_path: Path,
) -> None:
    telemetry = _memory_telemetry(tmp_path)
    sentinel = "SENTINEL_DO_NOT_EXPORT_postgresql://admin:secret@db/private"
    sql = f"SELECT * FROM private_accounts /* {sentinel} */"
    cause = RuntimeError(f"upstream DSN leaked: {sentinel}")

    with pytest.raises(ValueError, match="private_accounts"):
        with telemetry.span("sanitized-exception"):
            raise ValueError(sql) from cause

    spans = telemetry.finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.status.status_code is StatusCode.ERROR
    assert span.status.description == SAFE_ERROR_STATUS_DESCRIPTION
    assert len(span.events) == 1
    event = span.events[0]
    assert event.name == "exception"
    assert dict(event.attributes or {}) == {
        "exception.type": "ValueError",
        "exception.escaped": False,
    }

    serialized = json.dumps(
        {
            "status": {
                "code": span.status.status_code.name,
                "description": span.status.description,
            },
            "events": [
                {"name": item.name, "attributes": dict(item.attributes or {})}
                for item in span.events
            ],
        },
        sort_keys=True,
    )
    assert "ValueError" in serialized
    assert sentinel not in serialized
    assert sql not in serialized
    assert str(cause) not in serialized
    assert "exception.message" not in serialized
    assert "exception.stacktrace" not in serialized
    assert "Traceback" not in serialized


def test_exception_type_is_ascii_sanitized_and_bounded(tmp_path: Path) -> None:
    telemetry = _memory_telemetry(tmp_path)
    exception_class = type("Unsafe/" + ("X" * 300), (RuntimeError,), {})

    with pytest.raises(exception_class):
        with telemetry.span("bounded-exception-type"):
            raise exception_class("secret exception message")

    event = telemetry.finished_spans()[0].events[0]
    exception_type = event.attributes["exception.type"]
    assert isinstance(exception_type, str)
    assert exception_type.startswith("Unsafe_")
    assert len(exception_type) == MAX_EXCEPTION_TYPE_LENGTH
    assert "/" not in exception_type


def _memory_telemetry(tmp_path: Path) -> TelemetryService:
    return TelemetryService.from_settings(
        Settings(
            environment="local",
            policy_version="test",
            auth_required=False,
            allowed_workspace=tmp_path,
            max_command_seconds=5,
            max_output_chars=1_000,
            otel_enabled=True,
            otel_exporter="memory",
        )
    )
