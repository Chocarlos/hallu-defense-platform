from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from opentelemetry.trace import StatusCode
from opentelemetry.util.types import AttributeValue

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


def test_arbitrary_span_attributes_and_events_are_recursively_redacted(tmp_path: Path) -> None:
    telemetry = _memory_telemetry(tmp_path)
    initial_attributes = cast(
        dict[str, AttributeValue],
        {
            "private_key": "-----BEGIN " + "PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----",
            "user.phone": 202_555_0198,
            "note": "charge 4111 1111 1111 1111",
            "secretary": "operations",
            "token_count": 7,
            "password_policy": "minimum 14 characters",
        },
    )

    with telemetry.span("tool.telemetry", attributes=initial_attributes) as span:
        span.set_attribute("ＡＣＣＥＳＳ＿ＫＥＹ", "AKIAABCDEFGHIJKLMNOP")
        span.add_event(
            "tool.event",
            attributes={
                "passport": "X1234567",
                "DOB": "1990-01-02",
                "home_address": "123 Example Street",
            },
        )

    exported = telemetry.finished_spans()[0]
    attributes = dict(exported.attributes or {})
    assert attributes == {
        "private_key": "[REDACTED]",
        "user.phone": "[REDACTED_PHONE]",
        "note": "charge [REDACTED_CARD]",
        "secretary": "operations",
        "token_count": 7,
        "password_policy": "minimum 14 characters",
        "ACCESS_KEY": "[REDACTED]",
    }
    assert len(exported.events) == 1
    assert dict(exported.events[0].attributes or {}) == {
        "passport": "[REDACTED_PASSPORT]",
        "DOB": "[REDACTED_DOB]",
        "home_address": "[REDACTED_ADDRESS]",
    }


def test_telemetry_replaces_cyclic_and_oversized_attributes_without_leaking(
    tmp_path: Path,
) -> None:
    telemetry = _memory_telemetry(tmp_path)
    cycle: dict[str, object] = {"sentinel": "CYCLE_SENTINEL_MUST_NOT_LEAK"}
    cycle["self"] = cycle
    oversized = "OVERSIZED_SENTINEL_MUST_NOT_LEAK" * 256

    with telemetry.span("bounded-attributes") as span:
        span.set_attribute("cyclic_payload", cast(AttributeValue, cycle))
        span.set_attribute("oversized_payload", oversized)

    attributes = dict(telemetry.finished_spans()[0].attributes or {})
    assert attributes == {
        "cyclic_payload": "[REDACTED_UNSAFE_STRUCTURE]",
        "oversized_payload": "[REDACTED_UNSAFE_STRUCTURE]",
    }
    assert "CYCLE_SENTINEL_MUST_NOT_LEAK" not in json.dumps(attributes)
    assert "OVERSIZED_SENTINEL_MUST_NOT_LEAK" not in json.dumps(attributes)


def test_telemetry_bounds_the_complete_event_attribute_mapping(tmp_path: Path) -> None:
    telemetry = _memory_telemetry(tmp_path)
    attributes = cast(
        dict[str, AttributeValue],
        {f"attribute_{index}": f"value-{index}" for index in range(65)},
    )

    with telemetry.span("bounded-event") as span:
        span.add_event("bulk-event", attributes=attributes)

    event_attributes = dict(telemetry.finished_spans()[0].events[0].attributes or {})
    assert event_attributes == {"telemetry.redaction": "[REDACTED_UNSAFE_STRUCTURE]"}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_telemetry_never_exports_non_finite_numbers(tmp_path: Path, value: float) -> None:
    telemetry = _memory_telemetry(tmp_path)

    with telemetry.span("finite-attributes") as span:
        span.set_attribute("unsafe_number", value)
        span.add_event("finite-event", attributes={"unsafe_number": value})

    exported = telemetry.finished_spans()[0]
    attributes = dict(exported.attributes or {})
    event_attributes = dict(exported.events[0].attributes or {})
    assert attributes["unsafe_number"] == "[REDACTED_UNSAFE_STRUCTURE]"
    assert event_attributes == {"telemetry.redaction": "[REDACTED_UNSAFE_STRUCTURE]"}
    json.dumps({"attributes": attributes, "event": event_attributes}, allow_nan=False)


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
