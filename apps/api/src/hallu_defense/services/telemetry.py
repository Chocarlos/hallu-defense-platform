from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

import requests
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode, Tracer
from opentelemetry.util.types import AttributeValue

from hallu_defense import __version__
from hallu_defense.config import Settings
from hallu_defense.outbound_http import (
    OutboundHttpPolicyError,
    outbound_http_policy_from_settings,
)
from hallu_defense.services.content_security import (
    REDACTED_UNSAFE_STRUCTURE,
    RedactionLimits,
    SensitiveDataRedactor,
)

MAX_EXCEPTION_TYPE_LENGTH = 128
SAFE_ERROR_STATUS_DESCRIPTION = "internal error"
_UNSAFE_EXCEPTION_TYPE_CHARACTER = re.compile(r"[^A-Za-z0-9_.-]")
_UNSAFE_TELEMETRY_IDENTIFIER_CHARACTER = re.compile(r"[^A-Za-z0-9_.\[\]-]")
_UNSAFE_TELEMETRY_NAME_CHARACTER = re.compile(r"[^A-Za-z0-9_. \[\]-]")
MAX_TELEMETRY_IDENTIFIER_LENGTH = 128
MAX_TELEMETRY_STRING_LENGTH = 4_096
_UNSUPPORTED_ATTRIBUTE = "[REDACTED_UNSUPPORTED_ATTRIBUTE]"
_TELEMETRY_REDACTOR = SensitiveDataRedactor(
    RedactionLimits(
        max_depth=8,
        max_nodes=256,
        max_items_per_container=64,
        max_string_chars=MAX_TELEMETRY_STRING_LENGTH,
        max_total_string_chars=16_384,
        max_number_chars=20,
    )
)


class SpanHandle(Protocol):
    def set_attribute(self, key: str, value: AttributeValue) -> None: ...

    def set_status(self, status: Status) -> None: ...

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, AttributeValue] | None = None,
    ) -> None: ...


class NoopSpanHandle:
    def set_attribute(self, key: str, value: AttributeValue) -> None:
        return None

    def set_status(self, status: Status) -> None:
        return None

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, AttributeValue] | None = None,
    ) -> None:
        return None


@dataclass(frozen=True)
class SanitizedSpanHandle:
    """Span facade that prevents arbitrary attributes and events from leaking data."""

    span: SpanHandle
    redactor: SensitiveDataRedactor = _TELEMETRY_REDACTOR

    def set_attribute(self, key: str, value: AttributeValue) -> None:
        safe_key = _sanitize_telemetry_identifier(key, fallback="telemetry.redacted_attribute")
        safe_value = _sanitize_attribute_value(key, value, redactor=self.redactor)
        self.span.set_attribute(safe_key, safe_value)

    def set_attributes(self, attributes: Mapping[str, AttributeValue]) -> None:
        for key, value in _sanitize_attribute_mapping(attributes, redactor=self.redactor).items():
            self.span.set_attribute(key, value)

    def set_status(self, status: Status) -> None:
        description = status.description
        if not description:
            self.span.set_status(status)
            return
        result = self.redactor.redact_text(description)
        safe_description = (
            result.value
            if result.complete and isinstance(result.value, str)
            else SAFE_ERROR_STATUS_DESCRIPTION
        )
        self.span.set_status(Status(status.status_code, safe_description))

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, AttributeValue] | None = None,
    ) -> None:
        safe_name = _sanitize_telemetry_name(name, fallback="redacted_event")
        safe_attributes = (
            _sanitize_attribute_mapping(attributes, redactor=self.redactor)
            if attributes is not None
            else None
        )
        self.span.add_event(safe_name, attributes=safe_attributes)


@dataclass(frozen=True)
class TelemetryService:
    enabled: bool
    provider: TracerProvider | None
    tracer: Tracer | None
    memory_exporter: InMemorySpanExporter | None

    @classmethod
    def from_settings(cls, settings: Settings) -> TelemetryService:
        if not settings.otel_enabled or settings.otel_exporter == "none":
            return cls(enabled=False, provider=None, tracer=None, memory_exporter=None)

        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": settings.otel_service_name,
                    "service.version": __version__,
                    "deployment.environment": settings.environment,
                }
            )
        )
        memory_exporter: InMemorySpanExporter | None = None
        exporter = _span_exporter(settings)
        if isinstance(exporter, InMemorySpanExporter):
            memory_exporter = exporter
            provider.add_span_processor(SimpleSpanProcessor(exporter))
        else:
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        return cls(
            enabled=True,
            provider=provider,
            tracer=provider.get_tracer("hallu_defense.api", __version__),
            memory_exporter=memory_exporter,
        )

    @contextmanager
    def request_span(self, *, method: str, trace_id: str) -> Iterator[SpanHandle]:
        if self.tracer is None:
            yield NoopSpanHandle()
            return
        with self.tracer.start_as_current_span(
            _sanitize_telemetry_name(f"HTTP {method}", fallback="HTTP request"),
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            safe_span = SanitizedSpanHandle(span)
            safe_span.set_attribute("app.trace_id", trace_id)
            safe_span.set_attribute("http.request.method", method)
            yield safe_span

    @contextmanager
    def span(
        self,
        name: str,
        *,
        attributes: Mapping[str, AttributeValue] | None = None,
    ) -> Iterator[SpanHandle]:
        if self.tracer is None:
            yield NoopSpanHandle()
            return
        with self.tracer.start_as_current_span(
            _sanitize_telemetry_name(name, fallback="redacted_span"),
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            safe_span = SanitizedSpanHandle(span)
            if attributes is not None:
                safe_span.set_attributes(attributes)
            try:
                yield safe_span
            except Exception as exc:
                self.record_exception(safe_span, exc)
                raise

    def finish_request_span(
        self,
        span: SpanHandle,
        *,
        route_path: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        span.set_attribute("http.route", route_path)
        span.set_attribute("http.response.status_code", status_code)
        span.set_attribute("app.outcome", "success" if status_code < 400 else "error")
        span.set_attribute("app.duration_ms", duration_ms)
        if status_code >= 500:
            span.set_status(Status(StatusCode.ERROR))
        else:
            span.set_status(Status(StatusCode.OK))

    def record_exception(self, span: SpanHandle, exception: BaseException) -> None:
        span.add_event(
            "exception",
            attributes={
                "exception.type": _sanitized_exception_type(exception),
                "exception.escaped": False,
            },
        )
        span.set_status(Status(StatusCode.ERROR, SAFE_ERROR_STATUS_DESCRIPTION))

    def finished_spans(self) -> tuple[ReadableSpan, ...]:
        if self.memory_exporter is None:
            return ()
        return tuple(self.memory_exporter.get_finished_spans())

    def clear_finished_spans(self) -> None:
        if self.memory_exporter is not None:
            self.memory_exporter.clear()


def _span_exporter(settings: Settings) -> SpanExporter:
    if settings.otel_exporter == "memory":
        return InMemorySpanExporter()
    if settings.otel_exporter == "console":
        return ConsoleSpanExporter()
    if settings.otel_exporter == "otlp":
        if not settings.otel_endpoint:
            raise ValueError("HALLU_DEFENSE_OTEL_ENDPOINT is required when exporter is otlp")
        try:
            outbound_http_policy_from_settings(settings).validate_url(settings.otel_endpoint)
        except OutboundHttpPolicyError:
            raise ValueError("OTLP endpoint is blocked by outbound policy") from None
        return OTLPSpanExporter(
            endpoint=settings.otel_endpoint,
            session=_otlp_no_redirect_session(),
        )
    raise ValueError(f"Unsupported OpenTelemetry exporter '{settings.otel_exporter}'")


def _sanitized_exception_type(exception: BaseException) -> str:
    type_name = _UNSAFE_EXCEPTION_TYPE_CHARACTER.sub("_", type(exception).__name__)
    return (type_name or "Exception")[:MAX_EXCEPTION_TYPE_LENGTH]


def _sanitize_telemetry_identifier(value: str, *, fallback: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    result = _TELEMETRY_REDACTOR.redact_text(normalized)
    if not result.complete or not isinstance(result.value, str):
        return fallback
    safe = _UNSAFE_TELEMETRY_IDENTIFIER_CHARACTER.sub("_", result.value).strip("_")
    return (safe or fallback)[:MAX_TELEMETRY_IDENTIFIER_LENGTH]


def _sanitize_telemetry_name(value: str, *, fallback: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    result = _TELEMETRY_REDACTOR.redact_text(normalized)
    if not result.complete or not isinstance(result.value, str):
        return fallback
    safe = _UNSAFE_TELEMETRY_NAME_CHARACTER.sub("_", result.value).strip("_ ")
    return (safe or fallback)[:MAX_TELEMETRY_IDENTIFIER_LENGTH]


def _sanitize_attribute_value(
    key: str,
    value: object,
    *,
    redactor: SensitiveDataRedactor,
) -> AttributeValue:
    result = redactor.redact({key: value})
    if not result.complete or not isinstance(result.value, dict):
        return REDACTED_UNSAFE_STRUCTURE
    sanitized = result.value.get(key, REDACTED_UNSAFE_STRUCTURE)
    return _coerce_attribute_value(sanitized)


def _sanitize_attribute_mapping(
    attributes: Mapping[str, AttributeValue],
    *,
    redactor: SensitiveDataRedactor,
) -> dict[str, AttributeValue]:
    result = redactor.redact(attributes)
    if not result.complete or not isinstance(result.value, dict):
        return {"telemetry.redaction": REDACTED_UNSAFE_STRUCTURE}
    return {
        _sanitize_telemetry_identifier(
            key, fallback="telemetry.redacted_attribute"
        ): _coerce_attribute_value(value)
        for key, value in result.value.items()
    }


def _coerce_attribute_value(sanitized: object) -> AttributeValue:
    if isinstance(sanitized, str | bool | int | float):
        return sanitized
    if isinstance(sanitized, list):
        if not sanitized:
            return ()
        element_type = type(sanitized[0])
        if element_type not in {str, bool, int, float} or any(
            type(item) is not element_type for item in sanitized
        ):
            return _UNSUPPORTED_ATTRIBUTE
        return tuple(sanitized)
    return _UNSUPPORTED_ATTRIBUTE


def _otlp_no_redirect_session() -> requests.Session:
    session = requests.Session()
    session.max_redirects = 0
    session.hooks["response"].append(_sanitize_otlp_response)
    return session


def _sanitize_otlp_response(
    response: requests.Response,
    *_args: object,
    **_kwargs: object,
) -> None:
    response.close()
    response._content = b""  # noqa: SLF001 - prevent requests/exporter from reading remote bodies
    response._content_consumed = True  # noqa: SLF001
    response.reason = "upstream response"
    if 300 <= response.status_code < 400:
        raise requests.exceptions.TooManyRedirects(
            "OTLP redirects are not allowed."
        ) from None
