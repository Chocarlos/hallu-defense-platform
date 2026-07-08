from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

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


class SpanHandle(Protocol):
    def set_attribute(self, key: str, value: AttributeValue) -> None: ...

    def set_status(self, status: Status) -> None: ...

    def record_exception(self, exception: BaseException) -> None: ...


class NoopSpanHandle:
    def set_attribute(self, key: str, value: AttributeValue) -> None:
        return None

    def set_status(self, status: Status) -> None:
        return None

    def record_exception(self, exception: BaseException) -> None:
        return None


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
    def request_span(self, *, method: str, path: str, trace_id: str) -> Iterator[SpanHandle]:
        if self.tracer is None:
            yield NoopSpanHandle()
            return
        with self.tracer.start_as_current_span(f"HTTP {method.upper()}") as span:
            span.set_attribute("app.trace_id", trace_id)
            span.set_attribute("http.request.method", method.upper())
            span.set_attribute("url.path", path)
            yield span

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
        with self.tracer.start_as_current_span(name) as span:
            if attributes is not None:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            try:
                yield span
            except Exception as exc:
                self.record_exception(span, exc)
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
        span.record_exception(exception)
        span.set_status(Status(StatusCode.ERROR, type(exception).__name__))

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
        return OTLPSpanExporter(endpoint=settings.otel_endpoint)
    raise ValueError(f"Unsupported OpenTelemetry exporter '{settings.otel_exporter}'")
