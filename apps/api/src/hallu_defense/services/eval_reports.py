from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from threading import Lock
from typing import Protocol
from uuid import uuid4

from pydantic import ValidationError

from hallu_defense.config import PRODUCTION_LIKE_ENVIRONMENTS, Settings
from hallu_defense.domain.models import (
    EvalReport,
    EvalReportListRequest,
    EvalReportPublishRequest,
)
from hallu_defense.services.postgres import SqlConnectionProvider

_POSTGRES_BACKENDS = {"postgres", "postgresql"}
_INSERT_REPORT_SQL = (
    "INSERT INTO eval_reports "
    "(report_id, tenant_id, suite, run_id, source, metrics, payload, published_by, published_at) "
    "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s)"
)
_SELECT_REPORTS_SQL = (
    "SELECT payload FROM eval_reports WHERE tenant_id=%s "
    "ORDER BY published_at DESC, id DESC LIMIT %s"
)
_SELECT_REPORTS_BY_SUITE_SQL = (
    "SELECT payload FROM eval_reports WHERE tenant_id=%s AND suite=%s "
    "ORDER BY published_at DESC, id DESC LIMIT %s"
)


class EvalReportError(RuntimeError):
    pass


class EvalReportConfigurationError(EvalReportError):
    pass


class EvalReportStorageError(EvalReportError):
    pass


class EvalReportStorage(Protocol):
    def append(self, report: EvalReport) -> None:
        ...

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        suite: str | None,
        limit: int,
    ) -> list[EvalReport]:
        ...


class MemoryEvalReportStorage:
    def __init__(self) -> None:
        self._lock = Lock()
        self._reports: list[EvalReport] = []

    def append(self, report: EvalReport) -> None:
        with self._lock:
            self._reports.append(report)

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        suite: str | None,
        limit: int,
    ) -> list[EvalReport]:
        with self._lock:
            reports = list(self._reports)
        return _filter_reports(reports, tenant_id=tenant_id, suite=suite, limit=limit)


class JsonlEvalReportStorage:
    def __init__(self, *, path: Path) -> None:
        self._path = path
        self._lock = Lock()
        self._reports = self._load()

    def append(self, report: EvalReport) -> None:
        record = {
            "record_type": "eval_report",
            "payload": report.model_dump(mode="json"),
        }
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            self._reports.append(report)

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        suite: str | None,
        limit: int,
    ) -> list[EvalReport]:
        with self._lock:
            reports = list(self._reports)
        return _filter_reports(reports, tenant_id=tenant_id, suite=suite, limit=limit)

    def _load(self) -> list[EvalReport]:
        if not self._path.exists():
            return []
        reports: list[EvalReport] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EvalReportStorageError(
                        f"Eval report record {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(record, Mapping):
                    raise EvalReportStorageError(
                        f"Eval report record {line_number} must be a JSON object"
                    )
                if record.get("record_type") != "eval_report":
                    raise EvalReportStorageError(
                        f"Eval report record {line_number} has unsupported record_type"
                    )
                payload = record.get("payload")
                if not isinstance(payload, Mapping):
                    raise EvalReportStorageError(
                        f"Eval report record {line_number} payload must be an object"
                    )
                try:
                    reports.append(EvalReport.model_validate(payload))
                except ValidationError as exc:
                    raise EvalReportStorageError(
                        f"Eval report record {line_number} payload is invalid"
                    ) from exc
        return reports


class PostgresEvalReportStorage:
    def __init__(self, *, connection: SqlConnectionProvider) -> None:
        self._connection = connection

    def append(self, report: EvalReport) -> None:
        self._connection.execute(
            _INSERT_REPORT_SQL,
            (
                report.report_id,
                report.tenant_id,
                report.suite,
                report.run_id,
                report.source,
                _dump_json(report.metrics.model_dump(mode="json")),
                _dump_json(report.model_dump(mode="json")),
                report.published_by,
                report.published_at,
            ),
        )

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        suite: str | None,
        limit: int,
    ) -> list[EvalReport]:
        if suite is None:
            rows = self._connection.fetch_all(_SELECT_REPORTS_SQL, (tenant_id, limit))
        else:
            rows = self._connection.fetch_all(
                _SELECT_REPORTS_BY_SUITE_SQL,
                (tenant_id, suite, limit),
            )
        reports: list[EvalReport] = []
        for row_number, row in enumerate(rows, start=1):
            payload = row.get("payload")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise EvalReportStorageError(
                        f"Postgres eval report row {row_number} payload is not valid JSON"
                    ) from exc
            if not isinstance(payload, Mapping):
                raise EvalReportStorageError(
                    f"Postgres eval report row {row_number} payload must be an object"
                )
            try:
                reports.append(EvalReport.model_validate(payload))
            except ValidationError as exc:
                raise EvalReportStorageError(
                    f"Postgres eval report row {row_number} payload is invalid"
                ) from exc
        return reports


class EvalReportRepository:
    def __init__(self, *, storage: EvalReportStorage) -> None:
        self._storage = storage

    def publish(
        self,
        *,
        tenant_id: str,
        request: EvalReportPublishRequest,
        published_by: str,
    ) -> EvalReport:
        report = EvalReport(
            report_id=f"evr_{uuid4().hex}",
            tenant_id=tenant_id,
            suite=request.suite,
            run_id=request.run_id,
            source=request.source,
            metrics=request.metrics,
            payload=request.payload,
            published_by=published_by,
        )
        self._storage.append(report)
        return report

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        request: EvalReportListRequest,
    ) -> list[EvalReport]:
        return self._storage.list_for_tenant(
            tenant_id=tenant_id,
            suite=request.suite,
            limit=request.limit,
        )


def create_eval_report_repository(
    settings: Settings,
    *,
    sql_provider: SqlConnectionProvider | None = None,
) -> EvalReportRepository:
    backend = settings.eval_reports_backend.strip().lower()
    if backend == "memory":
        if settings.environment.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS:
            raise EvalReportConfigurationError(
                "Production and staging must configure a persistent eval reports backend."
            )
        return EvalReportRepository(storage=MemoryEvalReportStorage())
    if backend == "jsonl":
        return EvalReportRepository(
            storage=JsonlEvalReportStorage(path=settings.eval_reports_path)
        )
    if backend in _POSTGRES_BACKENDS:
        if sql_provider is None:
            raise EvalReportConfigurationError(
                "Postgres eval reports backend requires an injected SqlConnectionProvider."
            )
        return EvalReportRepository(storage=PostgresEvalReportStorage(connection=sql_provider))
    raise EvalReportConfigurationError(
        f"Unsupported eval reports backend: {settings.eval_reports_backend}"
    )


def _filter_reports(
    reports: list[EvalReport],
    *,
    tenant_id: str,
    suite: str | None,
    limit: int,
) -> list[EvalReport]:
    filtered = [
        report
        for report in reports
        if report.tenant_id == tenant_id and (suite is None or report.suite == suite)
    ]
    return sorted(
        filtered,
        key=lambda report: (report.published_at, report.report_id),
        reverse=True,
    )[:limit]


def _dump_json(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
