from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from hallu_defense.api import routes
from hallu_defense.config import Settings
from hallu_defense.domain.models import EvalReportListRequest, EvalReportPublishRequest
from hallu_defense.main import app
from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.eval_reports import (
    EvalReportConfigurationError,
    EvalReportRepository,
    JsonlEvalReportStorage,
    MemoryEvalReportStorage,
    PostgresEvalReportStorage,
    create_eval_report_repository,
)
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.postgres import RecordingSqlProvider


def _publish_request(
    *,
    suite: str = "scenarios",
    run_id: str = "run-1",
) -> EvalReportPublishRequest:
    return EvalReportPublishRequest(
        suite=suite,
        run_id=run_id,
        source="unit-test",
        metrics={
            "scenario_count": 21,
            "pass_rate": 1.0,
            "p95_latency_ms": 4.79,
            "groundedness": 0.98,
            "faithfulness": 0.99,
        },
        payload={"report_path": "evals/reports/scenario-metrics.json"},
    )


def _payload() -> dict[str, object]:
    return _publish_request().model_dump(mode="json")


def _settings(
    *,
    environment: str = "local",
    backend: str = "memory",
    path: Path | None = None,
) -> Settings:
    return Settings(
        environment=environment,
        policy_version="test",
        auth_required=False,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
        eval_reports_backend=backend,
        eval_reports_path=path or Path("var/evals/test-eval-reports.jsonl"),
    )


def test_memory_eval_reports_are_tenant_scoped_and_filtered() -> None:
    repository = EvalReportRepository(storage=MemoryEvalReportStorage())
    repository.publish(
        tenant_id="tenant-a",
        request=_publish_request(suite="scenarios", run_id="run-a"),
        published_by="publisher-a",
    )
    repository.publish(
        tenant_id="tenant-b",
        request=_publish_request(suite="smoke", run_id="run-b"),
        published_by="publisher-b",
    )

    listed = repository.list_for_tenant(
        tenant_id="tenant-a",
        request=EvalReportListRequest(suite="scenarios"),
    )

    assert [report.tenant_id for report in listed] == ["tenant-a"]
    assert [report.suite for report in listed] == ["scenarios"]
    assert listed[0].published_by == "publisher-a"


def test_jsonl_eval_reports_persist_and_reload(tmp_path: Path) -> None:
    path = tmp_path / "eval-reports.jsonl"
    repository = EvalReportRepository(storage=JsonlEvalReportStorage(path=path))
    published = repository.publish(
        tenant_id="tenant-a",
        request=_publish_request(),
        published_by="publisher-a",
    )

    reloaded = EvalReportRepository(storage=JsonlEvalReportStorage(path=path))
    listed = reloaded.list_for_tenant(
        tenant_id="tenant-a",
        request=EvalReportListRequest(limit=10),
    )

    assert listed[0].report_id == published.report_id
    stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert stored["record_type"] == "eval_report"
    assert stored["payload"]["tenant_id"] == "tenant-a"


def test_postgres_eval_reports_use_tenant_scoped_sql() -> None:
    provider = RecordingSqlProvider()
    repository = EvalReportRepository(
        storage=PostgresEvalReportStorage(connection=provider)
    )
    report = repository.publish(
        tenant_id="tenant-a",
        request=_publish_request(),
        published_by="publisher-a",
    )
    assert provider.calls[0][0] == "execute"
    assert "INSERT INTO eval_reports" in provider.calls[0][1]
    assert provider.calls[0][2][1] == "tenant-a"

    list_provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": report.model_dump(mode="json")}]
    )
    list_repository = EvalReportRepository(
        storage=PostgresEvalReportStorage(connection=list_provider)
    )
    listed = list_repository.list_for_tenant(
        tenant_id="tenant-a",
        request=EvalReportListRequest(suite="scenarios", limit=5),
    )

    assert listed[0].report_id == report.report_id
    assert "WHERE tenant_id=%s AND suite=%s" in list_provider.calls[0][1]
    assert list_provider.calls[0][2] == ("tenant-a", "scenarios", 5)


def test_eval_report_factory_fails_closed_in_production_without_persistent_backend() -> None:
    with pytest.raises(EvalReportConfigurationError, match="persistent eval reports backend"):
        create_eval_report_repository(_settings(environment="production", backend="memory"))


def test_eval_report_factory_requires_sql_provider_for_postgres() -> None:
    with pytest.raises(EvalReportConfigurationError, match="SqlConnectionProvider"):
        create_eval_report_repository(_settings(backend="postgres"))


def test_eval_report_publish_list_metrics_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = AuditLedger()
    metrics = PrometheusMetrics(
        service_name="hallu-defense-api",
        service_version="test",
        environment="test",
    )
    monkeypatch.setattr(
        routes,
        "eval_report_repository",
        EvalReportRepository(storage=MemoryEvalReportStorage()),
    )
    monkeypatch.setattr(routes, "audit_ledger", audit)
    monkeypatch.setattr(routes, "metrics_collector", metrics)

    client = TestClient(app)
    publish = client.post(
        "/evals/reports/publish",
        json=_payload(),
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_eval_publish_api",
            "x-subject-id": "publisher-a",
            "x-roles": "eval_publisher",
        },
    )
    assert publish.status_code == 200, publish.text
    published = publish.json()["report"]
    assert published["tenant_id"] == "tenant-a"
    assert published["published_by"] == "publisher-a"

    tenant_b = client.post(
        "/evals/reports/publish",
        json={**_payload(), "run_id": "run-b"},
        headers={
            "x-tenant-id": "tenant-b",
            "x-trace-id": "tr_eval_publish_api_b",
            "x-subject-id": "publisher-b",
            "x-roles": "eval_publisher",
        },
    )
    assert tenant_b.status_code == 200

    listed = client.post(
        "/evals/reports/list",
        json={"suite": "scenarios", "limit": 10},
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_eval_list_api",
            "x-subject-id": "auditor-a",
            "x-roles": "auditor",
        },
    )
    assert listed.status_code == 200, listed.text
    reports = listed.json()["reports"]
    assert [report["tenant_id"] for report in reports] == ["tenant-a"]
    assert reports[0]["report_id"] == published["report_id"]

    events = audit.export_events(tenant_id="tenant-a", trace_id="tr_eval_publish_api")
    assert [event.event_type for event in events] == ["eval_report_published"]
    assert events[0].metadata["suite"] == "scenarios"

    metrics_body = client.get("/metrics").text
    assert 'hallu_eval_pass_rate{suite="scenarios"} 1' in metrics_body
    assert 'hallu_eval_p95_latency_ms{suite="scenarios"} 4.79' in metrics_body
    assert 'hallu_eval_scenario_count{suite="scenarios"} 21' in metrics_body
    assert "hallu_eval_groundedness 0.98" in metrics_body
    assert "hallu_eval_faithfulness 0.99" in metrics_body


def test_eval_report_routes_enforce_roles_when_auth_is_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        routes,
        "eval_report_repository",
        EvalReportRepository(storage=MemoryEvalReportStorage()),
    )
    client = TestClient(app)

    publish_forbidden = client.post(
        "/evals/reports/publish",
        json=_payload(),
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_eval_publish_forbidden",
            "x-subject-id": "verifier-a",
            "x-roles": "verifier",
        },
    )
    list_forbidden = client.post(
        "/evals/reports/list",
        json={},
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_eval_list_forbidden",
            "x-subject-id": "publisher-a",
            "x-roles": "eval_publisher",
        },
    )

    assert publish_forbidden.status_code == 403
    assert list_forbidden.status_code == 403
