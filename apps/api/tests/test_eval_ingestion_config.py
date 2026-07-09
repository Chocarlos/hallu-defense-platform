from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci import check_eval_ingestion_config as gate


def _texts() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in (
            gate.CONFIG,
            gate.SERVICE,
            gate.ROUTES,
            gate.DEPENDENCIES,
            gate.METRICS,
            gate.MIGRATION,
            gate.PUBLISH_SCRIPT,
            gate.MAKEFILE,
            gate.CI_WORKFLOW,
            gate.SECURITY_WORKFLOW,
            gate.LIVE_WORKFLOW,
            gate.AUTH_DOC,
            gate.GRAFANA_CHECK,
            gate.DASHBOARD,
        )
    }


def test_eval_ingestion_config_validates_current_repo() -> None:
    gate.validate_eval_ingestion_config()


def test_eval_ingestion_config_rejects_missing_migration_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texts = _texts()
    texts[gate.MIGRATION] = texts[gate.MIGRATION].replace(
        "idx_eval_reports_tenant_suite_published_at",
        "idx_eval_reports_published_at",
    )
    monkeypatch.setattr(gate, "_read", lambda path: texts[path])

    with pytest.raises(gate.EvalIngestionConfigError, match="tenant-scoped report storage"):
        gate.validate_eval_ingestion_config()


def test_eval_ingestion_config_rejects_missing_fail_closed_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texts = _texts()
    texts[gate.SERVICE] = texts[gate.SERVICE].replace(
        "Production and staging must configure a persistent eval reports backend",
        "local eval reports backend",
    )
    monkeypatch.setattr(gate, "_read", lambda path: texts[path])

    with pytest.raises(gate.EvalIngestionConfigError, match="memory/jsonl/postgres"):
        gate.validate_eval_ingestion_config()


def test_eval_ingestion_config_rejects_missing_route_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texts = _texts()
    texts[gate.ROUTES] = texts[gate.ROUTES].replace("record_eval_report", "record_report")
    monkeypatch.setattr(gate, "_read", lambda path: texts[path])

    with pytest.raises(gate.EvalIngestionConfigError, match="emit metrics"):
        gate.validate_eval_ingestion_config()


def test_eval_ingestion_config_rejects_missing_ci_wiring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texts = _texts()
    texts[gate.CI_WORKFLOW] = texts[gate.CI_WORKFLOW].replace(
        "scripts/ci/check_eval_ingestion_config.py",
        "",
    )
    monkeypatch.setattr(gate, "_read", lambda path: texts[path])

    with pytest.raises(gate.EvalIngestionConfigError, match="Backend CI"):
        gate.validate_eval_ingestion_config()
