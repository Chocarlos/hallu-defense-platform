from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
SERVICE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "eval_reports.py"
ROUTES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "routes.py"
DEPENDENCIES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
METRICS = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "metrics.py"
MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "005_eval_reports.sql"
PUBLISH_SCRIPT = ROOT / "scripts" / "dev" / "publish_eval_reports.py"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "live.yml"
AUTH_DOC = ROOT / "docs" / "security" / "auth-rbac.md"
GRAFANA_CHECK = ROOT / "scripts" / "ci" / "check_grafana_dashboards.py"
DASHBOARD = ROOT / "infra" / "grafana" / "dashboards" / "hallu-defense-overview.json"


class EvalIngestionConfigError(RuntimeError):
    pass


def validate_eval_ingestion_config(root: Path = ROOT) -> None:
    del root
    paths = {
        "config": CONFIG,
        "service": SERVICE,
        "routes": ROUTES,
        "dependencies": DEPENDENCIES,
        "metrics": METRICS,
        "migration": MIGRATION,
        "publish_script": PUBLISH_SCRIPT,
        "makefile": MAKEFILE,
        "ci_workflow": CI_WORKFLOW,
        "security_workflow": SECURITY_WORKFLOW,
        "live_workflow": LIVE_WORKFLOW,
        "auth_doc": AUTH_DOC,
        "grafana_check": GRAFANA_CHECK,
        "dashboard": DASHBOARD,
    }
    texts = {name: _read(path) for name, path in paths.items()}
    errors: list[str] = []

    _require(
        texts["config"],
        [
            "eval_reports_backend",
            "eval_reports_path",
            "HALLU_DEFENSE_EVAL_REPORTS_BACKEND",
            "HALLU_DEFENSE_EVAL_REPORTS_PATH",
        ],
        "Settings must expose eval report backend/path env keys",
        errors,
    )
    _require(
        texts["service"],
        [
            "MemoryEvalReportStorage",
            "JsonlEvalReportStorage",
            "PostgresEvalReportStorage",
            "Production and staging must configure a persistent eval reports backend",
            "report.tenant_id == tenant_id",
            "WHERE tenant_id=%s",
        ],
        "Eval report service must provide memory/jsonl/postgres tenant-scoped persistence",
        errors,
    )
    _require(
        texts["routes"],
        [
            '"/evals/reports/publish"',
            '"/evals/reports/list"',
            'event_type="eval_report_published"',
            "record_eval_report",
            "enforce_when_auth_optional=True",
        ],
        "Eval report routes must publish/list, audit, emit metrics, and enforce RBAC",
        errors,
    )
    _require(
        texts["dependencies"],
        [
            "EVAL_PUBLISHER_ROLE",
            '"POST /evals/reports/publish"',
            '"POST /evals/reports/list"',
            "create_eval_report_repository",
            "settings.eval_reports_backend",
        ],
        "Dependency wiring must include RBAC and fail-closed repository factory",
        errors,
    )
    _require(
        texts["metrics"],
        [
            "hallu_eval_pass_rate",
            "hallu_eval_p95_latency_ms",
            "hallu_eval_scenario_count",
            "hallu_eval_groundedness",
            "hallu_eval_faithfulness",
            "record_eval_report",
        ],
        "Prometheus eval gauges must be emitted on publish",
        errors,
    )
    _require(
        texts["migration"],
        [
            "CREATE TABLE IF NOT EXISTS eval_reports",
            "tenant_id TEXT NOT NULL",
            "metrics JSONB NOT NULL",
            "payload JSONB NOT NULL",
            "idx_eval_reports_tenant_suite_published_at",
        ],
        "005_eval_reports.sql must create tenant-scoped report storage",
        errors,
    )
    _require(
        texts["publish_script"],
        [
            "HALLU_DEFENSE_LIVE_EVAL_REPORT_PUBLISH_SMOKE_ENABLED",
            "/evals/reports/publish",
            "/evals/reports/list",
            "/metrics",
            "eval_publisher",
        ],
        "Publish smoke must be env-gated and exercise publish/list/metrics",
        errors,
    )
    _require(
        texts["makefile"],
        [
            "eval-ingestion-config:",
            "scripts/ci/check_eval_ingestion_config.py",
            "eval-report-publish-smoke:",
            "scripts/dev/publish_eval_reports.py --live-smoke",
        ],
        "Makefile must expose eval ingestion config and publish smoke targets",
        errors,
    )
    _require(
        texts["ci_workflow"],
        ["Check eval ingestion config", "scripts/ci/check_eval_ingestion_config.py"],
        "Backend CI must run the eval ingestion config gate",
        errors,
    )
    _require(
        texts["security_workflow"],
        ["scripts/ci/check_eval_ingestion_config.py"],
        "Security CI must run the eval ingestion config gate",
        errors,
    )
    _require(
        texts["live_workflow"],
        [
            "eval-reports-live",
            "HALLU_DEFENSE_LIVE_EVAL_REPORT_PUBLISH_SMOKE_ENABLED",
            "HALLU_DEFENSE_EVAL_REPORTS_BACKEND: postgres",
            "scripts/dev/publish_eval_reports.py --live-smoke",
        ],
        "Live workflow must wire the env-gated eval report publish smoke",
        errors,
    )
    _require(
        texts["auth_doc"],
        [
            "`POST /evals/reports/publish` | `eval_publisher`",
            "`POST /evals/reports/list` | `auditor` or `verifier`",
        ],
        "RBAC docs must cover eval report publish/list",
        errors,
    )
    _require(
        texts["grafana_check"],
        [
            "hallu_eval_pass_rate",
            "hallu_eval_p95_latency_ms",
            "hallu_eval_scenario_count",
        ],
        "Grafana dashboard lint must require eval metrics",
        errors,
    )
    _require(
        texts["dashboard"],
        ["Eval Runtime", "hallu_eval_pass_rate", "hallu_eval_p95_latency_ms"],
        "Grafana dashboard must include an eval runtime panel",
        errors,
    )

    if errors:
        raise EvalIngestionConfigError("\n".join(errors))
    print("Validated eval report ingestion configuration.")


def _read(path: Path) -> str:
    if not path.is_file():
        raise EvalIngestionConfigError(f"Required file is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def _require(text: str, needles: list[str], label: str, errors: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        errors.append(f"{label}; missing: {missing}")


if __name__ == "__main__":
    validate_eval_ingestion_config()
