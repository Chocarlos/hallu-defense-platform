from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = ROOT / "infra" / "grafana" / "dashboards"
DATASOURCE_FILE = ROOT / "infra" / "grafana" / "provisioning" / "datasources" / "prometheus.yml"
DASHBOARD_PROVIDER_FILE = (
    ROOT / "infra" / "grafana" / "provisioning" / "dashboards" / "hallu-defense.yml"
)

REQUIRED_METRICS = {
    "hallu_http_requests_total",
    "hallu_http_request_duration_seconds_bucket",
    "hallu_verification_runs_total",
    "hallu_verification_run_duration_seconds_bucket",
    "hallu_claim_verdicts_total",
    "hallu_policy_decisions_total",
    "hallu_policy_evaluation_duration_seconds_bucket",
    "hallu_approval_requests_total",
    "hallu_approval_decisions_total",
    "hallu_sandbox_runs_total",
    "hallu_sandbox_run_duration_seconds_bucket",
}
REQUIRED_PANEL_TITLES = {
    "HTTP Request Rate",
    "HTTP P95 Latency",
    "Verification Runs By Final Decision",
    "Verification P95 Latency",
    "Claim Verdicts",
    "Policy Decisions",
    "Policy P95 Latency",
    "Approval Requests",
    "Approval Decisions",
    "Sandbox Runs",
    "Sandbox P95 Latency",
}
FORBIDDEN_QUERY_TERMS = {
    "tenant_id",
    "tool_name",
    "source_ref",
    "command=",
    "repo_ref",
    "document_id",
    "api_key",
    "secret",
    "token",
    "password",
}
PROMQL_METRIC_RE = re.compile(r"\b(hallu_[a-zA-Z0-9_:]+)\b")


def main() -> None:
    errors: list[str] = []
    dashboards = sorted(DASHBOARD_DIR.glob("*.json"))
    if not dashboards:
        errors.append(f"No Grafana dashboards found in {DASHBOARD_DIR.relative_to(ROOT)}")

    _validate_provisioning(errors)
    observed_metrics: set[str] = set()
    observed_titles: set[str] = set()
    dashboard_count = 0
    panel_count = 0

    for dashboard_path in dashboards:
        dashboard_count += 1
        dashboard = _read_json(dashboard_path, errors)
        if dashboard is None:
            continue
        panel_count += _validate_dashboard(
            dashboard_path,
            dashboard,
            observed_metrics,
            observed_titles,
            errors,
        )

    missing_metrics = REQUIRED_METRICS - observed_metrics
    if missing_metrics:
        errors.append(f"Missing required dashboard metrics: {', '.join(sorted(missing_metrics))}")

    missing_titles = REQUIRED_PANEL_TITLES - observed_titles
    if missing_titles:
        errors.append(f"Missing required dashboard panels: {', '.join(sorted(missing_titles))}")

    if errors:
        print("Grafana dashboard validation failed:")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)

    print(f"Validated {dashboard_count} Grafana dashboard file(s) with {panel_count} panel(s).")


def _validate_provisioning(errors: list[str]) -> None:
    datasource_text = _read_text(DATASOURCE_FILE, errors)
    if datasource_text is not None:
        for expected in ["uid: prometheus", "type: prometheus", "url: http://prometheus:9090"]:
            if expected not in datasource_text:
                errors.append(f"{DATASOURCE_FILE.relative_to(ROOT)} missing `{expected}`")

    provider_text = _read_text(DASHBOARD_PROVIDER_FILE, errors)
    if provider_text is not None:
        for expected in ["folder: Hallu Defense", "path: /var/lib/grafana/dashboards"]:
            if expected not in provider_text:
                errors.append(f"{DASHBOARD_PROVIDER_FILE.relative_to(ROOT)} missing `{expected}`")


def _read_text(path: Path, errors: list[str]) -> str | None:
    if not path.exists():
        errors.append(f"Missing required file {path.relative_to(ROOT)}")
        return None
    return path.read_text(encoding="utf-8")


def _read_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{path.relative_to(ROOT)} must contain a JSON object")
        return None
    return payload


def _validate_dashboard(
    path: Path,
    dashboard: dict[str, Any],
    observed_metrics: set[str],
    observed_titles: set[str],
    errors: list[str],
) -> int:
    if not _nonempty_string(dashboard.get("uid")):
        errors.append(f"{path.relative_to(ROOT)} missing non-empty dashboard uid")
    if not _nonempty_string(dashboard.get("title")):
        errors.append(f"{path.relative_to(ROOT)} missing non-empty title")
    if not isinstance(dashboard.get("schemaVersion"), int):
        errors.append(f"{path.relative_to(ROOT)} missing integer schemaVersion")

    panels = dashboard.get("panels")
    if not isinstance(panels, list) or not panels:
        errors.append(f"{path.relative_to(ROOT)} must contain at least one panel")
        return 0

    panel_ids: set[int] = set()
    panel_count = 0
    for panel in _iter_panels(panels):
        panel_count += 1
        _validate_panel(path, panel, panel_ids, observed_metrics, observed_titles, errors)

    return panel_count


def _iter_panels(panels: list[Any]) -> Iterator[dict[str, Any]]:
    for panel in panels:
        if not isinstance(panel, dict):
            continue
        yield panel
        nested = panel.get("panels")
        if isinstance(nested, list):
            yield from _iter_panels(nested)


def _validate_panel(
    path: Path,
    panel: dict[str, Any],
    panel_ids: set[int],
    observed_metrics: set[str],
    observed_titles: set[str],
    errors: list[str],
) -> None:
    panel_id = panel.get("id")
    if not isinstance(panel_id, int):
        errors.append(f"{path.relative_to(ROOT)} has panel without integer id")
    elif panel_id in panel_ids:
        errors.append(f"{path.relative_to(ROOT)} has duplicate panel id {panel_id}")
    else:
        panel_ids.add(panel_id)

    title = panel.get("title")
    if not _nonempty_string(title):
        errors.append(f"{path.relative_to(ROOT)} panel {panel_id} missing non-empty title")
    else:
        observed_titles.add(title)

    targets = panel.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append(f"{path.relative_to(ROOT)} panel `{title}` must contain Prometheus targets")
        return

    panel_datasource = _datasource_uid(panel.get("datasource"))
    for target in targets:
        if not isinstance(target, dict):
            errors.append(f"{path.relative_to(ROOT)} panel `{title}` contains a non-object target")
            continue
        expr = target.get("expr")
        if not _nonempty_string(expr):
            errors.append(f"{path.relative_to(ROOT)} panel `{title}` has a target without expr")
            continue
        target_datasource = _datasource_uid(target.get("datasource")) or panel_datasource
        if target_datasource != "prometheus":
            errors.append(f"{path.relative_to(ROOT)} panel `{title}` target must use prometheus datasource")
        lowered_expr = expr.lower()
        forbidden = sorted(term for term in FORBIDDEN_QUERY_TERMS if term in lowered_expr)
        if forbidden:
            errors.append(f"{path.relative_to(ROOT)} panel `{title}` query uses forbidden terms: {', '.join(forbidden)}")
        observed_metrics.update(PROMQL_METRIC_RE.findall(expr))


def _datasource_uid(value: object) -> str | None:
    if isinstance(value, dict):
        uid = value.get("uid")
        return uid if isinstance(uid, str) else None
    if isinstance(value, str):
        return value
    return None


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


if __name__ == "__main__":
    main()
