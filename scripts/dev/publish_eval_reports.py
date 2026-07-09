"""Publish offline eval report artifacts into the runtime eval-report API.

The script is safe by default for CI: ``--live-smoke`` exits as skipped unless
``HALLU_DEFENSE_LIVE_EVAL_REPORT_PUBLISH_SMOKE_ENABLED=true`` is set. When
enabled it publishes one report, lists it back for the same tenant, and verifies
the Prometheus eval gauges exposed by the API.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_PATH = ROOT / "evals" / "reports" / "scenario-metrics.json"
LIVE_SMOKE_ENV = "HALLU_DEFENSE_LIVE_EVAL_REPORT_PUBLISH_SMOKE_ENABLED"


class EvalReportPublishError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.live_smoke and not _env_enabled(LIVE_SMOKE_ENV):
        print(json.dumps({"status": "skipped", "reason": f"{LIVE_SMOKE_ENV} is not true"}))
        return 0

    try:
        report_payload = _load_report(args.report_path)
        publish_payload = _build_publish_payload(
            report_payload,
            suite=args.suite,
            run_id=args.run_id,
            source=args.source or _source_for_path(args.report_path),
        )
        publish_response = _post_json(
            f"{args.api_url.rstrip('/')}/evals/reports/publish",
            publish_payload,
            headers=_headers(args.tenant_id, args.trace_id, args.subject_id, args.roles),
        )
        report = publish_response.get("report")
        if not isinstance(report, dict):
            raise EvalReportPublishError("Publish response did not include a report object.")
        report_id = _required_str(report, "report_id")
        list_response = _post_json(
            f"{args.api_url.rstrip('/')}/evals/reports/list",
            {"suite": args.suite, "limit": 5},
            headers=_headers(args.tenant_id, args.trace_id, args.subject_id, args.list_roles),
        )
        reports = list_response.get("reports")
        if not isinstance(reports, list) or not any(
            isinstance(item, dict) and item.get("report_id") == report_id for item in reports
        ):
            raise EvalReportPublishError("Published report was not returned by tenant-scoped list.")
        if args.live_smoke:
            metrics_body = _get_text(
                f"{args.api_url.rstrip('/')}/metrics",
                headers=_headers(
                    args.tenant_id,
                    args.trace_id,
                    args.subject_id,
                    "metrics_reader",
                ),
            )
            _assert_metrics(metrics_body, suite=args.suite, publish_payload=publish_payload)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "report_id": report_id,
                    "suite": args.suite,
                    "tenant_id": args.tenant_id,
                    "scenario_count": publish_payload["metrics"]["scenario_count"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except EvalReportPublishError as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":")))
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-smoke", action="store_true")
    parser.add_argument(
        "--api-url",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_API_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path(os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_PATH", DEFAULT_REPORT_PATH)),
    )
    parser.add_argument(
        "--suite",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_SUITE", "scenarios"),
    )
    parser.add_argument(
        "--run-id",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_RUN_ID", "local-eval-report"),
    )
    parser.add_argument("--source", default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_SOURCE"))
    parser.add_argument(
        "--tenant-id",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_TENANT", "tenant-evals"),
    )
    parser.add_argument(
        "--subject-id",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_SUBJECT", "eval-publisher"),
    )
    parser.add_argument(
        "--roles",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_ROLES", "eval_publisher"),
    )
    parser.add_argument(
        "--list-roles",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_LIST_ROLES", "auditor"),
    )
    parser.add_argument(
        "--trace-id",
        default=os.getenv("HALLU_DEFENSE_EVAL_REPORT_PUBLISH_TRACE_ID", "tr_eval_publish_smoke"),
    )
    return parser.parse_args(argv)


def _load_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise EvalReportPublishError(f"Eval report file does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvalReportPublishError(f"Eval report file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise EvalReportPublishError("Eval report JSON must be an object.")
    return payload


def _source_for_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return path.name


def _build_publish_payload(
    report: dict[str, Any],
    *,
    suite: str,
    run_id: str,
    source: str,
) -> dict[str, Any]:
    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        raise EvalReportPublishError("Eval report must contain a metrics object.")
    publish_metrics = {
        "scenario_count": _number(metrics, "scenario_count", integer=True),
        "pass_rate": _pass_rate(metrics),
        "p95_latency_ms": _number(metrics, "p95_latency_ms"),
    }
    for key in ("groundedness", "faithfulness"):
        value = metrics.get(key)
        if value is not None:
            publish_metrics[key] = _coerce_number(value, key)
    return {
        "suite": suite,
        "run_id": run_id,
        "source": source,
        "metrics": publish_metrics,
        "payload": report,
    }


def _pass_rate(metrics: dict[str, Any]) -> float:
    if "pass_rate" in metrics:
        return _number(metrics, "pass_rate")
    if "final_decision_accuracy" in metrics:
        return _number(metrics, "final_decision_accuracy")
    raise EvalReportPublishError("Eval metrics must include pass_rate or final_decision_accuracy.")


def _number(metrics: dict[str, Any], key: str, *, integer: bool = False) -> float | int:
    if key not in metrics:
        raise EvalReportPublishError(f"Eval metrics missing required field: {key}")
    value = _coerce_number(metrics[key], key)
    return int(value) if integer else value


def _coerce_number(value: Any, key: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvalReportPublishError(f"Eval metric {key} must be numeric.")
    numeric = float(value)
    if numeric < 0:
        raise EvalReportPublishError(f"Eval metric {key} must be non-negative.")
    return numeric


def _post_json(url: str, payload: dict[str, Any], *, headers: dict[str, str]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={**headers, "content-type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise EvalReportPublishError(f"POST {url} failed: {exc}") from exc
    if not isinstance(decoded, dict):
        raise EvalReportPublishError(f"POST {url} returned a non-object JSON payload.")
    return decoded


def _get_text(url: str, *, headers: dict[str, str]) -> str:
    req = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(req, timeout=10) as response:
            return response.read().decode("utf-8")
    except (error.URLError, TimeoutError) as exc:
        raise EvalReportPublishError(f"GET {url} failed: {exc}") from exc


def _headers(tenant_id: str, trace_id: str, subject_id: str, roles: str) -> dict[str, str]:
    return {
        "x-tenant-id": tenant_id,
        "x-trace-id": trace_id,
        "x-subject-id": subject_id,
        "x-roles": roles,
    }


def _assert_metrics(
    body: str,
    *,
    suite: str,
    publish_payload: dict[str, Any],
) -> None:
    expected = [
        f'hallu_eval_pass_rate{{suite="{suite}"}}',
        f'hallu_eval_p95_latency_ms{{suite="{suite}"}}',
        f'hallu_eval_scenario_count{{suite="{suite}"}}',
    ]
    metrics = publish_payload["metrics"]
    if "groundedness" in metrics:
        expected.append("hallu_eval_groundedness")
    if "faithfulness" in metrics:
        expected.append("hallu_eval_faithfulness")
    missing = [metric for metric in expected if metric not in body]
    if missing:
        raise EvalReportPublishError(f"Metrics response missing eval gauges: {missing}")


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise EvalReportPublishError(f"Response field {key} must be a non-empty string.")
    return value


def _env_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
