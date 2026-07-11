from __future__ import annotations

import json
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

try:
    from evals.runners.thresholds import evaluate_thresholds, load_suite_thresholds
except ImportError:  # running as a standalone script (python evals/runners/scenarios.py)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from evals.runners.thresholds import evaluate_thresholds, load_suite_thresholds

from hallu_defense.config import Settings
from hallu_defense.domain.models import RepoChecksRunRequest
from hallu_defense.main import app
from hallu_defense.services.sandbox import SandboxError, SandboxRunner

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_SET = ROOT / "evals" / "golden_sets" / "scenarios.json"
REPORT_PATH = ROOT / "evals" / "reports" / "scenario-metrics.json"
HISTORY_PATH = ROOT / "evals" / "reports" / "scenario-history.json"
HISTORY_LIMIT = 50


def main() -> None:
    report = evaluate_scenarios(write_report=True)
    failures = [
        failure
        for result in report["scenarios"]
        for failure in result.get("failures", [])
        if isinstance(failure, str)
    ]
    failures.extend(_metric_failures(report["metrics"]))

    if failures:
        print("Scenario eval failures:")
        for failure in failures:
            print(f"- {failure}")
        print(f"Metrics report written to {REPORT_PATH}")
        raise SystemExit(1)

    print(
        f"Scenario evals passed for {report['metrics']['scenario_count']} scenarios. "
        f"Metrics report written to {REPORT_PATH}."
    )
    print(json.dumps(report["metrics"], indent=2, sort_keys=True))


def evaluate_scenarios(*, write_report: bool) -> dict[str, Any]:
    scenarios = load_scenarios()
    client = TestClient(app)
    results = [_run_scenario(client, scenario) for scenario in scenarios]
    metrics = compute_metrics(results)
    report = {"metrics": metrics, "scenarios": results}
    if write_report:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _append_history(metrics)
    return report


def load_scenarios() -> list[dict[str, Any]]:
    payload = json.loads(GOLDEN_SET.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("scenario golden set must be a list")
    return [scenario for scenario in payload if isinstance(scenario, dict)]


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(results)
    passed_count = sum(1 for result in results if result["passed"])
    verification = [result for result in results if result["kind"] == "verification_run"]
    tool_high_risk = [result for result in results if result["id"] == "tool_high_risk_without_approval"]
    secret_redaction = [result for result in results if result["id"] == "tool_secret_leakage_redaction"]
    prompt_injection_ids = {
        "direct_prompt_injection_blocked",
        "indirect_prompt_injection_blocked",
        "direct_prompt_injection_text_blocked",
        "indirect_prompt_injection_document_blocked",
    }
    data_poisoning_ids = {"data_poisoning_blocked", "data_poisoning_document_blocked"}
    false_repo_claim_ids = {
        "code_false_file_claim_with_sandbox_inspection",
        "code_false_function_claim_with_sandbox_inspection",
    }
    semantic_repo_claim_ids = {
        "code_semantic_implementation_claim_without_changed_terms",
        "code_fix_claim_rejects_broad_successful_command",
        "code_fix_claim_supported_by_targeted_command",
    }
    prompt_injection = [
        result for result in results if result["id"] in prompt_injection_ids
    ]
    data_poisoning = [
        result for result in results if result["id"] in data_poisoning_ids
    ]
    tool_contradiction = [
        result for result in results if result["id"] == "tool_contradictory_output_requires_repair"
    ]
    false_repo_claims = [
        result for result in results if result["id"] in false_repo_claim_ids
    ]
    semantic_repo_claims = [
        result for result in results if result["id"] in semantic_repo_claim_ids
    ]
    sandbox = [result for result in results if result["kind"] == "sandbox_run"]
    by_category: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        category = str(result["category"])
        by_category.setdefault(category, []).append(result)

    return {
        "scenario_count": scenario_count,
        "passed_count": passed_count,
        "pass_rate": _ratio(passed_count, scenario_count),
        "category_pass_rate": {
            category: _ratio(sum(1 for item in items if item["passed"]), len(items))
            for category, items in sorted(by_category.items())
        },
        "verification_decision_accuracy": _ratio(
            sum(
                1
                for result in verification
                if result["observed"].get("final_decision")
                == result["expected"].get("final_decision")
            ),
            len(verification),
        ),
        "blocked_high_risk_rate": _ratio(
            sum(1 for result in tool_high_risk if result["observed"].get("approval_required") is True),
            len(tool_high_risk),
        ),
        "secret_redaction_rate": _ratio(
            sum(
                1
                for result in secret_redaction
                if result["observed"].get("sanitized_output")
                == result["expected"].get("sanitized_output")
            ),
            len(secret_redaction),
        ),
        "prompt_injection_block_rate": _ratio(
            sum(1 for result in prompt_injection if _blocked_result(result)),
            len(prompt_injection),
        ),
        "data_poisoning_block_rate": _ratio(
            sum(1 for result in data_poisoning if _blocked_result(result)),
            len(data_poisoning),
        ),
        "tool_contradiction_guard_rate": _ratio(
            sum(1 for result in tool_contradiction if result["observed"].get("action") == "rewrite"),
            len(tool_contradiction),
        ),
        "repo_false_claim_block_rate": _ratio(
            sum(1 for result in false_repo_claims if _blocked_result(result)),
            len(false_repo_claims),
        ),
        "repo_semantic_claim_decision_accuracy": _ratio(
            sum(
                1
                for result in semantic_repo_claims
                if result["observed"].get("final_decision")
                == result["expected"].get("final_decision")
            ),
            len(semantic_repo_claims),
        ),
        "blocking_precision": _blocking_precision(results),
        "sandbox_block_rate": _ratio(
            sum(1 for result in sandbox if result["observed"].get("blocked") is True),
            len(sandbox),
        ),
        "p95_latency_ms": round(_percentile_95(result["latency_ms"] for result in results), 3),
    }


def _run_scenario(client: TestClient, scenario: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    kind = _string_field(scenario, "kind")
    if kind == "verification_run":
        observed = _run_verification_scenario(client, scenario)
    elif kind == "policy_evaluate":
        observed = _run_policy_scenario(client, scenario)
    elif kind == "tool_validate_input":
        observed = _run_tool_scenario(client, "/tools/validate-input", scenario)
    elif kind == "tool_validate_output":
        observed = _run_tool_scenario(client, "/tools/validate-output", scenario)
    elif kind == "sandbox_run":
        observed = _run_sandbox_scenario(scenario)
    else:
        observed = {"error": f"unsupported scenario kind: {kind}"}
    latency_ms = (time.perf_counter() - started) * 1_000
    expected = _mapping_field(scenario, "expect")
    failures = _compare_expected(scenario, expected, observed)
    return {
        "id": _string_field(scenario, "id"),
        "kind": kind,
        "category": _string_field(scenario, "category"),
        "latency_ms": round(latency_ms, 3),
        "expected": expected,
        "observed": observed,
        "passed": not failures,
        "failures": failures,
    }


def _run_verification_scenario(client: TestClient, scenario: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        "/verification/run",
        json={"tenant_id": "eval-scenarios", **_mapping_field(scenario, "request")},
        headers={"x-tenant-id": "eval-scenarios"},
    )
    payload = response.json() if response.content else {}
    verdicts = payload.get("verdicts") if isinstance(payload, dict) else []
    return {
        "status_code": response.status_code,
        "trace_present": bool(payload.get("trace_id")) if isinstance(payload, dict) else False,
        "claim_count": len(payload.get("claims", [])) if isinstance(payload, dict) else 0,
        "verdict_statuses": _verdict_field(verdicts, "status"),
        "verdict_actions": _verdict_field(verdicts, "action"),
        "unsupported_claim_count": sum(
            1
            for verdict in verdicts
            if isinstance(verdict, dict) and verdict.get("status") != "SUPPORTED"
        )
        if isinstance(verdicts, list)
        else 0,
        "final_decision": payload.get("final_decision") if isinstance(payload, dict) else None,
    }


def _run_tool_scenario(client: TestClient, path: str, scenario: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        path,
        json=_mapping_field(scenario, "request"),
        headers={"x-tenant-id": "eval-scenarios", "x-roles": "verifier"},
    )
    payload = response.json() if response.content else {}
    observed: dict[str, Any] = {"status_code": response.status_code}
    if isinstance(payload, dict):
        for key in (
            "allowed",
            "action",
            "approval_required",
            "approval_id",
            "sanitized_output",
        ):
            if key in payload:
                observed[key] = payload[key]
    return observed


def _run_policy_scenario(client: TestClient, scenario: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        "/policy/evaluate",
        json=_mapping_field(scenario, "request"),
        headers={
            "x-tenant-id": "eval-scenarios",
            "x-roles": "policy_evaluator",
            "x-trace-id": f"tr_{_string_field(scenario, 'id')}",
        },
    )
    payload = response.json() if response.content else {}
    observed: dict[str, Any] = {"status_code": response.status_code}
    if isinstance(payload, dict):
        for key in ("allowed", "action", "matched_rules"):
            if key in payload:
                observed[key] = payload[key]
        observed["trace_present"] = bool(payload.get("trace_id"))
    return observed


def _run_sandbox_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    request = _mapping_field(scenario, "request")
    with tempfile.TemporaryDirectory(prefix="hallu-eval-sandbox-") as tmp_dir:
        workspace = Path(tmp_dir)
        _write_workspace(workspace, _mapping_field(scenario, "workspace"))
        runner = SandboxRunner(
            Settings(
                environment="test",
                policy_version="eval-scenarios",
                auth_required=False,
                allowed_workspace=workspace,
                max_command_seconds=5,
                max_output_chars=1000,
            )
        )
        try:
            run = runner.run(RepoChecksRunRequest(**request))
        except SandboxError as exc:
            return {"blocked": True, "error": str(exc)}
        return {
            "blocked": False,
            "exit_codes": run.exit_codes,
            "verdict": run.verdict.value,
            "artifact_count": len(run.artifacts),
        }


def _write_workspace(workspace: Path, fixture: Mapping[str, Any]) -> None:
    repo_ref = fixture.get("repo_ref")
    if not isinstance(repo_ref, str):
        return
    repo = workspace / repo_ref
    repo.mkdir(parents=True, exist_ok=True)
    files = fixture.get("files")
    if not isinstance(files, dict):
        return
    for relative_path, content in files.items():
        if not isinstance(relative_path, str) or not isinstance(content, str):
            continue
        target = (repo / relative_path).resolve()
        target.relative_to(repo.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _compare_expected(
    scenario: dict[str, Any],
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    scenario_id = _string_field(scenario, "id")
    for key, expected_value in expected.items():
        if key == "approval_id_prefix":
            approval_id = observed.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id.startswith(str(expected_value)):
                failures.append(f"{scenario_id}: approval_id does not start with {expected_value!r}")
            continue
        if key == "error_contains":
            error = observed.get("error")
            if not isinstance(error, str) or str(expected_value) not in error:
                failures.append(f"{scenario_id}: error does not contain {expected_value!r}")
            continue
        if observed.get(key) != expected_value:
            failures.append(
                f"{scenario_id}: expected {key}={expected_value!r}, got {observed.get(key)!r}"
            )
    return failures


def _mapping_field(payload: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return dict(value) if isinstance(value, dict) else {}


def _string_field(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else ""


def _verdict_field(verdicts: object, key: str) -> list[Any]:
    if not isinstance(verdicts, list):
        return []
    return [verdict[key] for verdict in verdicts if isinstance(verdict, dict) and key in verdict]


def _metric_failures(metrics: Mapping[str, Any]) -> list[str]:
    suite_config = load_suite_thresholds("scenarios")
    return evaluate_thresholds(metrics, suite_config)


def _append_history(metrics: Mapping[str, Any]) -> None:
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    created_at = created_at.replace("+00:00", "Z")
    existing_runs = _load_history_runs()
    run_id = _unique_history_run_id(created_at, existing_runs)
    payload = _history_payload(
        existing_runs,
        metrics,
        run_id=run_id,
        created_at=created_at,
        limit=HISTORY_LIMIT,
    )
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_history_runs() -> list[dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    payload = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scenario history report must be an object")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("scenario history report must contain a runs array")
    return [run for run in runs if isinstance(run, dict)]


def _history_payload(
    existing_runs: list[dict[str, Any]],
    metrics: Mapping[str, Any],
    *,
    run_id: str,
    created_at: str,
    limit: int,
) -> dict[str, Any]:
    if limit <= 0:
        raise ValueError("scenario history limit must be positive")
    entry = {
        "run_id": run_id,
        "created_at": created_at,
        "metrics": dict(metrics),
    }
    return {"runs": [*existing_runs, entry][-limit:]}


def _unique_history_run_id(created_at: str, existing_runs: list[dict[str, Any]]) -> str:
    base = "scenario-" + (
        created_at.removesuffix("Z")
        .replace("-", "")
        .replace(":", "")
        .replace("T", "-")
    )
    existing_ids = {run.get("run_id") for run in existing_runs}
    if base not in existing_ids:
        return base
    suffix = 2
    while f"{base}-{suffix}" in existing_ids:
        suffix += 1
    return f"{base}-{suffix}"


def _blocked_result(result: Mapping[str, Any]) -> bool:
    observed = result.get("observed")
    if not isinstance(observed, dict):
        return False
    return (
        observed.get("action") == "block"
        or observed.get("final_decision") == "blocked"
        or observed.get("blocked") is True
        or "block" in observed.get("verdict_actions", [])
    )


def _expected_blocked_result(result: Mapping[str, Any]) -> bool:
    expected = result.get("expected")
    if not isinstance(expected, dict):
        return False
    return (
        expected.get("action") == "block"
        or expected.get("final_decision") == "blocked"
        or expected.get("blocked") is True
        or "block" in expected.get("verdict_actions", [])
    )


def _blocking_precision(results: Iterable[Mapping[str, Any]]) -> float:
    true_positives = 0
    false_positives = 0
    for result in results:
        if not _blocked_result(result):
            continue
        if _expected_blocked_result(result):
            true_positives += 1
        else:
            false_positives += 1

    predicted_blocks = true_positives + false_positives
    if predicted_blocks == 0:
        # Precision is undefined without a predicted positive. Returning zero
        # makes the quality gate fail closed instead of reporting a vacuous 1.0.
        return 0.0
    return round(true_positives / predicted_blocks, 6)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return round(numerator / denominator, 6)


def _percentile_95(values: Iterable[float]) -> float:
    sorted_values = sorted(values)
    if not sorted_values:
        return 0.0
    index = max(0, min(len(sorted_values) - 1, int(len(sorted_values) * 0.95 + 0.999999) - 1))
    return sorted_values[index]


if __name__ == "__main__":
    main()
