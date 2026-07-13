from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

from fastapi.testclient import TestClient
from httpx2 import Response

try:
    from evals.runners.thresholds import evaluate_thresholds, load_suite_thresholds
except ImportError:  # running as a standalone script (python evals/runners/smoke.py)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from evals.runners.thresholds import evaluate_thresholds, load_suite_thresholds

from hallu_defense.main import app

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_SET = ROOT / "evals" / "golden_sets" / "smoke.json"
REPORT_PATH = ROOT / "evals" / "reports" / "smoke-metrics.json"
EVAL_TENANT_ID = "eval-smoke"
SUPPORTED_STATUSES = {"SUPPORTED"}
ALLOW_DECISIONS = {"allow"}


class _VerificationClient(Protocol):
    def post(
        self,
        url: str,
        *,
        json: Any,
        headers: dict[str, str],
    ) -> Response: ...


def main() -> None:
    scenarios = json.loads(GOLDEN_SET.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    with TestClient(app) as client:
        for scenario in scenarios:
            started = time.perf_counter()
            response = _post_verification_scenario(client, scenario)
            latency_ms = (time.perf_counter() - started) * 1_000
            if response.status_code != 200:
                failures.append(f"{scenario['id']}: status {response.status_code}")
                continue
            payload = response.json()
            results.append(_scenario_result(scenario, payload, latency_ms))
            if not payload.get("trace_id"):
                failures.append(f"{scenario['id']}: missing trace_id")
            if not payload.get("claims"):
                failures.append(f"{scenario['id']}: missing claims")
            if not payload.get("verdicts"):
                failures.append(f"{scenario['id']}: missing verdicts")
            if payload.get("final_decision") != scenario["expected_final_decision"]:
                failures.append(
                    f"{scenario['id']}: expected {scenario['expected_final_decision']} "
                    f"got {payload.get('final_decision')}"
                )

    metrics = compute_metrics(results)
    failures.extend(_metric_failures(metrics))
    _write_report(results, metrics)

    if failures:
        print("Eval smoke failures:")
        for failure in failures:
            print(f"- {failure}")
        print(f"Metrics report written to {REPORT_PATH}")
        raise SystemExit(1)

    print(
        f"Eval smoke passed for {len(scenarios)} scenarios. "
        f"Metrics report written to {REPORT_PATH}."
    )
    print(json.dumps(metrics, indent=2, sort_keys=True))


def _post_verification_scenario(
    client: _VerificationClient,
    scenario: dict[str, Any],
) -> Response:
    return client.post(
        "/verification/run",
        json={
            "tenant_id": EVAL_TENANT_ID,
            "message_text": scenario["message_text"],
            "task_type": scenario["task_type"],
            "documents": scenario["documents"],
        },
        headers={"x-tenant-id": EVAL_TENANT_ID},
    )


def _scenario_result(
    scenario: dict[str, Any],
    payload: dict[str, Any],
    latency_ms: float,
) -> dict[str, Any]:
    claims = payload.get("claims") if isinstance(payload.get("claims"), list) else []
    verdicts = payload.get("verdicts") if isinstance(payload.get("verdicts"), list) else []
    expected_claims = [_normalize_claim(item) for item in scenario.get("expected_claims", [])]
    expected_unsupported = [
        _normalize_claim(item) for item in scenario.get("expected_unsupported_claims", [])
    ]
    actual_claims = [
        _normalize_claim(_claim_text(claim))
        for claim in claims
        if isinstance(claim, dict) and _claim_text(claim)
    ]
    verdict_by_claim = {
        verdict.get("claim_id"): verdict
        for verdict in verdicts
        if isinstance(verdict, dict) and isinstance(verdict.get("claim_id"), str)
    }
    unsupported_hits = 0
    for expected_claim in expected_unsupported:
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            if _normalize_claim(_claim_text(claim)) != expected_claim:
                continue
            verdict = verdict_by_claim.get(claim.get("claim_id"))
            status = verdict.get("status") if isinstance(verdict, dict) else None
            if status not in SUPPORTED_STATUSES:
                unsupported_hits += 1
            break

    return {
        "id": scenario["id"],
        "latency_ms": round(latency_ms, 3),
        "expected_final_decision": scenario["expected_final_decision"],
        "final_decision": payload.get("final_decision"),
        "trace_present": bool(payload.get("trace_id")),
        "claim_ledger_present": bool(claims),
        "verdict_ledger_present": bool(verdicts),
        "expected_claims": expected_claims,
        "actual_claims": actual_claims,
        "expected_unsupported_claims": expected_unsupported,
        "unsupported_hits": unsupported_hits,
        "supported_verdicts": sum(
            1
            for verdict in verdicts
            if isinstance(verdict, dict) and verdict.get("status") in SUPPORTED_STATUSES
        ),
        "supported_verdicts_with_evidence": sum(
            1
            for verdict in verdicts
            if isinstance(verdict, dict)
            and verdict.get("status") in SUPPORTED_STATUSES
            and bool(verdict.get("evidence_ids"))
        ),
        "verdict_count": len(verdicts),
        "cost_usd": float(payload.get("cost_usd", 0.0) or 0.0),
    }


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, float | int]:
    scenario_count = len(results)
    expected_claim_total = sum(len(result["expected_claims"]) for result in results)
    actual_claim_total = sum(len(result["actual_claims"]) for result in results)
    matched_claim_total = sum(
        len(set(result["expected_claims"]).intersection(result["actual_claims"]))
        for result in results
    )
    unsupported_expected_total = sum(len(result["expected_unsupported_claims"]) for result in results)
    unsupported_hits = sum(int(result["unsupported_hits"]) for result in results)
    supported_verdicts = sum(int(result["supported_verdicts"]) for result in results)
    supported_with_evidence = sum(int(result["supported_verdicts_with_evidence"]) for result in results)
    verdict_count = sum(int(result["verdict_count"]) for result in results)
    expected_allow = [result for result in results if result["expected_final_decision"] in ALLOW_DECISIONS]
    expected_non_allow = [
        result for result in results if result["expected_final_decision"] not in ALLOW_DECISIONS
    ]

    return {
        "scenario_count": scenario_count,
        "final_decision_accuracy": _ratio(
            sum(1 for result in results if result["final_decision"] == result["expected_final_decision"]),
            scenario_count,
        ),
        "trace_coverage": _ratio(sum(1 for result in results if result["trace_present"]), scenario_count),
        "claim_ledger_coverage": _ratio(
            sum(1 for result in results if result["claim_ledger_present"]),
            scenario_count,
        ),
        "verdict_ledger_coverage": _ratio(
            sum(1 for result in results if result["verdict_ledger_present"]),
            scenario_count,
        ),
        "claim_precision": _ratio(matched_claim_total, actual_claim_total),
        "claim_recall": _ratio(matched_claim_total, expected_claim_total),
        "unsupported_claim_recall": _ratio(unsupported_hits, unsupported_expected_total),
        "groundedness": _ratio(supported_with_evidence, supported_verdicts),
        "faithfulness": _ratio(supported_with_evidence, verdict_count),
        "false_positive_blocking": _ratio(
            sum(1 for result in expected_allow if result["final_decision"] not in ALLOW_DECISIONS),
            len(expected_allow),
        ),
        "critical_pass_through": _ratio(
            sum(1 for result in expected_non_allow if result["final_decision"] in ALLOW_DECISIONS),
            len(expected_non_allow),
        ),
        "p95_latency_ms": round(_percentile_95(result["latency_ms"] for result in results), 3),
        "cost_per_run_usd": round(
            sum(float(result["cost_usd"]) for result in results) / scenario_count
            if scenario_count
            else 0.0,
            6,
        ),
    }


def _metric_failures(metrics: dict[str, float | int]) -> list[str]:
    suite_config = load_suite_thresholds("smoke")
    return evaluate_thresholds(metrics, suite_config)


def _write_report(results: list[dict[str, Any]], metrics: dict[str, float | int]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps({"metrics": metrics, "scenarios": results}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _claim_text(claim: dict[str, Any]) -> str:
    text = claim.get("canonical_form") or claim.get("text") or ""
    return text if isinstance(text, str) else ""


def _normalize_claim(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().lower().rstrip(".").split())


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
