from __future__ import annotations

from evals.runners import scenarios as scenarios_runner
from evals.runners import smoke as smoke_runner


def _passing_smoke_metrics() -> dict[str, float | int]:
    return {
        "final_decision_accuracy": 1.0,
        "trace_coverage": 1.0,
        "claim_ledger_coverage": 1.0,
        "verdict_ledger_coverage": 1.0,
        "claim_precision": 1.0,
        "claim_recall": 1.0,
        "unsupported_claim_recall": 1.0,
        "groundedness": 1.0,
        "faithfulness": 0.5,
        "false_positive_blocking": 0.0,
        "critical_pass_through": 0.0,
        "p95_latency_ms": 100.0,
        "cost_per_run_usd": 0.0,
    }


def test_smoke_metric_failures_empty_when_all_thresholds_met() -> None:
    assert smoke_runner._metric_failures(_passing_smoke_metrics()) == []


def test_smoke_metric_failures_reports_regression_below_floor() -> None:
    metrics = _passing_smoke_metrics()
    metrics["groundedness"] = 0.8

    failures = smoke_runner._metric_failures(metrics)

    assert any("groundedness" in failure for failure in failures)


def test_smoke_metric_failures_reports_latency_ceiling_breach() -> None:
    metrics = _passing_smoke_metrics()
    metrics["p95_latency_ms"] = 5_000.0

    failures = smoke_runner._metric_failures(metrics)

    assert any("p95_latency_ms" in failure for failure in failures)


def test_smoke_metric_failures_reports_false_positive_blocking_regression() -> None:
    metrics = _passing_smoke_metrics()
    metrics["false_positive_blocking"] = 0.25

    failures = smoke_runner._metric_failures(metrics)

    assert any("false_positive_blocking" in failure for failure in failures)


def _passing_scenario_metrics() -> dict[str, object]:
    return {
        "pass_rate": 1.0,
        "verification_decision_accuracy": 1.0,
        "blocked_high_risk_rate": 1.0,
        "secret_redaction_rate": 1.0,
        "prompt_injection_block_rate": 1.0,
        "data_poisoning_block_rate": 1.0,
        "tool_contradiction_guard_rate": 1.0,
        "repo_false_claim_block_rate": 1.0,
        "repo_semantic_claim_decision_accuracy": 1.0,
        "blocking_precision": 1.0,
        "sandbox_block_rate": 1.0,
        "category_pass_rate": {"documents": 1.0, "tools": 1.0, "sandbox": 1.0},
        "p95_latency_ms": 50.0,
    }


def test_scenario_metric_failures_empty_when_all_thresholds_met() -> None:
    assert scenarios_runner._metric_failures(_passing_scenario_metrics()) == []


def test_scenario_metric_failures_reports_guardrail_regression() -> None:
    metrics = _passing_scenario_metrics()
    metrics["secret_redaction_rate"] = 0.9

    failures = scenarios_runner._metric_failures(metrics)

    assert any("secret_redaction_rate" in failure for failure in failures)


def test_scenario_metric_failures_reports_category_regression() -> None:
    metrics = _passing_scenario_metrics()
    metrics["category_pass_rate"] = {"documents": 1.0, "tools": 0.75, "sandbox": 1.0}

    failures = scenarios_runner._metric_failures(metrics)

    assert any("category tools pass_rate" in failure for failure in failures)


def test_scenario_metric_failures_reports_pass_rate_regression() -> None:
    metrics = _passing_scenario_metrics()
    metrics["pass_rate"] = 0.95

    failures = scenarios_runner._metric_failures(metrics)

    assert any("pass_rate" in failure for failure in failures)


def test_scenario_metric_failures_reports_blocking_precision_regression() -> None:
    metrics = _passing_scenario_metrics()
    metrics["blocking_precision"] = 0.91

    failures = scenarios_runner._metric_failures(metrics)

    assert any("blocking_precision" in failure for failure in failures)
