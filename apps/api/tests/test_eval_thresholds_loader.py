from __future__ import annotations

from evals.runners.thresholds import (
    THRESHOLDS_PATH,
    ThresholdConfigError,
    evaluate_thresholds,
    load_suite_thresholds,
    load_thresholds,
    suite_thresholds,
)

import pytest


def test_thresholds_config_file_loads_smoke_and_scenario_suites() -> None:
    config = load_thresholds(THRESHOLDS_PATH)

    assert config["schema_version"] == "eval-thresholds.v1"
    smoke = suite_thresholds(config, "smoke")
    scenarios = suite_thresholds(config, "scenarios")
    assert "final_decision_accuracy" in smoke["min"]
    assert "groundedness" in smoke["min"]
    assert "faithfulness" in smoke["min"]
    assert "cost_per_run_usd" in smoke["max"]
    assert "category_pass_rate_min" in scenarios["min"]
    assert "blocked_high_risk_rate" in scenarios["min"]


def test_suite_thresholds_rejects_missing_suite() -> None:
    with pytest.raises(ThresholdConfigError, match="missing 'nonexistent' section"):
        suite_thresholds({"smoke": {}}, "nonexistent")


def test_load_suite_thresholds_reads_configured_suite() -> None:
    suite = load_suite_thresholds("smoke")

    assert suite["min"]["groundedness"] == 1.0


def test_evaluate_thresholds_passes_when_all_metrics_satisfy_config() -> None:
    suite_config = {
        "min": {"accuracy": 1.0},
        "max": {"p95_latency_ms": 2500.0},
    }
    metrics = {"accuracy": 1.0, "p95_latency_ms": 120.0}

    assert evaluate_thresholds(metrics, suite_config) == []


def test_evaluate_thresholds_flags_metric_below_minimum() -> None:
    suite_config = {"min": {"accuracy": 1.0}, "max": {}}
    metrics = {"accuracy": 0.9}

    failures = evaluate_thresholds(metrics, suite_config)

    assert failures == ["metric accuracy expected >= 1.0, got 0.9"]


def test_evaluate_thresholds_flags_metric_above_maximum() -> None:
    suite_config = {"min": {}, "max": {"p95_latency_ms": 100.0}}
    metrics = {"p95_latency_ms": 150.0}

    failures = evaluate_thresholds(metrics, suite_config)

    assert failures == ["metric p95_latency_ms expected <= 100.0, got 150.0"]


def test_evaluate_thresholds_flags_missing_metric() -> None:
    suite_config = {"min": {"accuracy": 1.0}, "max": {}}

    failures = evaluate_thresholds({}, suite_config)

    assert failures == ["metric accuracy missing from computed metrics"]


def test_evaluate_thresholds_flags_category_below_floor() -> None:
    suite_config = {"min": {"category_pass_rate_min": 1.0}, "max": {}}
    metrics = {"category_pass_rate": {"documents": 1.0, "tools": 0.5}}

    failures = evaluate_thresholds(metrics, suite_config)

    assert failures == ["category tools pass_rate expected >= 1.0, got 0.5"]


def test_evaluate_thresholds_flags_missing_category_metric() -> None:
    suite_config = {"min": {"category_pass_rate_min": 1.0}, "max": {}}

    failures = evaluate_thresholds({}, suite_config)

    assert failures == ["metric category_pass_rate missing from computed metrics"]
