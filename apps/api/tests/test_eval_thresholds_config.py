from __future__ import annotations

import copy

import pytest

from scripts.ci.check_eval_thresholds_config import (
    CI_WORKFLOW_PATH,
    EVALS_WORKFLOW_PATH,
    MAKEFILE_PATH,
    SCENARIOS_RUNNER_PATH,
    SMOKE_RUNNER_PATH,
    THRESHOLDS_PATH,
    EvalThresholdsConfigError,
    load_thresholds_config,
    validate_supporting_files,
    validate_thresholds_config,
)


def _supporting_texts() -> dict[str, str]:
    return {
        "smoke_runner_text": SMOKE_RUNNER_PATH.read_text(encoding="utf-8"),
        "scenarios_runner_text": SCENARIOS_RUNNER_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "evals_workflow_text": EVALS_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def test_eval_thresholds_config_validates_current_file() -> None:
    config = load_thresholds_config(THRESHOLDS_PATH)

    validate_thresholds_config(config)


def test_eval_thresholds_config_wiring_is_valid() -> None:
    validate_supporting_files(**_supporting_texts())


def test_eval_thresholds_config_rejects_weakened_min_floor() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    config["smoke"]["min"]["final_decision_accuracy"] = 0.9

    with pytest.raises(EvalThresholdsConfigError, match="smoke.min.final_decision_accuracy must be >= 1.0"):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_weakened_max_ceiling() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    config["scenarios"]["max"]["p95_latency_ms"] = 999_999.0

    with pytest.raises(EvalThresholdsConfigError, match="scenarios.max.p95_latency_ms must be <= 2500.0"):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_removed_min_metric() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    del config["smoke"]["min"]["groundedness"]

    with pytest.raises(EvalThresholdsConfigError, match="smoke.min.groundedness must be configured"):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_removed_category_floor() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    del config["scenarios"]["min"]["category_pass_rate_min"]

    with pytest.raises(
        EvalThresholdsConfigError, match="scenarios.min.category_pass_rate_min must be configured"
    ):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_weakened_blocking_precision_floor() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    config["scenarios"]["min"]["blocking_precision"] = 0.919

    with pytest.raises(
        EvalThresholdsConfigError,
        match=r"scenarios\.min\.blocking_precision must be >= 0\.92",
    ):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_wrong_schema_version() -> None:
    config = copy.deepcopy(load_thresholds_config(THRESHOLDS_PATH))
    config["schema_version"] = "eval-thresholds.v0"

    with pytest.raises(EvalThresholdsConfigError, match="schema_version must be eval-thresholds.v1"):
        validate_thresholds_config(config)


def test_eval_thresholds_config_rejects_missing_runner_wiring() -> None:
    texts = _supporting_texts()
    texts["smoke_runner_text"] = texts["smoke_runner_text"].replace("evals.runners.thresholds", "")

    with pytest.raises(EvalThresholdsConfigError, match="smoke.py must load thresholds"):
        validate_supporting_files(**texts)


def test_eval_thresholds_config_rejects_missing_ci_wiring() -> None:
    texts = _supporting_texts()
    texts["ci_workflow_text"] = texts["ci_workflow_text"].replace(
        "scripts/ci/check_eval_thresholds_config.py", ""
    )

    with pytest.raises(EvalThresholdsConfigError, match="CI workflow must run"):
        validate_supporting_files(**texts)


def test_eval_thresholds_config_rejects_missing_evals_workflow_wiring() -> None:
    texts = _supporting_texts()
    texts["evals_workflow_text"] = texts["evals_workflow_text"].replace(
        "scripts/ci/check_eval_thresholds_config.py", ""
    )

    with pytest.raises(EvalThresholdsConfigError, match="evals workflow must run"):
        validate_supporting_files(**texts)


def test_eval_thresholds_config_rejects_missing_api_source_path() -> None:
    texts = _supporting_texts()
    texts["evals_workflow_text"] = texts["evals_workflow_text"].replace(
        "PYTHONPATH: ${{ github.workspace }}/apps/api/src",
        "PYTHONPATH: apps/missing/src",
    )

    with pytest.raises(EvalThresholdsConfigError, match="API source through PYTHONPATH"):
        validate_supporting_files(**texts)


def test_eval_thresholds_config_rejects_missing_makefile_wiring() -> None:
    texts = _supporting_texts()
    texts["makefile_text"] = texts["makefile_text"].replace("eval-thresholds-config:", "")

    with pytest.raises(EvalThresholdsConfigError, match="Makefile must expose"):
        validate_supporting_files(**texts)
