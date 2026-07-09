from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
THRESHOLDS_PATH = ROOT / "evals" / "config" / "thresholds.json"

CATEGORY_FLOOR_KEY = "category_pass_rate_min"
CATEGORY_METRIC_KEY = "category_pass_rate"


class ThresholdConfigError(ValueError):
    pass


def load_thresholds(path: Path = THRESHOLDS_PATH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ThresholdConfigError(f"{path} must contain a JSON object")
    return payload


def suite_thresholds(config: Mapping[str, Any], suite: str) -> dict[str, Any]:
    suite_config = config.get(suite)
    if not isinstance(suite_config, dict):
        raise ThresholdConfigError(f"thresholds config missing '{suite}' section")
    return suite_config


def load_suite_thresholds(suite: str, path: Path = THRESHOLDS_PATH) -> dict[str, Any]:
    return suite_thresholds(load_thresholds(path), suite)


def evaluate_thresholds(
    metrics: Mapping[str, Any],
    suite_config: Mapping[str, Any],
) -> list[str]:
    """Compare computed eval metrics against configured min/max thresholds.

    Returns a list of human-readable failure strings; an empty list means the
    metrics satisfy every configured threshold, including the per-category
    floor applied to any ``category_pass_rate`` metric.
    """
    failures: list[str] = []
    minimums = suite_config.get("min")
    minimums = minimums if isinstance(minimums, Mapping) else {}
    maximums = suite_config.get("max")
    maximums = maximums if isinstance(maximums, Mapping) else {}

    for metric, floor in minimums.items():
        if metric == CATEGORY_FLOOR_KEY:
            continue
        failures.extend(_check_minimum(metrics, metric, floor))

    for metric, ceiling in maximums.items():
        failures.extend(_check_maximum(metrics, metric, ceiling))

    category_floor = minimums.get(CATEGORY_FLOOR_KEY)
    if category_floor is not None:
        failures.extend(_check_category_minimum(metrics, category_floor))

    return failures


def _check_minimum(metrics: Mapping[str, Any], metric: str, floor: Any) -> list[str]:
    if metric not in metrics:
        return [f"metric {metric} missing from computed metrics"]
    value = float(metrics[metric])
    if value < float(floor):
        return [f"metric {metric} expected >= {floor}, got {value}"]
    return []


def _check_maximum(metrics: Mapping[str, Any], metric: str, ceiling: Any) -> list[str]:
    if metric not in metrics:
        return [f"metric {metric} missing from computed metrics"]
    value = float(metrics[metric])
    if value > float(ceiling):
        return [f"metric {metric} expected <= {ceiling}, got {value}"]
    return []


def _check_category_minimum(metrics: Mapping[str, Any], floor: Any) -> list[str]:
    category_rates = metrics.get(CATEGORY_METRIC_KEY)
    if not isinstance(category_rates, Mapping) or not category_rates:
        return [f"metric {CATEGORY_METRIC_KEY} missing from computed metrics"]
    failures: list[str] = []
    for category in sorted(category_rates):
        rate = float(category_rates[category])
        if rate < float(floor):
            failures.append(
                f"category {category} pass_rate expected >= {floor}, got {rate}"
            )
    return failures
