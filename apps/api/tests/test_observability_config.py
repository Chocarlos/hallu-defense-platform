from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from observability config test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_observability_config = importlib.import_module("scripts.ci.check_observability_config")
ObservabilityConfigError = check_observability_config.ObservabilityConfigError
load_current_config = check_observability_config.load_current_config
validate_observability_config = check_observability_config.validate_observability_config


def _current_inputs() -> dict[str, object]:
    return dict(load_current_config())


def test_observability_config_validates_current_repository() -> None:
    validate_observability_config(**_current_inputs())


def test_observability_config_rejects_missing_otel_file_exporter() -> None:
    inputs = _current_inputs()
    otel = copy.deepcopy(inputs["otel"])
    assert isinstance(otel, dict)
    exporters = otel["exporters"]
    assert isinstance(exporters, dict)
    exporters.pop("file")
    service = otel["service"]
    assert isinstance(service, dict)
    pipelines = service["pipelines"]
    assert isinstance(pipelines, dict)
    traces = pipelines["traces"]
    assert isinstance(traces, dict)
    traces["exporters"] = ["debug"]
    inputs["otel"] = otel

    with pytest.raises(ObservabilityConfigError, match="file"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_missing_compose_mount() -> None:
    inputs = _current_inputs()
    inputs["compose_text"] = str(inputs["compose_text"]).replace(
        "      - ./var/otel:/otel-output\n",
        "",
    )

    with pytest.raises(ObservabilityConfigError, match="var/otel:/otel-output"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_inline_prometheus_credentials() -> None:
    inputs = _current_inputs()
    prometheus = copy.deepcopy(inputs["prometheus_prod"])
    assert isinstance(prometheus, dict)
    scrape_configs = prometheus["scrape_configs"]
    assert isinstance(scrape_configs, list)
    scrape = scrape_configs[0]
    assert isinstance(scrape, dict)
    authorization = scrape["authorization"]
    assert isinstance(authorization, dict)
    authorization.pop("credentials_file")
    authorization["credentials"] = "not-allowed"
    inputs["prometheus_prod"] = prometheus

    with pytest.raises(ObservabilityConfigError, match="credentials_file"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_default_ci_live_script_wiring() -> None:
    inputs = _current_inputs()
    inputs["ci_workflow_text"] = (
        str(inputs["ci_workflow_text"]) + "\n      - run: python scripts/dev/live_otel_export_check.py\n"
    )

    with pytest.raises(ObservabilityConfigError, match="must not run live observability script"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_missing_makefile_target() -> None:
    inputs = _current_inputs()
    inputs["makefile_text"] = str(inputs["makefile_text"]).replace(
        "observability-config:\n\t$(PY) scripts/ci/check_observability_config.py\n\n",
        "",
    ).replace("observability-config ", "")

    with pytest.raises(ObservabilityConfigError, match="observability-config"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_missing_live_workflow_gate() -> None:
    inputs = _current_inputs()
    inputs["live_workflow_text"] = str(inputs["live_workflow_text"]).replace(
        'HALLU_DEFENSE_LIVE_OBSERVABILITY_SMOKE_ENABLED: "true"',
        'HALLU_DEFENSE_LIVE_OBSERVABILITY_SMOKE_ENABLED: "false"',
    )

    with pytest.raises(ObservabilityConfigError, match="LIVE_OBSERVABILITY"):
        validate_observability_config(**inputs)


def test_observability_config_rejects_missing_sensitive_attribute_assertions() -> None:
    inputs = _current_inputs()
    inputs["otel_export_check_text"] = str(inputs["otel_export_check_text"]).replace(
        "SENSITIVE_ATTRIBUTE_KEY_FRAGMENTS",
        "SAFE_ATTRIBUTE_KEY_FRAGMENTS",
    )

    with pytest.raises(ObservabilityConfigError, match="SENSITIVE_ATTRIBUTE_KEY_FRAGMENTS"):
        validate_observability_config(**inputs)
