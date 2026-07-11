from __future__ import annotations

import copy

import pytest

from scripts.ci.check_metrics_token_materializer import (
    MetricsTokenMaterializerConfigError,
    load_current_config,
    validate_metrics_token_materializer_config,
)


def _current_inputs() -> dict[str, object]:
    return dict(load_current_config())


def test_metrics_token_materializer_config_validates_current_repository() -> None:
    validate_metrics_token_materializer_config(**_current_inputs())


def test_gate_rejects_secret_source_that_bypasses_secret_manager() -> None:
    inputs = _current_inputs()
    inputs["cli_text"] = str(inputs["cli_text"]).replace(
        "create_secret_manager(settings)",
        'os.getenv("METRICS_TOKEN_VALUE")',
    )

    with pytest.raises(MetricsTokenMaterializerConfigError, match="SecretManager source"):
        validate_metrics_token_materializer_config(**inputs)


def test_gate_rejects_hardcoded_runtime_token_assignment() -> None:
    inputs = _current_inputs()
    inputs["core_text"] = (
        f"{inputs['core_text']}\nFALLBACK_TOKEN_VALUE = 'hardcoded-runtime-value'\n"
    )

    with pytest.raises(MetricsTokenMaterializerConfigError, match="hardcoded token value"):
        validate_metrics_token_materializer_config(**inputs)


def test_gate_rejects_prometheus_materializer_path_drift() -> None:
    inputs = _current_inputs()
    prometheus = copy.deepcopy(inputs["prometheus"])
    assert isinstance(prometheus, dict)
    scrape_configs = prometheus["scrape_configs"]
    assert isinstance(scrape_configs, list)
    scrape = scrape_configs[0]
    assert isinstance(scrape, dict)
    authorization = scrape["authorization"]
    assert isinstance(authorization, dict)
    authorization["credentials_file"] = "/run/secrets/different-file"
    inputs["prometheus"] = prometheus

    with pytest.raises(MetricsTokenMaterializerConfigError, match="credentials_file"):
        validate_metrics_token_materializer_config(**inputs)


def test_gate_requires_sidecar_and_systemd_documentation() -> None:
    inputs = _current_inputs()
    inputs["docs_text"] = str(inputs["docs_text"]).replace("systemd", "service-manager")

    with pytest.raises(MetricsTokenMaterializerConfigError, match="systemd"):
        validate_metrics_token_materializer_config(**inputs)


def test_gate_requires_makefile_target_and_security_wiring() -> None:
    inputs = _current_inputs()
    inputs["makefile_text"] = str(inputs["makefile_text"]).replace(
        "metrics-token-materializer-config:\n"
        "\t$(PY) scripts/ci/check_metrics_token_materializer.py\n\n",
        "",
    ).replace("metrics-token-materializer-config ", "")

    with pytest.raises(MetricsTokenMaterializerConfigError, match="Makefile must expose"):
        validate_metrics_token_materializer_config(**inputs)


def test_gate_requires_ci_and_security_workflow_wiring() -> None:
    inputs = _current_inputs()
    inputs["ci_workflow_text"] = str(inputs["ci_workflow_text"]).replace(
        "scripts/ci/check_metrics_token_materializer.py",
        "scripts/ci/not_the_materializer_gate.py",
    )

    with pytest.raises(MetricsTokenMaterializerConfigError, match="CI workflow"):
        validate_metrics_token_materializer_config(**inputs)
