from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from local runtime config test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_local_runtime_config = importlib.import_module("scripts.ci.check_local_runtime_config")
CI_WORKFLOW_PATH = check_local_runtime_config.CI_WORKFLOW_PATH
DOCKER_COMPOSE_PATH = check_local_runtime_config.DOCKER_COMPOSE_PATH
KEYCLOAK_REALM_PATH = check_local_runtime_config.KEYCLOAK_REALM_PATH
GRAFANA_DASHBOARD_PROVIDER_PATH = check_local_runtime_config.GRAFANA_DASHBOARD_PROVIDER_PATH
GRAFANA_DATASOURCE_PATH = check_local_runtime_config.GRAFANA_DATASOURCE_PATH
LocalRuntimeConfigError = check_local_runtime_config.LocalRuntimeConfigError
MAKEFILE_PATH = check_local_runtime_config.MAKEFILE_PATH
OTEL_CONFIG_PATH = check_local_runtime_config.OTEL_CONFIG_PATH
PROMETHEUS_CONFIG_PATH = check_local_runtime_config.PROMETHEUS_CONFIG_PATH
load_yaml_file = check_local_runtime_config.load_yaml_file
validate_local_runtime_config = check_local_runtime_config.validate_local_runtime_config


def _current_inputs() -> dict[str, object]:
    return {
        "compose": load_yaml_file(DOCKER_COMPOSE_PATH),
        "prometheus": load_yaml_file(PROMETHEUS_CONFIG_PATH),
        "otel": load_yaml_file(OTEL_CONFIG_PATH),
        "grafana_datasource_text": GRAFANA_DATASOURCE_PATH.read_text(encoding="utf-8"),
        "grafana_dashboard_provider_text": GRAFANA_DASHBOARD_PROVIDER_PATH.read_text(
            encoding="utf-8"
        ),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def test_local_runtime_config_accepts_current_repository() -> None:
    validate_local_runtime_config(**_current_inputs())


def test_local_runtime_config_rejects_missing_required_service() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    services.pop("minio")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="minio"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_latest_images() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    redis = services["redis"]
    assert isinstance(redis, dict)
    redis["image"] = "redis:latest"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="latest"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_missing_api_dependency() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    api = services["api"]
    assert isinstance(api, dict)
    depends_on = api["depends_on"]
    assert isinstance(depends_on, list)
    depends_on.remove("opensearch")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="opensearch"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_opensearch_initial_password() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    environment = opensearch["environment"]
    assert isinstance(environment, dict)
    environment.pop("OPENSEARCH_INITIAL_ADMIN_PASSWORD")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="initial admin password"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_broken_prometheus_scrape_target() -> None:
    inputs = _current_inputs()
    prometheus = copy.deepcopy(inputs["prometheus"])
    assert isinstance(prometheus, dict)
    scrape_configs = prometheus["scrape_configs"]
    assert isinstance(scrape_configs, list)
    static_configs = scrape_configs[0]["static_configs"]
    assert isinstance(static_configs, list)
    static_configs[0]["targets"] = ["localhost:8000"]
    inputs["prometheus"] = prometheus

    with pytest.raises(LocalRuntimeConfigError, match="api:8000"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_broken_otel_pipeline() -> None:
    inputs = _current_inputs()
    otel = copy.deepcopy(inputs["otel"])
    assert isinstance(otel, dict)
    service = otel["service"]
    assert isinstance(service, dict)
    pipelines = service["pipelines"]
    assert isinstance(pipelines, dict)
    traces = pipelines["traces"]
    assert isinstance(traces, dict)
    traces["exporters"] = []
    inputs["otel"] = otel

    with pytest.raises(LocalRuntimeConfigError, match="debug"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_broken_grafana_provisioning() -> None:
    inputs = _current_inputs()
    inputs["grafana_datasource_text"] = str(inputs["grafana_datasource_text"]).replace(
        "url: http://prometheus:9090",
        "url: http://localhost:9090",
    )

    with pytest.raises(LocalRuntimeConfigError, match="prometheus:9090"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_makefile_and_ci_wiring() -> None:
    inputs = _current_inputs()
    inputs["makefile_text"] = str(inputs["makefile_text"]).replace(
        "local-runtime-config:\n\t$(PY) scripts/ci/check_local_runtime_config.py\n",
        "",
    )
    inputs["ci_workflow_text"] = str(inputs["ci_workflow_text"]).replace(
        "python scripts/ci/check_local_runtime_config.py",
        "python scripts/ci/missing_local_runtime_config.py",
    )

    with pytest.raises(LocalRuntimeConfigError, match="local-runtime-config"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_missing_keycloak_service() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    services.pop("keycloak")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="keycloak"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_missing_vault_service() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    services.pop("vault")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="vault"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_vault_latest_image() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    vault = services["vault"]
    assert isinstance(vault, dict)
    vault["image"] = "hashicorp/vault:latest"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="latest"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_vault_without_dev_mode() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    vault = services["vault"]
    assert isinstance(vault, dict)
    vault["command"] = ["server"]
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="dev mode"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_keycloak_latest_image() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    keycloak = services["keycloak"]
    assert isinstance(keycloak, dict)
    keycloak["image"] = "quay.io/keycloak/keycloak:latest"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="latest"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_keycloak_command_without_import_realm() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    keycloak = services["keycloak"]
    assert isinstance(keycloak, dict)
    keycloak["command"] = ["start-dev"]
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="import-realm"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_keycloak_realm_missing_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    realm = json.loads(KEYCLOAK_REALM_PATH.read_text(encoding="utf-8"))
    realm["roles"]["realm"] = [
        role for role in realm["roles"]["realm"] if role["name"] != "eval_publisher"
    ]
    mutated = tmp_path / "realm-hallu-defense.json"
    mutated.write_text(json.dumps(realm), encoding="utf-8")
    monkeypatch.setattr(check_local_runtime_config, "KEYCLOAK_REALM_PATH", mutated)

    with pytest.raises(LocalRuntimeConfigError, match="eval_publisher"):
        validate_local_runtime_config(**_current_inputs())


def test_local_runtime_config_rejects_keycloak_realm_with_embedded_pem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    realm = json.loads(KEYCLOAK_REALM_PATH.read_text(encoding="utf-8"))
    # Build the PEM header from fragments so the test source never itself
    # matches the secret_scan private-key pattern.
    realm["description"] = "-----" + "BEGIN"
    mutated = tmp_path / "realm-hallu-defense.json"
    mutated.write_text(json.dumps(realm), encoding="utf-8")
    monkeypatch.setattr(check_local_runtime_config, "KEYCLOAK_REALM_PATH", mutated)

    with pytest.raises(LocalRuntimeConfigError, match="PEM"):
        validate_local_runtime_config(**_current_inputs())
