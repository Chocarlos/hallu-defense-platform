from __future__ import annotations

import copy
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from hallu_defense.config import (
    RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
    RUNTIME_ROLE_WORKER,
    load_settings,
)


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


@pytest.mark.parametrize(
    ("service_name", "expected_role", "expected_backend"),
    [
        ("ingestion-worker", RUNTIME_ROLE_WORKER, "hybrid"),
        (
            "opensearch-bootstrap",
            RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
            "opensearch",
        ),
    ],
)
def test_local_compose_worker_and_bootstrap_env_pass_real_settings_loader(
    monkeypatch: pytest.MonkeyPatch,
    service_name: str,
    expected_role: str,
    expected_backend: str,
) -> None:
    compose = load_yaml_file(DOCKER_COMPOSE_PATH)
    services = compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    environment = service["environment"]
    assert isinstance(environment, dict)
    for key in tuple(os.environ):
        if key.startswith("HALLU_DEFENSE_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(str(key), str(value))

    settings = load_settings(expected_runtime_role=expected_role)

    assert settings.runtime_role == expected_role
    assert settings.rag_index_backend == expected_backend


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

    with pytest.raises(LocalRuntimeConfigError, match="must equal redis:7-alpine@sha256"):
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
    assert isinstance(depends_on, dict)
    depends_on.pop("opensearch-bootstrap")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="opensearch-bootstrap"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_successful_opensearch_bootstrap() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    worker = services["ingestion-worker"]
    assert isinstance(worker, dict)
    dependencies = worker["depends_on"]
    assert isinstance(dependencies, dict)
    bootstrap = dependencies["opensearch-bootstrap"]
    assert isinstance(bootstrap, dict)
    bootstrap["condition"] = "service_started"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="successful OpenSearch bootstrap"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_worker_runtime_dependencies() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    worker = services["ingestion-worker"]
    assert isinstance(worker, dict)
    environment = worker["environment"]
    assert isinstance(environment, dict)
    environment.pop("HALLU_DEFENSE_AUDIT_LEDGER_BACKEND")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="AUDIT_LEDGER_BACKEND"):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize(
    ("legacy_key", "legacy_value"),
    [
        ("plugins.security.disabled", "true"),
        ("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "legacy-local-password"),
    ],
)
def test_local_runtime_config_rejects_removed_opensearch_plugin_configuration(
    legacy_key: str,
    legacy_value: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    environment = opensearch["environment"]
    assert isinstance(environment, dict)
    environment[legacy_key] = legacy_value
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="removed plugin setting"):
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


def test_local_runtime_config_rejects_otel_pipeline_missing_file_exporter() -> None:
    inputs = _current_inputs()
    otel = copy.deepcopy(inputs["otel"])
    assert isinstance(otel, dict)
    service = otel["service"]
    assert isinstance(service, dict)
    pipelines = service["pipelines"]
    assert isinstance(pipelines, dict)
    traces = pipelines["traces"]
    assert isinstance(traces, dict)
    traces["exporters"] = ["debug"]
    inputs["otel"] = otel

    with pytest.raises(LocalRuntimeConfigError, match="file sink"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_otel_file_exporter_wrong_path() -> None:
    inputs = _current_inputs()
    otel = copy.deepcopy(inputs["otel"])
    assert isinstance(otel, dict)
    exporters = otel["exporters"]
    assert isinstance(exporters, dict)
    file_exporter = exporters["file"]
    assert isinstance(file_exporter, dict)
    file_exporter["path"] = "/tmp/spans.jsonl"
    inputs["otel"] = otel

    with pytest.raises(LocalRuntimeConfigError, match="/otel-output/spans.jsonl"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_otel_file_exporter_missing_rotation() -> None:
    inputs = _current_inputs()
    otel = copy.deepcopy(inputs["otel"])
    assert isinstance(otel, dict)
    exporters = otel["exporters"]
    assert isinstance(exporters, dict)
    file_exporter = exporters["file"]
    assert isinstance(file_exporter, dict)
    rotation = file_exporter["rotation"]
    assert isinstance(rotation, dict)
    rotation.pop("max_megabytes")
    inputs["otel"] = otel

    with pytest.raises(LocalRuntimeConfigError, match="rotation.max_megabytes"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_missing_otel_output_volume_mount() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    otel_collector = services["otel-collector"]
    assert isinstance(otel_collector, dict)
    volumes = otel_collector["volumes"]
    assert isinstance(volumes, list)
    volumes.remove("./var/otel:/otel-output")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="otel-output"):
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


def test_local_runtime_config_rejects_broken_ingestion_worker_command() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    worker = services["ingestion-worker"]
    assert isinstance(worker, dict)
    worker["command"] = ["python", "-m", "hallu_defense.main"]
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="ingestion-worker command"):
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

    with pytest.raises(LocalRuntimeConfigError, match="first-party Vault image"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_wrong_vault_dockerfile() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    vault = services["vault"]
    assert isinstance(vault, dict)
    vault["build"] = {"context": ".", "dockerfile": "infra/docker/api.Dockerfile"}
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="hardened Vault Dockerfile"):
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


def test_local_runtime_config_rejects_external_keycloak_image() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    keycloak = services["keycloak"]
    assert isinstance(keycloak, dict)
    keycloak["image"] = "quay.io/keycloak/keycloak:latest"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="first-party Keycloak image"):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize(
    ("service_name", "external_image", "expected_message"),
    [
        ("grafana", "grafana/grafana:13.1.0", "first-party Grafana image"),
        (
            "opensearch",
            "opensearchproject/opensearch:3.7.0",
            "first-party OpenSearch image",
        ),
        ("minio", "minio/minio:latest", "first-party SeaweedFS image"),
    ],
)
def test_local_runtime_config_rejects_external_hardened_service_images(
    service_name: str,
    external_image: str,
    expected_message: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    service["image"] = external_image
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match=expected_message):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize("service_name", ["grafana", "opensearch", "minio"])
def test_local_runtime_config_rejects_writable_hardened_services(
    service_name: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    service["read_only"] = False
    service["cap_drop"] = []
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="read-only|drop all"):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize("service_name", ["grafana", "opensearch", "minio", "keycloak"])
def test_local_runtime_config_rejects_weak_tmpfs_options(service_name: str) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    tmpfs = service["tmpfs"]
    assert isinstance(tmpfs, list)
    mount_path = str(tmpfs[0]).split(":", 1)[0]
    tmpfs[0] = f"{mount_path}:rw"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="exact hardened tmpfs"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_ephemeral_opensearch_config_mount() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    tmpfs = opensearch["tmpfs"]
    assert isinstance(tmpfs, list)
    opensearch["tmpfs"] = [
        value for value in tmpfs if "/usr/share/opensearch/config:" not in str(value)
    ]
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="exact hardened tmpfs.*config"):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize(
    "java_opts",
    [
        "-Xms512m -Xmx512m",
        (
            "-Xms512m -Xmx512m "
            "-Dorg.bouncycastle.native.cpu_variant=java "
            "-Dorg.bouncycastle.native.cpu_variant=native"
        ),
    ],
)
def test_local_runtime_config_requires_opensearch_java_only_crypto(
    java_opts: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    environment = opensearch["environment"]
    assert isinstance(environment, dict)
    environment["OPENSEARCH_JAVA_OPTS"] = java_opts
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="Bouncy Castle Java"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_requires_opensearch_transport_loopback() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    environment = opensearch["environment"]
    assert isinstance(environment, dict)
    environment["transport.host"] = "0.0.0.0"
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="transport.*loopback"):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("privileged", True, "must not be privileged"),
        ("cap_add", ["SYS_ADMIN"], "must not set cap_add"),
        ("pid", "host", "must not override pid"),
        ("network_mode", "host", "must not override network_mode"),
        (
            "security_opt",
            ["no-new-privileges:true", "seccomp=unconfined"],
            "only no-new-privileges",
        ),
    ],
)
def test_local_runtime_config_rejects_privilege_reintroduction(
    key: str,
    value: object,
    message: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    opensearch = services["opensearch"]
    assert isinstance(opensearch, dict)
    opensearch[key] = value
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match=message):
        validate_local_runtime_config(**inputs)


@pytest.mark.parametrize(
    ("service_name", "user"),
    [("grafana", "0:0"), ("opensearch", "0:0"), ("minio", "0:0")],
)
def test_local_runtime_config_rejects_root_user_override(
    service_name: str,
    user: str,
) -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    service["user"] = user
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="user override"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_runtime_overlay_and_docker_socket() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    grafana = services["grafana"]
    assert isinstance(grafana, dict)
    volumes = grafana["volumes"]
    assert isinstance(volumes, list)
    volumes.append("/var/run/docker.sock:/var/run/docker.sock")
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="volumes.*hardened allowlist"):
        validate_local_runtime_config(**inputs)


def test_local_runtime_config_rejects_seaweedfs_without_precreated_buckets() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    services = compose["services"]
    assert isinstance(services, dict)
    minio = services["minio"]
    assert isinstance(minio, dict)
    minio["command"] = ["mini", "-dir=/data", "-s3.port=9000"]
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="approved S3 contract"):
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


def test_local_runtime_config_rejects_writable_keycloak() -> None:
    inputs = _current_inputs()
    compose = copy.deepcopy(inputs["compose"])
    assert isinstance(compose, dict)
    services = compose["services"]
    assert isinstance(services, dict)
    keycloak = services["keycloak"]
    assert isinstance(keycloak, dict)
    keycloak["read_only"] = False
    keycloak["cap_drop"] = []
    inputs["compose"] = compose

    with pytest.raises(LocalRuntimeConfigError, match="read-only|drop all"):
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
