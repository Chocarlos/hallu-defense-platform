from __future__ import annotations

import copy
import importlib
import os
import sys
from pathlib import Path

import pytest

import hallu_defense.config as config_module
from hallu_defense.config import (
    RUNTIME_ROLE_API,
    RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
    Settings,
    load_settings,
    validate_runtime_transport_settings,
)
from hallu_defense.services.eval_reports import (
    EvalReportRepository,
    create_eval_report_repository,
)
from hallu_defense.services.postgres import RecordingSqlProvider
from hallu_defense.services.providers import create_model_provider
from hallu_defense.services.secrets import EnvSecretManager


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from production profile test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_prod_profile_config = importlib.import_module("scripts.ci.check_prod_profile_config")
BASE_COMPOSE_PATH = check_prod_profile_config.BASE_COMPOSE_PATH
CI_WORKFLOW_PATH = check_prod_profile_config.CI_WORKFLOW_PATH
LIVE_WORKFLOW_PATH = check_prod_profile_config.LIVE_WORKFLOW_PATH
MAKEFILE_PATH = check_prod_profile_config.MAKEFILE_PATH
PROD_COMPOSE_PATH = check_prod_profile_config.PROD_COMPOSE_PATH
PROD_DOC_PATH = check_prod_profile_config.PROD_DOC_PATH
PROMETHEUS_PROD_PATH = check_prod_profile_config.PROMETHEUS_PROD_PATH
ProdProfileConfigError = check_prod_profile_config.ProdProfileConfigError
SECURITY_WORKFLOW_PATH = check_prod_profile_config.SECURITY_WORKFLOW_PATH
load_yaml_file = check_prod_profile_config.load_yaml_file
run_compose_config_if_available = check_prod_profile_config.run_compose_config_if_available
validate_prod_profile_config = check_prod_profile_config.validate_prod_profile_config


def _current_inputs() -> dict[str, object]:
    return {
        "base_compose": load_yaml_file(BASE_COMPOSE_PATH),
        "prod_compose": load_yaml_file(PROD_COMPOSE_PATH),
        "prometheus_prod": load_yaml_file(PROMETHEUS_PROD_PATH),
        "prod_doc_text": PROD_DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def _service_env(prod_compose: dict[str, object], service_name: str) -> dict[str, object]:
    services = prod_compose["services"]
    assert isinstance(services, dict)
    service = services[service_name]
    assert isinstance(service, dict)
    env = service["environment"]
    assert isinstance(env, dict)
    return env


def _api_env(prod_compose: dict[str, object]) -> dict[str, object]:
    return _service_env(prod_compose, "api")


def test_prod_profile_config_accepts_current_repository() -> None:
    validate_prod_profile_config(**_current_inputs())


def test_prod_profile_config_requires_opensearch_bootstrap_service() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    services = prod_compose["services"]
    assert isinstance(services, dict)
    services.pop("opensearch-bootstrap")
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="opensearch-bootstrap"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize("service_name", ["api", "ingestion-worker"])
def test_prod_profile_config_requires_successful_bootstrap_dependency(
    service_name: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    service = prod_compose["services"][service_name]  # type: ignore[index]
    assert isinstance(service, dict)
    dependencies = service["depends_on"]
    assert isinstance(dependencies, dict)
    dependency = dependencies["opensearch-bootstrap"]
    assert isinstance(dependency, dict)
    dependency["condition"] = "service_started"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(
        ProdProfileConfigError,
        match="service_completed_successfully",
    ):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_POSTGRES_DSN",
        "HALLU_DEFENSE_OIDC_JWKS_PATH",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND",
        "HALLU_DEFENSE_PROVIDER_BACKEND",
        "HALLU_DEFENSE_OTEL_ENDPOINT",
        "HALLU_DEFENSE_SANDBOX_BACKEND",
    ],
)
def test_prod_profile_bootstrap_rejects_unrelated_runtime_settings(
    setting: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "opensearch-bootstrap")[setting] = "forbidden"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="unrelated runtime configuration"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_RUNTIME_ROLE",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "HALLU_DEFENSE_VAULT_ADDR",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
    ],
)
def test_prod_profile_bootstrap_requires_minimal_environment(setting: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "opensearch-bootstrap").pop(setting)
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


def test_prod_profile_bootstrap_rejects_literal_vault_token() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "opensearch-bootstrap")["HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN"] = (
        "embedded-value"
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="unrelated runtime configuration"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "destination",
    [
        "/run/hallu-defense/vault/ca.crt:ro",
        "/run/hallu-defense/opensearch/ca.crt:ro",
    ],
)
def test_prod_profile_bootstrap_requires_only_ca_mounts(destination: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    service = prod_compose["services"]["opensearch-bootstrap"]  # type: ignore[index]
    assert isinstance(service, dict)
    volumes = service["volumes"]
    assert isinstance(volumes, list)
    service["volumes"] = [volume for volume in volumes if destination not in str(volume)]
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="volumes missing"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_bootstrap_uses_same_api_image_definition() -> None:
    inputs = _current_inputs()
    base_compose = copy.deepcopy(inputs["base_compose"])
    assert isinstance(base_compose, dict)
    service = base_compose["services"]["opensearch-bootstrap"]  # type: ignore[index]
    assert isinstance(service, dict)
    service["build"] = {"context": ".", "dockerfile": "other.Dockerfile"}
    inputs["base_compose"] = base_compose

    with pytest.raises(ProdProfileConfigError, match="exact API image"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_bootstrap_runs_packaged_cli() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    service = prod_compose["services"]["opensearch-bootstrap"]  # type: ignore[index]
    assert isinstance(service, dict)
    service["command"] = ["python", "-c", "pass"]
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="packaged template bootstrap CLI"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_memory_backends() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_AUDIT_LEDGER_BACKEND"] = "memory"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="memory/local backend"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_memory_eval_reports_backend() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_EVAL_REPORTS_BACKEND"] = "memory"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="EVAL_REPORTS_BACKEND"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_missing_or_mock_provider_backend() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_PROVIDER_BACKEND"] = "mock"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="PROVIDER_BACKEND|non-mock"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_OPA_ENABLED",
        "HALLU_DEFENSE_OPA_PATH",
        "HALLU_DEFENSE_OPA_POLICY_DIR",
    ],
)
def test_prod_profile_config_requires_fixed_opa_runtime(setting: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose).pop(setting)
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH",
    ],
)
def test_prod_profile_config_requires_runtime_security_settings(setting: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose).pop(setting)
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID",
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT_HTTPS",
    ],
)
def test_prod_profile_config_requires_kubernetes_interpolations(setting: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose).pop(setting)
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_local_worker_environment() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "ingestion-worker")["HALLU_DEFENSE_ENV"] = "local"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="ingestion-worker environment"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_literal_oidc_placeholder() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_OIDC_ISSUER"] = (
        "https://auth.example.invalid/realms/hallu-defense"
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="required interpolation"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_local_vault_service_in_merged_profile() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    services = prod_compose["services"]
    assert isinstance(services, dict)
    services["vault"] = {"image": "hashicorp/vault:1.17"}
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="local-only service vault"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_requires_api_environment_override() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    api = prod_compose["services"]["api"]  # type: ignore[index]
    assert isinstance(api, dict)
    api["environment"] = dict(_api_env(prod_compose))
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="environment must use Compose !override"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_requires_vault_token_on_worker() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "ingestion-worker").pop("HALLU_DEFENSE_VAULT_TOKEN_FILE")
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="VAULT_TOKEN_FILE"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_requires_logical_approval_commitment_secret() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose).pop("HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME")
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="COMMITMENT_SECRET_NAME"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_rejects_literal_top_level_secret_source() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    secrets = prod_compose["secrets"]
    assert isinstance(secrets, dict)
    runtime_token = secrets["hallu_runtime_vault_token"]
    assert isinstance(runtime_token, dict)
    runtime_token["file"] = "embedded-token"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="required host file interpolation"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_rejects_ignored_compose_secret_mode_claim() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    api = prod_compose["services"]["api"]  # type: ignore[index]
    assert isinstance(api, dict)
    mounts = api["secrets"]
    assert isinstance(mounts, list)
    first_mount = mounts[0]
    assert isinstance(first_mount, dict)
    first_mount["mode"] = 0o666
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="ownership/mode.*preflight"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_rejects_plaintext_runtime_secret_environment() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_RUNTIME_VAULT_TOKEN"] = "embedded"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="forbidden production configuration"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_AUTH_REQUIRED",
        "HALLU_DEFENSE_AUTH_CLAIMS_MODE",
        "HALLU_DEFENSE_OIDC_ISSUER",
        "HALLU_DEFENSE_OIDC_AUDIENCE",
        "HALLU_DEFENSE_OIDC_JWKS_PATH",
        "HALLU_DEFENSE_CORS_ALLOW_ORIGINS",
    ],
)
def test_prod_profile_worker_rejects_api_http_identity_settings(setting: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "ingestion-worker")[setting] = "forbidden"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="API-only credentials/config"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_opa_runtime_on_worker() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "ingestion-worker")["HALLU_DEFENSE_OPA_ENABLED"] = "true"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="API-only credentials/config"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_sandbox_credentials_on_worker() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, "ingestion-worker")["HALLU_DEFENSE_SANDBOX_BACKEND"] = "kubernetes"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="API-only credentials/config"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("read_only", False, "read_only"),
        ("cap_drop", [], "drop ALL"),
        ("security_opt", [], "no-new-privileges"),
        ("tmpfs", [], "tmpfs"),
    ],
)
def test_prod_profile_config_requires_hardened_api_runtime(
    field: str,
    value: object,
    message: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    services = prod_compose["services"]
    assert isinstance(services, dict)
    api = services["api"]
    assert isinstance(api, dict)
    api[field] = value
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=message):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_requires_worker_trust_mount_override() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    worker = prod_compose["services"]["ingestion-worker"]  # type: ignore[index]
    assert isinstance(worker, dict)
    worker["volumes"] = [".:/workspace:ro"]
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="Compose !override|volumes missing"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize("service_name", ["api", "ingestion-worker"])
def test_prod_profile_config_requires_hybrid_rag_backend(service_name: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, service_name)["HALLU_DEFENSE_RAG_INDEX_BACKEND"] = "pgvector"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="RAG_INDEX_BACKEND.*hybrid"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize("service_name", ["api", "ingestion-worker"])
@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
    ],
)
def test_prod_profile_config_requires_opensearch_interpolations(
    service_name: str,
    setting: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, service_name).pop(setting)
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize("service_name", ["api", "ingestion-worker"])
@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://search.example.test"),
        ("HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME", ""),
        (
            "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
            "Basic embedded-credential",
        ),
    ],
)
def test_prod_profile_config_rejects_unsafe_opensearch_values(
    service_name: str,
    setting: str,
    value: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, service_name)[setting] = value
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match=setting):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize("service_name", ["api", "ingestion-worker"])
@pytest.mark.parametrize(
    "setting",
    [
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION",
        "HALLU_DEFENSE_OPENSEARCH_PASSWORD",
        "HALLU_DEFENSE_OPENSEARCH_API_KEY",
    ],
)
def test_prod_profile_config_rejects_plaintext_opensearch_credential_env(
    service_name: str,
    setting: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _service_env(prod_compose, service_name)[setting] = "embedded-value"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="plaintext OpenSearch credential"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_runtime_rejects_unlisted_opensearch_origin() -> None:
    settings = Settings(
        environment="production",
        policy_version="test",
        auth_required=True,
        allowed_workspace=ROOT,
        max_command_seconds=30,
        max_output_chars=12000,
        secrets_backend="vault",
        vault_addr="https://vault.example.test",
        rag_index_backend="hybrid",
        postgres_dsn="postgresql://runtime@postgres/hallu",
        opensearch_endpoint="https://search.example.test",
        opensearch_authorization_secret_name="rag/opensearch/authorization",
        outbound_https_allowed_origins=("https://vault.example.test",),
    )

    with pytest.raises(
        config_module.RuntimeTransportConfigurationError,
        match="HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    ):
        validate_runtime_transport_settings(settings)


def test_prod_profile_runtime_backends_construct_without_fail_open_defaults() -> None:
    prod_compose = load_yaml_file(PROD_COMPOSE_PATH)
    assert isinstance(prod_compose, dict)
    env = _api_env(prod_compose)
    settings = Settings(
        environment=str(env["HALLU_DEFENSE_ENV"]),
        policy_version="test",
        auth_required=True,
        allowed_workspace=ROOT,
        max_command_seconds=30,
        max_output_chars=12000,
        provider_backend=str(env["HALLU_DEFENSE_PROVIDER_BACKEND"]),
        provider_model="verification-model",
        openai_compatible_base_url="https://llm.example.test/v1",
        openai_compatible_api_key_secret_name="providers/openai/api-key",
        secrets_backend="vault",
        vault_addr="https://vault.example.test",
        outbound_https_allowed_origins=(
            "https://vault.example.test",
            "https://llm.example.test",
        ),
        eval_reports_backend=str(env["HALLU_DEFENSE_EVAL_REPORTS_BACKEND"]),
    )

    validate_runtime_transport_settings(settings)
    provider = create_model_provider(settings, EnvSecretManager("TEST_"))
    repository = create_eval_report_repository(
        settings,
        sql_provider=RecordingSqlProvider(),
    )

    assert provider.provider_name == "openai-compatible"
    assert isinstance(repository, EvalReportRepository)


def test_prod_profile_config_rejects_unsigned_headers() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_AUTH_CLAIMS_MODE"] = "unsigned_headers"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="oidc_jwt"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_host_sandbox_backend() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_SANDBOX_BACKEND"] = "host"
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="host sandbox"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_docker_sandbox_and_socket() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_SANDBOX_BACKEND"] = "docker"
    services = prod_compose["services"]
    assert isinstance(services, dict)
    api = services["api"]
    assert isinstance(api, dict)
    volumes = api["volumes"]
    assert isinstance(volumes, list)
    volumes.append("/var/run/docker.sock:/var/run/docker.sock")
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="Kubernetes|Docker socket"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_direct_redis_url() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL"] = (
        "rediss://redis.example.test:6380/0"
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="forbidden production"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "destination",
    [
        "/run/hallu-defense/vault/ca.crt:ro",
        "/run/hallu-defense/opensearch/ca.crt:ro",
        "/run/hallu-defense/redis/ca.crt:ro",
        "/var/run/secrets/kubernetes.io/serviceaccount/token:ro",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt:ro",
    ],
)
def test_prod_profile_config_requires_read_only_trust_and_identity_mounts(
    destination: str,
) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    api = prod_compose["services"]["api"]  # type: ignore[index]
    assert isinstance(api, dict)
    volumes = api["volumes"]
    assert isinstance(volumes, list)
    api["volumes"] = [volume for volume in volumes if destination not in str(volume)]
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="volumes missing"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_requires_tenant_workspace_read_only_mount() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    api = prod_compose["services"]["api"]  # type: ignore[index]
    assert isinstance(api, dict)
    volumes = api["volumes"]
    assert isinstance(volumes, list)
    api["volumes"] = type(volumes)(
        str(volume).replace(":/workspace:ro", ":/workspace:rw") for volume in volumes
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="workspace:ro"):
        validate_prod_profile_config(**inputs)


@pytest.mark.parametrize(
    "destination",
    [
        "/run/hallu-defense/vault/ca.crt:ro",
        "/run/hallu-defense/opensearch/ca.crt:ro",
    ],
)
def test_prod_profile_config_requires_worker_ca_mounts(destination: str) -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    worker = prod_compose["services"]["ingestion-worker"]  # type: ignore[index]
    assert isinstance(worker, dict)
    volumes = worker["volumes"]
    assert isinstance(volumes, list)
    worker["volumes"] = [volume for volume in volumes if destination not in str(volume)]
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="volumes missing"):
        validate_prod_profile_config(**inputs)


def test_rendered_prod_api_environment_passes_real_settings_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prod_compose = load_yaml_file(PROD_COMPOSE_PATH)
    assert isinstance(prod_compose, dict)
    raw_env = _api_env(prod_compose)
    substitutions = {
        "HALLU_DEFENSE_OIDC_ISSUER": "https://auth.example.test/realms/hallu-defense",
        "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
        "HALLU_DEFENSE_CORS_ALLOW_ORIGINS": "https://console.example.test",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
            "https://vault.example.test,https://llm.example.test,"
            "https://otel.example.test,https://search.example.test"
        ),
        "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
        "HALLU_DEFENSE_PROVIDER_MODEL": "verification-model",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": ("rag/opensearch/authorization"),
        "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL": "https://llm.example.test/v1",
        "HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME": ("providers/openai/api-key"),
        "HALLU_DEFENSE_OTEL_ENDPOINT": "https://otel.example.test/v1/traces",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE": (
            "registry.example.test/sandbox@sha256:"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE": "hallu-sandbox",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME": "hallu-sandbox-workspace",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME": ("hallu-sandbox-deny-egress"),
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID": "tenant-compose",
        "KUBERNETES_SERVICE_HOST": "kubernetes.example.test",
        "KUBERNETES_SERVICE_PORT_HTTPS": "443",
    }
    rendered_env: dict[str, str] = {}
    for key, raw_value in raw_env.items():
        value = str(raw_value)
        if value.startswith("${") and ":?" in value:
            interpolation_name = value[2:].partition(":?")[0]
            value = substitutions[interpolation_name]
        rendered_env[key] = value

    policy_dir = tmp_path / "policies"
    workspace = tmp_path / "workspace"
    policy_dir.mkdir()
    workspace.mkdir()
    (policy_dir / "policy.rego").write_text("package fixture\n", encoding="utf-8")
    jwks_path = tmp_path / "jwks.json"
    vault_ca_path = tmp_path / "vault-ca.crt"
    redis_ca_path = tmp_path / "redis-ca.crt"
    opensearch_ca_path = tmp_path / "opensearch-ca.crt"
    postgres_ca_path = tmp_path / "postgres-ca.crt"
    vault_token_path = tmp_path / "vault-token"
    postgres_dsn_path = tmp_path / "postgres-dsn"
    jwks_path.write_text('{"keys": []}', encoding="utf-8")
    vault_ca_path.write_text("fixture-ca", encoding="utf-8")
    redis_ca_path.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca_path.write_text("fixture-ca", encoding="utf-8")
    postgres_ca_path.write_text("fixture-ca", encoding="utf-8")
    vault_token_path.write_text("runtime-fixture-value\n", encoding="utf-8")
    postgres_dsn_path.write_text(
        "postgresql://runtime_user:runtime_value@db.example.test:5432/runtime_db"
        f"?sslmode=verify-full&sslrootcert={postgres_ca_path.resolve().as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable\n",
        encoding="utf-8",
    )
    os.chmod(vault_token_path, 0o440)
    os.chmod(postgres_dsn_path, 0o440)
    rendered_env.update(
        {
            "HALLU_DEFENSE_OIDC_JWKS_PATH": str(jwks_path.resolve()),
            "HALLU_DEFENSE_VAULT_CA_CERT_PATH": str(vault_ca_path.resolve()),
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH": str(redis_ca_path.resolve()),
            "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": str(opensearch_ca_path.resolve()),
            "HALLU_DEFENSE_VAULT_TOKEN_FILE": str(vault_token_path.resolve()),
            "HALLU_DEFENSE_POSTGRES_DSN_FILE": str(postgres_dsn_path.resolve()),
            "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": str(postgres_ca_path.resolve()),
            "HALLU_DEFENSE_OPA_PATH": str(Path(sys.executable).resolve()),
            "HALLU_DEFENSE_OPA_POLICY_DIR": str(policy_dir.resolve()),
            "HALLU_DEFENSE_ALLOWED_WORKSPACE": str(workspace.resolve()),
        }
    )
    for key in tuple(os.environ):
        if key.startswith("HALLU_DEFENSE_") or key.startswith("KUBERNETES_SERVICE_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in rendered_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(config_module, "POSIX_OPA_PERMISSION_CHECKS", False)

    settings = load_settings(expected_runtime_role=RUNTIME_ROLE_API)

    assert settings.tool_validation_rate_limit_backend == "redis"
    assert settings.tool_validation_rate_limit_redis_url is None
    assert settings.sandbox_backend == "kubernetes"
    assert settings.opa_enabled is True
    assert settings.max_request_body_bytes == 1048576
    assert settings.rag_index_backend == "hybrid"
    assert settings.opensearch_endpoint == "https://search.example.test"


def test_rendered_prod_bootstrap_environment_passes_pinned_settings_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prod_compose = load_yaml_file(PROD_COMPOSE_PATH)
    assert isinstance(prod_compose, dict)
    raw_env = _service_env(prod_compose, "opensearch-bootstrap")
    substitutions = {
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
            "https://vault.example.test,https://search.example.test"
        ),
        "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": ("rag/opensearch/authorization"),
    }
    rendered_env: dict[str, str] = {}
    for key, raw_value in raw_env.items():
        value = str(raw_value)
        if value.startswith("${") and ":?" in value:
            interpolation_name = value[2:].partition(":?")[0]
            value = substitutions[interpolation_name]
        elif value == "${HALLU_DEFENSE_OPENSEARCH_INDEX_NAME:-hallu_evidence}":
            value = "hallu_evidence"
        rendered_env[key] = value

    vault_ca_path = tmp_path / "vault-ca.crt"
    opensearch_ca_path = tmp_path / "opensearch-ca.crt"
    vault_token_path = tmp_path / "vault-token"
    vault_ca_path.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca_path.write_text("fixture-ca", encoding="utf-8")
    vault_token_path.write_text("guard-value\n", encoding="utf-8")
    os.chmod(vault_token_path, 0o440)
    rendered_env["HALLU_DEFENSE_VAULT_CA_CERT_PATH"] = str(vault_ca_path)
    rendered_env["HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH"] = str(opensearch_ca_path)
    rendered_env["HALLU_DEFENSE_VAULT_TOKEN_FILE"] = str(vault_token_path)
    for key in tuple(os.environ):
        if key.startswith("HALLU_DEFENSE_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in rendered_env.items():
        monkeypatch.setenv(key, value)

    settings = load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)

    assert settings.runtime_role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    assert settings.rag_index_backend == "opensearch"
    assert settings.postgres_dsn is None
    assert settings.opensearch_endpoint == "https://search.example.test"
    assert settings.opensearch_authorization_secret_name == ("rag/opensearch/authorization")


def test_rendered_prod_worker_environment_is_minimal_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prod_compose = load_yaml_file(PROD_COMPOSE_PATH)
    assert isinstance(prod_compose, dict)
    raw_env = _service_env(prod_compose, "ingestion-worker")
    substitutions = {
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
            "https://vault.example.test,https://search.example.test"
        ),
        "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": ("rag/opensearch/authorization"),
    }
    rendered_env: dict[str, str] = {}
    for key, raw_value in raw_env.items():
        value = str(raw_value)
        if value.startswith("${") and ":?" in value:
            interpolation_name = value[2:].partition(":?")[0]
            value = substitutions[interpolation_name]
        elif value == "${HALLU_DEFENSE_OPENSEARCH_INDEX_NAME:-hallu_evidence}":
            value = "hallu_evidence"
        rendered_env[key] = value

    vault_ca_path = tmp_path / "vault-ca.crt"
    opensearch_ca_path = tmp_path / "opensearch-ca.crt"
    postgres_ca_path = tmp_path / "postgres-ca.crt"
    vault_token_path = tmp_path / "vault-token"
    postgres_dsn_path = tmp_path / "postgres-dsn"
    vault_ca_path.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca_path.write_text("fixture-ca", encoding="utf-8")
    postgres_ca_path.write_text("fixture-ca", encoding="utf-8")
    vault_token_path.write_text("guard-value\n", encoding="utf-8")
    postgres_dsn_path.write_text(
        "postgresql://worker@postgres.example.test/runtime"
        f"?sslmode=verify-full&sslrootcert={postgres_ca_path.resolve().as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable\n",
        encoding="utf-8",
    )
    os.chmod(vault_token_path, 0o440)
    os.chmod(postgres_dsn_path, 0o440)
    rendered_env["HALLU_DEFENSE_VAULT_CA_CERT_PATH"] = str(vault_ca_path)
    rendered_env["HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH"] = str(opensearch_ca_path)
    rendered_env["HALLU_DEFENSE_VAULT_TOKEN_FILE"] = str(vault_token_path)
    rendered_env["HALLU_DEFENSE_POSTGRES_DSN_FILE"] = str(postgres_dsn_path)
    rendered_env["HALLU_DEFENSE_POSTGRES_CA_CERT_PATH"] = str(postgres_ca_path.resolve())
    for key in tuple(os.environ):
        if key.startswith("HALLU_DEFENSE_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in rendered_env.items():
        monkeypatch.setenv(key, value)

    settings = load_settings(expected_runtime_role=config_module.RUNTIME_ROLE_WORKER)

    assert settings.runtime_role == config_module.RUNTIME_ROLE_WORKER
    assert settings.auth_required is False
    assert settings.oidc_issuer is None
    assert settings.metrics_bearer_token_secret_name == "observability/metrics-scrape-token"
    assert settings.provider_backend == "mock"
    assert settings.sandbox_backend == "docker"
    assert settings.rag_index_backend == "hybrid"


def test_prod_profile_config_rejects_default_credentials() -> None:
    inputs = _current_inputs()
    prod_compose = copy.deepcopy(inputs["prod_compose"])
    assert isinstance(prod_compose, dict)
    _api_env(prod_compose)["HALLU_DEFENSE_POSTGRES_DSN"] = (
        "postgresql://hallu:hallu@postgres:5432/hallu_defense"
    )
    inputs["prod_compose"] = prod_compose

    with pytest.raises(ProdProfileConfigError, match="default credential"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_rejects_inline_prometheus_credentials() -> None:
    inputs = _current_inputs()
    prometheus_prod = copy.deepcopy(inputs["prometheus_prod"])
    assert isinstance(prometheus_prod, dict)
    scrape_configs = prometheus_prod["scrape_configs"]
    assert isinstance(scrape_configs, list)
    scrape = scrape_configs[0]
    assert isinstance(scrape, dict)
    authorization = scrape["authorization"]
    assert isinstance(authorization, dict)
    authorization["credentials"] = "inline-token-value"
    inputs["prometheus_prod"] = prometheus_prod

    with pytest.raises(ProdProfileConfigError, match="inline credentials"):
        validate_prod_profile_config(**inputs)


def test_prod_profile_config_compose_config_skips_without_docker() -> None:
    result = run_compose_config_if_available(runner=("definitely-missing-docker", "compose"))

    assert result["status"] == "skipped"
    assert "docker-compose.prod.yml" in result["command"]
