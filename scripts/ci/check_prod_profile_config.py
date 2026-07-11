from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE_PATH = ROOT / "docker-compose.yml"
PROD_COMPOSE_PATH = ROOT / "docker-compose.prod.yml"
PROMETHEUS_PROD_PATH = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
PROD_DOC_PATH = ROOT / "docs" / "deployment" / "production-profile.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"
SECRET_PREFLIGHT_PATH = ROOT / "scripts" / "dev" / "preflight_runtime_secret_files.py"
POSTGRES_TLS_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "postgres_tls.py"

PROMETHEUS_METRICS_CREDENTIALS_FILE = "/run/secrets/hallu_defense_metrics_bearer_token"
COMPOSE_CONFIG_COMMAND = (
    "docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet"
)

REQUIRED_API_FIXED_ENV = {
    "HALLU_DEFENSE_ENV": "production",
    "HALLU_DEFENSE_AUTH_REQUIRED": "true",
    "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES": "1048576",
    "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS": "15",
    "HALLU_DEFENSE_AUTH_CLAIMS_MODE": "oidc_jwt",
    "HALLU_DEFENSE_OIDC_JWKS_PATH": "/run/hallu-defense/keycloak-jwks.json",
    "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
    "HALLU_DEFENSE_VAULT_MOUNT": "secret",
    "HALLU_DEFENSE_VAULT_TOKEN_FILE": "/run/secrets/hallu_defense_vault_token",
    "HALLU_DEFENSE_VAULT_CA_CERT_PATH": "/run/hallu-defense/vault/ca.crt",
    "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME": "observability/metrics-scrape-token",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND": "redis",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS": "120",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS": "60",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME": (
        "quotas/tool-validation/redis-url"
    ),
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS": "1",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH": (
        "/run/hallu-defense/redis/ca.crt"
    ),
    "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
    "HALLU_DEFENSE_POSTGRES_DSN_FILE": "/run/secrets/hallu_defense_postgres_dsn",
    "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": "/run/hallu-defense/postgres/ca.crt",
    "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND": "postgres",
    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME": (
        "approvals/tool-call-commitment-key"
    ),
    "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
    "HALLU_DEFENSE_EVAL_REPORTS_BACKEND": "postgres",
    "HALLU_DEFENSE_PROVIDER_BACKEND": "openai-compatible",
    "HALLU_DEFENSE_OPA_ENABLED": "true",
    "HALLU_DEFENSE_OPA_PATH": "/usr/local/bin/opa",
    "HALLU_DEFENSE_OPA_POLICY_DIR": "/app/infra/opa/policies",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "hybrid",
    "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": ("/run/hallu-defense/opensearch/ca.crt"),
    "HALLU_DEFENSE_INGESTION_MODE": "async",
    "HALLU_DEFENSE_OTEL_ENABLED": "true",
    "HALLU_DEFENSE_OTEL_EXPORTER": "otlp",
    "HALLU_DEFENSE_SANDBOX_BACKEND": "kubernetes",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH": "/workspace",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS": "0.25",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_JOB_TTL_SECONDS": "60",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_API_REQUEST_TIMEOUT_SECONDS": "5",
    "HALLU_DEFENSE_ALLOWED_WORKSPACE": "/workspace",
}
REQUIRED_API_INTERPOLATED_ENV = {
    "HALLU_DEFENSE_OIDC_ISSUER",
    "HALLU_DEFENSE_OIDC_AUDIENCE",
    "HALLU_DEFENSE_CORS_ALLOW_ORIGINS",
    "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
    "HALLU_DEFENSE_VAULT_ADDR",
    "HALLU_DEFENSE_PROVIDER_MODEL",
    "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL",
    "HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
    "HALLU_DEFENSE_OTEL_ENDPOINT",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT_HTTPS",
}
REQUIRED_CONSOLE_FIXED_ENV = {
    "HALLU_DEFENSE_ENV": "production",
    "HALLU_DEFENSE_CONSOLE_AUTH_MODE": "oidc",
    "HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM": "tenant_id",
    "HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM": "roles",
    "HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES": (
        "verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator"
    ),
}
REQUIRED_CONSOLE_INTERPOLATED_ENV = {
    "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN",
    "HALLU_DEFENSE_CONSOLE_API_ORIGIN",
    "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER",
    "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID",
    "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE",
}
REQUIRED_WORKER_FIXED_ENV = {
    "HALLU_DEFENSE_ENV": "production",
    "HALLU_DEFENSE_RUNTIME_ROLE": "worker",
    "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
    "HALLU_DEFENSE_VAULT_MOUNT": "secret",
    "HALLU_DEFENSE_VAULT_TOKEN_FILE": "/run/secrets/hallu_defense_vault_token",
    "HALLU_DEFENSE_VAULT_CA_CERT_PATH": "/run/hallu-defense/vault/ca.crt",
    "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME": (
        "observability/metrics-scrape-token"
    ),
    "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
    "HALLU_DEFENSE_POSTGRES_DSN_FILE": "/run/secrets/hallu_defense_postgres_dsn",
    "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": "/run/hallu-defense/postgres/ca.crt",
    "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "hybrid",
    "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": ("/run/hallu-defense/opensearch/ca.crt"),
    "HALLU_DEFENSE_INGESTION_MODE": "async",
    "HALLU_DEFENSE_INGESTION_WORKER_ID": "compose-production-ingestion-worker",
    "HALLU_DEFENSE_INGESTION_WORKER_POLL_SECONDS": "2",
    "HALLU_DEFENSE_INGESTION_WORKER_BATCH_SIZE": "10",
}
REQUIRED_WORKER_INTERPOLATED_ENV = {
    "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
    "HALLU_DEFENSE_VAULT_ADDR",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
}
REQUIRED_BOOTSTRAP_FIXED_ENV = {
    "HALLU_DEFENSE_ENV": "production",
    "HALLU_DEFENSE_RUNTIME_ROLE": "opensearch-bootstrap",
    "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
    "HALLU_DEFENSE_VAULT_MOUNT": "secret",
    "HALLU_DEFENSE_VAULT_TOKEN_FILE": "/run/secrets/hallu_defense_vault_token",
    "HALLU_DEFENSE_VAULT_CA_CERT_PATH": "/run/hallu-defense/vault/ca.crt",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
    "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS": "5",
    "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": ("/run/hallu-defense/opensearch/ca.crt"),
}
REQUIRED_BOOTSTRAP_INTERPOLATED_ENV = {
    "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
    "HALLU_DEFENSE_VAULT_ADDR",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
}
BOOTSTRAP_INDEX_NAME_ENV = "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME"
BOOTSTRAP_INDEX_NAME_INTERPOLATION = (
    "${HALLU_DEFENSE_OPENSEARCH_INDEX_NAME:-hallu_evidence}"
)
FORBIDDEN_WORKER_ENV = {
    "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV",
    "HALLU_DEFENSE_POSTGRES_DSN",
    "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN",
    "HALLU_DEFENSE_AUTH_REQUIRED",
    "HALLU_DEFENSE_AUTH_CLAIMS_MODE",
    "HALLU_DEFENSE_OIDC_ISSUER",
    "HALLU_DEFENSE_OIDC_AUDIENCE",
    "HALLU_DEFENSE_OIDC_JWKS_PATH",
    "HALLU_DEFENSE_CORS_ALLOW_ORIGINS",
    "HALLU_DEFENSE_PROVIDER_BACKEND",
    "HALLU_DEFENSE_PROVIDER_MODEL",
    "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL",
    "HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME",
    "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND",
    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
    "HALLU_DEFENSE_EVAL_REPORTS_BACKEND",
    "HALLU_DEFENSE_OTEL_ENDPOINT",
    "HALLU_DEFENSE_OPA_ENABLED",
    "HALLU_DEFENSE_OPA_PATH",
    "HALLU_DEFENSE_OPA_POLICY_DIR",
    "HALLU_DEFENSE_SANDBOX_BACKEND",
    "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PATH",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT_HTTPS",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL",
}
ALLOWED_OPENSEARCH_SECRET_NAME_ENV = (
    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME"
)
OPENSEARCH_PLAINTEXT_CREDENTIAL_MARKERS = frozenset(
    {"AUTHORIZATION", "PASSWORD", "USERNAME", "API_KEY", "TOKEN", "CREDENTIAL"}
)
FORBIDDEN_API_ENV = {
    "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV",
    "HALLU_DEFENSE_POSTGRES_DSN",
    "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN",
    "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PATH",
    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL",
}
LOCAL_ONLY_SERVICES = {
    "prometheus",
    "grafana",
    "otel-collector",
    "postgres",
    "opensearch",
    "redis",
    "minio",
    "keycloak",
    "vault",
}
DEFAULT_CREDENTIAL_MARKERS = {
    "hallu:hallu",
    "minioadmin",
    "change-me",
    "local-dev-only",
    "admin:admin",
    "dev-root",
}


class ProdProfileConfigError(ValueError):
    pass


class ComposeResetScalar:
    def __init__(self, value: object) -> None:
        self.value = value


class ComposeResetSequence(list[object]):
    pass


class ComposeOverrideMapping(dict[str, object]):
    pass


class ComposeOverrideSequence(list[object]):
    pass


class ComposeYamlLoader(yaml.SafeLoader):
    pass


def _construct_compose_reset(loader: ComposeYamlLoader, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        raw = loader.construct_scalar(node)
        value = None if raw.strip().lower() in {"", "null", "~"} else raw
        return ComposeResetScalar(value)
    if isinstance(node, yaml.SequenceNode):
        return ComposeResetSequence(loader.construct_sequence(node, deep=True))
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    raise ProdProfileConfigError("Unsupported Compose !reset YAML node")


def _construct_compose_override(loader: ComposeYamlLoader, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return ComposeOverrideMapping(loader.construct_mapping(node, deep=True))
    if isinstance(node, yaml.SequenceNode):
        return ComposeOverrideSequence(loader.construct_sequence(node, deep=True))
    return loader.construct_scalar(node)


ComposeYamlLoader.add_constructor("!reset", _construct_compose_reset)
ComposeYamlLoader.add_constructor("!override", _construct_compose_override)


def load_yaml_file(path: Path) -> Mapping[str, object]:
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeYamlLoader)
    if not isinstance(loaded, Mapping):
        raise ProdProfileConfigError(
            f"{path.relative_to(ROOT)} must contain a YAML object"
        )
    return loaded


def validate_prod_profile_config(
    *,
    base_compose: Mapping[str, object],
    prod_compose: Mapping[str, object],
    prometheus_prod: Mapping[str, object],
    prod_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_base_and_overlay_parse(base_compose, prod_compose, errors)
    _validate_file_backed_secrets(prod_compose, errors)
    _validate_api_overlay(prod_compose, errors)
    _validate_prometheus_config(prometheus_prod, errors)
    _validate_no_default_credentials(prod_compose, errors)
    _validate_supporting_files(
        prod_doc_text=prod_doc_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        live_workflow_text=live_workflow_text,
        errors=errors,
    )
    if errors:
        raise ProdProfileConfigError("\n".join(errors))


def _validate_file_backed_secrets(
    prod_compose: Mapping[str, object],
    errors: list[str],
) -> None:
    secrets = _mapping(prod_compose.get("secrets"), "prod top-level secrets", errors)
    expected_files = {
        "hallu_runtime_vault_token": "${HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE:?set the runtime Vault token file path}",
        "hallu_bootstrap_vault_token": "${HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE:?set the bootstrap Vault token file path}",
        "hallu_runtime_postgres_dsn": "${HALLU_DEFENSE_POSTGRES_DSN_FILE:?set the runtime PostgreSQL DSN file path}",
        "hallu_migrations_postgres_dsn": "${HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE:?set the migration PostgreSQL DSN file path}",
    }
    if set(secrets) != set(expected_files):
        errors.append(
            "prod profile must declare exactly four file-backed runtime secrets"
        )
        return
    for name, expected_file in expected_files.items():
        definition = _mapping(secrets.get(name), f"prod secret {name}", errors)
        if definition != {"file": expected_file}:
            errors.append(
                f"prod secret {name} must use its required host file interpolation"
            )
    try:
        preflight_text = SECRET_PREFLIGHT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"runtime secret-file preflight could not be read: {exc}")
        return
    for marker in (
        "SECRET_FILE_ENVIRONMENTS",
        "EXPECTED_OWNER_UID = 0",
        "EXPECTED_READER_GID = 10001",
        "EXPECTED_MODE = 0o440",
        "EXPECTED_PARENT_MODE = 0o750",
        "path.lstat()",
        "_validate_secret_parent_chain",
        "read_runtime_secret_file",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH",
        "validate_postgres_tls_inputs",
        "validate_postgres_tls",
    ):
        if marker not in preflight_text:
            errors.append(f"runtime secret-file preflight missing `{marker}`")
    try:
        postgres_tls_text = POSTGRES_TLS_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"PostgreSQL TLS policy could not be read: {exc}")
        return
    for marker in (
        "sslmode=verify-full",
        "ssl_min_protocol_version=TLSv1.3",
        "gssencmode=disable",
        "sslrootcert",
        "KIND_POSTGRES_HOST",
        "kind_insecure_tls_enabled",
    ):
        if marker not in postgres_tls_text:
            errors.append(f"PostgreSQL TLS policy missing `{marker}`")


def _validate_service_secret_mounts(
    service: Mapping[str, object],
    *,
    service_label: str,
    expected_sources: tuple[str, ...],
    errors: list[str],
) -> None:
    raw_mounts = service.get("secrets")
    if not isinstance(raw_mounts, Sequence) or isinstance(raw_mounts, str):
        errors.append(f"prod {service_label} must mount file-backed Compose secrets")
        return
    mounts = [mount for mount in raw_mounts if isinstance(mount, Mapping)]
    if len(mounts) != len(raw_mounts):
        errors.append(f"prod {service_label} secret mounts must be objects")
        return
    if tuple(str(mount.get("source", "")) for mount in mounts) != expected_sources:
        errors.append(f"prod {service_label} has incorrect secret sources")
    expected_targets = (
        ("hallu_defense_vault_token", "hallu_defense_postgres_dsn")
        if len(expected_sources) == 2
        else ("hallu_defense_postgres_dsn",)
        if expected_sources == ("hallu_migrations_postgres_dsn",)
        else ("hallu_defense_vault_token",)
    )
    for mount, expected_target in zip(mounts, expected_targets, strict=True):
        if mount.get("target") != expected_target or set(mount) != {"source", "target"}:
            errors.append(
                f"prod {service_label} secret {expected_target} must be a plain file bind; "
                "host ownership/mode is enforced by preflight"
            )


def run_compose_config_if_available(
    *,
    runner: Sequence[str] = ("docker", "compose"),
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    executable = shutil.which(runner[0])
    if executable is None:
        return {
            "status": "skipped",
            "reason": f"{runner[0]} executable is unavailable",
            "command": COMPOSE_CONFIG_COMMAND,
        }

    compose_env = dict(os.environ)
    if env is not None:
        compose_env.update(env)
    compose_env.update(
        {
            "HALLU_DEFENSE_OIDC_ISSUER": "https://auth.example.test/realms/hallu-defense",
            "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
            "HALLU_DEFENSE_CORS_ALLOW_ORIGINS": "https://console.example.test",
            "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN": "https://console.example.test",
            "HALLU_DEFENSE_CONSOLE_API_ORIGIN": "https://api.example.test",
            "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER": (
                "https://auth.example.test/realms/hallu-defense"
            ),
            "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID": "hallu-defense-console",
            "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE": "hallu-defense-api",
            "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
                "https://vault.example.test,https://llm.example.test,"
                "https://otel.example.test,https://search.example.test"
            ),
            "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
            "HALLU_DEFENSE_VAULT_CA_CERT_HOST_PATH": "./var/vault/ca.crt",
            "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH": "./var/postgres/ca.crt",
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_HOST_PATH": (
                "./var/redis/ca.crt"
            ),
            "HALLU_DEFENSE_OPENSEARCH_CA_CERT_HOST_PATH": ("./var/opensearch/ca.crt"),
            "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE": "./var/secrets/runtime-vault-token",
            "HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE": (
                "./var/secrets/bootstrap-vault-token"
            ),
            "HALLU_DEFENSE_POSTGRES_DSN_FILE": "./var/secrets/runtime-postgres-dsn",
            "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE": (
                "./var/secrets/migrations-postgres-dsn"
            ),
            "HALLU_DEFENSE_PROVIDER_MODEL": "verification-model",
            "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL": "https://llm.example.test/v1",
            "HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME": (
                "providers/openai/api-key"
            ),
            "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
            "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": (
                "rag/opensearch/authorization"
            ),
            "HALLU_DEFENSE_OTEL_ENDPOINT": "https://otel.example.test/v1/traces",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE": (
                "registry.example.test/hallu-defense-sandbox@sha256:"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE": "hallu-sandbox",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME": "hallu-sandbox-workspace",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME": (
                "hallu-sandbox-deny-egress"
            ),
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID": "tenant-compose",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_TOKEN_HOST_PATH": (
                "./var/kubernetes/serviceaccount/token"
            ),
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_CA_HOST_PATH": (
                "./var/kubernetes/serviceaccount/ca.crt"
            ),
            "KUBERNETES_SERVICE_HOST": "kubernetes.example.test",
            "KUBERNETES_SERVICE_PORT_HTTPS": "443",
            "HALLU_DEFENSE_OIDC_JWKS_FILE": "./var/keycloak/jwks.json",
            "HALLU_DEFENSE_ALLOWED_WORKSPACE_HOST": ".",
        }
    )
    result = subprocess.run(
        [
            executable,
            *runner[1:],
            "-f",
            str(BASE_COMPOSE_PATH),
            "-f",
            str(PROD_COMPOSE_PATH),
            "config",
            "--quiet",
        ],
        cwd=ROOT,
        env=compose_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ProdProfileConfigError(
            "docker compose base+prod config failed: "
            + (
                result.stderr.strip()
                or result.stdout.strip()
                or f"exit {result.returncode}"
            )
        )
    services_result = subprocess.run(
        [
            executable,
            *runner[1:],
            "-f",
            str(BASE_COMPOSE_PATH),
            "-f",
            str(PROD_COMPOSE_PATH),
            "config",
            "--services",
        ],
        cwd=ROOT,
        env=compose_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if services_result.returncode != 0:
        raise ProdProfileConfigError(
            "docker compose could not enumerate merged production services: "
            + (
                services_result.stderr.strip()
                or services_result.stdout.strip()
                or f"exit {services_result.returncode}"
            )
        )
    merged_services = {
        line.strip() for line in services_result.stdout.splitlines() if line.strip()
    }
    unexpected_local_services = LOCAL_ONLY_SERVICES & merged_services
    if unexpected_local_services:
        raise ProdProfileConfigError(
            "merged production Compose still contains local-only services: "
            + ", ".join(sorted(unexpected_local_services))
        )
    if merged_services != {
        "api",
        "console",
        "ingestion-worker",
        "opensearch-bootstrap",
        "postgres-migrations",
    }:
        raise ProdProfileConfigError(
            "merged production Compose services must be api, console, "
            "ingestion-worker, opensearch-bootstrap, and postgres-migrations"
        )
    return {
        "status": "passed",
        "command": COMPOSE_CONFIG_COMMAND,
        "services": sorted(merged_services),
    }


def _validate_base_and_overlay_parse(
    base_compose: Mapping[str, object],
    prod_compose: Mapping[str, object],
    errors: list[str],
) -> None:
    base_services = _mapping(
        base_compose.get("services"), "docker-compose.yml services", errors
    )
    prod_services = _mapping(
        prod_compose.get("services"), "docker-compose.prod.yml services", errors
    )
    for service_name in {
        "api",
        "console",
        "ingestion-worker",
        "opensearch-bootstrap",
        *LOCAL_ONLY_SERVICES,
    }:
        if service_name not in base_services:
            errors.append(f"base compose missing service {service_name}")
    for service_name in (
        "api",
        "ingestion-worker",
        "opensearch-bootstrap",
        "postgres-migrations",
        "console",
    ):
        if service_name not in prod_services:
            errors.append(f"prod compose overlay missing service {service_name}")
    for service_name in LOCAL_ONLY_SERVICES:
        reset = prod_services.get(service_name)
        if not isinstance(reset, ComposeResetScalar) or reset.value is not None:
            errors.append(
                f"prod compose must remove local-only service {service_name} with !reset null"
            )
    console = _mapping(prod_services.get("console"), "prod console service", errors)
    console_env = _mapping(
        console.get("environment"), "prod console environment", errors
    )
    if not isinstance(console_env, ComposeOverrideMapping):
        errors.append(
            "prod console environment must use Compose !override to prevent local fixture inheritance"
        )
    _validate_production_runtime_environment(
        console_env,
        service_label="console",
        fixed=REQUIRED_CONSOLE_FIXED_ENV,
        interpolated=REQUIRED_CONSOLE_INTERPOLATED_ENV,
        errors=errors,
    )
    forbidden_console_env = {
        key
        for key in console_env
        if str(key).startswith("NEXT_PUBLIC_")
        or str(key).startswith("HALLU_DEFENSE_CONSOLE_ALLOW_")
        or str(key).startswith("HALLU_DEFENSE_CONSOLE_LOCAL_")
    }
    if forbidden_console_env:
        errors.append(
            "prod console contains build-time or unsigned local configuration: "
            + ", ".join(sorted(str(key) for key in forbidden_console_env))
        )
    _validate_hardened_service(console, service_label="console", errors=errors)
    console_tmpfs = _string_sequence(console.get("tmpfs"), "prod console tmpfs", errors)
    if not any(
        mount.startswith("/app/apps/console/.next/cache:")
        and {"rw", "noexec", "nosuid", "nodev"}.issubset(
            set(mount.partition(":")[2].split(","))
        )
        for mount in console_tmpfs
    ):
        errors.append(
            "prod console must use a bounded hardened tmpfs for the Next cache"
        )
    api = _mapping(base_services.get("api"), "base api service", errors)
    bootstrap = _mapping(
        base_services.get("opensearch-bootstrap"),
        "base opensearch-bootstrap service",
        errors,
    )
    if bootstrap.get("build") != api.get("build"):
        errors.append(
            "base opensearch-bootstrap must use the exact API image build definition"
        )


def _validate_api_overlay(
    prod_compose: Mapping[str, object], errors: list[str]
) -> None:
    services = _mapping(
        prod_compose.get("services"), "docker-compose.prod.yml services", errors
    )
    api = _mapping(services.get("api"), "prod api service", errors)
    env = _mapping(api.get("environment"), "prod api environment", errors)
    if not isinstance(env, ComposeOverrideMapping):
        errors.append(
            "prod api environment must use Compose !override to prevent base-env inheritance"
        )
    _validate_production_runtime_environment(
        env,
        service_label="api",
        fixed=REQUIRED_API_FIXED_ENV,
        interpolated=REQUIRED_API_INTERPOLATED_ENV,
        errors=errors,
    )
    _validate_opensearch_environment(env, service_label="api", errors=errors)
    unexpected_api_env = FORBIDDEN_API_ENV & set(env)
    if unexpected_api_env:
        errors.append(
            "prod api contains forbidden production configuration: "
            + ", ".join(sorted(unexpected_api_env))
        )
    _validate_hardened_service(api, service_label="api", errors=errors)
    _validate_service_secret_mounts(
        api,
        service_label="api",
        expected_sources=("hallu_runtime_vault_token", "hallu_runtime_postgres_dsn"),
        errors=errors,
    )

    worker = _mapping(
        services.get("ingestion-worker"), "prod ingestion-worker service", errors
    )
    worker_env = _mapping(
        worker.get("environment"),
        "prod ingestion-worker environment",
        errors,
    )
    if not isinstance(worker_env, ComposeOverrideMapping):
        errors.append(
            "prod ingestion-worker environment must use Compose !override to prevent base-env inheritance"
        )
    _validate_production_runtime_environment(
        worker_env,
        service_label="ingestion-worker",
        fixed=REQUIRED_WORKER_FIXED_ENV,
        interpolated=REQUIRED_WORKER_INTERPOLATED_ENV,
        errors=errors,
    )
    _validate_opensearch_environment(
        worker_env,
        service_label="ingestion-worker",
        errors=errors,
    )
    _validate_hardened_service(worker, service_label="ingestion-worker", errors=errors)
    _validate_service_secret_mounts(
        worker,
        service_label="ingestion-worker",
        expected_sources=("hallu_runtime_vault_token", "hallu_runtime_postgres_dsn"),
        errors=errors,
    )
    unexpected_worker_env = FORBIDDEN_WORKER_ENV & set(worker_env)
    if unexpected_worker_env:
        errors.append(
            "prod ingestion-worker must not receive API-only credentials/config: "
            + ", ".join(sorted(unexpected_worker_env))
        )

    _validate_bootstrap_dependency(api, service_label="api", errors=errors)

    raw_api_volumes = api.get("volumes")
    if not isinstance(raw_api_volumes, ComposeOverrideSequence):
        errors.append("prod api volumes must use Compose !override")
    api_volumes = _string_sequence(raw_api_volumes, "prod api volumes", errors)
    for marker in (
        "${HALLU_DEFENSE_OIDC_JWKS_FILE:?",
        ":/run/hallu-defense/keycloak-jwks.json:ro",
        "${HALLU_DEFENSE_VAULT_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/vault/ca.crt:ro",
        "${HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/postgres/ca.crt:ro",
        "${HALLU_DEFENSE_OPENSEARCH_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/opensearch/ca.crt:ro",
        "${HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_HOST_PATH:?",
        ":/run/hallu-defense/redis/ca.crt:ro",
        "${HALLU_DEFENSE_ALLOWED_WORKSPACE_HOST:?",
        ":/workspace:ro",
        "${HALLU_DEFENSE_SANDBOX_KUBERNETES_TOKEN_HOST_PATH:?",
        ":/var/run/secrets/kubernetes.io/serviceaccount/token:ro",
        "${HALLU_DEFENSE_SANDBOX_KUBERNETES_CA_HOST_PATH:?",
        ":/var/run/secrets/kubernetes.io/serviceaccount/ca.crt:ro",
    ):
        if not any(marker in volume for volume in api_volumes):
            errors.append(f"prod api volumes missing required marker {marker}")
    if any("docker.sock" in volume for volume in api_volumes):
        errors.append("prod api must not mount the root-equivalent Docker socket")

    _validate_bootstrap_dependency(
        worker,
        service_label="ingestion-worker",
        errors=errors,
    )
    raw_worker_volumes = worker.get("volumes")
    if not isinstance(raw_worker_volumes, ComposeOverrideSequence):
        errors.append("prod ingestion-worker volumes must use Compose !override")
    worker_volumes = _string_sequence(
        raw_worker_volumes,
        "prod ingestion-worker volumes",
        errors,
    )
    for marker in (
        "${HALLU_DEFENSE_VAULT_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/vault/ca.crt:ro",
        "${HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/postgres/ca.crt:ro",
        "${HALLU_DEFENSE_OPENSEARCH_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/opensearch/ca.crt:ro",
    ):
        if not any(marker in volume for volume in worker_volumes):
            errors.append(
                f"prod ingestion-worker volumes missing required marker {marker}"
            )
    if len(worker_volumes) != 3:
        errors.append(
            "prod ingestion-worker volumes must contain only the Vault, PostgreSQL, and OpenSearch CA mounts"
        )
    _validate_opensearch_bootstrap_overlay(services, errors)
    _validate_postgres_migrations_overlay(services, errors)


def _validate_bootstrap_dependency(
    service: Mapping[str, object],
    *,
    service_label: str,
    errors: list[str],
) -> None:
    raw_dependencies = service.get("depends_on")
    if not isinstance(raw_dependencies, ComposeOverrideMapping):
        errors.append(f"prod {service_label} depends_on must use Compose !override")
    dependencies = _mapping(
        raw_dependencies,
        f"prod {service_label} depends_on",
        errors,
    )
    if set(dependencies) != {"opensearch-bootstrap", "postgres-migrations"}:
        errors.append(
            f"prod {service_label} must depend only on bootstrap and migrations"
        )
        return
    bootstrap_dependency = _mapping(
        dependencies.get("opensearch-bootstrap"),
        f"prod {service_label} opensearch-bootstrap dependency",
        errors,
    )
    if bootstrap_dependency.get("condition") != "service_completed_successfully":
        errors.append(
            f"prod {service_label} must wait for opensearch-bootstrap "
            "service_completed_successfully"
        )
    migration_dependency = _mapping(
        dependencies.get("postgres-migrations"),
        f"prod {service_label} postgres-migrations dependency",
        errors,
    )
    if migration_dependency.get("condition") != "service_completed_successfully":
        errors.append(
            f"prod {service_label} must wait for postgres-migrations "
            "service_completed_successfully"
        )


def _validate_postgres_migrations_overlay(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    migrations = _mapping(
        services.get("postgres-migrations"),
        "prod postgres-migrations service",
        errors,
    )
    env = _mapping(
        migrations.get("environment"),
        "prod postgres-migrations environment",
        errors,
    )
    if not isinstance(env, ComposeOverrideMapping):
        errors.append("prod postgres-migrations environment must use Compose !override")
    if env != {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE": "/run/secrets/hallu_defense_postgres_dsn",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": "/run/hallu-defense/postgres/ca.crt",
    }:
        errors.append(
            "prod postgres-migrations must read only its scoped migration DSN file"
        )
    _validate_service_secret_mounts(
        migrations,
        service_label="postgres-migrations",
        expected_sources=("hallu_migrations_postgres_dsn",),
        errors=errors,
    )
    dependencies = _mapping(
        migrations.get("depends_on"),
        "prod postgres-migrations depends_on",
        errors,
    )
    if not isinstance(migrations.get("depends_on"), ComposeOverrideMapping):
        errors.append("prod postgres-migrations depends_on must use Compose !override")
    if set(dependencies) != {"opensearch-bootstrap"}:
        errors.append(
            "prod postgres-migrations must depend only on opensearch-bootstrap"
        )
    bootstrap = _mapping(
        dependencies.get("opensearch-bootstrap"),
        "prod postgres-migrations bootstrap dependency",
        errors,
    )
    if bootstrap.get("condition") != "service_completed_successfully":
        errors.append(
            "prod postgres-migrations must wait for successful OpenSearch bootstrap"
        )
    _validate_hardened_service(
        migrations,
        service_label="postgres-migrations",
        errors=errors,
    )
    if migrations.get("restart") != "no":
        errors.append("prod postgres-migrations must remain a restart:no one-shot")
    raw_volumes = migrations.get("volumes")
    migration_volumes = _string_sequence(
        raw_volumes,
        "prod postgres-migrations volumes",
        errors,
    )
    expected_ca_mount = (
        "${HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH:?set the host PostgreSQL CA file path}:"
        "/run/hallu-defense/postgres/ca.crt:ro"
    )
    if not isinstance(raw_volumes, ComposeOverrideSequence) or migration_volumes != (
        expected_ca_mount,
    ):
        errors.append(
            "prod postgres-migrations must mount only the managed PostgreSQL CA read-only"
        )
    if "build" in migrations or "image" in migrations:
        errors.append("prod postgres-migrations must inherit the API image")


def _validate_opensearch_bootstrap_overlay(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    bootstrap = _mapping(
        services.get("opensearch-bootstrap"),
        "prod opensearch-bootstrap service",
        errors,
    )
    env = _mapping(
        bootstrap.get("environment"),
        "prod opensearch-bootstrap environment",
        errors,
    )
    if not isinstance(env, ComposeOverrideMapping):
        errors.append(
            "prod opensearch-bootstrap environment must use Compose !override"
        )
    for key, expected in REQUIRED_BOOTSTRAP_FIXED_ENV.items():
        if env.get(key) != expected:
            errors.append(
                f"prod opensearch-bootstrap environment {key} must be {expected}"
            )
    for key in REQUIRED_BOOTSTRAP_INTERPOLATED_ENV:
        value = env.get(key)
        expected_prefix = f"${{{key}:?"
        if not isinstance(value, str) or not value.startswith(expected_prefix):
            errors.append(
                f"prod opensearch-bootstrap environment {key} must use required "
                f"interpolation {expected_prefix}...}}"
            )
    if env.get(BOOTSTRAP_INDEX_NAME_ENV) != BOOTSTRAP_INDEX_NAME_INTERPOLATION:
        errors.append(
            "prod opensearch-bootstrap environment OPENSEARCH_INDEX_NAME must use "
            "the bounded hallu_evidence default interpolation"
        )
    allowed_env = (
        set(REQUIRED_BOOTSTRAP_FIXED_ENV)
        | REQUIRED_BOOTSTRAP_INTERPOLATED_ENV
        | {BOOTSTRAP_INDEX_NAME_ENV}
    )
    unexpected_env = set(env) - allowed_env
    if unexpected_env:
        errors.append(
            "prod opensearch-bootstrap contains unrelated runtime configuration: "
            + ", ".join(sorted(str(key) for key in unexpected_env))
        )
    _validate_opensearch_environment(
        env,
        service_label="opensearch-bootstrap",
        errors=errors,
    )
    _validate_hardened_service(
        bootstrap,
        service_label="opensearch-bootstrap",
        errors=errors,
    )
    _validate_service_secret_mounts(
        bootstrap,
        service_label="opensearch-bootstrap",
        expected_sources=("hallu_bootstrap_vault_token",),
        errors=errors,
    )

    command = _string_sequence(
        bootstrap.get("command"),
        "prod opensearch-bootstrap command",
        errors,
    )
    if not isinstance(bootstrap.get("command"), ComposeOverrideSequence):
        errors.append("prod opensearch-bootstrap command must use Compose !override")
    if command != (
        "python",
        "/app/scripts/dev/bootstrap_opensearch_template.py",
    ):
        errors.append(
            "prod opensearch-bootstrap must run the packaged template bootstrap CLI"
        )
    if "build" in bootstrap or "image" in bootstrap:
        errors.append(
            "prod opensearch-bootstrap must inherit the exact API image definition"
        )
    if bootstrap.get("restart") != "no":
        errors.append("prod opensearch-bootstrap must set restart: no")
    if not _is_empty_compose_reset(bootstrap.get("depends_on")):
        errors.append(
            "prod opensearch-bootstrap depends_on must reset local OpenSearch dependencies"
        )

    raw_volumes = bootstrap.get("volumes")
    if not isinstance(raw_volumes, ComposeOverrideSequence):
        errors.append("prod opensearch-bootstrap volumes must use Compose !override")
    volumes = _string_sequence(
        raw_volumes,
        "prod opensearch-bootstrap volumes",
        errors,
    )
    for marker in (
        "${HALLU_DEFENSE_VAULT_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/vault/ca.crt:ro",
        "${HALLU_DEFENSE_OPENSEARCH_CA_CERT_HOST_PATH:?",
        ":/run/hallu-defense/opensearch/ca.crt:ro",
    ):
        if not any(marker in volume for volume in volumes):
            errors.append(
                f"prod opensearch-bootstrap volumes missing required marker {marker}"
            )
    if len(volumes) != 2:
        errors.append(
            "prod opensearch-bootstrap volumes must contain only the Vault and "
            "OpenSearch CA mounts"
        )


def _validate_opensearch_environment(
    env: Mapping[str, object],
    *,
    service_label: str,
    errors: list[str],
) -> None:
    for key in env:
        normalized_key = str(key).upper()
        if not normalized_key.startswith("HALLU_DEFENSE_OPENSEARCH_"):
            continue
        if normalized_key == ALLOWED_OPENSEARCH_SECRET_NAME_ENV:
            continue
        if any(
            marker in normalized_key
            for marker in OPENSEARCH_PLAINTEXT_CREDENTIAL_MARKERS
        ):
            errors.append(
                f"prod {service_label} must not contain plaintext OpenSearch credential env {key}"
            )


def _validate_hardened_service(
    service: Mapping[str, object],
    *,
    service_label: str,
    errors: list[str],
) -> None:
    if service.get("read_only") is not True:
        errors.append(f"prod {service_label} must set read_only: true")
    cap_drop = _string_sequence(
        service.get("cap_drop"),
        f"prod {service_label} cap_drop",
        errors,
    )
    if "ALL" not in cap_drop:
        errors.append(f"prod {service_label} must drop ALL Linux capabilities")
    security_opt = _string_sequence(
        service.get("security_opt"),
        f"prod {service_label} security_opt",
        errors,
    )
    if "no-new-privileges:true" not in security_opt:
        errors.append(f"prod {service_label} must set no-new-privileges:true")
    tmpfs = _string_sequence(
        service.get("tmpfs"),
        f"prod {service_label} tmpfs",
        errors,
    )
    required_tmp_options = {"rw", "noexec", "nosuid", "nodev"}
    tmp_mount = next((item for item in tmpfs if item.startswith("/tmp:")), None)
    tmp_options = set(tmp_mount.partition(":")[2].split(",")) if tmp_mount else set()
    if not required_tmp_options.issubset(tmp_options):
        errors.append(
            f"prod {service_label} must mount /tmp as rw,noexec,nosuid,nodev tmpfs"
        )


def _validate_production_runtime_environment(
    env: Mapping[str, object],
    *,
    service_label: str,
    fixed: Mapping[str, str],
    interpolated: set[str],
    errors: list[str],
) -> None:
    for key, expected in fixed.items():
        if env.get(key) != expected:
            errors.append(f"prod {service_label} environment {key} must be {expected}")
    for key in interpolated:
        value = env.get(key)
        expected_prefix = f"${{{key}:?"
        if not isinstance(value, str) or not value.startswith(expected_prefix):
            errors.append(
                f"prod {service_label} environment {key} must use required interpolation "
                f"{expected_prefix}...}}"
            )

    for backend_key in {
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND",
        "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND",
        "HALLU_DEFENSE_EVAL_REPORTS_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
    } & set(env):
        if str(env.get(backend_key, "")).lower() in {"memory", "local", "jsonl"}:
            errors.append(
                f"production {service_label} must not use memory/local backend for {backend_key}"
            )
    if service_label == "api":
        if str(env.get("HALLU_DEFENSE_AUTH_CLAIMS_MODE", "")).lower() != "oidc_jwt":
            errors.append("production api must use oidc_jwt and never unsigned headers")
        provider_backend = str(env.get("HALLU_DEFENSE_PROVIDER_BACKEND", "")).lower()
        if provider_backend in {"", "mock"}:
            errors.append(
                f"production {service_label} must configure a non-mock provider backend"
            )
        if str(env.get("HALLU_DEFENSE_SANDBOX_BACKEND", "")).lower() != "kubernetes":
            errors.append("production api must use the Kubernetes sandbox backend")
        jwks_path = str(env.get("HALLU_DEFENSE_OIDC_JWKS_PATH", ""))
        if not jwks_path.startswith("/run/") or "jwks" not in jwks_path:
            errors.append("production profile must use a mounted JWKS path")
    if str(env.get("HALLU_DEFENSE_SANDBOX_BACKEND", "")).lower() == "host":
        errors.append(f"production {service_label} must not use host sandbox backend")


def _is_empty_compose_reset(value: object) -> bool:
    return isinstance(value, ComposeResetSequence) and not value


def _validate_prometheus_config(
    prometheus_prod: Mapping[str, object],
    errors: list[str],
) -> None:
    scrape_configs = _sequence(
        prometheus_prod.get("scrape_configs"), "prometheus prod scrape_configs", errors
    )
    api_scrape = None
    for scrape in scrape_configs:
        candidate = _mapping(scrape, "prometheus prod scrape_config", errors)
        if candidate.get("job_name") == "hallu-defense-api":
            api_scrape = candidate
            break
    if api_scrape is None:
        errors.append("prometheus.prod.yml missing hallu-defense-api scrape job")
        return
    auth = _mapping(
        api_scrape.get("authorization"), "prometheus prod authorization", errors
    )
    if auth.get("type") != "Bearer":
        errors.append("prometheus prod scrape must use Bearer authorization")
    if auth.get("credentials_file") != PROMETHEUS_METRICS_CREDENTIALS_FILE:
        errors.append("prometheus prod scrape must read JWT from credentials_file")
    if "credentials" in auth:
        errors.append("prometheus prod scrape must not inline credentials")


def _validate_no_default_credentials(
    value: object, errors: list[str], path: str = "prod compose"
) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            _validate_no_default_credentials(nested, errors, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, str):
        for index, nested in enumerate(value):
            _validate_no_default_credentials(nested, errors, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for marker in DEFAULT_CREDENTIAL_MARKERS:
        if marker in lowered:
            errors.append(f"{path} contains default credential marker {marker!r}")


def _validate_supporting_files(
    *,
    prod_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_prod_profile_config.py"
    for marker in (
        "docker-compose.prod.yml",
        COMPOSE_CONFIG_COMMAND,
        "skips when Docker is unavailable",
        "scripts/dev/export_keycloak_jwks.py",
        "HALLU_DEFENSE_INGESTION_MODE=async",
        "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES=1048576",
        "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS=15",
        "HALLU_DEFENSE_PROVIDER_BACKEND=openai-compatible",
        "HALLU_DEFENSE_EVAL_REPORTS_BACKEND=postgres",
        "HALLU_DEFENSE_OPA_ENABLED=true",
        "HALLU_DEFENSE_OPA_PATH=/usr/local/bin/opa",
        "HALLU_DEFENSE_OPA_POLICY_DIR=/app/infra/opa/policies",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH=/run/hallu-defense/vault/ca.crt",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND=hybrid",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH=/run/hallu-defense/opensearch/ca.crt",
        "HALLU_DEFENSE_RUNTIME_ROLE=opensearch-bootstrap",
        "python /app/scripts/dev/bootstrap_opensearch_template.py",
        "service_completed_successfully",
        "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH",
        "sslmode=verify-full",
        "ssl_min_protocol_version=TLSv1.3",
        "gssencmode=disable",
        "postgres-migrations",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND=redis",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME=quotas/tool-validation/redis-url",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH=/run/hallu-defense/redis/ca.crt",
        "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "minimum RBAC",
        "OPA 1.17.0",
        "read_only: true",
        "no-new-privileges:true",
        "rw,noexec,nosuid,nodev",
        "root-owned",
        "Compose `!reset null`",
        "required interpolation",
        "separate minimal environment",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "redirects are rejected",
        "root:10001",
        "mode 0440",
        "mode 0750",
        "hallu-deploy",
        "make prod-profile-up",
        "make prod-profile-rotate-secrets",
        "--force-recreate",
    ):
        if marker not in prod_doc_text:
            errors.append(f"production profile docs missing `{marker}`")
    if "docker.sock" in prod_doc_text:
        errors.append("production profile docs must not retain Docker socket guidance")
    for marker in (
        "prod-secret-files-preflight:",
        "scripts/dev/preflight_runtime_secret_files.py",
        "prod-profile-up: prod-secret-files-preflight prod-profile-config",
        "docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d",
        "prod-profile-rotate-secrets: prod-secret-files-preflight prod-profile-config",
        "up -d --force-recreate",
    ):
        if marker not in makefile_text:
            errors.append(
                f"Makefile missing mandatory production preflight marker `{marker}`"
            )
    for target, marker in (
        ("prod-profile-config", script),
        ("prod-profile-e2e", "scripts/dev/live_prod_profile_e2e.py"),
        ("keycloak-jwks-export", "scripts/dev/export_keycloak_jwks.py"),
    ):
        if f"{target}:" not in makefile_text or marker not in makefile_text:
            errors.append(f"Makefile must expose {target}")
        if not _makefile_phony_includes(makefile_text, target):
            errors.append(f"Makefile .PHONY must include {target}")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_prod_profile_config.py")
    security_section = makefile_text.partition("security-check:")[2]
    if script not in security_section:
        errors.append("security-check must include check_prod_profile_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_prod_profile_config.py")
    if "prod-profile-e2e:" not in live_workflow_text:
        errors.append("live workflow must include prod-profile-e2e job")
    if "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_ENABLED" not in live_workflow_text:
        errors.append("prod-profile-e2e job must wire the prod profile smoke env gate")


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    phony_line = next(
        (line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), ""
    )
    return target in phony_line.split()


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _sequence(value: object, path: str, errors: list[str]) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return value
    errors.append(f"{path} must be a list")
    return ()


def _string_sequence(value: object, path: str, errors: list[str]) -> tuple[str, ...]:
    sequence = _sequence(value, path, errors)
    strings: list[str] = []
    for item in sequence:
        if isinstance(item, str):
            strings.append(item)
        else:
            errors.append(f"{path} must contain only strings")
    return tuple(strings)


def main() -> None:
    validate_prod_profile_config(
        base_compose=load_yaml_file(BASE_COMPOSE_PATH),
        prod_compose=load_yaml_file(PROD_COMPOSE_PATH),
        prometheus_prod=load_yaml_file(PROMETHEUS_PROD_PATH),
        prod_doc_text=PROD_DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    compose_result = run_compose_config_if_available()
    suffix = (
        "Docker compose config skipped because Docker is unavailable."
        if compose_result["status"] == "skipped"
        else "Docker compose base+prod config passed."
    )
    print(
        "Validated production profile Compose overlay and runtime gate configuration. "
        + suffix
    )


if __name__ == "__main__":
    main()
