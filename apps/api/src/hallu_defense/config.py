from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpPolicyError,
    outbound_http_policy_from_settings,
)
from hallu_defense.postgres_tls import (
    PostgresTlsConfigurationError,
    validate_postgres_tls,
)
from hallu_defense.runtime_secrets import (
    RuntimeSecretError,
    load_runtime_secret_from_os,
    read_runtime_secret_file,
)

PRODUCTION_LIKE_ENVIRONMENTS = {"production", "staging"}
KNOWN_ENVIRONMENTS = frozenset(
    {"local", "development", "test", "ci", "staging", "production"}
)
KUBERNETES_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
KUBERNETES_DNS_SUBDOMAIN_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
SECRET_MANAGER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,255}$")
ENVIRONMENT_VARIABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_OPENSEARCH_INDEX_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
AUTH_CLAIMS_MODE_OIDC_JWT = "oidc_jwt"
AUTH_CLAIMS_MODE_SIGNED_HEADERS = "signed_headers"
AUTH_CLAIMS_MODE_UNSIGNED_HEADERS = "unsigned_headers"
DEFAULT_CORS_ALLOW_ORIGINS: tuple[str, ...] = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)
INGESTION_MODE_SYNC = "sync"
INGESTION_MODE_ASYNC = "async"
RUNTIME_ROLE_API = "api"
RUNTIME_ROLE_WORKER = "worker"
RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP = "opensearch-bootstrap"
RUNTIME_ROLES = frozenset(
    {RUNTIME_ROLE_API, RUNTIME_ROLE_WORKER, RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP}
)
POSIX_OPA_PERMISSION_CHECKS = os.name == "posix"
OPA_WRITE_MODE_MASK = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_REQUEST_BODY_BYTES_UPPER_BOUND = 16 * 1024 * 1024
DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS = 15
REQUEST_BODY_TIMEOUT_SECONDS_UPPER_BOUND = 60


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class AuthConfigurationError(ValueError):
    pass


class EnvironmentConfigurationError(ValueError):
    pass


def normalize_environment(value: str) -> str:
    environment = value.strip().lower()
    if environment not in KNOWN_ENVIRONMENTS:
        raise EnvironmentConfigurationError(
            "HALLU_DEFENSE_ENV must be local, development, test, ci, staging, or production."
        )
    return environment


class CorsConfigurationError(ValueError):
    pass


class RateLimitConfigurationError(ValueError):
    pass


class OpaConfigurationError(ValueError):
    pass


class SandboxConfigurationError(ValueError):
    pass


class MetricsAuthConfigurationError(ValueError):
    pass


class IngestionConfigurationError(ValueError):
    pass


class RagRuntimeConfigurationError(ValueError):
    pass


class RuntimeTransportConfigurationError(ValueError):
    pass


class RuntimeRoleConfigurationError(ValueError):
    pass


class RequestBodyConfigurationError(ValueError):
    pass


class OpenSearchBootstrapConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    environment: str
    policy_version: str
    auth_required: bool
    allowed_workspace: Path
    max_command_seconds: int
    max_output_chars: int
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    request_body_timeout_seconds: int = DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS
    runtime_role: str = RUNTIME_ROLE_API
    sandbox_backend: str = "docker"
    sandbox_docker_image: str = "hallu-defense-sandbox:ci"
    sandbox_docker_path: str = "docker"
    sandbox_docker_memory_mb: int = 512
    sandbox_docker_cpus: float = 1.0
    sandbox_docker_pids_limit: int = 256
    sandbox_docker_timeout_grace_seconds: float = 2.0
    sandbox_kubernetes_image: str = ""
    sandbox_kubernetes_kind_local_image: bool = False
    sandbox_kubernetes_namespace: str = ""
    sandbox_kubernetes_pvc_name: str = ""
    sandbox_kubernetes_workspace_mount_path: str = ""
    sandbox_kubernetes_network_policy_name: str = ""
    sandbox_kubernetes_tenant_id: str = ""
    sandbox_kubernetes_poll_interval_seconds: float = 0.25
    sandbox_kubernetes_job_ttl_seconds: int = 60
    sandbox_kubernetes_api_request_timeout_seconds: float = 5.0
    sandbox_kubernetes_setup_grace_seconds: float = 15.0
    auth_claims_mode: str = "unsigned_headers"
    auth_claims_signature_secret_name: str = "auth/trusted-header-signing-key"
    auth_claims_signature_tolerance_seconds: int = 300
    metrics_bearer_token_secret_name: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_path: Path | None = None
    oidc_jwks_url: str | None = None
    oidc_discovery_url: str | None = None
    oidc_jwks_cache_ttl_seconds: int = 300
    oidc_http_timeout_seconds: int = 3
    oidc_subject_claim: str = "sub"
    oidc_roles_claim: str = "roles"
    oidc_tenant_claim: str = "tenant_id"
    oidc_clock_skew_seconds: int = 60
    opa_enabled: bool = False
    opa_path: str | None = None
    opa_policy_dir: Path = Path("infra/opa/policies")
    opa_timeout_seconds: int = 3
    otel_enabled: bool = True
    otel_service_name: str = "hallu-defense-api"
    otel_exporter: str = "memory"
    otel_endpoint: str | None = None
    outbound_https_allowed_origins: tuple[str, ...] = ()
    secrets_backend: str = "env"
    env_secret_prefix: str = "HALLU_DEFENSE_SECRET_"
    vault_addr: str | None = None
    vault_mount: str = "secret"
    vault_namespace: str | None = None
    vault_token_env: str = "HALLU_DEFENSE_VAULT_TOKEN"
    vault_token_file: Path | None = None
    vault_timeout_seconds: int = 3
    vault_ca_cert_path: Path | None = None
    provider_backend: str = "mock"
    provider_model: str = "mock-verifier"
    provider_timeout_seconds: int = 15
    provider_nli_enabled: bool = False
    openai_compatible_base_url: str = "https://api.openai.com/v1"
    openai_compatible_api_key_secret_name: str = "providers/openai/api-key"
    ollama_base_url: str = "http://localhost:11434"
    mock_provider_response: str = "mock provider response"
    rag_index_backend: str = "local"
    rag_index_timeout_seconds: int = 5
    opensearch_endpoint: str = "http://localhost:9200"
    opensearch_index_name: str = "hallu_evidence"
    opensearch_authorization_secret_name: str | None = None
    opensearch_ca_cert_path: Path | None = None
    opensearch_kind_insecure_http_enabled: bool = False
    postgres_dsn: str | None = field(default=None, repr=False)
    postgres_ca_cert_path: Path | None = None
    postgres_kind_insecure_tls_enabled: bool = False
    postgres_pool_min_size: int = 1
    postgres_pool_max_size: int = 8
    postgres_pool_timeout_seconds: float = 10.0
    pgvector_table_name: str = "rag_evidence_chunks"
    rag_embedding_dimension: int = 16
    audit_ledger_backend: str = "memory"
    audit_ledger_path: Path = Path("var/audit/audit-ledger.jsonl")
    audit_export_max_records: int = 1000
    eval_reports_backend: str = "memory"
    eval_reports_path: Path = Path("var/evals/eval-reports.jsonl")
    approval_queue_backend: str = "memory"
    approval_queue_path: Path = Path("var/approvals/approval-queue.jsonl")
    approval_execution_grant_ttl_seconds: int = 900
    approval_tool_call_commitment_secret_name: str | None = None
    tool_validation_rate_limit_backend: str = "memory"
    tool_validation_rate_limit_max_requests: int = 120
    tool_validation_rate_limit_window_seconds: int = 60
    tool_validation_rate_limit_redis_url_secret_name: str = "quotas/tool-validation/redis-url"
    tool_validation_rate_limit_redis_url: str | None = field(default=None, repr=False)
    tool_validation_rate_limit_redis_timeout_seconds: float = 1.0
    tool_validation_rate_limit_redis_ca_path: Path | None = None
    corpus_grants_backend: str = "memory"
    corpus_grants_path: Path = Path("var/rag/corpus-grants.jsonl")
    corpus_grants_table_name: str = "rag_corpus_grants"
    ingestion_mode: str = INGESTION_MODE_SYNC
    ingestion_worker_id: str = "ingestion-worker-local"
    ingestion_worker_poll_seconds: float = 2.0
    ingestion_worker_batch_size: int = 10
    ingestion_worker_max_attempts: int = 5
    ingestion_worker_backoff_base_seconds: float = 30.0
    ingestion_worker_lock_timeout_seconds: float = 300.0
    ingestion_worker_heartbeat_seconds: float = 30.0
    ingestion_backfill_page_size: int = 100
    cors_allow_origins: tuple[str, ...] = DEFAULT_CORS_ALLOW_ORIGINS


def load_settings(*, expected_runtime_role: str | None = None) -> Settings:
    runtime_role = (
        os.getenv(
            "HALLU_DEFENSE_RUNTIME_ROLE",
            expected_runtime_role or RUNTIME_ROLE_API,
        )
        .strip()
        .lower()
    )
    workspace = os.getenv("HALLU_DEFENSE_ALLOWED_WORKSPACE", os.getcwd())
    ingestion_lock_timeout_seconds = float(
        os.getenv("HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS", "300")
    )
    default_heartbeat_seconds = min(30.0, ingestion_lock_timeout_seconds / 3)
    ingestion_heartbeat_seconds = float(
        os.getenv(
            "HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS",
            str(default_heartbeat_seconds),
        )
    )
    settings = Settings(
        environment=normalize_environment(os.getenv("HALLU_DEFENSE_ENV", "local")),
        policy_version=os.getenv("HALLU_DEFENSE_POLICY_VERSION", "2026-07-07"),
        auth_required=_env_bool("HALLU_DEFENSE_AUTH_REQUIRED", False),
        auth_claims_mode=os.getenv(
            "HALLU_DEFENSE_AUTH_CLAIMS_MODE", AUTH_CLAIMS_MODE_UNSIGNED_HEADERS
        )
        .strip()
        .lower(),
        auth_claims_signature_secret_name=os.getenv(
            "HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_SECRET_NAME",
            "auth/trusted-header-signing-key",
        ),
        auth_claims_signature_tolerance_seconds=int(
            os.getenv("HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS", "300")
        ),
        metrics_bearer_token_secret_name=(
            os.getenv("HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME") or None
        ),
        oidc_issuer=os.getenv("HALLU_DEFENSE_OIDC_ISSUER") or None,
        oidc_audience=os.getenv("HALLU_DEFENSE_OIDC_AUDIENCE") or None,
        oidc_jwks_path=(
            Path(os.environ["HALLU_DEFENSE_OIDC_JWKS_PATH"]).resolve()
            if os.getenv("HALLU_DEFENSE_OIDC_JWKS_PATH")
            else None
        ),
        oidc_jwks_url=os.getenv("HALLU_DEFENSE_OIDC_JWKS_URL") or None,
        oidc_discovery_url=os.getenv("HALLU_DEFENSE_OIDC_DISCOVERY_URL") or None,
        oidc_jwks_cache_ttl_seconds=int(
            os.getenv("HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS", "300")
        ),
        oidc_http_timeout_seconds=int(os.getenv("HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS", "3")),
        oidc_subject_claim=os.getenv("HALLU_DEFENSE_OIDC_SUBJECT_CLAIM", "sub"),
        oidc_roles_claim=os.getenv("HALLU_DEFENSE_OIDC_ROLES_CLAIM", "roles"),
        oidc_tenant_claim=os.getenv("HALLU_DEFENSE_OIDC_TENANT_CLAIM", "tenant_id"),
        oidc_clock_skew_seconds=int(os.getenv("HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS", "60")),
        allowed_workspace=Path(workspace).resolve(),
        max_command_seconds=int(os.getenv("HALLU_DEFENSE_MAX_COMMAND_SECONDS", "30")),
        max_output_chars=int(os.getenv("HALLU_DEFENSE_MAX_OUTPUT_CHARS", "12000")),
        max_request_body_bytes=int(
            os.getenv(
                "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES",
                str(DEFAULT_MAX_REQUEST_BODY_BYTES),
            )
        ),
        request_body_timeout_seconds=int(
            os.getenv(
                "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS",
                str(DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS),
            )
        ),
        runtime_role=runtime_role,
        sandbox_backend=os.getenv("HALLU_DEFENSE_SANDBOX_BACKEND", "docker").strip().lower(),
        sandbox_docker_image=os.getenv(
            "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
            "hallu-defense-sandbox:ci",
        ),
        sandbox_docker_path=os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_PATH", "docker"),
        sandbox_docker_memory_mb=int(os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB", "512")),
        sandbox_docker_cpus=float(os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_CPUS", "1.0")),
        sandbox_docker_pids_limit=int(os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT", "256")),
        sandbox_docker_timeout_grace_seconds=float(
            os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS", "2")
        ),
        sandbox_kubernetes_image=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
            "",
        ),
        sandbox_kubernetes_kind_local_image=_env_bool(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE",
            False,
        ),
        sandbox_kubernetes_namespace=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE",
            "",
        ),
        sandbox_kubernetes_pvc_name=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
            "",
        ),
        sandbox_kubernetes_workspace_mount_path=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH",
            "",
        ),
        sandbox_kubernetes_network_policy_name=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
            "",
        ),
        sandbox_kubernetes_tenant_id=os.getenv(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID",
            "",
        ),
        sandbox_kubernetes_poll_interval_seconds=float(
            os.getenv("HALLU_DEFENSE_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS", "0.25")
        ),
        sandbox_kubernetes_job_ttl_seconds=int(
            os.getenv("HALLU_DEFENSE_SANDBOX_KUBERNETES_JOB_TTL_SECONDS", "60")
        ),
        sandbox_kubernetes_api_request_timeout_seconds=float(
            os.getenv(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_API_REQUEST_TIMEOUT_SECONDS",
                "5",
            )
        ),
        sandbox_kubernetes_setup_grace_seconds=float(
            os.getenv(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_SETUP_GRACE_SECONDS",
                "15",
            )
        ),
        opa_enabled=_env_bool("HALLU_DEFENSE_OPA_ENABLED", False),
        opa_path=os.getenv("HALLU_DEFENSE_OPA_PATH"),
        opa_policy_dir=Path(
            os.getenv("HALLU_DEFENSE_OPA_POLICY_DIR", "infra/opa/policies")
        ).resolve(),
        opa_timeout_seconds=int(os.getenv("HALLU_DEFENSE_OPA_TIMEOUT_SECONDS", "3")),
        otel_enabled=_env_bool("HALLU_DEFENSE_OTEL_ENABLED", True),
        otel_service_name=os.getenv("HALLU_DEFENSE_OTEL_SERVICE_NAME", "hallu-defense-api"),
        otel_exporter=os.getenv("HALLU_DEFENSE_OTEL_EXPORTER", "memory").strip().lower(),
        otel_endpoint=os.getenv("HALLU_DEFENSE_OTEL_ENDPOINT"),
        outbound_https_allowed_origins=_parse_outbound_https_allowed_origins(
            os.getenv("HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS")
        ),
        secrets_backend=os.getenv("HALLU_DEFENSE_SECRETS_BACKEND", "env").strip().lower(),
        env_secret_prefix=os.getenv("HALLU_DEFENSE_ENV_SECRET_PREFIX", "HALLU_DEFENSE_SECRET_"),
        vault_addr=os.getenv("HALLU_DEFENSE_VAULT_ADDR") or None,
        vault_mount=os.getenv("HALLU_DEFENSE_VAULT_MOUNT", "secret"),
        vault_namespace=os.getenv("HALLU_DEFENSE_VAULT_NAMESPACE") or None,
        vault_token_env=os.getenv("HALLU_DEFENSE_VAULT_TOKEN_ENV", "HALLU_DEFENSE_VAULT_TOKEN"),
        vault_token_file=(
            # Preserve the lexical Kubernetes projected-Secret path. Resolving
            # it here would pin the settings object to one versioned ``..data``
            # target and make subsequent atomic Secret rotations invisible.
            Path(os.environ["HALLU_DEFENSE_VAULT_TOKEN_FILE"])
            if os.getenv("HALLU_DEFENSE_VAULT_TOKEN_FILE")
            else None
        ),
        vault_timeout_seconds=int(os.getenv("HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS", "3")),
        vault_ca_cert_path=(
            Path(os.environ["HALLU_DEFENSE_VAULT_CA_CERT_PATH"]).resolve()
            if os.getenv("HALLU_DEFENSE_VAULT_CA_CERT_PATH")
            else None
        ),
        provider_backend=os.getenv("HALLU_DEFENSE_PROVIDER_BACKEND", "mock").strip().lower(),
        provider_model=os.getenv("HALLU_DEFENSE_PROVIDER_MODEL", "mock-verifier"),
        provider_timeout_seconds=int(os.getenv("HALLU_DEFENSE_PROVIDER_TIMEOUT_SECONDS", "15")),
        provider_nli_enabled=_env_bool("HALLU_DEFENSE_PROVIDER_NLI_ENABLED", False),
        openai_compatible_base_url=os.getenv(
            "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL",
            "https://api.openai.com/v1",
        ),
        openai_compatible_api_key_secret_name=os.getenv(
            "HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME",
            "providers/openai/api-key",
        ),
        ollama_base_url=os.getenv("HALLU_DEFENSE_OLLAMA_BASE_URL", "http://localhost:11434"),
        mock_provider_response=os.getenv(
            "HALLU_DEFENSE_MOCK_PROVIDER_RESPONSE", "mock provider response"
        ),
        rag_index_backend=os.getenv(
            "HALLU_DEFENSE_RAG_INDEX_BACKEND",
            ("opensearch" if runtime_role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP else "local"),
        )
        .strip()
        .lower(),
        rag_index_timeout_seconds=int(os.getenv("HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS", "5")),
        opensearch_endpoint=os.getenv("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://localhost:9200"),
        opensearch_index_name=os.getenv("HALLU_DEFENSE_OPENSEARCH_INDEX_NAME", "hallu_evidence"),
        opensearch_authorization_secret_name=(
            os.environ["HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME"]
            if "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME" in os.environ
            else None
        ),
        opensearch_ca_cert_path=(
            Path(os.environ["HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH"]).resolve()
            if os.getenv("HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH")
            else None
        ),
        opensearch_kind_insecure_http_enabled=_env_bool(
            "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED",
            False,
        ),
        postgres_dsn=load_runtime_secret_from_os(
            value_variable="HALLU_DEFENSE_POSTGRES_DSN",
            file_variable="HALLU_DEFENSE_POSTGRES_DSN_FILE",
        ),
        postgres_ca_cert_path=(
            Path(os.environ["HALLU_DEFENSE_POSTGRES_CA_CERT_PATH"])
            if os.getenv("HALLU_DEFENSE_POSTGRES_CA_CERT_PATH")
            else None
        ),
        postgres_kind_insecure_tls_enabled=_env_bool(
            "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
            False,
        ),
        postgres_pool_min_size=int(os.getenv("HALLU_DEFENSE_POSTGRES_POOL_MIN_SIZE", "1")),
        postgres_pool_max_size=int(os.getenv("HALLU_DEFENSE_POSTGRES_POOL_MAX_SIZE", "8")),
        postgres_pool_timeout_seconds=float(
            os.getenv("HALLU_DEFENSE_POSTGRES_POOL_TIMEOUT_SECONDS", "10")
        ),
        pgvector_table_name=os.getenv("HALLU_DEFENSE_PGVECTOR_TABLE_NAME", "rag_evidence_chunks"),
        rag_embedding_dimension=int(os.getenv("HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION", "16")),
        audit_ledger_backend=os.getenv("HALLU_DEFENSE_AUDIT_LEDGER_BACKEND", "memory")
        .strip()
        .lower(),
        audit_ledger_path=Path(
            os.getenv("HALLU_DEFENSE_AUDIT_LEDGER_PATH", "var/audit/audit-ledger.jsonl")
        ).resolve(),
        audit_export_max_records=int(os.getenv("HALLU_DEFENSE_AUDIT_EXPORT_MAX_RECORDS", "1000")),
        eval_reports_backend=os.getenv("HALLU_DEFENSE_EVAL_REPORTS_BACKEND", "memory")
        .strip()
        .lower(),
        eval_reports_path=Path(
            os.getenv("HALLU_DEFENSE_EVAL_REPORTS_PATH", "var/evals/eval-reports.jsonl")
        ).resolve(),
        approval_queue_backend=os.getenv("HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND", "memory")
        .strip()
        .lower(),
        approval_queue_path=Path(
            os.getenv("HALLU_DEFENSE_APPROVAL_QUEUE_PATH", "var/approvals/approval-queue.jsonl")
        ).resolve(),
        approval_execution_grant_ttl_seconds=int(
            os.getenv("HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS", "900")
        ),
        approval_tool_call_commitment_secret_name=(
            os.getenv("HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME") or None
        ),
        tool_validation_rate_limit_backend=os.getenv(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND",
            "memory",
        )
        .strip()
        .lower(),
        tool_validation_rate_limit_max_requests=int(
            os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS", "120")
        ),
        tool_validation_rate_limit_window_seconds=int(
            os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS", "60")
        ),
        tool_validation_rate_limit_redis_url_secret_name=os.getenv(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
            "quotas/tool-validation/redis-url",
        ),
        tool_validation_rate_limit_redis_url=(
            os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL") or None
        ),
        tool_validation_rate_limit_redis_timeout_seconds=float(
            os.getenv(
                "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS",
                "1",
            )
        ),
        tool_validation_rate_limit_redis_ca_path=(
            Path(os.environ["HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH"]).resolve()
            if os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH")
            else None
        ),
        corpus_grants_backend=os.getenv("HALLU_DEFENSE_CORPUS_GRANTS_BACKEND", "memory")
        .strip()
        .lower(),
        corpus_grants_path=Path(
            os.getenv("HALLU_DEFENSE_CORPUS_GRANTS_PATH", "var/rag/corpus-grants.jsonl")
        ).resolve(),
        corpus_grants_table_name=os.getenv(
            "HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME",
            "rag_corpus_grants",
        ),
        ingestion_mode=os.getenv("HALLU_DEFENSE_INGESTION_MODE", INGESTION_MODE_SYNC)
        .strip()
        .lower(),
        ingestion_worker_id=os.getenv(
            "HALLU_DEFENSE_INGESTION_WORKER_ID",
            "ingestion-worker-local",
        ),
        ingestion_worker_poll_seconds=float(
            os.getenv("HALLU_DEFENSE_INGESTION_WORKER_POLL_SECONDS", "2")
        ),
        ingestion_worker_batch_size=int(
            os.getenv("HALLU_DEFENSE_INGESTION_WORKER_BATCH_SIZE", "10")
        ),
        ingestion_worker_max_attempts=int(
            os.getenv("HALLU_DEFENSE_INGESTION_WORKER_MAX_ATTEMPTS", "5")
        ),
        ingestion_worker_backoff_base_seconds=float(
            os.getenv("HALLU_DEFENSE_INGESTION_WORKER_BACKOFF_BASE_SECONDS", "30")
        ),
        ingestion_worker_lock_timeout_seconds=ingestion_lock_timeout_seconds,
        ingestion_worker_heartbeat_seconds=ingestion_heartbeat_seconds,
        ingestion_backfill_page_size=int(
            os.getenv("HALLU_DEFENSE_INGESTION_BACKFILL_PAGE_SIZE", "100")
        ),
        cors_allow_origins=_parse_cors_allow_origins(os.getenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS")),
    )
    validate_runtime_role_settings(settings, expected_runtime_role=expected_runtime_role)
    validate_vault_token_source(settings)
    validate_postgres_transport_settings(settings)
    if runtime_role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP:
        validate_opensearch_bootstrap_settings(settings)
        validate_runtime_transport_settings(settings)
        return settings
    validate_request_body_settings(settings)
    validate_ingestion_settings(settings)
    validate_rag_index_settings(settings)
    if runtime_role == RUNTIME_ROLE_API:
        validate_auth_settings(settings)
        validate_metrics_auth_settings(settings)
        validate_cors_settings(settings)
        validate_rate_limit_settings(settings)
        validate_opa_settings(settings)
        validate_sandbox_settings(settings)
        validate_runtime_transport_settings(settings)
    elif runtime_role == RUNTIME_ROLE_WORKER:
        validate_worker_runtime_settings(settings)
        validate_runtime_transport_settings(settings)
    return settings


def validate_postgres_transport_settings(settings: Settings) -> None:
    dsn = settings.postgres_dsn
    if dsn is None or not dsn.strip():
        if settings.postgres_kind_insecure_tls_enabled:
            raise PostgresTlsConfigurationError(
                "The Kind PostgreSQL TLS exception requires a PostgreSQL DSN."
            )
        return
    validate_postgres_tls(
        dsn,
        environment=settings.environment,
        ca_cert_path=settings.postgres_ca_cert_path,
        kind_insecure_tls_enabled=settings.postgres_kind_insecure_tls_enabled,
    )


def validate_request_body_settings(settings: Settings) -> None:
    if not 1 <= settings.max_request_body_bytes <= MAX_REQUEST_BODY_BYTES_UPPER_BOUND:
        raise RequestBodyConfigurationError(
            "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES must be between 1 and "
            f"{MAX_REQUEST_BODY_BYTES_UPPER_BOUND}."
        )
    if not 1 <= settings.request_body_timeout_seconds <= REQUEST_BODY_TIMEOUT_SECONDS_UPPER_BOUND:
        raise RequestBodyConfigurationError(
            "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS must be between 1 and "
            f"{REQUEST_BODY_TIMEOUT_SECONDS_UPPER_BOUND}."
        )


def validate_vault_token_source(settings: Settings) -> None:
    if (
        normalize_environment(settings.environment) not in PRODUCTION_LIKE_ENVIRONMENTS
        or settings.secrets_backend.strip().lower() != "vault"
    ):
        return
    if os.getenv("HALLU_DEFENSE_VAULT_TOKEN_ENV"):
        raise RuntimeRoleConfigurationError(
            "Production must not configure HALLU_DEFENSE_VAULT_TOKEN_ENV; use the file-only source."
        )
    if os.getenv(settings.vault_token_env):
        raise RuntimeRoleConfigurationError(
            "Production Vault tokens must not be supplied through process environment values."
        )
    token_file = settings.vault_token_file
    if token_file is None:
        raise RuntimeRoleConfigurationError(
            "Production Vault access requires HALLU_DEFENSE_VAULT_TOKEN_FILE."
        )
    try:
        read_runtime_secret_file(
            str(token_file),
            variable_name="HALLU_DEFENSE_VAULT_TOKEN_FILE",
        )
    except RuntimeSecretError as exc:
        raise RuntimeRoleConfigurationError(str(exc)) from exc


def validate_runtime_role_settings(
    settings: Settings,
    *,
    expected_runtime_role: str | None = None,
) -> None:
    role = settings.runtime_role.strip().lower()
    errors: list[str] = []
    if role not in RUNTIME_ROLES:
        errors.append("HALLU_DEFENSE_RUNTIME_ROLE must be api, worker, or opensearch-bootstrap.")
    if expected_runtime_role is not None and role != expected_runtime_role:
        errors.append("HALLU_DEFENSE_RUNTIME_ROLE does not match the executable runtime role.")
    if (
        role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
        and expected_runtime_role != RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    ):
        errors.append(
            "The opensearch-bootstrap runtime role may only be selected by its pinned CLI."
        )
    if errors:
        raise RuntimeRoleConfigurationError("\n".join(errors))


def validate_worker_runtime_settings(settings: Settings) -> None:
    """Validate only dependencies the ingestion worker actually constructs."""
    production_like = normalize_environment(settings.environment) in PRODUCTION_LIKE_ENVIRONMENTS
    errors: list[str] = []
    if settings.ingestion_mode.strip().lower() != INGESTION_MODE_ASYNC:
        errors.append("Worker runtime requires HALLU_DEFENSE_INGESTION_MODE=async.")
    if not settings.postgres_dsn or not settings.postgres_dsn.strip():
        errors.append("Worker runtime requires HALLU_DEFENSE_POSTGRES_DSN.")
    if settings.audit_ledger_backend.strip().lower() not in {"postgres", "postgresql"}:
        errors.append("Worker runtime requires a PostgreSQL audit ledger backend.")
    if settings.corpus_grants_backend.strip().lower() not in {"postgres", "postgresql"}:
        errors.append("Worker runtime requires a PostgreSQL corpus grants backend.")
    if settings.rag_index_backend.strip().lower() not in {
        "pgvector",
        "opensearch",
        "hybrid",
    }:
        errors.append("Worker runtime requires a persistent RAG index backend.")
    if production_like:
        if settings.secrets_backend.strip().lower() != "vault":
            errors.append("Production worker runtime requires the Vault secret backend.")
        normalized_mount = settings.vault_mount.strip("/")
        if not normalized_mount or "/" in normalized_mount:
            errors.append("Production worker HALLU_DEFENSE_VAULT_MOUNT must be one path segment.")
        if settings.vault_timeout_seconds <= 0:
            errors.append("Production worker HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS must be positive.")
        if (
            settings.vault_token_file is None
            and ENVIRONMENT_VARIABLE_NAME_RE.fullmatch(settings.vault_token_env) is None
        ):
            errors.append("Production worker HALLU_DEFENSE_VAULT_TOKEN_ENV must be canonical.")
        vault_ca_path = settings.vault_ca_cert_path
        if vault_ca_path is None:
            errors.append("Production worker runtime requires HALLU_DEFENSE_VAULT_CA_CERT_PATH.")
        elif not vault_ca_path.is_file():
            errors.append("Production worker runtime Vault CA file is unavailable.")
    if errors:
        raise RuntimeRoleConfigurationError("\n".join(errors))


def validate_opensearch_bootstrap_settings(settings: Settings) -> None:
    """Validate only dependencies used by the one-shot template bootstrap CLI."""
    validate_rag_index_settings(settings)
    production_like = normalize_environment(settings.environment) in PRODUCTION_LIKE_ENVIRONMENTS
    kind_internal_http = is_kind_internal_opensearch_http(settings)
    errors: list[str] = []

    if settings.rag_index_backend.strip().lower() != "opensearch":
        errors.append("OpenSearch bootstrap requires HALLU_DEFENSE_RAG_INDEX_BACKEND=opensearch.")
    if SAFE_OPENSEARCH_INDEX_NAME_RE.fullmatch(settings.opensearch_index_name) is None:
        errors.append("HALLU_DEFENSE_OPENSEARCH_INDEX_NAME must be a safe identifier.")

    secrets_backend = settings.secrets_backend.strip().lower()
    if production_like and secrets_backend != "vault":
        errors.append(
            "Production OpenSearch bootstrap requires HALLU_DEFENSE_SECRETS_BACKEND=vault."
        )
    if secrets_backend == "vault":
        normalized_mount = settings.vault_mount.strip("/")
        if not normalized_mount or "/" in normalized_mount:
            errors.append("HALLU_DEFENSE_VAULT_MOUNT must be one non-empty path segment.")
        if settings.vault_timeout_seconds <= 0:
            errors.append("HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS must be positive.")
        if (
            settings.vault_token_file is None
            and ENVIRONMENT_VARIABLE_NAME_RE.fullmatch(settings.vault_token_env) is None
        ):
            errors.append(
                "HALLU_DEFENSE_VAULT_TOKEN_ENV must be a canonical environment variable name."
            )
        vault_ca_path = settings.vault_ca_cert_path
        if production_like and vault_ca_path is None:
            errors.append(
                "Production OpenSearch bootstrap requires HALLU_DEFENSE_VAULT_CA_CERT_PATH."
            )
        elif vault_ca_path is not None and not vault_ca_path.is_file():
            errors.append("HALLU_DEFENSE_VAULT_CA_CERT_PATH is unavailable.")

    if production_like and not kind_internal_http and settings.opensearch_ca_cert_path is None:
        errors.append(
            "Production OpenSearch bootstrap requires HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH."
        )

    if errors:
        raise OpenSearchBootstrapConfigurationError("\n".join(errors))


def validate_rag_index_settings(settings: Settings) -> None:
    backend = settings.rag_index_backend.strip().lower()
    environment = normalize_environment(settings.environment)
    uses_opensearch = backend in {"opensearch", "hybrid"}
    uses_pgvector = backend in {"pgvector", "hybrid"}
    bootstrap_role = settings.runtime_role.strip().lower() == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    errors: list[str] = []

    if backend not in {"local", "opensearch", "pgvector", "hybrid"}:
        errors.append(
            "HALLU_DEFENSE_RAG_INDEX_BACKEND must be local, opensearch, pgvector, or hybrid."
        )
    if settings.rag_index_timeout_seconds <= 0:
        errors.append("HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS must be positive.")
    if uses_pgvector and not (settings.postgres_dsn and settings.postgres_dsn.strip()):
        errors.append("The pgvector and hybrid RAG backends require HALLU_DEFENSE_POSTGRES_DSN.")
    if uses_opensearch and not settings.opensearch_endpoint.strip():
        errors.append("The OpenSearch and hybrid RAG backends require an endpoint.")

    secret_name = settings.opensearch_authorization_secret_name
    if secret_name is not None and not secret_name.strip():
        errors.append("HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME must not be blank.")
    elif secret_name is not None and not _valid_secret_manager_name(secret_name):
        errors.append(
            "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME must be a logical "
            "SecretManager path, not an authorization value."
        )
    ca_path = settings.opensearch_ca_cert_path
    if ca_path is not None and not ca_path.is_file():
        errors.append("HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH is unavailable.")

    kind_http_requested = settings.opensearch_kind_insecure_http_enabled
    kind_internal_http = is_kind_internal_opensearch_http(settings)
    if kind_http_requested and not kind_internal_http:
        errors.append(
            "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED is restricted to the "
            "exact internal kind OpenSearch service."
        )
    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if bootstrap_role and backend != "opensearch":
            errors.append("Production OpenSearch bootstrap requires the opensearch RAG backend.")
        elif not bootstrap_role and backend != "hybrid":
            errors.append("Production and staging require the hybrid RAG backend.")
        if uses_opensearch and not kind_internal_http:
            if secret_name is None or not secret_name.strip():
                errors.append("Production OpenSearch requires an authorization SecretManager name.")
            if settings.secrets_backend.strip().lower() != "vault":
                errors.append(
                    "Production OpenSearch authorization requires the Vault secret backend."
                )
        if kind_internal_http and secret_name is not None:
            errors.append(
                "The kind-only insecure OpenSearch dependency must not receive credentials."
            )

    if errors:
        raise RagRuntimeConfigurationError("\n".join(errors))


def _valid_secret_manager_name(value: str) -> bool:
    return (
        SECRET_MANAGER_NAME_RE.fullmatch(value) is not None
        and not value.startswith("/")
        and not value.endswith("/")
        and "//" not in value
        and all(part not in {".", ".."} for part in value.split("/"))
    )


def is_kind_internal_opensearch_http(settings: Settings) -> bool:
    if not settings.opensearch_kind_insecure_http_enabled:
        return False
    try:
        parsed = urlparse(settings.opensearch_endpoint)
        port = parsed.port
    except ValueError:
        return False
    hostname = parsed.hostname or ""
    return (
        normalize_environment(settings.environment) == "production"
        and parsed.scheme == "http"
        and port == 9200
        and hostname == "hallu-defense-opensearch"
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and not parsed.query
        and not parsed.fragment
    )


def _parse_cors_allow_origins(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_CORS_ALLOW_ORIGINS
    origins: list[str] = []
    for candidate in raw.split(","):
        origin = candidate.strip()
        if origin and origin not in origins:
            origins.append(origin)
    return tuple(origins)


def _parse_outbound_https_allowed_origins(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return ()
    return tuple(candidate.strip() for candidate in raw.split(","))


def validate_cors_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    errors: list[str] = []

    if not settings.cors_allow_origins:
        errors.append("HALLU_DEFENSE_CORS_ALLOW_ORIGINS must contain at least one origin.")
    for origin in settings.cors_allow_origins:
        if origin == "*" or "*" in origin:
            errors.append("HALLU_DEFENSE_CORS_ALLOW_ORIGINS must not contain wildcard origins.")
            continue
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            errors.append(
                f"HALLU_DEFENSE_CORS_ALLOW_ORIGINS entry must be an absolute HTTP(S) origin: {origin}"
            )
            continue
        if parsed.path or parsed.params or parsed.query or parsed.fragment:
            errors.append(
                f"HALLU_DEFENSE_CORS_ALLOW_ORIGINS entry must not include a path or query: {origin}"
            )
            continue
        if environment in PRODUCTION_LIKE_ENVIRONMENTS and parsed.scheme != "https":
            errors.append(
                f"HALLU_DEFENSE_CORS_ALLOW_ORIGINS entry must use https in production and staging: {origin}"
            )

    if errors:
        raise CorsConfigurationError("\n".join(errors))


def validate_rate_limit_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    backend = settings.tool_validation_rate_limit_backend.strip().lower()
    errors: list[str] = []
    if backend not in {"memory", "redis"}:
        errors.append("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND must be memory or redis.")
    if backend == "memory" and environment not in {"local", "test"}:
        errors.append(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND=memory is allowed only "
            "in local or test environments."
        )
    if settings.tool_validation_rate_limit_max_requests <= 0:
        errors.append("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS must be positive.")
    if settings.tool_validation_rate_limit_window_seconds <= 0:
        errors.append("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS must be positive.")
    if settings.tool_validation_rate_limit_redis_timeout_seconds <= 0:
        errors.append(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS must be positive."
        )
    if backend == "redis" and not settings.tool_validation_rate_limit_redis_url_secret_name.strip():
        errors.append(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME must not be blank."
        )
    direct_url = settings.tool_validation_rate_limit_redis_url
    if direct_url is not None and environment not in {"local", "test"}:
        errors.append(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL is allowed only in local or test environments."
        )
    ca_path = settings.tool_validation_rate_limit_redis_ca_path
    if ca_path is not None and not ca_path.is_file():
        errors.append(
            "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH must reference an existing file."
        )
    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if backend != "redis":
            errors.append(
                "Production and staging must set "
                "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND=redis."
            )
        if settings.secrets_backend.strip().lower() != "vault":
            errors.append(
                "Production and staging must resolve the tool-validation Redis URL through Vault."
            )
        if direct_url is not None:
            errors.append(
                "Production and staging must not configure the tool-validation Redis URL directly."
            )
        if ca_path is None:
            errors.append(
                "Production and staging must set "
                "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH."
            )
    if errors:
        raise RateLimitConfigurationError("\n".join(errors))


def validate_opa_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    production_like = environment in PRODUCTION_LIKE_ENVIRONMENTS
    errors: list[str] = []

    if settings.opa_timeout_seconds <= 0:
        errors.append("HALLU_DEFENSE_OPA_TIMEOUT_SECONDS must be positive.")

    if production_like and not settings.opa_enabled:
        errors.append(
            "Production and staging API runtimes must set HALLU_DEFENSE_OPA_ENABLED=true."
        )

    if settings.opa_enabled:
        policy_dir = settings.opa_policy_dir
        if not policy_dir.is_dir():
            errors.append("HALLU_DEFENSE_OPA_POLICY_DIR must reference an existing directory.")
        if production_like and not policy_dir.is_absolute():
            errors.append(
                "HALLU_DEFENSE_OPA_POLICY_DIR must be absolute in production and staging."
            )

    if production_like:
        opa_path_value = settings.opa_path.strip() if settings.opa_path is not None else ""
        if not opa_path_value:
            errors.append("Production and staging API runtimes must set HALLU_DEFENSE_OPA_PATH.")
        else:
            opa_path = Path(opa_path_value)
            if not opa_path.is_absolute():
                errors.append("HALLU_DEFENSE_OPA_PATH must be absolute in production and staging.")
            if not opa_path.is_file() or not os.access(opa_path, os.X_OK):
                errors.append("HALLU_DEFENSE_OPA_PATH must reference an executable file.")
            elif settings.opa_enabled:
                errors.extend(
                    _validate_posix_opa_runtime_permissions(
                        opa_path=opa_path,
                        policy_dir=settings.opa_policy_dir,
                    )
                )

    if errors:
        raise OpaConfigurationError("\n".join(errors))


def _validate_posix_opa_runtime_permissions(
    *,
    opa_path: Path,
    policy_dir: Path,
) -> list[str]:
    if not POSIX_OPA_PERMISSION_CHECKS:
        return []

    errors: list[str] = []
    targets: list[tuple[str, Path, str]] = [
        ("HALLU_DEFENSE_OPA_PATH", opa_path, "file"),
        ("HALLU_DEFENSE_OPA_POLICY_DIR", policy_dir, "directory"),
    ]
    try:
        for root, directories, files in os.walk(policy_dir, followlinks=False):
            root_path = Path(root)
            targets.extend(
                ("OPA policy tree", root_path / name, "directory") for name in directories
            )
            targets.extend(("OPA policy tree", root_path / name, "file") for name in files)
    except OSError:
        return ["HALLU_DEFENSE_OPA_POLICY_DIR permissions could not be verified."]

    for label, path, expected_kind in targets:
        try:
            metadata = os.lstat(path)
        except OSError:
            errors.append(f"{label} permissions could not be verified.")
            continue
        actual_kind_is_valid = (
            stat.S_ISREG(metadata.st_mode)
            if expected_kind == "file"
            else stat.S_ISDIR(metadata.st_mode)
        )
        if not actual_kind_is_valid:
            errors.append(f"{label} must not contain symlinks or special files.")
            continue
        if metadata.st_uid != 0:
            errors.append(f"{label} must be root-owned in production and staging.")
        if metadata.st_mode & OPA_WRITE_MODE_MASK:
            errors.append(f"{label} must have all POSIX write mode bits disabled.")
        try:
            runtime_can_write = os.access(path, os.W_OK)
        except OSError:
            runtime_can_write = True
        if runtime_can_write:
            errors.append(f"{label} must not be writable by the API runtime identity.")
    return errors


def validate_sandbox_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    backend = settings.sandbox_backend.strip().lower()
    errors: list[str] = []

    if backend not in {"docker", "kubernetes"}:
        errors.append(
            "HALLU_DEFENSE_SANDBOX_BACKEND must be docker or kubernetes; "
            "host subprocess execution cannot enforce sandbox network isolation."
        )
    if environment in PRODUCTION_LIKE_ENVIRONMENTS and backend != "kubernetes":
        errors.append(
            "Production and staging require "
            "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation."
        )
    if backend != "kubernetes" and settings.sandbox_kubernetes_kind_local_image:
        errors.append(
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE is valid only for the Kubernetes backend."
        )
    if not settings.sandbox_docker_image.strip():
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE must not be empty.")
    if not settings.sandbox_docker_path.strip():
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_PATH must not be empty.")
    if settings.sandbox_docker_memory_mb <= 0:
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB must be positive.")
    if settings.sandbox_docker_cpus <= 0:
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_CPUS must be positive.")
    if settings.sandbox_docker_pids_limit <= 0:
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT must be positive.")
    if settings.sandbox_docker_timeout_grace_seconds <= 0:
        errors.append("HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS must be positive.")
    if backend == "kubernetes":
        if (
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}",
                settings.sandbox_kubernetes_tenant_id,
            )
            is None
        ):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID must be a non-empty canonical tenant identifier."
            )
        if not _valid_container_image(settings.sandbox_kubernetes_image):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE must be a non-latest image reference."
            )
        elif (
            environment in PRODUCTION_LIKE_ENVIRONMENTS
            and not settings.sandbox_kubernetes_kind_local_image
            and re.search(
                r"@sha256:[0-9a-f]{64}$",
                settings.sandbox_kubernetes_image,
            )
            is None
        ):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE must be pinned by sha256 digest in production and staging."
            )
        if settings.sandbox_kubernetes_kind_local_image and (
            settings.sandbox_kubernetes_image != "hallu-defense-sandbox:ci"
        ):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE permits only the isolated hallu-defense-sandbox:ci image."
            )
        if not _valid_kubernetes_name(
            settings.sandbox_kubernetes_namespace,
            max_length=63,
            allow_subdomains=False,
        ):
            errors.append("HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE must be a valid DNS label.")
        if not _valid_kubernetes_name(
            settings.sandbox_kubernetes_pvc_name,
            max_length=253,
            allow_subdomains=True,
        ):
            errors.append("HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME must be a valid DNS name.")
        if not _valid_kubernetes_name(
            settings.sandbox_kubernetes_network_policy_name,
            max_length=253,
            allow_subdomains=True,
        ):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME must be a valid DNS name."
            )
        if not _valid_container_mount_path(settings.sandbox_kubernetes_workspace_mount_path):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH must be an absolute, canonical non-root path."
            )
        if settings.sandbox_kubernetes_poll_interval_seconds <= 0:
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS must be positive."
            )
        if settings.sandbox_kubernetes_job_ttl_seconds <= 0:
            errors.append("HALLU_DEFENSE_SANDBOX_KUBERNETES_JOB_TTL_SECONDS must be positive.")
        if settings.sandbox_kubernetes_api_request_timeout_seconds <= 0:
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_API_REQUEST_TIMEOUT_SECONDS must be positive."
            )
        if not (
            0 < settings.sandbox_kubernetes_setup_grace_seconds <= 120
        ):
            errors.append(
                "HALLU_DEFENSE_SANDBOX_KUBERNETES_SETUP_GRACE_SECONDS must be greater than zero and at most 120."
            )

    if errors:
        raise SandboxConfigurationError("\n".join(errors))


def _valid_kubernetes_name(
    value: str,
    *,
    max_length: int,
    allow_subdomains: bool,
) -> bool:
    normalized = value.strip()
    if normalized != value or not 0 < len(normalized) <= max_length:
        return False
    if allow_subdomains:
        return KUBERNETES_DNS_SUBDOMAIN_RE.fullmatch(normalized) is not None and all(
            len(label) <= 63 and KUBERNETES_DNS_LABEL_RE.fullmatch(label) is not None
            for label in normalized.split(".")
        )
    return KUBERNETES_DNS_LABEL_RE.fullmatch(normalized) is not None


def _valid_container_mount_path(value: str) -> bool:
    normalized = value.strip()
    if normalized != value or not normalized.startswith("/") or normalized == "/":
        return False
    path = PurePosixPath(normalized)
    reserved_roots = (
        PurePosixPath("/tmp"),
        PurePosixPath("/hallu-results"),
        PurePosixPath("/var/run/secrets"),
    )
    return str(path) == normalized and not any(
        path == root or root in path.parents for root in reserved_roots
    )


def _valid_container_image(value: str) -> bool:
    normalized = value.strip()
    image_name = normalized.rsplit("/", 1)[-1]
    has_tag = ":" in image_name and not image_name.endswith(":")
    has_digest = re.search(r"@sha256:[0-9a-fA-F]{64}$", normalized) is not None
    return (
        normalized == value
        and bool(normalized)
        and not normalized.endswith(":latest")
        and not any(character.isspace() for character in normalized)
        and (has_tag or has_digest)
    )


def validate_ingestion_settings(settings: Settings) -> None:
    mode = settings.ingestion_mode.strip().lower()
    errors: list[str] = []

    if mode not in {INGESTION_MODE_SYNC, INGESTION_MODE_ASYNC}:
        errors.append("HALLU_DEFENSE_INGESTION_MODE must be sync or async.")
    if (
        normalize_environment(settings.environment) in PRODUCTION_LIKE_ENVIRONMENTS
        and mode != INGESTION_MODE_ASYNC
    ):
        errors.append("Production and staging require HALLU_DEFENSE_INGESTION_MODE=async.")
    if mode == INGESTION_MODE_ASYNC and not (
        settings.postgres_dsn and settings.postgres_dsn.strip()
    ):
        errors.append("HALLU_DEFENSE_INGESTION_MODE=async requires HALLU_DEFENSE_POSTGRES_DSN.")
    if not settings.ingestion_worker_id.strip():
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_ID must not be empty.")
    if settings.ingestion_worker_poll_seconds <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_POLL_SECONDS must be positive.")
    if settings.ingestion_worker_batch_size <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_BATCH_SIZE must be positive.")
    if settings.ingestion_worker_max_attempts <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_MAX_ATTEMPTS must be positive.")
    if settings.ingestion_worker_backoff_base_seconds <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_BACKOFF_BASE_SECONDS must be positive.")
    if settings.ingestion_worker_lock_timeout_seconds <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS must be positive.")
    if settings.ingestion_worker_heartbeat_seconds <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS must be positive.")
    elif (
        settings.ingestion_worker_lock_timeout_seconds > 0
        and settings.ingestion_worker_heartbeat_seconds
        >= settings.ingestion_worker_lock_timeout_seconds
    ):
        errors.append(
            "HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS must be less than "
            "HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS."
        )
    if settings.ingestion_backfill_page_size <= 0:
        errors.append("HALLU_DEFENSE_INGESTION_BACKFILL_PAGE_SIZE must be positive.")

    if errors:
        raise IngestionConfigurationError("\n".join(errors))


def validate_auth_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    claims_mode = settings.auth_claims_mode.strip().lower()
    errors: list[str] = []

    if claims_mode not in {
        AUTH_CLAIMS_MODE_UNSIGNED_HEADERS,
        AUTH_CLAIMS_MODE_SIGNED_HEADERS,
        AUTH_CLAIMS_MODE_OIDC_JWT,
    }:
        errors.append(
            "HALLU_DEFENSE_AUTH_CLAIMS_MODE must be unsigned_headers, signed_headers, or oidc_jwt."
        )
    if settings.auth_claims_signature_tolerance_seconds <= 0:
        errors.append("HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS must be positive.")
    if (
        claims_mode == AUTH_CLAIMS_MODE_SIGNED_HEADERS
        and not settings.auth_claims_signature_secret_name.strip()
    ):
        errors.append("HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_SECRET_NAME is required in signed mode.")
    if claims_mode == AUTH_CLAIMS_MODE_OIDC_JWT:
        if not settings.oidc_issuer:
            errors.append("HALLU_DEFENSE_OIDC_ISSUER is required in oidc_jwt mode.")
        if not settings.oidc_audience:
            errors.append("HALLU_DEFENSE_OIDC_AUDIENCE is required in oidc_jwt mode.")
        if (
            settings.oidc_jwks_path is None
            and not settings.oidc_jwks_url
            and not settings.oidc_discovery_url
        ):
            errors.append(
                "HALLU_DEFENSE_OIDC_JWKS_PATH, HALLU_DEFENSE_OIDC_JWKS_URL, "
                "or HALLU_DEFENSE_OIDC_DISCOVERY_URL is required in oidc_jwt mode."
            )
        if settings.oidc_clock_skew_seconds < 0:
            errors.append("HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS must be zero or positive.")
        if settings.oidc_jwks_cache_ttl_seconds <= 0:
            errors.append("HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS must be positive.")
        if settings.oidc_http_timeout_seconds <= 0:
            errors.append("HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS must be positive.")
        for name, value in {
            "HALLU_DEFENSE_OIDC_JWKS_URL": settings.oidc_jwks_url,
            "HALLU_DEFENSE_OIDC_DISCOVERY_URL": settings.oidc_discovery_url,
        }.items():
            if value is not None:
                _validate_oidc_url(name, value, environment, errors)

    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if not settings.auth_required:
            errors.append("Production and staging must set HALLU_DEFENSE_AUTH_REQUIRED=true.")
        if claims_mode not in {AUTH_CLAIMS_MODE_SIGNED_HEADERS, AUTH_CLAIMS_MODE_OIDC_JWT}:
            errors.append(
                "Production and staging must set HALLU_DEFENSE_AUTH_CLAIMS_MODE=signed_headers or oidc_jwt."
            )

    if errors:
        raise AuthConfigurationError("\n".join(errors))


def validate_metrics_auth_settings(settings: Settings) -> None:
    environment = normalize_environment(settings.environment)
    secret_name = settings.metrics_bearer_token_secret_name
    normalized_secret_name = secret_name.strip() if secret_name is not None else ""
    errors: list[str] = []

    if secret_name is not None and not normalized_secret_name:
        errors.append(
            "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME must not be blank; "
            "unset it only in local/test/dev/CI environments."
        )

    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if not normalized_secret_name:
            errors.append(
                "Production and staging must set HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME."
            )
        if settings.secrets_backend.strip().lower() == "env":
            errors.append(
                "Production and staging must not use the env secrets backend for the "
                "metrics bearer token; configure the vault backend instead."
            )

    if errors:
        raise MetricsAuthConfigurationError("\n".join(errors))


def validate_runtime_transport_settings(settings: Settings) -> None:
    errors: list[str] = []
    try:
        policy = outbound_http_policy_from_settings(settings)
    except OutboundHttpPolicyError as exc:
        errors.append(str(exc))
        policy = None

    if settings.secrets_backend.strip().lower() == "vault":
        _validate_outbound_endpoint(
            "HALLU_DEFENSE_VAULT_ADDR",
            settings.vault_addr,
            policy=policy,
            errors=errors,
        )

    provider_backend = settings.provider_backend.strip().lower()
    if provider_backend in {"openai", "openai-compatible"}:
        _validate_outbound_endpoint(
            "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL",
            settings.openai_compatible_base_url,
            policy=policy,
            errors=errors,
        )
    elif provider_backend == "ollama":
        _validate_outbound_endpoint(
            "HALLU_DEFENSE_OLLAMA_BASE_URL",
            settings.ollama_base_url,
            policy=policy,
            errors=errors,
        )

    oidc_remote = (
        settings.auth_claims_mode.strip().lower() == AUTH_CLAIMS_MODE_OIDC_JWT
        and settings.oidc_jwks_path is None
    )
    if oidc_remote:
        for env_name, endpoint in (
            ("HALLU_DEFENSE_OIDC_ISSUER", settings.oidc_issuer),
            ("HALLU_DEFENSE_OIDC_JWKS_URL", settings.oidc_jwks_url),
            ("HALLU_DEFENSE_OIDC_DISCOVERY_URL", settings.oidc_discovery_url),
        ):
            if endpoint is not None:
                _validate_outbound_endpoint(
                    env_name,
                    endpoint,
                    policy=policy,
                    errors=errors,
                )

    if settings.rag_index_backend.strip().lower() in {"opensearch", "hybrid"}:
        if not is_kind_internal_opensearch_http(settings):
            _validate_outbound_endpoint(
                "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
                settings.opensearch_endpoint,
                policy=policy,
                errors=errors,
            )

    if settings.otel_enabled and settings.otel_exporter.strip().lower() == "otlp":
        _validate_outbound_endpoint(
            "HALLU_DEFENSE_OTEL_ENDPOINT",
            settings.otel_endpoint,
            policy=policy,
            errors=errors,
        )

    if errors:
        raise RuntimeTransportConfigurationError("\n".join(errors))


def _validate_outbound_endpoint(
    env_name: str,
    value: str | None,
    *,
    policy: OutboundHttpPolicy | None,
    errors: list[str],
) -> None:
    if value is None or not value.strip():
        errors.append(f"{env_name} must be configured as an absolute HTTP(S) URL.")
        return
    if policy is None:
        return
    try:
        policy.validate_url(value)
    except OutboundHttpPolicyError:
        errors.append(f"{env_name} is invalid or is not in the outbound HTTPS allowlist.")


def _validate_oidc_url(
    env_name: str,
    value: str,
    environment: str,
    errors: list[str],
) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        errors.append(f"{env_name} must be an absolute HTTP(S) URL.")
        return
    if environment in PRODUCTION_LIKE_ENVIRONMENTS and parsed.scheme != "https":
        errors.append(f"{env_name} must use https in production and staging.")
