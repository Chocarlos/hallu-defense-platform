from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

PRODUCTION_LIKE_ENVIRONMENTS = {"production", "staging"}
AUTH_CLAIMS_MODE_OIDC_JWT = "oidc_jwt"
AUTH_CLAIMS_MODE_SIGNED_HEADERS = "signed_headers"
AUTH_CLAIMS_MODE_UNSIGNED_HEADERS = "unsigned_headers"
DEFAULT_CORS_ALLOW_ORIGINS: tuple[str, ...] = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class AuthConfigurationError(ValueError):
    pass


class CorsConfigurationError(ValueError):
    pass


class RateLimitConfigurationError(ValueError):
    pass


class SandboxConfigurationError(ValueError):
    pass


class MetricsAuthConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    environment: str
    policy_version: str
    auth_required: bool
    allowed_workspace: Path
    max_command_seconds: int
    max_output_chars: int
    sandbox_backend: str = "host"
    sandbox_docker_image: str = "hallu-defense-sandbox:ci"
    sandbox_docker_path: str = "docker"
    sandbox_docker_memory_mb: int = 512
    sandbox_docker_cpus: float = 1.0
    sandbox_docker_pids_limit: int = 256
    sandbox_docker_timeout_grace_seconds: float = 2.0
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
    opa_policy_dir: Path = Path("infra/opa")
    opa_timeout_seconds: int = 3
    otel_enabled: bool = True
    otel_service_name: str = "hallu-defense-api"
    otel_exporter: str = "memory"
    otel_endpoint: str | None = None
    secrets_backend: str = "env"
    env_secret_prefix: str = "HALLU_DEFENSE_SECRET_"
    vault_addr: str | None = None
    vault_mount: str = "secret"
    vault_namespace: str | None = None
    vault_token_env: str = "HALLU_DEFENSE_VAULT_TOKEN"
    vault_timeout_seconds: int = 3
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
    postgres_dsn: str | None = None
    postgres_pool_min_size: int = 1
    postgres_pool_max_size: int = 8
    postgres_pool_timeout_seconds: float = 10.0
    pgvector_table_name: str = "rag_evidence_chunks"
    rag_embedding_dimension: int = 16
    audit_ledger_backend: str = "memory"
    audit_ledger_path: Path = Path("var/audit/audit-ledger.jsonl")
    audit_export_max_records: int = 1000
    approval_queue_backend: str = "memory"
    approval_queue_path: Path = Path("var/approvals/approval-queue.jsonl")
    approval_execution_grant_ttl_seconds: int = 900
    tool_validation_rate_limit_max_requests: int = 120
    tool_validation_rate_limit_window_seconds: int = 60
    corpus_grants_backend: str = "memory"
    corpus_grants_path: Path = Path("var/rag/corpus-grants.jsonl")
    corpus_grants_table_name: str = "rag_corpus_grants"
    cors_allow_origins: tuple[str, ...] = DEFAULT_CORS_ALLOW_ORIGINS


def load_settings() -> Settings:
    workspace = os.getenv("HALLU_DEFENSE_ALLOWED_WORKSPACE", os.getcwd())
    settings = Settings(
        environment=os.getenv("HALLU_DEFENSE_ENV", "local"),
        policy_version=os.getenv("HALLU_DEFENSE_POLICY_VERSION", "2026-07-07"),
        auth_required=_env_bool("HALLU_DEFENSE_AUTH_REQUIRED", False),
        auth_claims_mode=os.getenv("HALLU_DEFENSE_AUTH_CLAIMS_MODE", AUTH_CLAIMS_MODE_UNSIGNED_HEADERS)
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
        oidc_jwks_cache_ttl_seconds=int(os.getenv("HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS", "300")),
        oidc_http_timeout_seconds=int(os.getenv("HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS", "3")),
        oidc_subject_claim=os.getenv("HALLU_DEFENSE_OIDC_SUBJECT_CLAIM", "sub"),
        oidc_roles_claim=os.getenv("HALLU_DEFENSE_OIDC_ROLES_CLAIM", "roles"),
        oidc_tenant_claim=os.getenv("HALLU_DEFENSE_OIDC_TENANT_CLAIM", "tenant_id"),
        oidc_clock_skew_seconds=int(os.getenv("HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS", "60")),
        allowed_workspace=Path(workspace).resolve(),
        max_command_seconds=int(os.getenv("HALLU_DEFENSE_MAX_COMMAND_SECONDS", "30")),
        max_output_chars=int(os.getenv("HALLU_DEFENSE_MAX_OUTPUT_CHARS", "12000")),
        sandbox_backend=os.getenv("HALLU_DEFENSE_SANDBOX_BACKEND", "host").strip().lower(),
        sandbox_docker_image=os.getenv(
            "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
            "hallu-defense-sandbox:ci",
        ),
        sandbox_docker_path=os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_PATH", "docker"),
        sandbox_docker_memory_mb=int(os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB", "512")),
        sandbox_docker_cpus=float(os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_CPUS", "1.0")),
        sandbox_docker_pids_limit=int(
            os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT", "256")
        ),
        sandbox_docker_timeout_grace_seconds=float(
            os.getenv("HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS", "2")
        ),
        opa_enabled=_env_bool("HALLU_DEFENSE_OPA_ENABLED", False),
        opa_path=os.getenv("HALLU_DEFENSE_OPA_PATH"),
        opa_policy_dir=Path(os.getenv("HALLU_DEFENSE_OPA_POLICY_DIR", "infra/opa")).resolve(),
        opa_timeout_seconds=int(os.getenv("HALLU_DEFENSE_OPA_TIMEOUT_SECONDS", "3")),
        otel_enabled=_env_bool("HALLU_DEFENSE_OTEL_ENABLED", True),
        otel_service_name=os.getenv("HALLU_DEFENSE_OTEL_SERVICE_NAME", "hallu-defense-api"),
        otel_exporter=os.getenv("HALLU_DEFENSE_OTEL_EXPORTER", "memory").strip().lower(),
        otel_endpoint=os.getenv("HALLU_DEFENSE_OTEL_ENDPOINT"),
        secrets_backend=os.getenv("HALLU_DEFENSE_SECRETS_BACKEND", "env").strip().lower(),
        env_secret_prefix=os.getenv("HALLU_DEFENSE_ENV_SECRET_PREFIX", "HALLU_DEFENSE_SECRET_"),
        vault_addr=os.getenv("HALLU_DEFENSE_VAULT_ADDR") or None,
        vault_mount=os.getenv("HALLU_DEFENSE_VAULT_MOUNT", "secret"),
        vault_namespace=os.getenv("HALLU_DEFENSE_VAULT_NAMESPACE") or None,
        vault_token_env=os.getenv("HALLU_DEFENSE_VAULT_TOKEN_ENV", "HALLU_DEFENSE_VAULT_TOKEN"),
        vault_timeout_seconds=int(os.getenv("HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS", "3")),
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
        mock_provider_response=os.getenv("HALLU_DEFENSE_MOCK_PROVIDER_RESPONSE", "mock provider response"),
        rag_index_backend=os.getenv("HALLU_DEFENSE_RAG_INDEX_BACKEND", "local").strip().lower(),
        rag_index_timeout_seconds=int(os.getenv("HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS", "5")),
        opensearch_endpoint=os.getenv("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://localhost:9200"),
        opensearch_index_name=os.getenv("HALLU_DEFENSE_OPENSEARCH_INDEX_NAME", "hallu_evidence"),
        postgres_dsn=os.getenv("HALLU_DEFENSE_POSTGRES_DSN") or None,
        postgres_pool_min_size=int(os.getenv("HALLU_DEFENSE_POSTGRES_POOL_MIN_SIZE", "1")),
        postgres_pool_max_size=int(os.getenv("HALLU_DEFENSE_POSTGRES_POOL_MAX_SIZE", "8")),
        postgres_pool_timeout_seconds=float(
            os.getenv("HALLU_DEFENSE_POSTGRES_POOL_TIMEOUT_SECONDS", "10")
        ),
        pgvector_table_name=os.getenv("HALLU_DEFENSE_PGVECTOR_TABLE_NAME", "rag_evidence_chunks"),
        rag_embedding_dimension=int(os.getenv("HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION", "16")),
        audit_ledger_backend=os.getenv("HALLU_DEFENSE_AUDIT_LEDGER_BACKEND", "memory").strip().lower(),
        audit_ledger_path=Path(
            os.getenv("HALLU_DEFENSE_AUDIT_LEDGER_PATH", "var/audit/audit-ledger.jsonl")
        ).resolve(),
        audit_export_max_records=int(
            os.getenv("HALLU_DEFENSE_AUDIT_EXPORT_MAX_RECORDS", "1000")
        ),
        approval_queue_backend=os.getenv("HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND", "memory")
        .strip()
        .lower(),
        approval_queue_path=Path(
            os.getenv("HALLU_DEFENSE_APPROVAL_QUEUE_PATH", "var/approvals/approval-queue.jsonl")
        ).resolve(),
        approval_execution_grant_ttl_seconds=int(
            os.getenv("HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS", "900")
        ),
        tool_validation_rate_limit_max_requests=int(
            os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS", "120")
        ),
        tool_validation_rate_limit_window_seconds=int(
            os.getenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS", "60")
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
        cors_allow_origins=_parse_cors_allow_origins(
            os.getenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS")
        ),
    )
    validate_auth_settings(settings)
    validate_metrics_auth_settings(settings)
    validate_cors_settings(settings)
    validate_rate_limit_settings(settings)
    validate_sandbox_settings(settings)
    return settings


def _parse_cors_allow_origins(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_CORS_ALLOW_ORIGINS
    origins: list[str] = []
    for candidate in raw.split(","):
        origin = candidate.strip()
        if origin and origin not in origins:
            origins.append(origin)
    return tuple(origins)


def validate_cors_settings(settings: Settings) -> None:
    environment = settings.environment.strip().lower()
    errors: list[str] = []

    if not settings.cors_allow_origins:
        errors.append("HALLU_DEFENSE_CORS_ALLOW_ORIGINS must contain at least one origin.")
    for origin in settings.cors_allow_origins:
        if origin == "*" or "*" in origin:
            errors.append(
                "HALLU_DEFENSE_CORS_ALLOW_ORIGINS must not contain wildcard origins."
            )
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
    errors: list[str] = []
    if settings.tool_validation_rate_limit_max_requests <= 0:
        errors.append("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS must be positive.")
    if settings.tool_validation_rate_limit_window_seconds <= 0:
        errors.append("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS must be positive.")
    if errors:
        raise RateLimitConfigurationError("\n".join(errors))


def validate_sandbox_settings(settings: Settings) -> None:
    environment = settings.environment.strip().lower()
    backend = settings.sandbox_backend.strip().lower()
    errors: list[str] = []

    if backend not in {"host", "docker"}:
        errors.append("HALLU_DEFENSE_SANDBOX_BACKEND must be host or docker.")
    if environment in PRODUCTION_LIKE_ENVIRONMENTS and backend == "host":
        errors.append("Production and staging must set HALLU_DEFENSE_SANDBOX_BACKEND=docker.")
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

    if errors:
        raise SandboxConfigurationError("\n".join(errors))


def validate_auth_settings(settings: Settings) -> None:
    environment = settings.environment.strip().lower()
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
    if claims_mode == AUTH_CLAIMS_MODE_SIGNED_HEADERS and not settings.auth_claims_signature_secret_name.strip():
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
    environment = settings.environment.strip().lower()
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
