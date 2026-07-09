from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infra" / "security" / "auth-policy.json"
ENV_EXAMPLE = ROOT / ".env.example"
AUTH_DOC = ROOT / "docs" / "security" / "auth-rbac.md"
SECURITY_DOC = ROOT / "SECURITY.md"
CONFIG_MODULE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
AUTH_SERVICE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "auth.py"
API_DEPENDENCIES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
OIDC_PROVIDER_SMOKE = ROOT / "scripts" / "ci" / "oidc_provider_smoke.py"
METRICS_PROD_SCRAPE_CONFIG = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"

REQUIRED_ENV_KEYS = {
    "HALLU_DEFENSE_AUTH_REQUIRED=false",
    "HALLU_DEFENSE_AUTH_CLAIMS_MODE=unsigned_headers",
    "HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_SECRET_NAME=auth/trusted-header-signing-key",
    "HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS=300",
    "HALLU_DEFENSE_OIDC_ISSUER=",
    "HALLU_DEFENSE_OIDC_AUDIENCE=",
    "HALLU_DEFENSE_OIDC_JWKS_PATH=",
    "HALLU_DEFENSE_OIDC_JWKS_URL=",
    "HALLU_DEFENSE_OIDC_DISCOVERY_URL=",
    "HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS=300",
    "HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS=3",
    "HALLU_DEFENSE_OIDC_SUBJECT_CLAIM=sub",
    "HALLU_DEFENSE_OIDC_ROLES_CLAIM=roles",
    "HALLU_DEFENSE_OIDC_TENANT_CLAIM=tenant_id",
    "HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS=60",
    "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED=false",
    "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT=",
    "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_SUBJECT=",
    "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_TENANT=",
    "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_REQUIRED_ROLE=",
    "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME=",
}


class AuthConfigError(ValueError):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AuthConfigError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return payload


def validate_policy(policy: Mapping[str, object]) -> None:
    errors: list[str] = []
    if policy.get("schema_version") != "auth-policy.v1":
        errors.append("schema_version must be auth-policy.v1")

    production = _mapping(policy.get("production"), "production", errors)
    if production.get("auth_required") is not True:
        errors.append("production.auth_required must be true")
    if production.get("claims_mode") != "oidc_jwt":
        errors.append("production.claims_mode must be oidc_jwt")
    if production.get("allow_unsigned_claim_headers") is not False:
        errors.append("production.allow_unsigned_claim_headers must be false")
    if production.get("tenant_source") != "verified_jwt_claim":
        errors.append("production.tenant_source must be verified_jwt_claim")
    if production.get("roles_source") != "verified_principal":
        errors.append("production.roles_source must be verified_principal")
    if production.get("jwt_signature_source") != "jwks":
        errors.append("production.jwt_signature_source must be jwks")
    if production.get("jwks_source") != ["path", "url", "discovery"]:
        errors.append("production.jwks_source must allow path, url, and discovery")
    if production.get("jwt_algorithms") != ["RS256"]:
        errors.append("production.jwt_algorithms must be ['RS256']")
    for key in ("oidc_issuer_required", "oidc_audience_required", "oidc_jwks_required"):
        if production.get(key) is not True:
            errors.append(f"production.{key} must be true")
    if production.get("jwks_refresh_on_unknown_kid") is not True:
        errors.append("production.jwks_refresh_on_unknown_kid must be true")
    if production.get("jwks_remote_cache_required") is not True:
        errors.append("production.jwks_remote_cache_required must be true")

    trusted_gateway = _mapping(policy.get("trusted_gateway"), "trusted_gateway", errors)
    if trusted_gateway.get("claims_mode") != "signed_headers":
        errors.append("trusted_gateway.claims_mode must be signed_headers")
    if trusted_gateway.get("tenant_header_must_be_signed") is not True:
        errors.append("trusted_gateway.tenant_header_must_be_signed must be true")
    if trusted_gateway.get("signing_key_reference") != "auth/trusted-header-signing-key":
        errors.append("trusted_gateway.signing_key_reference must reference the signing key")

    local = _mapping(policy.get("local_development"), "local_development", errors)
    if local.get("auth_required_default") is not False:
        errors.append("local_development.auth_required_default must be false")
    if local.get("claims_mode_default") != "unsigned_headers":
        errors.append("local_development.claims_mode_default must be unsigned_headers")
    if local.get("allowed") is not True:
        errors.append("local_development.allowed must be true")

    controls = _mapping(policy.get("runtime_controls"), "runtime_controls", errors)
    for key in (
        "endpoint_role_matrix_required",
        "admin_superrole_allowed",
        "approval_decisions_always_require_reviewer",
        "signed_claims_require_timestamp",
    ):
        if controls.get(key) is not True:
            errors.append(f"runtime_controls.{key} must be true")
    replay_window = controls.get("signed_claims_replay_window_seconds_max")
    if not isinstance(replay_window, int) or replay_window > 300:
        errors.append("runtime_controls.signed_claims_replay_window_seconds_max must be <= 300")

    metrics_scrape_auth = _mapping(policy.get("metrics_scrape_auth"), "metrics_scrape_auth", errors)
    if metrics_scrape_auth.get("bearer_token_alternative_allowed") is not True:
        errors.append("metrics_scrape_auth.bearer_token_alternative_allowed must be true")
    if (
        metrics_scrape_auth.get("bearer_token_secret_reference_env")
        != "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME"
    ):
        errors.append(
            "metrics_scrape_auth.bearer_token_secret_reference_env must reference "
            "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME"
        )
    if metrics_scrape_auth.get("constant_time_comparison_required") is not True:
        errors.append("metrics_scrape_auth.constant_time_comparison_required must be true")
    if metrics_scrape_auth.get("fail_closed_when_unconfigured") is not True:
        errors.append("metrics_scrape_auth.fail_closed_when_unconfigured must be true")

    if errors:
        raise AuthConfigError("\n".join(errors))


def validate_supporting_files(
    *,
    env_example_text: str,
    auth_doc_text: str,
    security_doc_text: str,
    config_text: str,
    auth_service_text: str,
    api_dependencies_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    smoke_script_text = OIDC_PROVIDER_SMOKE.read_text(encoding="utf-8")
    _require(env_example_text, REQUIRED_ENV_KEYS, ".env.example", errors)
    _require(
        auth_doc_text,
        {
            "oidc_jwt",
            "Authorization: Bearer <OIDC JWT>",
            "HALLU_DEFENSE_OIDC_JWKS_PATH",
            "HALLU_DEFENSE_OIDC_JWKS_URL",
            "HALLU_DEFENSE_OIDC_DISCOVERY_URL",
            "HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS",
            "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED",
            "RS256",
            "signed_headers",
            "Endpoint Role Matrix",
            "HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS",
            "Local development with `HALLU_DEFENSE_AUTH_REQUIRED=false`",
            "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
            "constant-time",
            "prometheus.prod.yml",
        },
        "docs/security/auth-rbac.md",
        errors,
    )
    _require(
        security_doc_text,
        {
            "endpoint-to-role matrix",
            "In-process OIDC JWT/JWKS",
            "direct JWKS URL",
            "OIDC discovery",
            "refresh on unknown",
            "Deployed identity-provider smoke tests",
        },
        "SECURITY.md",
        errors,
    )
    _require(
        config_text,
        {
            "Production and staging must set HALLU_DEFENSE_AUTH_REQUIRED=true",
            "Production and staging must set HALLU_DEFENSE_AUTH_CLAIMS_MODE=signed_headers or oidc_jwt",
            "HALLU_DEFENSE_OIDC_ISSUER is required in oidc_jwt mode.",
            "HALLU_DEFENSE_OIDC_JWKS_PATH, HALLU_DEFENSE_OIDC_JWKS_URL, ",
            "HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS must be positive.",
            "validate_auth_settings(settings)",
            "validate_metrics_auth_settings(settings)",
            "metrics_bearer_token_secret_name",
            "Production and staging must set HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME.",
            "must not use the env secrets backend",
        },
        "config.py",
        errors,
    )
    _require(
        auth_service_text,
        {"ADMIN_ROLE", "require_any_role", "sign_trusted_headers", "METRICS_READER_ROLE"},
        "auth.py",
        errors,
    )
    _require(
        api_dependencies_text,
        {
            "ENDPOINT_ROLE_REQUIREMENTS",
            "OidcJwtValidator",
            "OidcJwksKeyNotFoundError",
            "Tenant header does not match OIDC token tenant claim.",
            "require_endpoint_roles",
            "signed_headers",
            "require_metrics_access",
            "_metrics_bearer_token_matches",
            "hmac.compare_digest",
        },
        "api/dependencies.py",
        errors,
    )
    _require(
        METRICS_PROD_SCRAPE_CONFIG.read_text(encoding="utf-8"),
        {"authorization:", "credentials_file", "type: Bearer"},
        "infra/prometheus/prometheus.prod.yml",
        errors,
    )
    _require(
        smoke_script_text,
        {
            "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED",
            "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT",
            "OidcJwtValidator",
            "OidcJwksResolver",
            "skipped deployed OIDC provider smoke",
        },
        "scripts/ci/oidc_provider_smoke.py",
        errors,
    )
    script = "scripts/ci/check_auth_config.py"
    smoke_script = "scripts/ci/oidc_provider_smoke.py"
    if "auth-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the auth-config gate")
    if "oidc-provider-smoke:" not in makefile_text or smoke_script not in makefile_text:
        errors.append("Makefile must expose the OIDC provider smoke gate")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_auth_config.py")
    if smoke_script not in ci_workflow_text:
        errors.append("CI workflow must run oidc_provider_smoke.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_auth_config.py")
    if smoke_script not in security_workflow_text:
        errors.append("security workflow must run oidc_provider_smoke.py")

    if errors:
        raise AuthConfigError("\n".join(errors))


def load_current_config() -> tuple[str, str, str, str, str, str, str, str, str]:
    return (
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        AUTH_DOC.read_text(encoding="utf-8"),
        SECURITY_DOC.read_text(encoding="utf-8"),
        CONFIG_MODULE.read_text(encoding="utf-8"),
        AUTH_SERVICE.read_text(encoding="utf-8"),
        API_DEPENDENCIES.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def main() -> None:
    validate_policy(load_policy())
    (
        env_example_text,
        auth_doc_text,
        security_doc_text,
        config_text,
        auth_service_text,
        api_dependencies_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()
    validate_supporting_files(
        env_example_text=env_example_text,
        auth_doc_text=auth_doc_text,
        security_doc_text=security_doc_text,
        config_text=config_text,
        auth_service_text=auth_service_text,
        api_dependencies_text=api_dependencies_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )
    print("Validated auth/RBAC configuration.")


if __name__ == "__main__":
    main()
