from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_MAIN_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "main.py"
POLICY_PATH = ROOT / "infra" / "security" / "auth-policy.json"
ENV_EXAMPLE = ROOT / ".env.example"
AUTH_DOC = ROOT / "docs" / "security" / "auth-rbac.md"
SECURITY_DOC = ROOT / "SECURITY.md"
CONFIG_MODULE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
AUTH_SERVICE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "auth.py"
API_DEPENDENCIES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
METRICS_TOKEN_VERIFIER = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "secret_token.py"
)
OIDC_PROVIDER_SMOKE = ROOT / "scripts" / "ci" / "oidc_provider_smoke.py"
LIVE_KEYCLOAK_SMOKE = ROOT / "scripts" / "dev" / "live_keycloak_oidc_smoke.py"
KEYCLOAK_REALM = ROOT / "infra" / "security" / "keycloak" / "realm-hallu-defense.json"
METRICS_PROD_SCRAPE_CONFIG = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "live.yml"

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
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_SUBJECT_CLAIM=azp",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_SUBJECT=hallu-defense-api",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_TENANT=tenant-a",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_REQUIRED_ROLE=approval_reviewer",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_API_BASE_URL=http://127.0.0.1:18081",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_ID=hallu-defense-limited",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_SECRET=limited-only",
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_EXPECTED_SUBJECT=hallu-defense-limited",
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
            "Local Keycloak + Uvicorn Live API Smoke",
            "scripts/dev/live_keycloak_oidc_smoke.py --api",
            "least-privilege token is rejected there with `403`",
            "audit event/export retains the JWT-derived tenant",
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
            "separately deployed Uvicorn API",
            "not evidence for an external",
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
            "validate_endpoint_auth_coverage",
            "__hallu_endpoint_key__",
            "signed_headers",
            "require_metrics_access",
            "_metrics_bearer_token_matches",
            "RotatingSecretTokenVerifier",
            "_metrics_bearer_token_verifier",
        },
        "api/dependencies.py",
        errors,
    )
    _require(
        METRICS_TOKEN_VERIFIER.read_text(encoding="utf-8"),
        {
            "hmac.compare_digest",
            "threading.Lock",
            "DEFAULT_SECRET_TOKEN_CACHE_TTL_SECONDS = 5.0",
            "cached.expires_at > now",
            "self._cached = None",
        },
        "services/secret_token.py",
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

    errors.extend(
        _live_keycloak_errors(
            live_script_text=LIVE_KEYCLOAK_SMOKE.read_text(encoding="utf-8"),
            realm_text=KEYCLOAK_REALM.read_text(encoding="utf-8"),
            live_workflow_text=LIVE_WORKFLOW.read_text(encoding="utf-8"),
        )
    )

    if errors:
        raise AuthConfigError("\n".join(errors))


def validate_live_keycloak_config(
    *,
    live_script_text: str,
    realm_text: str,
    live_workflow_text: str,
) -> None:
    errors = _live_keycloak_errors(
        live_script_text=live_script_text,
        realm_text=realm_text,
        live_workflow_text=live_workflow_text,
    )
    if errors:
        raise AuthConfigError("\n".join(errors))


def _live_keycloak_errors(
    *,
    live_script_text: str,
    realm_text: str,
    live_workflow_text: str,
) -> list[str]:
    errors: list[str] = []
    _require(
        live_script_text,
        {
            "API_BASE_URL_ENV",
            "LIMITED_CLIENT_ID_ENV",
            "class UrlLibJsonHttpClient",
            "open_url_no_redirect",
            "response.read(_MAX_HTTP_RESPONSE_BYTES + 1)",
            "client_secret: str = field(repr=False)",
            "_EXPLICIT_LOOPBACK_HOSTS",
            "plain HTTP is allowed only for an explicit loopback host",
            "OIDC issuer, discovery URL, and token endpoint must share one origin",
            "_validate_oidc_urls(config)",
            "_require_status(unauthenticated.status_code, 401",
            "_require_status(reviewer.status_code, 200",
            "_require_status(limited.status_code, 403",
            "_require_status(mismatch.status_code, 401",
            "_require_status(audit_export.status_code, 200",
            "_audit_events_preserve_tenant",
            "unexpected live Keycloak OIDC smoke failure",
        },
        "scripts/dev/live_keycloak_oidc_smoke.py",
        errors,
    )
    _require(
        API_MAIN_PATH.read_text(encoding="utf-8"),
        {"validate_endpoint_auth_coverage(router.routes)"},
        "api/main.py",
        errors,
    )
    for forbidden in ("from fastapi.testclient", "hallu_defense.main"):
        if forbidden in live_script_text:
            errors.append(
                "scripts/dev/live_keycloak_oidc_smoke.py must cross the Uvicorn "
                f"HTTP boundary; found forbidden `{forbidden}`"
            )

    try:
        realm: object = json.loads(realm_text)
    except json.JSONDecodeError:
        errors.append("Keycloak realm must be valid JSON")
        realm = {}
    realm_mapping = _mapping(realm, "Keycloak realm", errors)
    clients = _objects_by_key(
        realm_mapping.get("clients"),
        key="clientId",
        label="Keycloak clients",
        errors=errors,
    )
    realm_users = realm_mapping.get("users")
    service_account_users = (
        [
            user
            for user in realm_users
            if isinstance(user, Mapping) and "serviceAccountClientId" in user
        ]
        if isinstance(realm_users, list)
        else realm_users
    )
    users = _objects_by_key(
        service_account_users,
        key="serviceAccountClientId",
        label="Keycloak service-account users",
        errors=errors,
    )
    reviewer = clients.get("hallu-defense-api")
    limited = clients.get("hallu-defense-limited")
    if reviewer is None:
        errors.append("Keycloak realm missing reviewer client hallu-defense-api")
    else:
        _validate_keycloak_client(
            reviewer,
            client_id="hallu-defense-api",
            expected_secret="local-dev-only",
            errors=errors,
        )
    if limited is None:
        errors.append("Keycloak realm missing least-privilege client hallu-defense-limited")
    else:
        _validate_keycloak_client(
            limited,
            client_id="hallu-defense-limited",
            expected_secret="limited-only",
            errors=errors,
        )

    reviewer_user = users.get("hallu-defense-api")
    reviewer_roles = _string_set(
        reviewer_user.get("realmRoles") if reviewer_user is not None else None,
        "reviewer service-account roles",
        errors,
    )
    for role in ("approval_reviewer", "auditor"):
        if role not in reviewer_roles:
            errors.append(f"reviewer service account missing required role {role}")
    limited_user = users.get("hallu-defense-limited")
    limited_roles = _string_set(
        limited_user.get("realmRoles") if limited_user is not None else None,
        "limited service-account roles",
        errors,
    )
    if limited_roles != {"verifier"}:
        errors.append("limited service account must have exactly the verifier role")

    keycloak_job = _workflow_job_section(live_workflow_text, "keycloak-live", errors)
    _require(
        keycloak_job,
        {
            "python -m uvicorn hallu_defense.main:app",
            "--no-access-log",
            "http://127.0.0.1:18081/ready",
            "HALLU_DEFENSE_AUTH_REQUIRED: \"true\"",
            "HALLU_DEFENSE_AUTH_CLAIMS_MODE: oidc_jwt",
            "HALLU_DEFENSE_OIDC_DISCOVERY_URL:",
            "HALLU_DEFENSE_OIDC_SUBJECT_CLAIM: azp",
            "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND: memory",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_SUBJECT: hallu-defense-api",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_TENANT: tenant-a",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_REQUIRED_ROLE: approval_reviewer",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_API_BASE_URL: http://127.0.0.1:18081",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_ID: hallu-defense-limited",
            "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_SECRET: limited-only",
            "python scripts/dev/live_keycloak_oidc_smoke.py --api",
            "kill \"${api_pid}\"",
            "docker compose stop keycloak",
            "docker compose rm -f keycloak",
        },
        "live workflow keycloak-live job",
        errors,
    )
    if "docker compose down" in keycloak_job:
        errors.append(
            "live workflow keycloak-live job must not run global docker compose down"
        )
    return errors


def _validate_keycloak_client(
    client: Mapping[str, object],
    *,
    client_id: str,
    expected_secret: str,
    errors: list[str],
) -> None:
    for setting, expected in {
        "enabled": True,
        "serviceAccountsEnabled": True,
        "publicClient": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "secret": expected_secret,
    }.items():
        if client.get(setting) != expected:
            errors.append(f"Keycloak client {client_id}.{setting} must be {expected!r}")

    mappers = client.get("protocolMappers")
    if not isinstance(mappers, list):
        errors.append(f"Keycloak client {client_id} protocolMappers must be a list")
        return
    mapper_configs: dict[str, Mapping[str, object]] = {}
    for mapper in mappers:
        if not isinstance(mapper, Mapping):
            continue
        mapper_type = mapper.get("protocolMapper")
        config = mapper.get("config")
        if isinstance(mapper_type, str) and isinstance(config, Mapping):
            mapper_configs[mapper_type] = config

    audience = mapper_configs.get("oidc-audience-mapper", {})
    if audience.get("included.client.audience") != "hallu-defense-api":
        errors.append(f"Keycloak client {client_id} must emit hallu-defense-api audience")
    if audience.get("access.token.claim") != "true":
        errors.append(f"Keycloak client {client_id} audience must be in access tokens")
    tenant = mapper_configs.get("oidc-hardcoded-claim-mapper", {})
    if tenant.get("claim.name") != "tenant_id" or tenant.get("claim.value") != "tenant-a":
        errors.append(f"Keycloak client {client_id} must emit tenant_id=tenant-a")
    roles = mapper_configs.get("oidc-usermodel-realm-role-mapper", {})
    if roles.get("claim.name") != "roles" or roles.get("multivalued") != "true":
        errors.append(f"Keycloak client {client_id} must emit multivalued roles")


def _objects_by_key(
    value: object,
    *,
    key: str,
    label: str,
    errors: list[str],
) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        errors.append(f"{label} must be a list")
        return {}
    objects: dict[str, Mapping[str, object]] = {}
    for item in value:
        if not isinstance(item, Mapping) or not isinstance(item.get(key), str):
            errors.append(f"{label} entries must contain string {key}")
            continue
        item_key = item[key]
        if item_key in objects:
            errors.append(f"{label} contains duplicate {key} {item_key}")
        objects[item_key] = item
    return objects


def _string_set(value: object, label: str, errors: list[str]) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{label} must be a list of strings")
        return set()
    return set(value)


def _workflow_job_section(text: str, job: str, errors: list[str]) -> str:
    lines = text.splitlines()
    marker = f"  {job}:"
    try:
        start = lines.index(marker)
    except ValueError:
        errors.append(f"live workflow missing {job} job")
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


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
