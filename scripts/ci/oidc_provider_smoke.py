from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_SRC = ROOT / "apps" / "api" / "src"
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

from hallu_defense.config import (  # noqa: E402
    AUTH_CLAIMS_MODE_OIDC_JWT,
    AuthConfigurationError,
    Settings,
    validate_auth_settings,
)
from hallu_defense.services.oidc import (  # noqa: E402
    JsonFetcher,
    OidcJwksResolver,
    OidcJwtValidationError,
    OidcJwtValidator,
)

SMOKE_ENABLED_ENV = "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED"
SMOKE_JWT_ENV = "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT"
SMOKE_EXPECTED_SUBJECT_ENV = "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_SUBJECT"
SMOKE_EXPECTED_TENANT_ENV = "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_TENANT"
SMOKE_REQUIRED_ROLE_ENV = "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_REQUIRED_ROLE"


class OidcProviderSmokeError(ValueError):
    pass


@dataclass(frozen=True)
class OidcProviderSmokeResult:
    status: str
    message: str


@dataclass(frozen=True)
class OidcProviderSmokeConfig:
    settings: Settings
    jwt_value: str
    expected_subject: str | None
    expected_tenant: str | None
    required_role: str | None


def run_smoke(
    env: Mapping[str, str] = os.environ,
    *,
    fetch_json: JsonFetcher | None = None,
) -> OidcProviderSmokeResult:
    if not _env_bool(env.get(SMOKE_ENABLED_ENV)):
        return OidcProviderSmokeResult(
            status="skipped",
            message=f"{SMOKE_ENABLED_ENV} is not true; skipped deployed OIDC provider smoke.",
        )

    config = _load_config(env)
    resolver = OidcJwksResolver(config.settings, fetch_json=fetch_json)
    try:
        jwks = resolver.resolve(force_refresh=True)
        claims = OidcJwtValidator(config.settings, jwks).validate(
            f"Bearer {config.jwt_value}",
        )
    except OidcJwtValidationError as exc:
        raise OidcProviderSmokeError(f"OIDC provider smoke failed: {exc}") from exc

    if config.expected_subject is not None and claims.principal.subject_id != config.expected_subject:
        raise OidcProviderSmokeError("OIDC provider smoke subject claim did not match expected subject.")
    if config.expected_tenant is not None and claims.tenant_id != config.expected_tenant:
        raise OidcProviderSmokeError("OIDC provider smoke tenant claim did not match expected tenant.")
    if config.required_role is not None and not claims.principal.has_role(config.required_role):
        raise OidcProviderSmokeError("OIDC provider smoke JWT did not include the required role.")

    source = "discovery" if config.settings.oidc_discovery_url else "jwks_url"
    return OidcProviderSmokeResult(
        status="passed",
        message=f"OIDC provider smoke passed for issuer {config.settings.oidc_issuer} via {source}.",
    )


def _load_config(env: Mapping[str, str]) -> OidcProviderSmokeConfig:
    issuer = _required_env(env, "HALLU_DEFENSE_OIDC_ISSUER")
    audience = _required_env(env, "HALLU_DEFENSE_OIDC_AUDIENCE")
    jwt_value = _required_env(env, SMOKE_JWT_ENV)
    jwks_url = _optional_env(env, "HALLU_DEFENSE_OIDC_JWKS_URL")
    discovery_url = _optional_env(env, "HALLU_DEFENSE_OIDC_DISCOVERY_URL")
    if not jwks_url and not discovery_url:
        raise OidcProviderSmokeError(
            "OIDC provider smoke requires HALLU_DEFENSE_OIDC_JWKS_URL "
            "or HALLU_DEFENSE_OIDC_DISCOVERY_URL."
        )

    settings = Settings(
        environment=_optional_env(env, "HALLU_DEFENSE_ENV") or "production",
        policy_version=_optional_env(env, "HALLU_DEFENSE_POLICY_VERSION") or "smoke",
        auth_required=True,
        allowed_workspace=ROOT,
        max_command_seconds=30,
        max_output_chars=12_000,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer=issuer,
        oidc_audience=audience,
        oidc_jwks_url=jwks_url,
        oidc_discovery_url=discovery_url,
        oidc_subject_claim=_optional_env(env, "HALLU_DEFENSE_OIDC_SUBJECT_CLAIM") or "sub",
        oidc_roles_claim=_optional_env(env, "HALLU_DEFENSE_OIDC_ROLES_CLAIM") or "roles",
        oidc_tenant_claim=_optional_env(env, "HALLU_DEFENSE_OIDC_TENANT_CLAIM") or "tenant_id",
        oidc_clock_skew_seconds=_int_env(env, "HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS", 60),
        oidc_jwks_cache_ttl_seconds=_int_env(env, "HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS", 300),
        oidc_http_timeout_seconds=_int_env(env, "HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS", 3),
    )
    try:
        validate_auth_settings(settings)
    except AuthConfigurationError as exc:
        raise OidcProviderSmokeError(f"OIDC provider smoke configuration is invalid: {exc}") from exc
    return OidcProviderSmokeConfig(
        settings=settings,
        jwt_value=jwt_value,
        expected_subject=_optional_env(env, SMOKE_EXPECTED_SUBJECT_ENV),
        expected_tenant=_optional_env(env, SMOKE_EXPECTED_TENANT_ENV),
        required_role=_optional_env(env, SMOKE_REQUIRED_ROLE_ENV),
    )


def _env_bool(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _required_env(env: Mapping[str, str], name: str) -> str:
    value = _optional_env(env, name)
    if value is None:
        raise OidcProviderSmokeError(f"{name} is required when {SMOKE_ENABLED_ENV}=true.")
    return value


def _optional_env(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional_env(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise OidcProviderSmokeError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise OidcProviderSmokeError(f"{name} must be positive.")
    return parsed


def main() -> None:
    try:
        result = run_smoke()
    except OidcProviderSmokeError as exc:
        print(str(exc))
        raise SystemExit(1) from exc
    print(result.message)


if __name__ == "__main__":
    main()
