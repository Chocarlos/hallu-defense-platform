"""Live Keycloak OIDC smoke against a separately running Uvicorn API.

The enabled ``--api`` mode never imports the FastAPI app or ``TestClient``. It
mints two real Keycloak service-account tokens and exercises the configured API
over HTTP. The default mode verifies the reviewer token directly against OIDC
discovery/JWKS. Both modes are skip-by-default and emit only bounded, redacted
status data.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib import error, request
from urllib.parse import urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings  # noqa: E402
from hallu_defense.outbound_http import (  # noqa: E402
    OutboundHttpRedirectError,
    open_url_no_redirect,
)
from hallu_defense.services.oidc import (  # noqa: E402
    JsonFetcher,
    OidcJwksResolver,
    OidcJwtValidationError,
    OidcJwtValidator,
    OidcPrincipalClaims,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_SMOKE_ENABLED"
ISSUER_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_ISSUER"
AUDIENCE_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_AUDIENCE"
DISCOVERY_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_DISCOVERY_URL"
SUBJECT_CLAIM_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_SUBJECT_CLAIM"
CLIENT_ID_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_CLIENT_ID"
CLIENT_SECRET_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_CLIENT_SECRET"
EXPECTED_SUBJECT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_SUBJECT"
EXPECTED_TENANT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_TENANT"
REQUIRED_ROLE_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_REQUIRED_ROLE"
API_BASE_URL_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_API_BASE_URL"
LIMITED_CLIENT_ID_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_ID"
LIMITED_CLIENT_SECRET_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_CLIENT_SECRET"
LIMITED_EXPECTED_SUBJECT_ENV = (
    "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_LIMITED_EXPECTED_SUBJECT"
)
HTTP_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_HTTP_TIMEOUT_SECONDS"

_MAX_HTTP_RESPONSE_BYTES = 1_048_576
_EXPLICIT_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_API_UNAUTHENTICATED_TRACE_ID = "tr_live_oidc_unauthenticated"
_API_REVIEWER_TRACE_ID = "tr_live_oidc_reviewer_allowed"
_API_LIMITED_TRACE_ID = "tr_live_oidc_limited_forbidden"
_API_MISMATCH_TRACE_ID = "tr_live_oidc_tenant_mismatch"
_API_AUDIT_EXPORT_TRACE_ID = "tr_live_oidc_audit_export"


class LiveKeycloakOidcSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ClientCredentials:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class LiveKeycloakOidcSmokeConfig:
    issuer: str
    audience: str
    discovery_url: str
    token_endpoint: str
    subject_claim: str
    reviewer_credentials: ClientCredentials
    expected_subject: str
    expected_tenant: str
    required_role: str
    http_timeout_seconds: int


@dataclass(frozen=True)
class LiveKeycloakOidcApiSmokeConfig:
    identity: LiveKeycloakOidcSmokeConfig
    api_base_url: str
    limited_credentials: ClientCredentials
    limited_expected_subject: str


@dataclass(frozen=True)
class JsonHttpResponse:
    status_code: int
    payload: Mapping[str, object]


@dataclass(frozen=True)
class _CanonicalHttpOrigin:
    scheme: str
    hostname: str
    port: int


class JsonHttpClient(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: int,
    ) -> JsonHttpResponse: ...


class UrlLibJsonHttpClient:
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: int,
    ) -> JsonHttpResponse:
        _validate_http_url(url, require_root=False)
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        api_request = request.Request(
            url,
            data=encoded,
            method="POST",
            headers={
                **headers,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with open_url_no_redirect(
                api_request,
                timeout=timeout_seconds,
            ) as response:
                raw = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
                status_code = response.status
        except OutboundHttpRedirectError:
            raise LiveKeycloakOidcSmokeError("API redirects are not allowed") from None
        except error.HTTPError as exc:
            status_code = exc.code
            exc.close()
            return JsonHttpResponse(status_code=status_code, payload={})
        except (error.URLError, TimeoutError, OSError):
            raise LiveKeycloakOidcSmokeError("API request failed") from None

        if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
            raise LiveKeycloakOidcSmokeError("API response exceeded the 1 MiB limit")
        if not raw:
            return JsonHttpResponse(status_code=status_code, payload={})
        try:
            decoded: object = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise LiveKeycloakOidcSmokeError("API response was not valid JSON") from None
        if not isinstance(decoded, Mapping):
            raise LiveKeycloakOidcSmokeError("API response must be a JSON object")
        return JsonHttpResponse(status_code=status_code, payload=decoded)


CredentialTokenMinter = Callable[[ClientCredentials], str]


def token_endpoint_for(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/token"


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    fetch_json: JsonFetcher | None = None,
    token_minter: CredentialTokenMinter | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return _skipped_result("verification")

    config = _config_from_env(effective_env)
    minter = token_minter or _token_minter_for(config)
    reviewer_token = minter(config.reviewer_credentials)
    reviewer_claims = _validated_claims(
        config,
        reviewer_token,
        fetch_json=fetch_json,
    )
    _require_expected_identity(
        reviewer_claims,
        expected_subject=config.expected_subject,
        expected_tenant=config.expected_tenant,
        required_role=config.required_role,
    )
    return {
        "status": "passed",
        "mode": "verification",
        "issuer": config.issuer,
        "subject": reviewer_claims.principal.subject_id,
        "tenant": reviewer_claims.tenant_id,
        "roles": sorted(reviewer_claims.principal.roles),
        "subject_verified": True,
        "tenant_verified": True,
        "role_verified": True,
    }


def run_api_from_env(
    env: Mapping[str, str] | None = None,
    *,
    fetch_json: JsonFetcher | None = None,
    token_minter: CredentialTokenMinter | None = None,
    http_client: JsonHttpClient | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return _skipped_result("api")

    config = _api_config_from_env(effective_env)
    minter = token_minter or _token_minter_for(config.identity)
    reviewer_token = minter(config.identity.reviewer_credentials)
    limited_token = minter(config.limited_credentials)

    reviewer_claims = _validated_claims(
        config.identity,
        reviewer_token,
        fetch_json=fetch_json,
    )
    _require_expected_identity(
        reviewer_claims,
        expected_subject=config.identity.expected_subject,
        expected_tenant=config.identity.expected_tenant,
        required_role=config.identity.required_role,
    )
    limited_claims = _validated_claims(
        config.identity,
        limited_token,
        fetch_json=fetch_json,
    )
    _require(
        limited_claims.principal.subject_id == config.limited_expected_subject,
        "limited-client subject claim did not match the expected subject",
    )
    _require(
        limited_claims.tenant_id == config.identity.expected_tenant,
        "limited-client tenant claim did not match the expected tenant",
    )
    _require(
        not limited_claims.principal.has_role(config.identity.required_role),
        "limited-client token unexpectedly contains the reviewer role",
    )
    return run_api_checks(
        config=config,
        reviewer_token=reviewer_token,
        limited_token=limited_token,
        http_client=http_client or UrlLibJsonHttpClient(),
    )


def run_api_checks(
    *,
    config: LiveKeycloakOidcApiSmokeConfig,
    reviewer_token: str,
    limited_token: str,
    http_client: JsonHttpClient,
) -> dict[str, object]:
    approvals_url = _api_url(config.api_base_url, "/approvals/list")
    audit_url = _api_url(config.api_base_url, "/audit/export")

    unauthenticated = http_client.post_json(
        approvals_url,
        headers={"x-trace-id": _API_UNAUTHENTICATED_TRACE_ID},
        payload={},
        timeout_seconds=config.identity.http_timeout_seconds,
    )
    reviewer = http_client.post_json(
        approvals_url,
        headers=_bearer_headers(reviewer_token, trace_id=_API_REVIEWER_TRACE_ID),
        payload={},
        timeout_seconds=config.identity.http_timeout_seconds,
    )
    limited = http_client.post_json(
        approvals_url,
        headers=_bearer_headers(limited_token, trace_id=_API_LIMITED_TRACE_ID),
        payload={},
        timeout_seconds=config.identity.http_timeout_seconds,
    )
    mismatch = http_client.post_json(
        approvals_url,
        headers={
            **_bearer_headers(reviewer_token, trace_id=_API_MISMATCH_TRACE_ID),
            "x-tenant-id": "tenant-intentional-mismatch",
        },
        payload={},
        timeout_seconds=config.identity.http_timeout_seconds,
    )
    audit_export = http_client.post_json(
        audit_url,
        headers=_bearer_headers(reviewer_token, trace_id=_API_AUDIT_EXPORT_TRACE_ID),
        payload={"trace_id": _API_REVIEWER_TRACE_ID, "include_events": True},
        timeout_seconds=config.identity.http_timeout_seconds,
    )

    _require_status(unauthenticated.status_code, 401, "unauthenticated request")
    _require_status(reviewer.status_code, 200, "reviewer request")
    _require_status(limited.status_code, 403, "limited-role request")
    _require_status(mismatch.status_code, 401, "tenant-mismatch request")
    _require_status(audit_export.status_code, 200, "audit export request")
    _require(
        _audit_events_preserve_tenant(
            audit_export.payload,
            config.identity.expected_tenant,
        ),
        "audit event/export did not preserve the JWT tenant",
    )
    return {
        "status": "passed",
        "mode": "api",
        "unauthenticated_rejected": True,
        "reviewer_allowed": True,
        "limited_role_rejected": True,
        "tenant_mismatch_rejected": True,
        "audit_tenant_preserved": True,
    }


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    api_mode = arguments == ["--api"]
    if arguments and not api_mode:
        print(_json_result({"status": "failed", "error": "unsupported arguments"}))
        return 1
    try:
        result = run_api_from_env(env) if api_mode else run_from_env(env)
    except LiveKeycloakOidcSmokeError as exc:
        print(
            _json_result(
                {
                    "status": "failed",
                    "mode": "api" if api_mode else "verification",
                    "error": _redact_configured_secrets(str(exc), env),
                }
            )
        )
        return 1
    except Exception:
        print(
            _json_result(
                {
                    "status": "failed",
                    "mode": "api" if api_mode else "verification",
                    "error": "unexpected live Keycloak OIDC smoke failure",
                }
            )
        )
        return 1
    print(_json_result(result))
    return 0


def _config_from_env(env: Mapping[str, str]) -> LiveKeycloakOidcSmokeConfig:
    issuer = _required(env, ISSUER_ENV)
    discovery_url = _required(env, DISCOVERY_ENV)
    config = LiveKeycloakOidcSmokeConfig(
        issuer=issuer,
        audience=_required(env, AUDIENCE_ENV),
        discovery_url=discovery_url,
        token_endpoint=token_endpoint_for(issuer),
        subject_claim=_required(env, SUBJECT_CLAIM_ENV),
        reviewer_credentials=ClientCredentials(
            client_id=_required(env, CLIENT_ID_ENV),
            client_secret=_required(env, CLIENT_SECRET_ENV),
        ),
        expected_subject=_required(env, EXPECTED_SUBJECT_ENV),
        expected_tenant=_required(env, EXPECTED_TENANT_ENV),
        required_role=_required(env, REQUIRED_ROLE_ENV),
        http_timeout_seconds=_int_env(env, HTTP_TIMEOUT_ENV, 3),
    )
    _validate_oidc_urls(config)
    return config


def _api_config_from_env(env: Mapping[str, str]) -> LiveKeycloakOidcApiSmokeConfig:
    config = LiveKeycloakOidcApiSmokeConfig(
        identity=_config_from_env(env),
        api_base_url=_required(env, API_BASE_URL_ENV),
        limited_credentials=ClientCredentials(
            client_id=_required(env, LIMITED_CLIENT_ID_ENV),
            client_secret=_required(env, LIMITED_CLIENT_SECRET_ENV),
        ),
        limited_expected_subject=_required(env, LIMITED_EXPECTED_SUBJECT_ENV),
    )
    _validate_http_url(config.api_base_url, require_root=True)
    return config


def _token_minter_for(config: LiveKeycloakOidcSmokeConfig) -> CredentialTokenMinter:
    def mint(credentials: ClientCredentials) -> str:
        return _mint_client_credentials_token(config, credentials)

    return mint


def _mint_client_credentials_token(
    config: LiveKeycloakOidcSmokeConfig,
    credentials: ClientCredentials,
) -> str:
    _validate_oidc_urls(config)
    body = urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
        }
    ).encode("ascii")
    token_request = request.Request(
        config.token_endpoint,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with open_url_no_redirect(
            token_request,
            timeout=config.http_timeout_seconds,
        ) as response:
            raw = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
    except OutboundHttpRedirectError:
        raise LiveKeycloakOidcSmokeError("Keycloak token redirects are not allowed") from None
    except error.HTTPError as exc:
        exc.close()
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token request to Keycloak failed"
        ) from None
    except (error.URLError, TimeoutError, OSError):
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token request to Keycloak failed"
        ) from None
    if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
        raise LiveKeycloakOidcSmokeError("Keycloak token response exceeded the 1 MiB limit")
    try:
        payload: object = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token response is not valid JSON"
        ) from None
    if not isinstance(payload, Mapping):
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token response must be a JSON object"
        )
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token response did not include an access token"
        )
    return access_token


def _validated_claims(
    config: LiveKeycloakOidcSmokeConfig,
    token: str,
    *,
    fetch_json: JsonFetcher | None,
) -> OidcPrincipalClaims:
    settings = _build_settings(config)
    resolver = OidcJwksResolver(settings, fetch_json=fetch_json)
    try:
        jwks = resolver.resolve(force_refresh=True)
        return OidcJwtValidator(settings, jwks).validate(f"Bearer {token}")
    except OidcJwtValidationError:
        raise LiveKeycloakOidcSmokeError(
            "live Keycloak OIDC token validation failed"
        ) from None


def _build_settings(config: LiveKeycloakOidcSmokeConfig) -> Settings:
    return Settings(
        environment="local",
        policy_version="live-keycloak-smoke",
        auth_required=True,
        allowed_workspace=ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer=config.issuer,
        oidc_audience=config.audience,
        oidc_discovery_url=config.discovery_url,
        oidc_subject_claim=config.subject_claim,
        oidc_http_timeout_seconds=config.http_timeout_seconds,
    )


def _require_expected_identity(
    claims: OidcPrincipalClaims,
    *,
    expected_subject: str,
    expected_tenant: str,
    required_role: str,
) -> None:
    _require(
        claims.principal.subject_id == expected_subject,
        "live Keycloak OIDC subject claim did not match the expected subject",
    )
    _require(
        claims.tenant_id == expected_tenant,
        "live Keycloak OIDC tenant claim did not match the expected tenant",
    )
    _require(
        claims.principal.has_role(required_role),
        "live Keycloak OIDC token did not include the required role",
    )


def _bearer_headers(token: str, *, trace_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "x-trace-id": trace_id,
    }


def _audit_events_preserve_tenant(payload: Mapping[str, object], expected_tenant: str) -> bool:
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        return False
    return all(
        isinstance(event, Mapping) and event.get("tenant_id") == expected_tenant
        for event in events
    )


def _require_status(actual: int, expected: int, label: str) -> None:
    _require(actual == expected, f"{label} returned status {actual}; expected {expected}")


def _api_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def _validate_oidc_urls(config: LiveKeycloakOidcSmokeConfig) -> None:
    issuer_origin = _validate_http_url(config.issuer, require_root=False)
    discovery_origin = _validate_http_url(config.discovery_url, require_root=False)
    token_origin = _validate_http_url(config.token_endpoint, require_root=False)
    if issuer_origin != discovery_origin or issuer_origin != token_origin:
        raise LiveKeycloakOidcSmokeError(
            "OIDC issuer, discovery URL, and token endpoint must share one origin"
        )


def _validate_http_url(value: str, *, require_root: bool) -> _CanonicalHttpOrigin:
    if (
        value != value.strip()
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
        or "\\" in value
    ):
        raise LiveKeycloakOidcSmokeError("configured HTTP URL is invalid")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise LiveKeycloakOidcSmokeError("configured HTTP URL is invalid") from None
    if parsed.username is not None or parsed.password is not None:
        raise LiveKeycloakOidcSmokeError("configured HTTP URL must not contain credentials")
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or not hostname.isascii()
        or "%" in parsed.netloc
        or parsed.netloc.endswith(":")
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise LiveKeycloakOidcSmokeError("configured HTTP URL is invalid")
    if parsed.scheme == "http" and hostname not in _EXPLICIT_LOOPBACK_HOSTS:
        raise LiveKeycloakOidcSmokeError(
            "plain HTTP is allowed only for an explicit loopback host"
        )
    if require_root and parsed.path not in {"", "/"}:
        raise LiveKeycloakOidcSmokeError("API base URL must not contain a path")
    canonical_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    return _CanonicalHttpOrigin(parsed.scheme, hostname, canonical_port)


def _skipped_result(mode: str) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "skipped",
        "mode": mode,
        "reason": f"set {ENABLED_ENV}=true to run the live Keycloak OIDC smoke",
    }
    if mode == "verification":
        result.update(
            {
                "subject_verified": False,
                "tenant_verified": False,
                "role_verified": False,
            }
        )
    else:
        result.update(
            {
                "unauthenticated_rejected": False,
                "reviewer_allowed": False,
                "limited_role_rejected": False,
                "tenant_mismatch_rejected": False,
                "audit_tenant_preserved": False,
            }
        )
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LiveKeycloakOidcSmokeError(message)


def _enabled(value: str) -> bool:
    return value.strip().lower() == "true"


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if value is None or not value.strip():
        raise LiveKeycloakOidcSmokeError(f"{name} is required when {ENABLED_ENV}=true")
    return value.strip()


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise LiveKeycloakOidcSmokeError(f"{name} must be an integer") from None
    if value <= 0 or value > 60:
        raise LiveKeycloakOidcSmokeError(f"{name} must be between 1 and 60")
    return value


def _redact_configured_secrets(text: str, env: Mapping[str, str] | None) -> str:
    source = env if env is not None else os.environ
    redacted = text
    for name in (CLIENT_SECRET_ENV, LIMITED_CLIENT_SECRET_ENV):
        secret = source.get(name, "").strip()
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
