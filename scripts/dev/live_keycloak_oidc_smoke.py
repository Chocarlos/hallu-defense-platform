"""Live Keycloak OIDC smoke for the ``oidc_jwt`` authentication path.

This mirrors the other ``scripts/dev/live_*_smoke.py`` scripts: skip-by-default,
``client_secret`` redacted in every output, and driven end-to-end offline by
injected fakes (a ``token_minter`` plus a ``fetch_json``) so the module is
exercised without a running Keycloak. The real (``ENABLED_ENV=true``) path is
live-pending: it needs a Keycloak reachable at the configured issuer and is
validated in the Docker/Keycloak environment provisioned by the compose/realm
work.

Two modes are provided:

``run_from_env`` (verification)
    Mint a ``client_credentials`` access token from Keycloak's token endpoint and
    verify it locally with :class:`OidcJwtValidator` against the JWKS resolved
    from discovery. Asserts the expected subject/tenant/role claims. Offline the
    token is provided by an injected ``token_minter`` and the JWKS by an injected
    ``fetch_json``; live the token is minted over urllib and the JWKS fetched over
    the network.

``run_api_from_env`` / ``run_api_checks`` (``--api``)
    Drive the FastAPI app in-process with :class:`TestClient` (no uvicorn), with
    discovery/JWKS pointing at Keycloak. Asserts an ``approval_reviewer`` token is
    authorised for ``POST /approvals/list`` (200), that a wrong-audience token and
    an expired token are rejected with 401, and that the token tenant claim
    propagates to the audit export when no ``x-tenant-id`` header is supplied. The
    negative-code assertions require a signer whose key matches the resolved
    JWKS, so they are validated offline with the injected keypair; the live api
    path covers the positive check and tenant propagation with a real token.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings  # noqa: E402
from hallu_defense.services.audit import AuditLedger  # noqa: E402
from hallu_defense.services.oidc import (  # noqa: E402
    JsonFetcher,
    OidcJwksResolver,
    OidcJwtValidationError,
    OidcJwtValidator,
)

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

ENABLED_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_SMOKE_ENABLED"
ISSUER_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_ISSUER"
AUDIENCE_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_AUDIENCE"
DISCOVERY_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_DISCOVERY_URL"
CLIENT_ID_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_CLIENT_ID"
CLIENT_SECRET_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_CLIENT_SECRET"
EXPECTED_SUBJECT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_SUBJECT"
EXPECTED_TENANT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_EXPECTED_TENANT"
REQUIRED_ROLE_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_REQUIRED_ROLE"
HTTP_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_KEYCLOAK_OIDC_HTTP_TIMEOUT_SECONDS"

API_CASE_VALID_REVIEWER = "valid_reviewer"
API_CASE_WRONG_AUDIENCE = "wrong_audience"
API_CASE_EXPIRED = "expired"
API_CASE_TENANT = "tenant"

_MAX_TOKEN_BYTES = 1_048_576
_API_PROBE_TRACE_ID = "tr_live_keycloak_oidc_probe"
_API_TENANT_TRACE_ID = "tr_live_keycloak_oidc_tenant"

TokenMinter = Callable[[], str]
ApiTokenFactory = Callable[[str], str]


class LiveKeycloakOidcSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveKeycloakOidcSmokeConfig:
    issuer: str
    audience: str
    discovery_url: str
    token_endpoint: str
    client_id: str | None = None
    client_secret: str | None = None
    expected_subject: str | None = None
    expected_tenant: str | None = None
    required_role: str | None = None
    http_timeout_seconds: int = 3


def token_endpoint_for(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/token"


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    fetch_json: JsonFetcher | None = None,
    token_minter: TokenMinter | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "mode": "verification",
            "reason": f"set {ENABLED_ENV}=true to run the live keycloak oidc smoke",
            "issuer": _optional(effective_env, ISSUER_ENV) or "",
            "subject_verified": False,
            "tenant_verified": False,
            "role_verified": False,
        }

    config = _config_from_env(effective_env, require_client_credentials=token_minter is None)
    minter = token_minter or _build_default_token_minter(config)
    return _run_verification(config, minter, fetch_json=fetch_json)


def run_api_from_env(
    env: Mapping[str, str] | None = None,
    *,
    fetch_json: JsonFetcher | None = None,
    token_factory: ApiTokenFactory | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "mode": "api",
            "reason": f"set {ENABLED_ENV}=true to run the live keycloak oidc api smoke",
            "approval_reviewer_allowed": False,
            "wrong_audience_rejected": False,
            "expired_rejected": False,
            "tenant_propagated": False,
        }

    if token_factory is not None:
        config = _config_from_env(effective_env, require_client_credentials=False)
        return run_api_checks(config=config, token_factory=token_factory, fetch_json=fetch_json)

    config = _config_from_env(effective_env, require_client_credentials=True)
    return _run_live_api_positive(config, fetch_json=fetch_json)


def run_api_checks(
    *,
    config: LiveKeycloakOidcSmokeConfig,
    token_factory: ApiTokenFactory,
    fetch_json: JsonFetcher | None = None,
    workspace: Path | None = None,
) -> dict[str, object]:
    """Assert the four OIDC RBAC/auth outcomes against the in-process API.

    ``token_factory`` mints a token per case key and must sign with a key that
    matches the resolved JWKS, so that wrong-audience and expired tokens fail for
    the intended reason (not merely on signature). Offline this is the embedded
    unit keypair; live wiring is validated in the Keycloak environment.
    """
    _require(
        config.expected_tenant is not None,
        "expected tenant is required for the api tenant-propagation check",
    )
    from fastapi.testclient import TestClient
    from hallu_defense.main import app

    settings = _build_settings(config, workspace=workspace)
    resolver = OidcJwksResolver(settings, fetch_json=fetch_json)
    ledger = AuditLedger()

    with _installed_oidc_dependencies(settings, resolver, ledger):
        client = TestClient(app)
        valid_code = _post_approvals_list(client, token_factory(API_CASE_VALID_REVIEWER))
        wrong_audience_code = _post_approvals_list(client, token_factory(API_CASE_WRONG_AUDIENCE))
        expired_code = _post_approvals_list(client, token_factory(API_CASE_EXPIRED))
        tenant_propagated = _check_tenant_propagation(
            client,
            ledger,
            token_factory(API_CASE_TENANT),
            config.expected_tenant,
        )

    _require(valid_code == 200, f"approval_reviewer token was not authorised (status {valid_code})")
    _require(
        wrong_audience_code == 401,
        f"wrong-audience token was not rejected with 401 (status {wrong_audience_code})",
    )
    _require(
        expired_code == 401,
        f"expired token was not rejected with 401 (status {expired_code})",
    )
    _require(tenant_propagated, "token tenant claim did not propagate to the audit export")
    return {
        "status": "passed",
        "mode": "api",
        "approval_reviewer_allowed": True,
        "wrong_audience_rejected": True,
        "expired_rejected": True,
        "tenant_propagated": True,
    }


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    api_mode = "--api" in arguments
    try:
        result = run_api_from_env(env) if api_mode else run_from_env(env)
    except Exception as exc:
        failure: dict[str, object] = {
            "status": "failed",
            "mode": "api" if api_mode else "verification",
            "error": _redact_client_secret(str(exc), env),
        }
        print(_json_result(failure))
        return 1
    print(_json_result(result))
    return 0


def _run_verification(
    config: LiveKeycloakOidcSmokeConfig,
    minter: TokenMinter,
    *,
    fetch_json: JsonFetcher | None,
) -> dict[str, object]:
    token = minter()
    settings = _build_settings(config)
    resolver = OidcJwksResolver(settings, fetch_json=fetch_json)
    try:
        jwks = resolver.resolve(force_refresh=True)
        claims = OidcJwtValidator(settings, jwks).validate(f"Bearer {token}")
    except OidcJwtValidationError as exc:
        raise LiveKeycloakOidcSmokeError(
            f"live keycloak oidc token validation failed: {exc}"
        ) from exc

    subject_verified = (
        config.expected_subject is None
        or claims.principal.subject_id == config.expected_subject
    )
    tenant_verified = config.expected_tenant is None or claims.tenant_id == config.expected_tenant
    role_verified = config.required_role is None or claims.principal.has_role(config.required_role)
    _require(subject_verified, "live keycloak oidc subject claim did not match the expected subject")
    _require(tenant_verified, "live keycloak oidc tenant claim did not match the expected tenant")
    _require(role_verified, "live keycloak oidc token did not include the required role")

    return {
        "status": "passed",
        "mode": "verification",
        "issuer": config.issuer,
        "subject": claims.principal.subject_id,
        "tenant": claims.tenant_id,
        "roles": sorted(claims.principal.roles),
        "subject_verified": True,
        "tenant_verified": True,
        "role_verified": True,
    }


def _run_live_api_positive(
    config: LiveKeycloakOidcSmokeConfig,
    *,
    fetch_json: JsonFetcher | None,
) -> dict[str, object]:
    _require(
        config.expected_tenant is not None,
        "expected tenant is required for the api tenant-propagation check",
    )
    from fastapi.testclient import TestClient
    from hallu_defense.main import app

    minted_token = _mint_client_credentials_token(config)
    settings = _build_settings(config)
    resolver = OidcJwksResolver(settings, fetch_json=fetch_json)
    ledger = AuditLedger()

    with _installed_oidc_dependencies(settings, resolver, ledger):
        client = TestClient(app)
        valid_code = _post_approvals_list(client, minted_token)
        tenant_propagated = _check_tenant_propagation(
            client, ledger, minted_token, config.expected_tenant
        )

    _require(valid_code == 200, f"approval_reviewer token was not authorised (status {valid_code})")
    _require(tenant_propagated, "token tenant claim did not propagate to the audit export")
    return {
        "status": "passed",
        "mode": "api",
        "approval_reviewer_allowed": True,
        "tenant_propagated": True,
        "wrong_audience_rejected": None,
        "expired_rejected": None,
        "note": (
            "negative-audience and expired rejections are validated offline; "
            "live api mode covers the positive path and tenant propagation"
        ),
    }


@contextmanager
def _installed_oidc_dependencies(
    settings: Settings,
    resolver: OidcJwksResolver,
    ledger: AuditLedger,
) -> Iterator[None]:
    import hallu_defense.api.dependencies as dependencies
    import hallu_defense.api.middleware as api_middleware

    saved_settings = dependencies.settings
    saved_resolver = dependencies._oidc_resolver
    saved_resolver_settings = dependencies._oidc_resolver_settings
    # ``audit_ledger`` is imported into the middleware module (not re-exported),
    # so it is swapped via getattr/setattr rather than direct attribute access.
    saved_ledger = getattr(api_middleware, "audit_ledger")
    dependencies.settings = settings
    dependencies._oidc_resolver = resolver
    dependencies._oidc_resolver_settings = settings
    setattr(api_middleware, "audit_ledger", ledger)
    try:
        yield
    finally:
        dependencies.settings = saved_settings
        dependencies._oidc_resolver = saved_resolver
        dependencies._oidc_resolver_settings = saved_resolver_settings
        setattr(api_middleware, "audit_ledger", saved_ledger)


def _post_approvals_list(client: TestClient, token: str) -> int:
    response = client.post(
        "/approvals/list",
        json={},
        headers={"Authorization": f"Bearer {token}", "x-trace-id": _API_PROBE_TRACE_ID},
    )
    status_code: int = response.status_code
    return status_code


def _check_tenant_propagation(
    client: TestClient,
    ledger: AuditLedger,
    token: str,
    expected_tenant: str | None,
) -> bool:
    response = client.post(
        "/approvals/list",
        json={},
        headers={"Authorization": f"Bearer {token}", "x-trace-id": _API_TENANT_TRACE_ID},
    )
    if response.status_code != 200:
        return False
    events = ledger.export_events(trace_id=_API_TENANT_TRACE_ID)
    return bool(events) and all(event.tenant_id == expected_tenant for event in events)


def _build_settings(
    config: LiveKeycloakOidcSmokeConfig,
    *,
    workspace: Path | None = None,
) -> Settings:
    return Settings(
        environment="local",
        policy_version="live-keycloak-smoke",
        auth_required=True,
        allowed_workspace=workspace or ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer=config.issuer,
        oidc_audience=config.audience,
        oidc_discovery_url=config.discovery_url,
        oidc_http_timeout_seconds=config.http_timeout_seconds,
    )


def _config_from_env(
    env: Mapping[str, str],
    *,
    require_client_credentials: bool,
) -> LiveKeycloakOidcSmokeConfig:
    issuer = _required(env, ISSUER_ENV)
    audience = _required(env, AUDIENCE_ENV)
    discovery_url = _required(env, DISCOVERY_ENV)
    client_id = _optional(env, CLIENT_ID_ENV)
    client_secret = _optional(env, CLIENT_SECRET_ENV)
    if require_client_credentials and (client_id is None or client_secret is None):
        raise LiveKeycloakOidcSmokeError(
            f"{CLIENT_ID_ENV} and {CLIENT_SECRET_ENV} are required to mint a "
            "live client-credentials token"
        )
    return LiveKeycloakOidcSmokeConfig(
        issuer=issuer,
        audience=audience,
        discovery_url=discovery_url,
        token_endpoint=token_endpoint_for(issuer),
        client_id=client_id,
        client_secret=client_secret,
        expected_subject=_optional(env, EXPECTED_SUBJECT_ENV),
        expected_tenant=_optional(env, EXPECTED_TENANT_ENV),
        required_role=_optional(env, REQUIRED_ROLE_ENV),
        http_timeout_seconds=_int_env(env, HTTP_TIMEOUT_ENV, 3),
    )


def _build_default_token_minter(config: LiveKeycloakOidcSmokeConfig) -> TokenMinter:
    def mint() -> str:
        return _mint_client_credentials_token(config)

    return mint


def _mint_client_credentials_token(config: LiveKeycloakOidcSmokeConfig) -> str:
    if not config.client_id or not config.client_secret:
        raise LiveKeycloakOidcSmokeError(
            "client id and secret are required to mint a client-credentials token"
        )
    body = urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }
    ).encode("ascii")
    request = Request(
        config.token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urlopen(request, timeout=config.http_timeout_seconds) as response:
            raw = response.read(_MAX_TOKEN_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token request to Keycloak failed"
        ) from exc
    if len(raw) > _MAX_TOKEN_BYTES:
        raise LiveKeycloakOidcSmokeError("client-credentials token response is too large")
    try:
        payload: object = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token response is not valid JSON"
        ) from exc
    if not isinstance(payload, Mapping):
        raise LiveKeycloakOidcSmokeError("client-credentials token response must be a JSON object")
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise LiveKeycloakOidcSmokeError(
            "client-credentials token response did not include an access_token"
        )
    return access_token


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LiveKeycloakOidcSmokeError(message)


def _enabled(value: str) -> bool:
    return value.strip().lower() == "true"


def _required(env: Mapping[str, str], name: str) -> str:
    value = _optional(env, name)
    if value is None:
        raise LiveKeycloakOidcSmokeError(f"{name} is required when {ENABLED_ENV}=true.")
    return value


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LiveKeycloakOidcSmokeError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise LiveKeycloakOidcSmokeError(f"{name} must be positive.")
    return parsed


def _redact_client_secret(text: str, env: Mapping[str, str] | None) -> str:
    source = env if env is not None else os.environ
    secret = source.get(CLIENT_SECRET_ENV, "").strip()
    if secret and secret in text:
        return text.replace(secret, "***")
    return text


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
