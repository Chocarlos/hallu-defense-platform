from __future__ import annotations

import json

import pytest

from scripts.dev import live_keycloak_oidc_smoke as smoke
from test_oidc_jwt import _jwks, _jwt

_ISSUER = "https://issuer.example"
_AUDIENCE = "hallu-defense-api"
_DISCOVERY = "https://issuer.example/.well-known/openid-configuration"
_JWKS_URI = "https://issuer.example/jwks.json"
# Short placeholder (never a real secret, < 16 chars so the secret scanner does
# not flag this file). It proves client_secret redaction: it must never survive
# into any emitted result.
_CLIENT_SECRET = "local-dev-only"


def _discovery_fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
    if url.endswith("/.well-known/openid-configuration"):
        return {"issuer": _ISSUER, "jwks_uri": _JWKS_URI}
    return dict(_jwks())


def _api_token_factory(case: str) -> str:
    if case == smoke.API_CASE_WRONG_AUDIENCE:
        return _jwt({"aud": "wrong-audience", "exp": 4102444800, "roles": ["approval_reviewer"]})
    if case == smoke.API_CASE_EXPIRED:
        return _jwt({"exp": 1900, "roles": ["approval_reviewer"]})
    return _jwt({"exp": 4102444800, "roles": ["approval_reviewer"]})


def _enabled_verification_env() -> dict[str, str]:
    return {
        smoke.ENABLED_ENV: "true",
        smoke.ISSUER_ENV: _ISSUER,
        smoke.AUDIENCE_ENV: _AUDIENCE,
        smoke.DISCOVERY_ENV: _DISCOVERY,
        smoke.EXPECTED_SUBJECT_ENV: "user-1",
        smoke.EXPECTED_TENANT_ENV: "tenant-a",
        smoke.REQUIRED_ROLE_ENV: "verifier",
    }


def test_skips_by_default_without_exposing_client_secret() -> None:
    result = smoke.run_from_env({smoke.CLIENT_SECRET_ENV: _CLIENT_SECRET})

    assert result["status"] == "skipped"
    assert result["mode"] == "verification"
    assert result["subject_verified"] is False
    assert result["tenant_verified"] is False
    assert result["role_verified"] is False
    assert _CLIENT_SECRET not in json.dumps(result)


def test_enabled_path_verifies_token_offline_with_injected_fakes() -> None:
    result = smoke.run_from_env(
        _enabled_verification_env(),
        token_minter=lambda: _jwt({"roles": ["verifier", "auditor"], "exp": 4102444800}),
        fetch_json=_discovery_fetch_json,
    )

    assert result["status"] == "passed"
    assert result["subject"] == "user-1"
    assert result["tenant"] == "tenant-a"
    assert result["subject_verified"] is True
    assert result["tenant_verified"] is True
    assert result["role_verified"] is True
    roles = result["roles"]
    assert isinstance(roles, list)
    assert "verifier" in roles


def test_enabled_path_rejects_subject_mismatch() -> None:
    env = _enabled_verification_env()
    env[smoke.EXPECTED_SUBJECT_ENV] = "other-user"

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="subject"):
        smoke.run_from_env(
            env,
            token_minter=lambda: _jwt({"roles": ["verifier"], "exp": 4102444800}),
            fetch_json=_discovery_fetch_json,
        )


def test_enabled_path_rejects_required_role_absent() -> None:
    env = _enabled_verification_env()
    env[smoke.REQUIRED_ROLE_ENV] = "approval_reviewer"

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="required role"):
        smoke.run_from_env(
            env,
            token_minter=lambda: _jwt({"roles": ["verifier"], "exp": 4102444800}),
            fetch_json=_discovery_fetch_json,
        )


def test_enabled_path_propagates_token_minter_failure() -> None:
    def _boom() -> str:
        raise smoke.LiveKeycloakOidcSmokeError("mint exploded")

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="mint exploded"):
        smoke.run_from_env(
            {
                smoke.ENABLED_ENV: "true",
                smoke.ISSUER_ENV: _ISSUER,
                smoke.AUDIENCE_ENV: _AUDIENCE,
                smoke.DISCOVERY_ENV: _DISCOVERY,
            },
            token_minter=_boom,
        )


def test_api_checks_enforce_oidc_auth_and_rbac_offline() -> None:
    config = smoke.LiveKeycloakOidcSmokeConfig(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        discovery_url=_DISCOVERY,
        token_endpoint=smoke.token_endpoint_for(_ISSUER),
        expected_tenant="tenant-a",
    )

    result = smoke.run_api_checks(
        config=config,
        token_factory=_api_token_factory,
        fetch_json=_discovery_fetch_json,
    )

    assert result == {
        "status": "passed",
        "mode": "api",
        "approval_reviewer_allowed": True,
        "wrong_audience_rejected": True,
        "expired_rejected": True,
        "tenant_propagated": True,
    }


def test_api_from_env_skips_by_default() -> None:
    result = smoke.run_api_from_env({})

    assert result["status"] == "skipped"
    assert result["mode"] == "api"
    assert result["approval_reviewer_allowed"] is False


def test_api_from_env_enabled_runs_checks_with_injected_factory() -> None:
    env = {
        smoke.ENABLED_ENV: "true",
        smoke.ISSUER_ENV: _ISSUER,
        smoke.AUDIENCE_ENV: _AUDIENCE,
        smoke.DISCOVERY_ENV: _DISCOVERY,
        smoke.EXPECTED_TENANT_ENV: "tenant-a",
    }

    result = smoke.run_api_from_env(
        env,
        token_factory=_api_token_factory,
        fetch_json=_discovery_fetch_json,
    )

    assert result["status"] == "passed"
    assert result["wrong_audience_rejected"] is True
    assert result["expired_rejected"] is True
    assert result["tenant_propagated"] is True


def test_redacts_client_secret_from_text() -> None:
    redacted = smoke._redact_client_secret(
        f"boom {_CLIENT_SECRET} tail",
        {smoke.CLIENT_SECRET_ENV: _CLIENT_SECRET},
    )

    assert _CLIENT_SECRET not in redacted
    assert "***" in redacted


def test_main_prints_skip_json_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
    assert payload["mode"] == "verification"


def test_main_api_mode_skip_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(["--api"], env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
    assert payload["mode"] == "api"


def test_main_reports_failure_when_client_credentials_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = smoke.main(
        env={
            smoke.ENABLED_ENV: "true",
            smoke.ISSUER_ENV: _ISSUER,
            smoke.AUDIENCE_ENV: _AUDIENCE,
            smoke.DISCOVERY_ENV: _DISCOVERY,
        }
    )

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert isinstance(payload["error"], str) and payload["error"]
