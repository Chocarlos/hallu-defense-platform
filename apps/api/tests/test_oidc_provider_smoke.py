from __future__ import annotations

import pytest

from scripts.ci.oidc_provider_smoke import (
    OidcProviderSmokeError,
    run_smoke,
)
from test_oidc_jwt import _jwks, _jwt


def test_oidc_provider_smoke_skips_when_not_enabled() -> None:
    result = run_smoke({})

    assert result.status == "skipped"
    assert "skipped" in result.message


def test_oidc_provider_smoke_requires_jwt_when_enabled() -> None:
    with pytest.raises(OidcProviderSmokeError, match="SMOKE_JWT"):
        run_smoke(
            {
                "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED": "true",
                "HALLU_DEFENSE_OIDC_ISSUER": "https://issuer.example",
                "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
                "HALLU_DEFENSE_OIDC_JWKS_URL": "https://issuer.example/jwks.json",
            }
        )


def test_oidc_provider_smoke_validates_discovery_jwks_and_jwt() -> None:
    calls: list[str] = []
    env = {
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED": "true",
        "HALLU_DEFENSE_OIDC_ISSUER": "https://issuer.example",
        "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
        "HALLU_DEFENSE_OIDC_DISCOVERY_URL": "https://issuer.example/.well-known/openid-configuration",
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT": _jwt({"exp": 4102444800}),
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_SUBJECT": "user-1",
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_TENANT": "tenant-a",
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_REQUIRED_ROLE": "verifier",
    }

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": "https://issuer.example",
                "jwks_uri": "https://issuer.example/keys/jwks.json",
            }
        return _jwks()

    result = run_smoke(env, fetch_json=fetch_json)

    assert result.status == "passed"
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/keys/jwks.json",
    ]


def test_oidc_provider_smoke_rejects_expected_subject_mismatch() -> None:
    env = {
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED": "true",
        "HALLU_DEFENSE_OIDC_ISSUER": "https://issuer.example",
        "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
        "HALLU_DEFENSE_OIDC_JWKS_URL": "https://issuer.example/jwks.json",
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT": _jwt({"exp": 4102444800}),
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_SUBJECT": "other-user",
    }

    with pytest.raises(OidcProviderSmokeError, match="subject"):
        run_smoke(env, fetch_json=lambda url, timeout_seconds: _jwks())


def test_oidc_provider_smoke_rejects_insecure_remote_url() -> None:
    env = {
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED": "true",
        "HALLU_DEFENSE_OIDC_ISSUER": "https://issuer.example",
        "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
        "HALLU_DEFENSE_OIDC_JWKS_URL": "http://issuer.example/jwks.json",
        "HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT": _jwt({"exp": 4102444800}),
    }

    with pytest.raises(OidcProviderSmokeError, match="https"):
        run_smoke(env, fetch_json=lambda url, timeout_seconds: _jwks())
