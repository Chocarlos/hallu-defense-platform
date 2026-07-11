from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from hallu_defense.api import dependencies
from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings
from hallu_defense.services.oidc import (
    OidcJwksResolver,
    OidcJwtValidationError,
    OidcJwtValidator,
    load_jwks,
)

_TEST_RSA_N_B64 = (
    "1qvbNpcUYXFHZMZhfty9kEMgkQI0MD_1lirbD7rxXbnLIJ39LMFxgJl6bb9Cb-LyUCOXSNPT80u4II"
    "_Fo11ZbdDevU4ltHtyo29YoFQ3l_BnOKknMbOf6kFMEj8GSLANcG767LzGgA598Gnvq4t4Za8kqBA"
    "kXsBTHUTG4WAWEyJKLpISB3ZYjqBatyZtb28KHFKJOnEZRO5phhPEtcS20JSO57vsAT-gA41Jv4Wy"
    "rdltS6xkf0zu2bfmIAbW7Ix9x55MiWxIftOLa-vsWHIPK_6bNCUckWQ_Y9pDxFIbCBcoUaqmTwID"
    "yxLJKvzLyXlltae_-QpSUnCICYb8DXp6lQ"
)
_TEST_RSA_E_B64 = "AQAB"
_TEST_RSA_D_B64 = (
    "u6hb5yrGzC_EY1nwHIBGzfeAXoL4sD0ZKH6qJOQc3vvtj8PMb_VijTKdjZamMzzG6jtSon1aSNKm"
    "UQCdmqOd65utOvs3hsBrhGdvqCg2uQGUmjl0Y8RMRPFz2HdzvNL5zJGXlJ-pPoRsn19b_i_bvbgP"
    "aUNDJ_kkLu_Sk231nh6-0vzu7r_JZaLS2B8OP3KNyzzz3iZGB1FONtUKY-0EMPy4kh_eccNQxlTd"
    "ypZKPmO7omJpNq3GV7BYYSAvkPCy2Uqgtbcj-NeCZQ0TWpQZmHbPVqjM-x-ANsKCoumXlrIeuEI"
    "Og95BKvXpJ_BjDwzN8jQUwhD658hioJM71QutuQ"
)
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _settings(jwks_path: Path | None = None, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": True,
        "allowed_workspace": Path("."),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
        "auth_claims_mode": AUTH_CLAIMS_MODE_OIDC_JWT,
        "oidc_issuer": "https://issuer.example",
        "oidc_audience": "hallu-defense-api",
        "oidc_jwks_path": jwks_path,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_oidc_validator_accepts_valid_rs256_jwt(tmp_path: Path) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt()

    claims = OidcJwtValidator(_settings(jwks_path), load_jwks(jwks_path)).validate(
        f"Bearer {signed_jwt}",
        current_time_seconds=2000,
    )

    assert claims.tenant_id == "tenant-a"
    assert claims.principal.subject_id == "user-1"
    assert claims.principal.has_role("verifier")
    assert claims.principal.has_role("auditor")


def test_oidc_validator_rejects_tampered_signature(tmp_path: Path) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt()
    tampered = signed_jwt[:-1] + ("A" if signed_jwt[-1] != "A" else "B")

    with pytest.raises(OidcJwtValidationError, match="signature"):
        OidcJwtValidator(_settings(jwks_path), load_jwks(jwks_path)).validate(
            f"Bearer {tampered}",
            current_time_seconds=2000,
        )


def test_oidc_validator_rejects_wrong_issuer(tmp_path: Path) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt({"iss": "https://other-issuer.example"})

    with pytest.raises(OidcJwtValidationError, match="issuer"):
        OidcJwtValidator(_settings(jwks_path), load_jwks(jwks_path)).validate(
            f"Bearer {signed_jwt}",
            current_time_seconds=2000,
        )


def test_oidc_validator_rejects_expired_token(tmp_path: Path) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt({"exp": 1900})

    with pytest.raises(OidcJwtValidationError, match="expired"):
        OidcJwtValidator(_settings(jwks_path), load_jwks(jwks_path)).validate(
            f"Bearer {signed_jwt}",
            current_time_seconds=2000,
        )


def test_oidc_request_context_derives_principal_and_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt({"exp": 4102444800})
    monkeypatch.setattr(dependencies, "settings", _settings(jwks_path))

    context = dependencies.get_request_context(
        request=_request(),
        x_tenant_id="tenant-a",
        authorization=f"Bearer {signed_jwt}",
    )

    assert context.tenant_id == "tenant-a"
    assert context.principal.subject_id == "user-1"
    assert context.principal.has_role("verifier")


def test_oidc_request_context_rejects_tenant_header_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jwks_path = _write_jwks(tmp_path)
    signed_jwt = _jwt({"exp": 4102444800})
    monkeypatch.setattr(dependencies, "settings", _settings(jwks_path))

    with pytest.raises(HTTPException) as exc_info:
        dependencies.get_request_context(
            request=_request(),
            x_tenant_id="tenant-b",
            authorization=f"Bearer {signed_jwt}",
        )

    assert exc_info.value.status_code == 401


def test_oidc_jwks_resolver_fetches_and_caches_remote_jwks() -> None:
    calls: list[tuple[str, int]] = []
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
        oidc_jwks_cache_ttl_seconds=60,
        oidc_http_timeout_seconds=7,
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        calls.append((url, timeout_seconds))
        return _jwks()

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: 1000.0)

    assert resolver.resolve() == _jwks()
    assert resolver.resolve() == _jwks()
    assert calls == [("https://issuer.example/jwks.json", 7)]


def test_oidc_jwks_resolver_refreshes_after_cache_ttl() -> None:
    calls: list[str] = []
    now = 1000.0
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
        oidc_jwks_cache_ttl_seconds=5,
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        calls.append(url)
        return _jwks()

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: now)

    resolver.resolve()
    now = 1004.0
    resolver.resolve()
    now = 1006.0
    resolver.resolve()

    assert calls == ["https://issuer.example/jwks.json", "https://issuer.example/jwks.json"]


def test_oidc_unknown_kid_refresh_is_single_flight_and_globally_cooled_down() -> None:
    calls: list[str] = []
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
        oidc_jwks_cache_ttl_seconds=60,
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        del timeout_seconds
        calls.append(url)
        return _jwks()

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: 1000.0)
    resolver.resolve()

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(
            executor.map(
                resolver.resolve_unknown_kid,
                [f"attacker-kid-{index}" for index in range(64)],
            )
        )

    assert all(result == _jwks() for result in results)
    assert calls == [
        "https://issuer.example/jwks.json",
        "https://issuer.example/jwks.json",
    ]


def test_oidc_unknown_kids_do_not_amplify_failed_forced_refresh() -> None:
    calls = 0
    fail = False
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
        oidc_jwks_cache_ttl_seconds=60,
    )

    def fetch_json(_url: str, _timeout_seconds: int) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if fail:
            raise OidcJwtValidationError("simulated JWKS outage")
        return _jwks()

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: 1000.0)
    resolver.resolve()
    fail = True

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(
            executor.map(
                resolver.resolve_unknown_kid,
                [f"outage-kid-{index}" for index in range(64)],
            )
        )

    assert all(result == _jwks() for result in results)
    assert calls == 2
    assert len(resolver._negative_kids) == 64


def test_oidc_legitimate_rotation_refreshes_after_unknown_kid_cooldown() -> None:
    now = 1000.0
    active_kid = "old-key"
    calls = 0
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
        oidc_jwks_cache_ttl_seconds=60,
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        nonlocal calls
        del url, timeout_seconds
        calls += 1
        payload = _jwks()
        keys = payload["keys"]
        assert isinstance(keys, list)
        keys[0] = {**keys[0], "kid": active_kid}
        return payload

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: now)
    resolver.resolve()
    resolver.resolve_unknown_kid("rotated-key")
    active_kid = "rotated-key"
    now = 1004.0
    assert not any(
        key.get("kid") == "rotated-key"
        for key in resolver.resolve_unknown_kid("rotated-key")["keys"]
    )
    now = 1006.0

    rotated = resolver.resolve_unknown_kid("rotated-key")

    assert any(key.get("kid") == "rotated-key" for key in rotated["keys"])
    assert calls == 3


def test_oidc_negative_kid_cache_is_bounded() -> None:
    settings = _settings(
        jwks_path=None,
        oidc_jwks_url="https://issuer.example/jwks.json",
    )
    resolver = OidcJwksResolver(
        settings,
        fetch_json=lambda _url, _timeout: _jwks(),
        clock=lambda: 1000.0,
    )
    resolver.resolve()

    for index in range(400):
        resolver.resolve_unknown_kid(f"random-kid-{index}")

    assert len(resolver._negative_kids) == 256


def test_oidc_jwks_resolver_discovers_jwks_uri() -> None:
    calls: list[str] = []
    settings = _settings(
        jwks_path=None,
        oidc_discovery_url="https://issuer.example/.well-known/openid-configuration",
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": "https://issuer.example",
                "jwks_uri": "https://issuer.example/keys/jwks.json",
            }
        return _jwks()

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json, clock=lambda: 1000.0)

    assert resolver.resolve() == _jwks()
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/keys/jwks.json",
    ]


def test_oidc_jwks_resolver_rejects_plaintext_discovered_jwks_in_production() -> None:
    settings = _settings(
        jwks_path=None,
        environment="production",
        oidc_discovery_url="https://issuer.example/.well-known/openid-configuration",
        outbound_https_allowed_origins=(
            "https://issuer.example",
            "https://jwks.internal",
        ),
    )

    def fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
        assert url.startswith("https://")
        return {
            "issuer": "https://issuer.example",
            "jwks_uri": "http://jwks.internal/keys.json",
        }

    resolver = OidcJwksResolver(settings, fetch_json=fetch_json)

    with pytest.raises(OidcJwtValidationError, match="HTTPS"):
        resolver.resolve()


def test_oidc_request_context_refreshes_jwks_on_unknown_kid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_jwt = _jwt({"exp": 4102444800})
    settings = _settings(jwks_path=None, oidc_jwks_url="https://issuer.example/jwks.json")
    resolver = _RotatingResolver()
    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(dependencies, "_oidc_jwks_resolver", lambda: resolver)

    context = dependencies.get_request_context(
        request=_request(),
        x_tenant_id="tenant-a",
        authorization=f"Bearer {signed_jwt}",
    )

    assert context.principal.subject_id == "user-1"
    assert resolver.force_refresh_calls == [False]
    assert resolver.unknown_kids == ["unit-key"]


class _RotatingResolver:
    def __init__(self) -> None:
        self.force_refresh_calls: list[bool] = []
        self.unknown_kids: list[str] = []

    def resolve(self, *, force_refresh: bool = False) -> dict[str, object]:
        self.force_refresh_calls.append(force_refresh)
        if force_refresh:
            return _jwks()
        stale = _jwks()
        keys = stale["keys"]
        assert isinstance(keys, list)
        stale_key = dict(keys[0])
        stale_key["kid"] = "stale-key"
        stale["keys"] = [stale_key]
        return stale

    def resolve_unknown_kid(self, kid: str) -> dict[str, object]:
        self.unknown_kids.append(kid)
        return _jwks()


def _request() -> Request:
    return Request({"type": "http", "headers": []})


def _write_jwks(tmp_path: Path) -> Path:
    jwks = _jwks()
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps(jwks), encoding="utf-8")
    return jwks_path


def _jwks() -> dict[str, object]:
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "unit-key",
                "use": "sig",
                "alg": "RS256",
                "n": _TEST_RSA_N_B64,
                "e": _TEST_RSA_E_B64,
            }
        ]
    }


def _jwt(overrides: dict[str, object] | None = None) -> str:
    header: dict[str, object] = {"alg": "RS256", "kid": "unit-key", "typ": "JWT"}
    payload: dict[str, object] = {
        "iss": "https://issuer.example",
        "aud": "hallu-defense-api",
        "sub": "user-1",
        "roles": ["verifier", "auditor"],
        "tenant_id": "tenant-a",
        "iat": 1900,
        "nbf": 1900,
        "exp": 2300,
    }
    payload.update(overrides or {})
    signing_input = f"{_b64url_json(header)}.{_b64url_json(payload)}".encode("ascii")
    signature = _sign_rs256(signing_input)
    return f"{signing_input.decode('ascii')}.{_b64url_bytes(signature)}"


def _sign_rs256(signing_input: bytes) -> bytes:
    n = _b64url_int(_TEST_RSA_N_B64)
    d = _b64url_int(_TEST_RSA_D_B64)
    size_bytes = (n.bit_length() + 7) // 8
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding_length = size_bytes - len(digest_info) - 3
    if padding_length < 8:
        raise AssertionError("Test RSA key is too small for RS256.")
    encoded_message = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    signature_int = pow(int.from_bytes(encoded_message, "big"), d, n)
    return signature_int.to_bytes(size_bytes, "big")


def _b64url_json(payload: dict[str, object]) -> str:
    return _b64url_bytes(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64url_int(value: str) -> int:
    padding_length = (-len(value)) % 4
    return int.from_bytes(base64.urlsafe_b64decode(value + ("=" * padding_length)), "big")


def _b64url_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
