from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.dev import live_keycloak_oidc_smoke as smoke
from test_oidc_jwt import _jwks, _jwt

_ISSUER = "https://issuer.example"
_AUDIENCE = "hallu-defense-api"
_DISCOVERY = "https://issuer.example/.well-known/openid-configuration"
_JWKS_URI = "https://issuer.example/jwks.json"
_CLIENT_SECRET = "dev-only"
_LIMITED_SECRET = "limited-only"
_REVIEWER_TOKEN = _jwt(
    {
        "azp": "hallu-defense-api",
        "roles": ["approval_reviewer", "auditor"],
        "exp": 4102444800,
    }
)
_LIMITED_TOKEN = _jwt(
    {
        "azp": "hallu-defense-limited",
        "roles": ["verifier"],
        "exp": 4102444800,
    }
)


class StubApiClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: int,
    ) -> smoke.JsonHttpResponse:
        self.calls.append(
            {
                "url": url,
                "authenticated": "Authorization" in headers,
                "trace_id": headers.get("x-trace-id"),
                "tenant_header": headers.get("x-tenant-id"),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        authorization = headers.get("Authorization")
        if url.endswith("/audit/export"):
            return smoke.JsonHttpResponse(
                status_code=200,
                payload={"events": [{"tenant_id": "tenant-a"}]},
            )
        if authorization is None:
            return smoke.JsonHttpResponse(status_code=401, payload={})
        if headers.get("x-tenant-id") == "tenant-intentional-mismatch":
            return smoke.JsonHttpResponse(status_code=401, payload={})
        if authorization == f"Bearer {_LIMITED_TOKEN}":
            return smoke.JsonHttpResponse(status_code=403, payload={})
        return smoke.JsonHttpResponse(status_code=200, payload={"approvals": []})


class FakeHttpResponse:
    status = 200

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_amount: int | None = None

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self.payload if amount < 0 else self.payload[:amount]


def _discovery_fetch_json(url: str, timeout_seconds: int) -> dict[str, object]:
    assert timeout_seconds == 3
    if url.endswith("/.well-known/openid-configuration"):
        return {"issuer": _ISSUER, "jwks_uri": _JWKS_URI}
    return dict(_jwks())


def _token_minter(credentials: smoke.ClientCredentials) -> str:
    if credentials.client_id == "hallu-defense-api":
        return _REVIEWER_TOKEN
    if credentials.client_id == "hallu-defense-limited":
        return _LIMITED_TOKEN
    raise AssertionError("unexpected client")


def _enabled_verification_env() -> dict[str, str]:
    return {
        smoke.ENABLED_ENV: "true",
        smoke.ISSUER_ENV: _ISSUER,
        smoke.AUDIENCE_ENV: _AUDIENCE,
        smoke.DISCOVERY_ENV: _DISCOVERY,
        smoke.SUBJECT_CLAIM_ENV: "azp",
        smoke.CLIENT_ID_ENV: "hallu-defense-api",
        smoke.CLIENT_SECRET_ENV: _CLIENT_SECRET,
        smoke.EXPECTED_SUBJECT_ENV: "hallu-defense-api",
        smoke.EXPECTED_TENANT_ENV: "tenant-a",
        smoke.REQUIRED_ROLE_ENV: "approval_reviewer",
    }


def _enabled_api_env() -> dict[str, str]:
    return {
        **_enabled_verification_env(),
        smoke.API_BASE_URL_ENV: "http://127.0.0.1:8001",
        smoke.LIMITED_CLIENT_ID_ENV: "hallu-defense-limited",
        smoke.LIMITED_CLIENT_SECRET_ENV: _LIMITED_SECRET,
        smoke.LIMITED_EXPECTED_SUBJECT_ENV: "hallu-defense-limited",
    }


def test_skips_by_default_without_exposing_client_secrets() -> None:
    result = smoke.run_from_env(
        {
            smoke.CLIENT_SECRET_ENV: _CLIENT_SECRET,
            smoke.LIMITED_CLIENT_SECRET_ENV: _LIMITED_SECRET,
        }
    )

    assert result["status"] == "skipped"
    assert result["mode"] == "verification"
    assert result["subject_verified"] is False
    assert _CLIENT_SECRET not in json.dumps(result)
    assert _LIMITED_SECRET not in json.dumps(result)


def test_enabled_verification_requires_and_checks_expected_identity() -> None:
    result = smoke.run_from_env(
        _enabled_verification_env(),
        token_minter=_token_minter,
        fetch_json=_discovery_fetch_json,
    )

    assert result["status"] == "passed"
    assert result["subject"] == "hallu-defense-api"
    assert result["tenant"] == "tenant-a"
    assert result["subject_verified"] is True
    assert result["tenant_verified"] is True
    assert result["role_verified"] is True


@pytest.mark.parametrize(
    "required_name",
    [
        smoke.EXPECTED_SUBJECT_ENV,
        smoke.EXPECTED_TENANT_ENV,
        smoke.REQUIRED_ROLE_ENV,
    ],
)
def test_enabled_verification_never_allows_missing_expectations(required_name: str) -> None:
    env = _enabled_verification_env()
    del env[required_name]

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match=required_name):
        smoke.run_from_env(
            env,
            token_minter=_token_minter,
            fetch_json=_discovery_fetch_json,
        )


def test_enabled_verification_rejects_subject_or_role_mismatch() -> None:
    env = _enabled_verification_env()
    env[smoke.EXPECTED_SUBJECT_ENV] = "another-client"

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="subject"):
        smoke.run_from_env(
            env,
            token_minter=_token_minter,
            fetch_json=_discovery_fetch_json,
        )

    env = _enabled_verification_env()
    env[smoke.REQUIRED_ROLE_ENV] = "rag_writer"
    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="required role"):
        smoke.run_from_env(
            env,
            token_minter=_token_minter,
            fetch_json=_discovery_fetch_json,
        )


def test_api_mode_exercises_remote_boundary_and_all_required_outcomes() -> None:
    client = StubApiClient()

    result = smoke.run_api_from_env(
        _enabled_api_env(),
        token_minter=_token_minter,
        fetch_json=_discovery_fetch_json,
        http_client=client,
    )

    assert result == {
        "status": "passed",
        "mode": "api",
        "unauthenticated_rejected": True,
        "reviewer_allowed": True,
        "limited_role_rejected": True,
        "tenant_mismatch_rejected": True,
        "audit_tenant_preserved": True,
    }
    assert len(client.calls) == 5
    assert all(
        str(call["url"]).startswith("http://127.0.0.1:8001/")
        for call in client.calls
    )
    assert any(
        call["url"] == "http://127.0.0.1:8001/audit/export"
        and call["payload"]
        == {"trace_id": "tr_live_oidc_reviewer_allowed", "include_events": True}
        for call in client.calls
    )


@pytest.mark.parametrize(
    "required_name",
    [
        smoke.API_BASE_URL_ENV,
        smoke.LIMITED_CLIENT_ID_ENV,
        smoke.LIMITED_CLIENT_SECRET_ENV,
        smoke.LIMITED_EXPECTED_SUBJECT_ENV,
    ],
)
def test_api_mode_requires_explicit_remote_and_limited_client_config(
    required_name: str,
) -> None:
    env = _enabled_api_env()
    del env[required_name]

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match=required_name):
        smoke.run_api_from_env(
            env,
            token_minter=_token_minter,
            fetch_json=_discovery_fetch_json,
            http_client=StubApiClient(),
        )


def test_plain_http_is_restricted_to_explicit_loopback_hosts() -> None:
    oidc_env = _enabled_verification_env()
    oidc_env[smoke.ISSUER_ENV] = "http://issuer.example/realms/hallu-defense"
    oidc_env[smoke.DISCOVERY_ENV] = (
        "http://issuer.example/realms/hallu-defense/.well-known/openid-configuration"
    )
    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="explicit loopback"):
        smoke.run_from_env(oidc_env, token_minter=_token_minter)

    api_env = _enabled_api_env()
    api_env[smoke.API_BASE_URL_ENV] = "http://api.example"
    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="explicit loopback"):
        smoke.run_api_from_env(api_env, token_minter=_token_minter)


@pytest.mark.parametrize(
    ("name", "url"),
    [
        (smoke.ISSUER_ENV, "https://user:pass@issuer.example"),
        (
            smoke.DISCOVERY_ENV,
            "https://user:pass@issuer.example/.well-known/openid-configuration",
        ),
        (smoke.API_BASE_URL_ENV, "https://user:pass@api.example"),
    ],
)
def test_configured_urls_reject_embedded_credentials(name: str, url: str) -> None:
    env = _enabled_api_env()
    env[name] = url

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="credentials"):
        smoke.run_api_from_env(env, token_minter=_token_minter)


def test_oidc_urls_must_share_a_canonical_origin() -> None:
    env = _enabled_verification_env()
    env[smoke.DISCOVERY_ENV] = (
        "https://other-issuer.example/.well-known/openid-configuration"
    )

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="share one origin"):
        smoke.run_from_env(env, token_minter=_token_minter)


@pytest.mark.parametrize(
    "ambiguous_url",
    [
        "http://127.0.0.1.evil.example",
        "http://2130706433",
        "http://localhost.",
        "http://[::ffff:127.0.0.1]",
    ],
)
def test_plain_http_rejects_ambiguous_loopback_spellings(ambiguous_url: str) -> None:
    env = _enabled_api_env()
    env[smoke.API_BASE_URL_ENV] = ambiguous_url

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="explicit loopback"):
        smoke.run_api_from_env(env, token_minter=_token_minter)


def test_canonical_origin_normalizes_default_https_port_and_allows_ipv6_loopback() -> None:
    env = _enabled_verification_env()
    env[smoke.DISCOVERY_ENV] = (
        "https://issuer.example:443/.well-known/openid-configuration"
    )

    config = smoke._config_from_env(env)

    assert config.expected_subject == "hallu-defense-api"
    assert smoke._validate_http_url(
        "http://[::1]:18081/",
        require_root=True,
    ) == smoke._CanonicalHttpOrigin("http", "::1", 18081)


def test_api_mode_rejects_limited_client_that_has_reviewer_role() -> None:
    elevated_limited = _jwt(
        {
            "azp": "hallu-defense-limited",
            "roles": ["approval_reviewer"],
            "exp": 4102444800,
        }
    )

    def elevated_minter(credentials: smoke.ClientCredentials) -> str:
        return _REVIEWER_TOKEN if credentials.client_id == "hallu-defense-api" else elevated_limited

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="unexpectedly"):
        smoke.run_api_from_env(
            _enabled_api_env(),
            token_minter=elevated_minter,
            fetch_json=_discovery_fetch_json,
            http_client=StubApiClient(),
        )


def test_token_minter_rejects_redirect_without_contacting_target() -> None:
    sink_hits: list[str] = []

    class SinkHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            sink_hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()
    sink_host, sink_port = sink.server_address

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(302)
            self.send_header("Location", f"http://{sink_host}:{sink_port}/sink")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    source_thread.start()
    source_host, source_port = source.server_address
    config = smoke._config_from_env(_enabled_verification_env())
    source_origin = f"http://{source_host}:{source_port}"
    source_issuer = f"{source_origin}/realms/hallu-defense"
    config = replace(
        config,
        issuer=source_issuer,
        discovery_url=f"{source_issuer}/.well-known/openid-configuration",
        token_endpoint=f"{source_origin}/token",
    )
    try:
        with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="redirect") as exc_info:
            smoke._mint_client_credentials_token(config, config.reviewer_credentials)
        assert exc_info.value.__cause__ is None
        assert sink_hits == []
    finally:
        source.shutdown()
        source.server_close()
        source_thread.join(timeout=3)
        sink.shutdown()
        sink.server_close()
        sink_thread.join(timeout=3)


def test_token_minter_revalidates_same_origin_before_sending_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        smoke._config_from_env(_enabled_verification_env()),
        token_endpoint="https://other-issuer.example/token",
    )
    opener_called = False

    def forbidden_opener(*_args: object, **_kwargs: object) -> FakeHttpResponse:
        nonlocal opener_called
        opener_called = True
        return FakeHttpResponse(b"{}")

    monkeypatch.setattr(smoke, "open_url_no_redirect", forbidden_opener)

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="share one origin"):
        smoke._mint_client_credentials_token(config, config.reviewer_credentials)

    assert opener_called is False


def test_token_response_is_bounded_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeHttpResponse(b"x" * (smoke._MAX_HTTP_RESPONSE_BYTES + 1))
    monkeypatch.setattr(smoke, "open_url_no_redirect", lambda *_args, **_kwargs: response)
    config = smoke._config_from_env(_enabled_verification_env())

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="1 MiB") as exc_info:
        smoke._mint_client_credentials_token(config, config.reviewer_credentials)

    assert response.read_amount == smoke._MAX_HTTP_RESPONSE_BYTES + 1
    assert _CLIENT_SECRET not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert _CLIENT_SECRET not in repr(config)


def test_api_client_rejects_response_over_one_mib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeHttpResponse(b"x" * (smoke._MAX_HTTP_RESPONSE_BYTES + 1))
    monkeypatch.setattr(smoke, "open_url_no_redirect", lambda *_args, **_kwargs: response)

    with pytest.raises(smoke.LiveKeycloakOidcSmokeError, match="1 MiB"):
        smoke.UrlLibJsonHttpClient().post_json(
            "http://127.0.0.1:8001/approvals/list",
            headers={},
            payload={},
            timeout_seconds=3,
        )


def test_main_redacts_configured_secrets_and_unexpected_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def known_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise smoke.LiveKeycloakOidcSmokeError(
            f"bad {_CLIENT_SECRET} and {_LIMITED_SECRET}"
        )

    monkeypatch.setattr(smoke, "run_api_from_env", known_failure)
    exit_code = smoke.main(["--api"], env=_enabled_api_env())
    output = capsys.readouterr().out
    assert exit_code == 1
    assert _CLIENT_SECRET not in output
    assert _LIMITED_SECRET not in output

    def unexpected_failure(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("opaque bearer material")

    monkeypatch.setattr(smoke, "run_api_from_env", unexpected_failure)
    exit_code = smoke.main(["--api"], env=_enabled_api_env())
    output = capsys.readouterr().out
    assert exit_code == 1
    assert "opaque bearer material" not in output
    assert "unexpected live Keycloak" in output


def test_script_contains_no_in_process_fastapi_client() -> None:
    script_text = (
        Path(__file__).parents[3] / "scripts/dev/live_keycloak_oidc_smoke.py"
    ).read_text(encoding="utf-8")

    assert "from fastapi.testclient" not in script_text
    assert "hallu_defense.main" not in script_text
