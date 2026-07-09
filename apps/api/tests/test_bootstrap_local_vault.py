from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from scripts.dev import bootstrap_local_vault as bootstrap


def test_bootstrap_seeds_required_kv2_secret_paths_without_value_output() -> None:
    calls: list[tuple[str, str, Mapping[str, object] | None]] = []

    def fake_request_json(
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object] | None,
        timeout_seconds: int,
    ) -> Mapping[str, object]:
        assert headers == {"X-Vault-Token": "tok"}
        assert timeout_seconds == 7
        calls.append((method, url, payload))
        return {}

    result = bootstrap.bootstrap_local_vault(
        bootstrap.LocalVaultBootstrapConfig(
            address="http://127.0.0.1:8200",
            mount="secret",
            token_env="VAULT_TOKEN_ENV_FOR_TEST",
            token="tok",
            timeout_seconds=7,
        ),
        request_json=fake_request_json,
    )

    assert result["status"] == "passed"
    assert result["seeded_names"] == list(bootstrap.LOCAL_VAULT_SECRET_NAMES)
    assert [call[0] for call in calls] == ["PUT", "PUT", "PUT"]
    assert [call[1] for call in calls] == [
        "http://127.0.0.1:8200/v1/secret/data/observability/metrics-scrape-token",
        "http://127.0.0.1:8200/v1/secret/data/auth/trusted-header-signing-key",
        "http://127.0.0.1:8200/v1/secret/data/backup/encryption-key",
    ]
    payloads = [call[2] for call in calls]
    assert all(isinstance(payload, Mapping) for payload in payloads)
    emitted = json.dumps(result)
    for payload in payloads:
        assert isinstance(payload, Mapping)
        data = payload["data"]
        assert isinstance(data, Mapping)
        value = data["value"]
        assert isinstance(value, str) and value
        assert value not in emitted


def test_bootstrap_rejects_non_loopback_vault_by_default() -> None:
    config = bootstrap.LocalVaultBootstrapConfig(
        address="https://vault.example",
        mount="secret",
        token_env="VAULT_TOKEN_ENV_FOR_TEST",
        token="tok",
    )

    with pytest.raises(bootstrap.LocalVaultBootstrapError, match="loopback"):
        bootstrap.bootstrap_local_vault(config, request_json=lambda *_args: {})


def test_run_from_env_uses_configured_token_env_and_defaults() -> None:
    seen_headers: list[Mapping[str, str]] = []

    def fake_request_json(
        _method: str,
        _url: str,
        headers: Mapping[str, str],
        _payload: Mapping[str, object] | None,
        _timeout_seconds: int,
    ) -> Mapping[str, object]:
        seen_headers.append(headers)
        return {}

    result = bootstrap.run_from_env(
        {
            bootstrap.ADDR_ENV: "http://localhost:8200",
            bootstrap.TOKEN_ENV_ENV: "CUSTOM_LOCAL_VAULT_TOKEN",
            "CUSTOM_LOCAL_VAULT_TOKEN": "tok",
        },
        request_json=fake_request_json,
    )

    assert result["status"] == "passed"
    assert seen_headers and all(headers["X-Vault-Token"] == "tok" for headers in seen_headers)


def test_main_reports_failure_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = bootstrap.main(env={bootstrap.ADDR_ENV: "https://vault.example"})

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert "loopback" in payload["error"]
