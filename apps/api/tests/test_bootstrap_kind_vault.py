from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from scripts.dev.bootstrap_kind_vault import (
    KindVaultBootstrapConfig,
    KindVaultBootstrapError,
    bootstrap_kind_vault,
)


class RecordingRequester:
    def __init__(self, *, health_failures: int = 0) -> None:
        self.health_failures = health_failures
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, object] | None,
        timeout_seconds: float,
        ca_path: Path,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "payload": payload,
                "timeout_seconds": timeout_seconds,
                "ca_path": ca_path,
            }
        )
        if method == "GET" and self.health_failures > 0:
            self.health_failures -= 1
            raise KindVaultBootstrapError("not ready")
        return {}


def test_kind_vault_bootstrap_waits_and_seeds_generated_credentials(tmp_path: Path) -> None:
    config = _config(tmp_path)
    requester = RecordingRequester(health_failures=2)
    sleeps: list[float] = []
    generated = iter(
        (
            "provider-generated-credential-value-0001",
            "metrics-generated-credential-value-00002",
            "approval-generated-commitment-key-000003",
        )
    )

    result = bootstrap_kind_vault(
        config,
        request_json=requester,
        monotonic=lambda: 0.0,
        sleep=sleeps.append,
        credential_factory=lambda: next(generated),
    )

    assert result == {
        "status": "passed",
        "vault_addr": "https://hallu-defense-vault:8200",
        "seeded_names": [
            "providers/openai/api-key",
            "observability/metrics-scrape-token",
            "approvals/tool-call-commitment-key",
        ],
        "seeded_count": 3,
    }
    assert sleeps == [1.0, 1.0]
    assert [call["method"] for call in requester.calls] == [
        "GET",
        "GET",
        "GET",
        "PUT",
        "PUT",
        "PUT",
    ]
    provider_put, metrics_put, approval_put = requester.calls[-3:]
    assert provider_put["url"] == (
        "https://hallu-defense-vault:8200/v1/secret/data/providers/openai/api-key"
    )
    assert provider_put["headers"] == {"X-Vault-Token": "root-token-value"}
    assert provider_put["payload"] == {
        "data": {"value": "provider-generated-credential-value-0001"}
    }
    assert metrics_put["url"] == (
        "https://hallu-defense-vault:8200/v1/secret/data/observability/metrics-scrape-token"
    )
    assert metrics_put["payload"] == {
        "data": {"value": "metrics-generated-credential-value-00002"}
    }
    assert approval_put["url"] == (
        "https://hallu-defense-vault:8200/v1/secret/data/"
        "approvals/tool-call-commitment-key"
    )
    assert approval_put["payload"] == {
        "data": {"value": "approval-generated-commitment-key-000003"}
    }
    assert "root-token-value" not in str(result)
    assert "provider-generated-credential-value-0001" not in str(result)
    assert "metrics-generated-credential-value-00002" not in str(result)
    assert "approval-generated-commitment-key-000003" not in str(result)


def test_kind_vault_bootstrap_fails_closed_when_health_deadline_expires(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, wait_seconds=1)
    requester = RecordingRequester(health_failures=1)
    monotonic_values = iter((0.0, 2.0))

    with pytest.raises(KindVaultBootstrapError, match="deadline"):
        bootstrap_kind_vault(
            config,
            request_json=requester,
            monotonic=lambda: next(monotonic_values),
            sleep=lambda _seconds: None,
        )

    assert [call["method"] for call in requester.calls] == ["GET"]


@pytest.mark.parametrize(
    ("address", "secret_name"),
    [
        ("http://hallu-defense-vault:8200", "providers/openai/api-key"),
        ("https://hallu-defense-vault:8200", "../provider-key"),
        ("https://user@hallu-defense-vault:8200", "providers/openai/api-key"),
    ],
)
def test_kind_vault_bootstrap_rejects_unsafe_boundaries(
    tmp_path: Path,
    address: str,
    secret_name: str,
) -> None:
    config = _config(tmp_path, address=address, provider_secret_name=secret_name)

    with pytest.raises(KindVaultBootstrapError):
        bootstrap_kind_vault(config, request_json=RecordingRequester())


def test_kind_vault_bootstrap_seeds_redis_url_and_removes_transient_file(
    tmp_path: Path,
) -> None:
    config = _redis_config(tmp_path)
    requester = RecordingRequester()

    result = bootstrap_kind_vault(config, request_json=requester)

    assert result == {
        "status": "passed",
        "vault_addr": "https://hallu-defense-vault:8200",
        "seeded_names": ["quotas/tool-validation/redis-url"],
        "seeded_count": 1,
    }
    assert config.redis_url_path is not None
    assert not config.redis_url_path.exists()
    assert config.ready_marker_path is not None
    assert config.ready_marker_path.read_text(encoding="utf-8") == "ready\n"
    redis_put = requester.calls[-1]
    assert redis_put["url"] == (
        "https://hallu-defense-vault:8200/v1/secret/data/"
        "quotas/tool-validation/redis-url"
    )
    payload = redis_put["payload"]
    assert isinstance(payload, Mapping)
    assert "rediss://hallu-rate-limiter:" in str(payload)
    assert "rediss://" not in str(result)


def test_kind_vault_bootstrap_rejects_plaintext_redis_url(tmp_path: Path) -> None:
    config = _redis_config(tmp_path, scheme="redis")

    with pytest.raises(KindVaultBootstrapError, match="canonical TLS"):
        bootstrap_kind_vault(config, request_json=RecordingRequester())

    assert config.redis_url_path is not None and config.redis_url_path.exists()


def _config(
    tmp_path: Path,
    *,
    address: str = "https://hallu-defense-vault:8200",
    provider_secret_name: str = "providers/openai/api-key",
    wait_seconds: int = 5,
) -> KindVaultBootstrapConfig:
    ca_path = tmp_path / "ca.crt"
    token_path = tmp_path / "root-token"
    ca_path.write_text("test-ca", encoding="utf-8")
    token_path.write_text("root-token-value", encoding="utf-8")
    return KindVaultBootstrapConfig(
        address=address,
        ca_path=ca_path,
        token_path=token_path,
        provider_secret_name=provider_secret_name,
        metrics_secret_name="observability/metrics-scrape-token",
        approval_commitment_secret_name="approvals/tool-call-commitment-key",
        wait_seconds=wait_seconds,
    )


def _redis_config(
    tmp_path: Path,
    *,
    scheme: str = "rediss",
) -> KindVaultBootstrapConfig:
    ca_path = tmp_path / "ca.crt"
    token_path = tmp_path / "root-token"
    redis_url_path = tmp_path / "redis-url"
    marker_path = tmp_path / "seeded"
    ca_path.write_text("test-ca", encoding="utf-8")
    token_path.write_text("root-token-value", encoding="utf-8")
    credential = "a" * 64
    redis_url_path.write_text(
        f"{scheme}://hallu-rate-limiter:{credential}@hallu-defense-redis:6379/0\n",
        encoding="utf-8",
    )
    return KindVaultBootstrapConfig(
        address="https://hallu-defense-vault:8200",
        ca_path=ca_path,
        token_path=token_path,
        provider_secret_name=None,
        metrics_secret_name=None,
        approval_commitment_secret_name=None,
        seed_core_credentials=False,
        redis_secret_name="quotas/tool-validation/redis-url",
        redis_url_path=redis_url_path,
        ready_marker_path=marker_path,
    )
