from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from hallu_defense.config import Settings
from hallu_defense.services.providers import (
    MockModelProvider,
    OpenAICompatibleProvider,
    OllamaProvider,
    ProviderConfigurationError,
    ProviderMessage,
    ProviderRequest,
    ProviderRequestError,
    create_model_provider,
)
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue


class RecordingTransport:
    def __init__(self, response: Mapping[str, object]) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


class StaticCredentialStore:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = values
        self.requested_names: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requested_names.append(name)
        if field != "value" or name not in self.values:
            raise SecretNotFoundError(name)
        return SecretValue(name=name, _value=self.values[name])


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "2026-07-07",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 30,
        "max_output_chars": 12000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _request() -> ProviderRequest:
    return ProviderRequest(
        messages=[
            ProviderMessage(role="system", content="Use citations."),
            ProviderMessage(role="user", content="Verify this claim."),
        ],
        temperature=0.2,
        max_tokens=128,
    )


def test_mock_provider_is_deterministic_and_network_free() -> None:
    provider = MockModelProvider(model="mock-model", response_text="grounded draft")

    response = provider.complete(_request())

    assert response.text == "grounded draft"
    assert response.provider == "mock"
    assert response.model == "mock-model"
    assert response.metadata == {"message_count": 2, "network": "disabled"}


def test_openai_compatible_provider_uses_secret_manager_and_safe_payload() -> None:
    transport = RecordingTransport(
        {
            "id": "cmpl_1",
            "model": "gpt-compatible",
            "choices": [{"message": {"content": "supported answer"}}],
            "usage": {"total_tokens": 9},
        }
    )
    store = StaticCredentialStore({"providers/openai/api-key": "unit-value"})
    provider = OpenAICompatibleProvider(
        base_url="https://llm.example/v1/",
        model="gpt-compatible",
        credential_secret_name="providers/openai/api-key",
        secret_manager=store,
        timeout_seconds=7,
        transport=transport,
    )

    response = provider.complete(_request())

    assert response.text == "supported answer"
    assert response.provider == "openai-compatible"
    assert response.metadata == {"id": "cmpl_1", "usage": {"total_tokens": 9}}
    assert store.requested_names == ["providers/openai/api-key"]
    assert transport.calls == [
        {
            "url": "https://llm.example/v1/chat/completions",
            "headers": {"Authorization": "Bearer unit-value"},
            "payload": {
                "model": "gpt-compatible",
                "messages": [
                    {"role": "system", "content": "Use citations."},
                    {"role": "user", "content": "Verify this claim."},
                ],
                "temperature": 0.2,
                "max_tokens": 128,
            },
            "timeout_seconds": 7,
        }
    ]
    assert "unit-value" not in repr(response)


def test_openai_compatible_provider_fails_closed_when_credential_missing() -> None:
    provider = OpenAICompatibleProvider(
        base_url="https://llm.example/v1",
        model="gpt-compatible",
        credential_secret_name="providers/openai/api-key",
        secret_manager=StaticCredentialStore({}),
        timeout_seconds=7,
        transport=RecordingTransport({}),
    )

    with pytest.raises(ProviderConfigurationError, match="credential"):
        provider.complete(_request())


def test_ollama_provider_uses_local_chat_endpoint_without_authorization_header() -> None:
    transport = RecordingTransport(
        {
            "model": "llama3.1",
            "message": {"role": "assistant", "content": "local answer"},
            "done": True,
            "eval_count": 12,
        }
    )
    provider = OllamaProvider(
        base_url="http://127.0.0.1:11434/",
        model="llama3.1",
        timeout_seconds=11,
        transport=transport,
    )

    response = provider.complete(_request())

    assert response.text == "local answer"
    assert response.provider == "ollama"
    assert response.metadata == {"done": True, "eval_count": 12}
    assert transport.calls[0]["url"] == "http://127.0.0.1:11434/api/chat"
    assert transport.calls[0]["headers"] == {}
    assert transport.calls[0]["payload"] == {
        "model": "llama3.1",
        "messages": [
            {"role": "system", "content": "Use citations."},
            {"role": "user", "content": "Verify this claim."},
        ],
        "stream": False,
        "options": {"temperature": 0.2},
    }


def test_provider_factory_rejects_mock_backend_in_production() -> None:
    settings = _settings(environment="production", provider_backend="mock")

    with pytest.raises(ProviderConfigurationError, match="mock provider"):
        create_model_provider(settings, StaticCredentialStore({}))


def test_provider_request_rejects_empty_messages() -> None:
    provider = MockModelProvider(model="mock-model", response_text="unused")

    with pytest.raises(ProviderRequestError, match="at least one message"):
        provider.complete(ProviderRequest(messages=[]))
