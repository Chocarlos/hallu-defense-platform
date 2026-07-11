from __future__ import annotations

import json
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol
from urllib import error, request

from hallu_defense.config import Settings
from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpPolicyError,
    OutboundHttpRedirectError,
    open_url_no_redirect,
    outbound_http_policy_from_settings,
)
from hallu_defense.services.secrets import (
    LOCAL_SECRET_BACKEND_ENVIRONMENTS,
    SecretAccessError,
    SecretManager,
    SecretNotFoundError,
)

ProviderRole = Literal["system", "user", "assistant", "tool"]
MAX_PROVIDER_HTTP_RESPONSE_BYTES = 1024 * 1024


class ProviderConfigurationError(RuntimeError):
    pass


class ProviderCredentialError(ProviderConfigurationError):
    pass


class ProviderRequestError(RuntimeError):
    pass


class ProviderResponseError(RuntimeError):
    pass


class ProviderResponseTooLargeError(ProviderResponseError):
    pass


@dataclass(frozen=True)
class ProviderMessage:
    role: ProviderRole
    content: str


@dataclass(frozen=True)
class ProviderRequest:
    messages: Sequence[ProviderMessage]
    model: str | None = None
    temperature: float = 0.0
    max_tokens: int | None = None


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    provider: str
    model: str
    metadata: Mapping[str, object] = field(default_factory=dict)


class ModelProvider(Protocol):
    provider_name: str

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse: ...


class JsonTransport(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]: ...


class UrllibJsonTransport:
    def __init__(
        self,
        *,
        policy: OutboundHttpPolicy | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._policy = policy or OutboundHttpPolicy.local_unrestricted()
        self._ssl_context = ssl_context

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        try:
            self._policy.validate_url(url)
        except OutboundHttpPolicyError:
            raise ProviderRequestError(
                "Provider endpoint is blocked by outbound policy."
            ) from None
        encoded = json.dumps(payload).encode("utf-8")
        provider_request = request.Request(
            url,
            data=encoded,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with open_url_no_redirect(
                provider_request,
                timeout=timeout_seconds,
                context=self._ssl_context,
            ) as response:
                body = response.read(MAX_PROVIDER_HTTP_RESPONSE_BYTES + 1)
        except OutboundHttpRedirectError:
            raise ProviderRequestError("Provider redirects are not allowed.") from None
        except error.HTTPError as exc:
            status_code = exc.code
            try:
                exc.close()
            finally:
                raise ProviderRequestError(
                    f"Provider request failed with HTTP status {status_code}."
                ) from None
        except error.URLError:
            raise ProviderRequestError("Provider request failed.") from None
        except (TimeoutError, OSError):
            raise ProviderRequestError("Provider request failed.") from None

        if len(body) > MAX_PROVIDER_HTTP_RESPONSE_BYTES:
            raise ProviderResponseTooLargeError(
                "Provider response exceeded the 1 MiB safety limit."
            )

        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ProviderResponseError(
                "Provider response was not valid UTF-8 JSON."
            ) from None
        if not isinstance(parsed, Mapping):
            raise ProviderResponseError("Provider response must be a JSON object.")
        return parsed


class MockModelProvider:
    provider_name = "mock"

    def __init__(self, *, model: str, response_text: str) -> None:
        if not model:
            raise ProviderConfigurationError("Mock provider model must be configured.")
        self._model = model
        self._response_text = response_text

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse:
        _validate_provider_request(provider_request)
        return ProviderResponse(
            text=self._response_text,
            provider=self.provider_name,
            model=provider_request.model or self._model,
            metadata={"message_count": len(provider_request.messages), "network": "disabled"},
        )


class OpenAICompatibleProvider:
    provider_name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        credential_secret_name: str,
        secret_manager: SecretManager,
        timeout_seconds: int,
        transport: JsonTransport | None = None,
        outbound_policy: OutboundHttpPolicy | None = None,
    ) -> None:
        if not base_url:
            raise ProviderConfigurationError("OpenAI-compatible base URL must be configured.")
        if not model:
            raise ProviderConfigurationError("OpenAI-compatible model must be configured.")
        if timeout_seconds <= 0:
            raise ProviderConfigurationError("Provider timeout must be greater than zero seconds.")
        self._endpoint = f"{base_url.rstrip('/')}/chat/completions"
        effective_policy = outbound_policy or OutboundHttpPolicy.local_unrestricted()
        try:
            effective_policy.validate_url(self._endpoint)
        except OutboundHttpPolicyError:
            raise ProviderConfigurationError(
                "OpenAI-compatible endpoint is blocked by outbound policy."
            ) from None
        self._model = model
        self._credential_secret_name = credential_secret_name
        self._secret_manager = secret_manager
        self._timeout_seconds = timeout_seconds
        self._transport = transport or UrllibJsonTransport(policy=effective_policy)

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse:
        _validate_provider_request(provider_request)
        model = provider_request.model or self._model
        credential = self._read_credential()
        payload: dict[str, object] = {
            "model": model,
            "messages": _messages_payload(provider_request.messages),
            "temperature": provider_request.temperature,
        }
        if provider_request.max_tokens is not None:
            payload["max_tokens"] = provider_request.max_tokens

        response = self._transport.post_json(
            self._endpoint,
            headers={"Authorization": f"Bearer {credential}"},
            payload=payload,
            timeout_seconds=self._timeout_seconds,
        )
        return ProviderResponse(
            text=_openai_text(response),
            provider=self.provider_name,
            model=_string_or_default(response.get("model"), model),
            metadata=_openai_metadata(response),
        )

    def _read_credential(self) -> str:
        try:
            return self._secret_manager.get_secret(self._credential_secret_name).reveal()
        except (SecretAccessError, SecretNotFoundError):
            raise ProviderCredentialError(
                "OpenAI-compatible provider credential is unavailable."
            ) from None


class OllamaProvider:
    provider_name = "ollama"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_seconds: int,
        transport: JsonTransport | None = None,
        outbound_policy: OutboundHttpPolicy | None = None,
    ) -> None:
        if not base_url:
            raise ProviderConfigurationError("Ollama base URL must be configured.")
        if not model:
            raise ProviderConfigurationError("Ollama model must be configured.")
        if timeout_seconds <= 0:
            raise ProviderConfigurationError("Provider timeout must be greater than zero seconds.")
        self._endpoint = f"{base_url.rstrip('/')}/api/chat"
        effective_policy = outbound_policy or OutboundHttpPolicy.local_unrestricted()
        try:
            effective_policy.validate_url(self._endpoint)
        except OutboundHttpPolicyError:
            raise ProviderConfigurationError(
                "Ollama endpoint is blocked by outbound policy."
            ) from None
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._transport = transport or UrllibJsonTransport(policy=effective_policy)

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse:
        _validate_provider_request(provider_request)
        model = provider_request.model or self._model
        payload: dict[str, object] = {
            "model": model,
            "messages": _messages_payload(provider_request.messages),
            "stream": False,
            "options": {"temperature": provider_request.temperature},
        }
        response = self._transport.post_json(
            self._endpoint,
            headers={},
            payload=payload,
            timeout_seconds=self._timeout_seconds,
        )
        return ProviderResponse(
            text=_ollama_text(response),
            provider=self.provider_name,
            model=_string_or_default(response.get("model"), model),
            metadata=_ollama_metadata(response),
        )


def create_model_provider(
    settings: Settings,
    secret_manager: SecretManager,
    *,
    transport: JsonTransport | None = None,
) -> ModelProvider:
    backend = settings.provider_backend.strip().lower()
    environment = settings.environment.strip().lower()

    if backend == "mock":
        if environment not in LOCAL_SECRET_BACKEND_ENVIRONMENTS:
            raise ProviderConfigurationError("The mock provider is only allowed outside production-like environments.")
        return MockModelProvider(
            model=settings.provider_model,
            response_text=settings.mock_provider_response,
        )

    if backend in {"openai", "openai-compatible"}:
        try:
            outbound_policy = outbound_http_policy_from_settings(settings)
        except OutboundHttpPolicyError:
            raise ProviderConfigurationError(
                "Provider outbound policy is invalid."
            ) from None
        return OpenAICompatibleProvider(
            base_url=settings.openai_compatible_base_url,
            model=settings.provider_model,
            credential_secret_name=settings.openai_compatible_api_key_secret_name,
            secret_manager=secret_manager,
            timeout_seconds=settings.provider_timeout_seconds,
            transport=transport,
            outbound_policy=outbound_policy,
        )

    if backend == "ollama":
        try:
            outbound_policy = outbound_http_policy_from_settings(settings)
        except OutboundHttpPolicyError:
            raise ProviderConfigurationError(
                "Provider outbound policy is invalid."
            ) from None
        return OllamaProvider(
            base_url=settings.ollama_base_url,
            model=settings.provider_model,
            timeout_seconds=settings.provider_timeout_seconds,
            transport=transport,
            outbound_policy=outbound_policy,
        )

    raise ProviderConfigurationError(f"Unsupported provider backend {settings.provider_backend!r}.")


def _validate_provider_request(provider_request: ProviderRequest) -> None:
    if not provider_request.messages:
        raise ProviderRequestError("Provider request must include at least one message.")
    if provider_request.temperature < 0 or provider_request.temperature > 2:
        raise ProviderRequestError("Provider request temperature must be between 0 and 2.")
    if provider_request.max_tokens is not None and provider_request.max_tokens <= 0:
        raise ProviderRequestError("Provider request max_tokens must be greater than zero.")
    for message in provider_request.messages:
        if not message.content.strip():
            raise ProviderRequestError("Provider messages must not be empty.")


def _messages_payload(messages: Sequence[ProviderMessage]) -> list[dict[str, str]]:
    return [{"role": message.role, "content": message.content} for message in messages]


def _openai_text(response: Mapping[str, object]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderResponseError("OpenAI-compatible response is missing choices.")
    first_choice = choices[0]
    if not isinstance(first_choice, Mapping):
        raise ProviderResponseError("OpenAI-compatible response choice must be an object.")
    message = first_choice.get("message")
    if isinstance(message, Mapping):
        content = message.get("content")
        if isinstance(content, str):
            return content
    text = first_choice.get("text")
    if isinstance(text, str):
        return text
    raise ProviderResponseError("OpenAI-compatible response does not contain text content.")


def _ollama_text(response: Mapping[str, object]) -> str:
    message = response.get("message")
    if isinstance(message, Mapping):
        content = message.get("content")
        if isinstance(content, str):
            return content
    raw_response = response.get("response")
    if isinstance(raw_response, str):
        return raw_response
    raise ProviderResponseError("Ollama response does not contain text content.")


def _openai_metadata(response: Mapping[str, object]) -> Mapping[str, object]:
    metadata: dict[str, object] = {}
    for key in ("id", "created", "usage"):
        value = response.get(key)
        if isinstance(value, str | int | float | bool | Mapping):
            metadata[key] = value
    return metadata


def _ollama_metadata(response: Mapping[str, object]) -> Mapping[str, object]:
    metadata: dict[str, object] = {}
    for key in ("done", "total_duration", "load_duration", "eval_count", "eval_duration"):
        value = response.get(key)
        if isinstance(value, str | int | float | bool):
            metadata[key] = value
    return metadata


def _string_or_default(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default
