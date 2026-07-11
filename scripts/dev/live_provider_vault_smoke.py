"""Opt-in Vault -> OpenAI-compatible -> Ollama provider connectivity smoke."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib import parse

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import Settings  # noqa: E402
from hallu_defense.services.providers import (  # noqa: E402
    JsonTransport,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
    ProviderCredentialError,
    ProviderMessage,
    ProviderRequest,
    ProviderRequestError,
    ProviderResponse,
    ProviderResponseError,
)
from hallu_defense.services.secrets import (  # noqa: E402
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
    SecretValue,
    create_secret_manager,
)
from scripts.dev.bootstrap_local_vault import (  # noqa: E402
    DEFAULT_LOCAL_VAULT_ADDR,
    DEFAULT_LOCAL_VAULT_MOUNT,
    DEFAULT_LOCAL_VAULT_TOKEN,
    DEFAULT_LOCAL_VAULT_TOKEN_ENV,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_VAULT_SMOKE_ENABLED"
VAULT_ADDR_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_VAULT_ADDR"
VAULT_MOUNT_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_VAULT_MOUNT"
VAULT_TOKEN_ENV_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_VAULT_TOKEN_ENV"
VAULT_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_VAULT_TIMEOUT_SECONDS"
OPENAI_BASE_URL_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_OPENAI_BASE_URL"
OLLAMA_BASE_URL_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_OLLAMA_BASE_URL"
MODEL_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_MODEL"
PROVIDER_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_TIMEOUT_SECONDS"
SECRET_NAME_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_SECRET_NAME"
ALLOW_NONLOCAL_ENV = "HALLU_DEFENSE_LIVE_PROVIDER_ALLOW_NONLOCAL"

DEFAULT_OPENAI_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_PROVIDER_SECRET_NAME = "providers/openai/api-key"
TOKEN_ENV_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SMOKE_PROMPT = "Reply with a short acknowledgement for the provider connectivity smoke."


class LiveProviderVaultSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveProviderVaultSmokeConfig:
    vault_addr: str
    vault_mount: str
    vault_token_env: str
    vault_token_value: str = field(repr=False)
    vault_timeout_seconds: int
    openai_base_url: str
    ollama_base_url: str
    model: str
    provider_timeout_seconds: int
    provider_secret_name: str = DEFAULT_PROVIDER_SECRET_NAME
    allow_nonlocal: bool = False


class RedactionCheckingSecretManager:
    def __init__(self, delegate: SecretManager) -> None:
        self._delegate = delegate
        self.accessed_names: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        credential = self._delegate.get_secret(name, field=field)
        raw_value = credential.reveal()
        if not raw_value:
            raise LiveProviderVaultSmokeError(f"secret {name!r} was empty")
        if raw_value in repr(credential) or raw_value in str(credential):
            raise LiveProviderVaultSmokeError(f"secret {name!r} leaked through repr/str")
        self.accessed_names.append(name)
        return credential


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    secret_manager: SecretManager | None = None,
    openai_transport: JsonTransport | None = None,
    ollama_transport: JsonTransport | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live provider/Vault smoke",
            "planned_checks": [
                "Vault provider credential",
                "OpenAI-compatible completion",
                "Ollama completion",
            ],
            "redacted": True,
        }

    config = _config_from_env(effective_env)
    _validate_config(config)
    manager = secret_manager or _build_secret_manager(config)
    with _patched_token_env(config.vault_token_env, config.vault_token_value):
        return run_provider_vault_smoke(
            config,
            secret_manager=manager,
            openai_transport=openai_transport,
            ollama_transport=ollama_transport,
        )


def run_provider_vault_smoke(
    config: LiveProviderVaultSmokeConfig,
    *,
    secret_manager: SecretManager,
    openai_transport: JsonTransport | None = None,
    ollama_transport: JsonTransport | None = None,
) -> dict[str, object]:
    _validate_config(config)
    checked_manager = RedactionCheckingSecretManager(secret_manager)
    provider_request = ProviderRequest(
        messages=[ProviderMessage(role="user", content=SMOKE_PROMPT)],
        temperature=0.0,
        max_tokens=32,
    )
    try:
        openai_response = OpenAICompatibleProvider(
            base_url=config.openai_base_url,
            model=config.model,
            credential_secret_name=config.provider_secret_name,
            secret_manager=checked_manager,
            timeout_seconds=config.provider_timeout_seconds,
            transport=openai_transport,
        ).complete(provider_request)
        ollama_response = OllamaProvider(
            base_url=config.ollama_base_url,
            model=config.model,
            timeout_seconds=config.provider_timeout_seconds,
            transport=ollama_transport,
        ).complete(provider_request)
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError) as exc:
        raise LiveProviderVaultSmokeError("Vault provider credential lookup failed") from exc
    except ProviderCredentialError as exc:
        raise LiveProviderVaultSmokeError("Vault provider credential lookup failed") from exc
    except ProviderConfigurationError as exc:
        raise LiveProviderVaultSmokeError("provider connectivity check failed") from exc
    except (ProviderRequestError, ProviderResponseError) as exc:
        raise LiveProviderVaultSmokeError("provider connectivity check failed") from exc

    if checked_manager.accessed_names != [config.provider_secret_name]:
        raise LiveProviderVaultSmokeError("OpenAI-compatible provider did not read the Vault secret")
    _require_nonempty_response(openai_response, "OpenAI-compatible")
    _require_nonempty_response(ollama_response, "Ollama")

    return {
        "status": "passed",
        "redacted": True,
        "checks": [
            {
                "name": "vault_provider_credential",
                "status": "passed",
                "secret_name": config.provider_secret_name,
                "value": "[redacted]",
            },
            {
                "name": "openai_compatible_completion",
                "status": "passed",
                "provider": openai_response.provider,
                "response": "[redacted]",
            },
            {
                "name": "ollama_completion",
                "status": "passed",
                "provider": ollama_response.provider,
                "response": "[redacted]",
            },
        ],
    }


def _build_secret_manager(config: LiveProviderVaultSmokeConfig) -> SecretManager:
    settings = Settings(
        environment="local",
        policy_version="live-provider-vault-smoke",
        auth_required=False,
        allowed_workspace=ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        secrets_backend="vault",
        vault_addr=config.vault_addr,
        vault_mount=config.vault_mount,
        vault_token_env=config.vault_token_env,
        vault_timeout_seconds=config.vault_timeout_seconds,
    )
    return create_secret_manager(settings)


def _config_from_env(env: Mapping[str, str]) -> LiveProviderVaultSmokeConfig:
    token_env = _optional(env, VAULT_TOKEN_ENV_ENV) or DEFAULT_LOCAL_VAULT_TOKEN_ENV
    model = _optional(env, MODEL_ENV)
    if model is None:
        raise LiveProviderVaultSmokeError(f"{MODEL_ENV} is required when the smoke is enabled")
    return LiveProviderVaultSmokeConfig(
        vault_addr=_optional(env, VAULT_ADDR_ENV) or DEFAULT_LOCAL_VAULT_ADDR,
        vault_mount=_optional(env, VAULT_MOUNT_ENV) or DEFAULT_LOCAL_VAULT_MOUNT,
        vault_token_env=token_env,
        vault_token_value=_optional(env, token_env) or DEFAULT_LOCAL_VAULT_TOKEN,
        vault_timeout_seconds=_int_env(env, VAULT_TIMEOUT_ENV, 3),
        openai_base_url=_optional(env, OPENAI_BASE_URL_ENV) or DEFAULT_OPENAI_BASE_URL,
        ollama_base_url=_optional(env, OLLAMA_BASE_URL_ENV) or DEFAULT_OLLAMA_BASE_URL,
        model=model,
        provider_timeout_seconds=_int_env(env, PROVIDER_TIMEOUT_ENV, 30),
        provider_secret_name=(
            _optional(env, SECRET_NAME_ENV) or DEFAULT_PROVIDER_SECRET_NAME
        ),
        allow_nonlocal=_enabled(env.get(ALLOW_NONLOCAL_ENV, "")),
    )


def _validate_config(config: LiveProviderVaultSmokeConfig) -> None:
    if not config.vault_mount.strip() or "/" in config.vault_mount.strip("/"):
        raise LiveProviderVaultSmokeError("Vault mount must be a single path segment")
    if TOKEN_ENV_PATTERN.fullmatch(config.vault_token_env) is None:
        raise LiveProviderVaultSmokeError("Vault token environment variable name is invalid")
    if not config.vault_token_value:
        raise LiveProviderVaultSmokeError("Vault token is required")
    if not config.model.strip():
        raise LiveProviderVaultSmokeError("provider model is required")
    if not config.provider_secret_name.strip():
        raise LiveProviderVaultSmokeError("provider secret name is required")
    if config.vault_timeout_seconds <= 0 or config.provider_timeout_seconds <= 0:
        raise LiveProviderVaultSmokeError("smoke timeouts must be positive")
    for label, url in (
        ("Vault", config.vault_addr),
        ("OpenAI-compatible provider", config.openai_base_url),
        ("Ollama provider", config.ollama_base_url),
    ):
        _validate_endpoint(label, url, allow_nonlocal=config.allow_nonlocal)


def _validate_endpoint(label: str, url: str, *, allow_nonlocal: bool) -> None:
    parsed = parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise LiveProviderVaultSmokeError(f"{label} URL must be absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise LiveProviderVaultSmokeError(f"{label} URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise LiveProviderVaultSmokeError(f"{label} URL must not contain query or fragment data")
    is_loopback = _is_loopback_host(parsed.hostname)
    if not is_loopback and not allow_nonlocal:
        raise LiveProviderVaultSmokeError(
            f"{label} URL must be loopback unless {ALLOW_NONLOCAL_ENV}=true"
        )
    if not is_loopback and parsed.scheme != "https":
        raise LiveProviderVaultSmokeError(f"non-loopback {label} URL must use HTTPS")


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _require_nonempty_response(response: ProviderResponse, label: str) -> None:
    if not response.text.strip():
        raise LiveProviderVaultSmokeError(f"{label} provider returned an empty response")


@contextmanager
def _patched_token_env(name: str, value: str) -> Iterator[None]:
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


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
        raise LiveProviderVaultSmokeError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise LiveProviderVaultSmokeError(f"{name} must be positive")
    return parsed


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    _ = argv
    try:
        result = run_from_env(env)
    except LiveProviderVaultSmokeError as exc:
        print(_json_result({"status": "failed", "error": str(exc), "redacted": True}))
        return 1
    except Exception:
        print(
            _json_result(
                {
                    "status": "failed",
                    "error": "unexpected provider/Vault smoke failure",
                    "redacted": True,
                }
            )
        )
        return 1
    print(_json_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
