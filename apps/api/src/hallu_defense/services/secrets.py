from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib import error, parse, request

from hallu_defense.config import Settings
from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpPolicyError,
    OutboundHttpRedirectError,
    open_url_no_redirect,
    outbound_http_policy_from_settings,
)
from hallu_defense.runtime_secrets import RuntimeSecretError, read_runtime_secret_file

LOCAL_SECRET_BACKEND_ENVIRONMENTS = {"ci", "dev", "development", "local", "test"}
SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,255}$")
MAX_VAULT_HTTP_RESPONSE_BYTES = 1024 * 1024


class SecretConfigurationError(RuntimeError):
    pass


class SecretNotFoundError(LookupError):
    pass


class SecretAccessError(RuntimeError):
    pass


class SecretResponseTooLargeError(SecretAccessError):
    pass


@dataclass(frozen=True)
class SecretValue:
    name: str
    _value: str = field(repr=False)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"SecretValue(name={self.name!r}, value='[redacted]')"

    def __str__(self) -> str:
        return "[redacted]"


class SecretManager(Protocol):
    def get_secret(self, name: str, *, field: str = "value") -> SecretValue: ...


class EnvSecretManager:
    def __init__(self, prefix: str) -> None:
        if not prefix or not prefix.endswith("_"):
            raise SecretConfigurationError("Environment secret prefix must be non-empty and end with '_'.")
        self._prefix = prefix

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        if field != "value":
            raise SecretAccessError("Environment secret backend only supports field='value'.")
        _validate_secret_name(name)
        env_name = self._env_name(name)
        raw_value = os.getenv(env_name)
        if raw_value is None:
            raise SecretNotFoundError(f"Secret {name!r} was not found in the environment backend.")
        return SecretValue(name=name, _value=raw_value)

    def _env_name(self, name: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
        return f"{self._prefix}{normalized}"


HttpJsonGetter = Callable[[str, Mapping[str, str], float], Mapping[str, object]]


class VaultSecretManager:
    def __init__(
        self,
        *,
        address: str,
        mount: str,
        token_env: str,
        token_file: Path | None = None,
        namespace: str | None = None,
        timeout_seconds: int = 3,
        ca_cert_path: Path | None = None,
        http_get_json: HttpJsonGetter | None = None,
        require_token: bool = False,
        outbound_policy: OutboundHttpPolicy | None = None,
    ) -> None:
        if not address:
            raise SecretConfigurationError("Vault address is required for the vault secret backend.")
        if not mount or "/" in mount.strip("/"):
            raise SecretConfigurationError("Vault mount must be a single non-empty path segment.")
        if not token_env:
            raise SecretConfigurationError("Vault token environment variable name is required.")
        if timeout_seconds <= 0:
            raise SecretConfigurationError("Vault timeout must be greater than zero seconds.")
        if ca_cert_path is not None and not ca_cert_path.is_file():
            raise SecretConfigurationError("Vault CA certificate file is unavailable.")

        self._address = address.rstrip("/")
        self._outbound_policy = outbound_policy or OutboundHttpPolicy.local_unrestricted()
        try:
            self._outbound_policy.validate_url(self._address)
        except OutboundHttpPolicyError:
            raise SecretConfigurationError(
                "Vault endpoint is blocked by outbound policy."
            ) from None
        self._mount = mount.strip("/")
        self._token_env = token_env
        self._token_file = token_file
        self._namespace = namespace
        self._timeout_seconds = timeout_seconds
        self._http_get_json = http_get_json or (
            lambda url, headers, timeout: _urllib_get_json(
                url,
                headers,
                timeout,
                ca_cert_path=ca_cert_path,
                policy=self._outbound_policy,
            )
        )

        if require_token:
            self._read_token()

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        _validate_secret_name(name)
        if not field or "/" in field:
            raise SecretAccessError("Vault secret field must be a non-empty key, not a path.")

        secret_path = "/".join(parse.quote(part, safe="") for part in name.split("/"))
        url = f"{self._address}/v1/{self._mount}/data/{secret_path}"
        try:
            self._outbound_policy.validate_url(url)
        except OutboundHttpPolicyError:
            raise SecretAccessError("Vault endpoint is blocked by outbound policy.") from None
        headers = {"X-Vault-Token": self._read_token()}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace

        payload = self._http_get_json(url, headers, self._timeout_seconds)
        secret_data = _vault_kv2_data(payload, name)
        raw_value = secret_data.get(field)
        if raw_value is None:
            raise SecretNotFoundError(f"Secret {name!r} does not contain field {field!r}.")
        if not isinstance(raw_value, str):
            raise SecretAccessError(f"Secret {name!r} field {field!r} must be a string value.")
        return SecretValue(name=name, _value=raw_value)

    def _read_token(self) -> str:
        if self._token_file is not None:
            try:
                return read_runtime_secret_file(
                    str(self._token_file),
                    variable_name="HALLU_DEFENSE_VAULT_TOKEN_FILE",
                )
            except RuntimeSecretError as exc:
                raise SecretConfigurationError(str(exc)) from exc
        token = os.getenv(self._token_env)
        if not token:
            raise SecretConfigurationError(
                f"Vault token environment variable {self._token_env!r} is not configured."
            )
        return token


def create_secret_manager(settings: Settings) -> SecretManager:
    backend = settings.secrets_backend.strip().lower()
    environment = settings.environment.strip().lower()

    if backend == "env":
        if environment not in LOCAL_SECRET_BACKEND_ENVIRONMENTS:
            raise SecretConfigurationError(
                "The env secret backend is only allowed for local, test, dev, or CI environments."
            )
        return EnvSecretManager(settings.env_secret_prefix)

    if backend == "vault":
        if settings.vault_addr is None:
            raise SecretConfigurationError("HALLU_DEFENSE_VAULT_ADDR is required for vault secrets.")
        try:
            outbound_policy = outbound_http_policy_from_settings(settings)
        except OutboundHttpPolicyError:
            raise SecretConfigurationError("Vault outbound policy is invalid.") from None
        return VaultSecretManager(
            address=settings.vault_addr,
            mount=settings.vault_mount,
            namespace=settings.vault_namespace,
            token_env=settings.vault_token_env,
            token_file=settings.vault_token_file,
            timeout_seconds=settings.vault_timeout_seconds,
            ca_cert_path=settings.vault_ca_cert_path,
            require_token=environment not in LOCAL_SECRET_BACKEND_ENVIRONMENTS,
            outbound_policy=outbound_policy,
        )

    raise SecretConfigurationError(f"Unsupported secret backend {settings.secrets_backend!r}.")


def _validate_secret_name(name: str) -> None:
    if not SECRET_NAME_RE.fullmatch(name):
        raise SecretAccessError("Secret names must use only letters, numbers, '.', '_', '-', and '/'.")
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise SecretAccessError("Secret names must be relative paths without empty segments.")
    if any(part in {".", ".."} for part in name.split("/")):
        raise SecretAccessError("Secret names must not contain traversal segments.")


def _vault_kv2_data(payload: Mapping[str, object], name: str) -> Mapping[str, object]:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise SecretAccessError(f"Vault response for secret {name!r} does not contain data.")
    nested = data.get("data")
    if not isinstance(nested, Mapping):
        raise SecretAccessError(f"Vault response for secret {name!r} is not a KV v2 payload.")
    return nested


def _urllib_get_json(
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    *,
    ca_cert_path: Path | None = None,
    policy: OutboundHttpPolicy | None = None,
) -> Mapping[str, object]:
    effective_policy = policy or OutboundHttpPolicy.local_unrestricted()
    try:
        effective_policy.validate_url(url)
    except OutboundHttpPolicyError:
        raise SecretAccessError("Vault endpoint is blocked by outbound policy.") from None
    vault_request = request.Request(url, headers=dict(headers), method="GET")
    context = (
        ssl.create_default_context(cafile=str(ca_cert_path))
        if ca_cert_path is not None
        else None
    )
    try:
        with open_url_no_redirect(
            vault_request,
            timeout=timeout_seconds,
            context=context,
        ) as response:
            raw_payload = response.read(MAX_VAULT_HTTP_RESPONSE_BYTES + 1)
    except OutboundHttpRedirectError:
        raise SecretAccessError("Vault redirects are not allowed.") from None
    except error.HTTPError as exc:
        status_code = exc.code
        try:
            exc.close()
        finally:
            if status_code == 404:
                raise SecretNotFoundError("Vault secret was not found.") from None
            raise SecretAccessError(
                f"Vault secret read failed with HTTP status {status_code}."
            ) from None
    except error.URLError:
        raise SecretAccessError("Vault secret read failed.") from None
    except (TimeoutError, OSError):
        raise SecretAccessError("Vault secret read failed.") from None

    if len(raw_payload) > MAX_VAULT_HTTP_RESPONSE_BYTES:
        raise SecretResponseTooLargeError("Vault response exceeded the 1 MiB safety limit.")

    try:
        parsed = json.loads(raw_payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SecretAccessError("Vault response was not valid UTF-8 JSON.") from None
    if not isinstance(parsed, Mapping):
        raise SecretAccessError("Vault response must be a JSON object.")
    return parsed
