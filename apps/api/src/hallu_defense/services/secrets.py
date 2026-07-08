from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib import error, parse, request

from hallu_defense.config import Settings

LOCAL_SECRET_BACKEND_ENVIRONMENTS = {"ci", "dev", "development", "local", "test"}
SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,255}$")


class SecretConfigurationError(RuntimeError):
    pass


class SecretNotFoundError(LookupError):
    pass


class SecretAccessError(RuntimeError):
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
        namespace: str | None = None,
        timeout_seconds: int = 3,
        http_get_json: HttpJsonGetter | None = None,
        require_token: bool = False,
    ) -> None:
        if not address:
            raise SecretConfigurationError("Vault address is required for the vault secret backend.")
        if not mount or "/" in mount.strip("/"):
            raise SecretConfigurationError("Vault mount must be a single non-empty path segment.")
        if not token_env:
            raise SecretConfigurationError("Vault token environment variable name is required.")
        if timeout_seconds <= 0:
            raise SecretConfigurationError("Vault timeout must be greater than zero seconds.")

        self._address = address.rstrip("/")
        self._mount = mount.strip("/")
        self._token_env = token_env
        self._namespace = namespace
        self._timeout_seconds = timeout_seconds
        self._http_get_json = http_get_json or _urllib_get_json

        if require_token:
            self._read_token()

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        _validate_secret_name(name)
        if not field or "/" in field:
            raise SecretAccessError("Vault secret field must be a non-empty key, not a path.")

        secret_path = "/".join(parse.quote(part, safe="") for part in name.split("/"))
        url = f"{self._address}/v1/{self._mount}/data/{secret_path}"
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
        return VaultSecretManager(
            address=settings.vault_addr,
            mount=settings.vault_mount,
            namespace=settings.vault_namespace,
            token_env=settings.vault_token_env,
            timeout_seconds=settings.vault_timeout_seconds,
            require_token=environment not in LOCAL_SECRET_BACKEND_ENVIRONMENTS,
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


def _urllib_get_json(url: str, headers: Mapping[str, str], timeout_seconds: float) -> Mapping[str, object]:
    vault_request = request.Request(url, headers=dict(headers), method="GET")
    try:
        with request.urlopen(vault_request, timeout=timeout_seconds) as response:
            raw_payload = response.read()
    except error.HTTPError as exc:
        if exc.code == 404:
            raise SecretNotFoundError("Vault secret was not found.") from exc
        raise SecretAccessError(f"Vault secret read failed with HTTP status {exc.code}.") from exc
    except error.URLError as exc:
        raise SecretAccessError("Vault secret read failed.") from exc

    parsed = json.loads(raw_payload.decode("utf-8"))
    if not isinstance(parsed, Mapping):
        raise SecretAccessError("Vault response must be a JSON object.")
    return parsed
