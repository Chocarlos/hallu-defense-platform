from __future__ import annotations

from pathlib import Path

import pytest

from hallu_defense.config import (
    DEFAULT_CORS_ALLOW_ORIGINS,
    CorsConfigurationError,
    Settings,
    load_settings,
    validate_cors_settings,
)


def _settings_with_origins(environment: str, origins: tuple[str, ...]) -> Settings:
    return Settings(
        environment=environment,
        policy_version="test",
        auth_required=False,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
        cors_allow_origins=origins,
    )


def test_default_cors_origins_used_when_env_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", raising=False)
    monkeypatch.delenv("HALLU_DEFENSE_ENV", raising=False)

    settings = load_settings()

    assert settings.cors_allow_origins == DEFAULT_CORS_ALLOW_ORIGINS
    assert "http://localhost:3000" in settings.cors_allow_origins


def test_cors_origins_env_is_trimmed_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_ENV", raising=False)
    monkeypatch.setenv(
        "HALLU_DEFENSE_CORS_ALLOW_ORIGINS",
        "http://localhost:3100, http://127.0.0.1:3100 ,http://localhost:3100",
    )

    settings = load_settings()

    assert settings.cors_allow_origins == (
        "http://localhost:3100",
        "http://127.0.0.1:3100",
    )


def test_wildcard_cors_origin_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_ENV", raising=False)
    monkeypatch.setenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", "*")

    with pytest.raises(CorsConfigurationError, match="wildcard"):
        load_settings()


def test_relative_cors_origin_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_ENV", raising=False)
    monkeypatch.setenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", "localhost:3100")

    with pytest.raises(CorsConfigurationError, match="absolute HTTP"):
        load_settings()


def test_cors_origin_with_path_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_ENV", raising=False)
    monkeypatch.setenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", "http://localhost:3100/console")

    with pytest.raises(CorsConfigurationError, match="path or query"):
        load_settings()


def test_production_rejects_plaintext_cors_origins() -> None:
    settings = _settings_with_origins("production", ("http://console.example.com",))

    with pytest.raises(CorsConfigurationError, match="https"):
        validate_cors_settings(settings)


def test_production_accepts_https_cors_origins() -> None:
    settings = _settings_with_origins("production", ("https://console.example.com",))

    validate_cors_settings(settings)


def test_empty_cors_origins_tuple_is_rejected() -> None:
    settings = _settings_with_origins("local", ())

    with pytest.raises(CorsConfigurationError, match="at least one origin"):
        validate_cors_settings(settings)
