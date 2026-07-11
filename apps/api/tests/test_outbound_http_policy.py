from __future__ import annotations

from pathlib import Path

import pytest

from hallu_defense.config import (
    RuntimeTransportConfigurationError,
    Settings,
    validate_runtime_transport_settings,
)
from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpPolicyError,
    canonicalize_https_origin,
)
from hallu_defense.services.oidc import OidcJwksResolver, OidcJwtValidationError
from hallu_defense.services.providers import ProviderConfigurationError, create_model_provider
from hallu_defense.services.rag_index import RagIndexConfigurationError, create_rag_index_backend
from hallu_defense.services.secrets import (
    SecretConfigurationError,
    SecretNotFoundError,
    SecretValue,
    create_secret_manager,
)
from hallu_defense.services.telemetry import TelemetryService


class EmptySecretManager:
    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        del field
        raise SecretNotFoundError(name)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_https_origins_are_idna_and_default_port_canonicalized() -> None:
    unicode_origin = canonicalize_https_origin("HTTPS://BÜCHER.Example:443")
    ipv6_origin = canonicalize_https_origin("https://[2001:db8::1]:8443")

    assert unicode_origin.value == "https://xn--bcher-kva.example"
    assert unicode_origin.port == 443
    assert ipv6_origin.value == "https://[2001:db8::1]:8443"


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.test",
        "https://user@example.test",
        "https://example.test/",
        "https://example.test?mode=test",
        "https://example.test#fragment",
        "https://*.example.test",
        "https://example.test.",
        "https://example.test:",
        " https://example.test",
    ],
)
def test_https_origin_rejects_non_origin_or_ambiguous_forms(origin: str) -> None:
    with pytest.raises(OutboundHttpPolicyError):
        canonicalize_https_origin(origin)


@pytest.mark.parametrize(
    "unsafe_character",
    [
        pytest.param("\\", id="backslash"),
        pytest.param("\x00", id="nul"),
        pytest.param("\x1f", id="c0-unit-separator"),
        pytest.param("\x7f", id="del"),
    ],
)
def test_origin_and_endpoint_parsers_reject_url_differential_characters(
    unsafe_character: str,
) -> None:
    with pytest.raises(OutboundHttpPolicyError, match="invalid"):
        canonicalize_https_origin(f"https://exa{unsafe_character}mple.test")

    with pytest.raises(OutboundHttpPolicyError, match="invalid"):
        OutboundHttpPolicy.local_unrestricted().validate_url(
            f"https://example.test/v1{unsafe_character}resource"
        )


def test_policy_rejects_canonical_duplicates() -> None:
    with pytest.raises(OutboundHttpPolicyError, match="duplicates"):
        OutboundHttpPolicy.from_values(
            environment="production",
            allowed_origins=("https://EXAMPLE.test", "https://example.test:443"),
        )


def test_production_requires_non_empty_allowlist() -> None:
    with pytest.raises(OutboundHttpPolicyError, match="non-empty"):
        OutboundHttpPolicy.from_values(environment="production", allowed_origins=())


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.1.8",
        "0.0.0.0",
        "224.0.0.8",
        "[::1]",
        "[fe80::1]",
        "[::]",
        "[ff02::1]",
        "localhost",
        "foo.localhost",
        "127.1",
        "127.000.000.001",
        "2130706433",
        "0x7f000001",
    ],
)
def test_production_rejects_unsafe_or_ambiguous_ip_literals(host: str) -> None:
    with pytest.raises(OutboundHttpPolicyError):
        OutboundHttpPolicy.from_values(
            environment="production",
            allowed_origins=(f"https://{host}",),
        )


def test_private_literal_is_allowed_only_when_explicitly_listed() -> None:
    policy = OutboundHttpPolicy.from_values(
        environment="production",
        allowed_origins=("https://10.20.30.40:8443",),
    )

    assert policy.validate_url("https://10.20.30.40:8443/v1").value == (
        "https://10.20.30.40:8443"
    )
    with pytest.raises(OutboundHttpPolicyError, match="not allowed"):
        policy.validate_url("https://10.20.30.41:8443/v1")


def test_local_runtime_keeps_plaintext_localhost_without_allowlist() -> None:
    policy = OutboundHttpPolicy.local_unrestricted()

    assert policy.validate_url("http://127.0.0.1:11434/api/chat") is None
    assert policy.validate_url("http://localhost:8200/v1/secret") is None


def test_runtime_transport_validation_covers_every_active_http_endpoint() -> None:
    settings = _settings(
        environment="production",
        auth_claims_mode="oidc_jwt",
        oidc_issuer="https://auth.example.test/realms/hallu-defense",
        oidc_jwks_url="https://auth.example.test/realms/hallu-defense/jwks",
        secrets_backend="vault",
        vault_addr="https://vault.example.test:8200",
        provider_backend="openai-compatible",
        openai_compatible_base_url="https://llm.example.test/v1",
        rag_index_backend="opensearch",
        opensearch_endpoint="https://search.example.test",
        otel_enabled=True,
        otel_exporter="otlp",
        otel_endpoint="https://otel.example.test/v1/traces",
        outbound_https_allowed_origins=(
            "https://auth.example.test",
            "https://vault.example.test:8200",
            "https://llm.example.test",
            "https://search.example.test",
            "https://otel.example.test",
        ),
    )

    validate_runtime_transport_settings(settings)


def test_runtime_transport_validation_rejects_unlisted_active_endpoint() -> None:
    settings = _settings(
        environment="production",
        provider_backend="openai-compatible",
        openai_compatible_base_url="https://unlisted.example.test/v1",
        outbound_https_allowed_origins=("https://approved.example.test",),
    )

    with pytest.raises(
        RuntimeTransportConfigurationError,
        match="OPENAI_COMPATIBLE_BASE_URL",
    ):
        validate_runtime_transport_settings(settings)


def test_network_factories_revalidate_endpoints_when_settings_loader_is_bypassed() -> None:
    allowed_origins = ("https://approved.example.test",)

    with pytest.raises(ProviderConfigurationError, match="blocked"):
        create_model_provider(
            _settings(
                environment="production",
                provider_backend="openai-compatible",
                openai_compatible_base_url="https://unlisted.example.test/v1",
                outbound_https_allowed_origins=allowed_origins,
            ),
            EmptySecretManager(),
        )

    with pytest.raises(SecretConfigurationError, match="blocked"):
        create_secret_manager(
            _settings(
                environment="production",
                secrets_backend="vault",
                vault_addr="https://unlisted.example.test",
                outbound_https_allowed_origins=allowed_origins,
            )
        )

    with pytest.raises(OidcJwtValidationError, match="blocked"):
        OidcJwksResolver(
            _settings(
                environment="production",
                oidc_issuer="https://unlisted.example.test",
                oidc_jwks_url="https://unlisted.example.test/jwks",
                outbound_https_allowed_origins=allowed_origins,
            )
        )

    with pytest.raises(RagIndexConfigurationError, match="blocked"):
        create_rag_index_backend(
            _settings(
                environment="production",
                rag_index_backend="opensearch",
                opensearch_endpoint="https://unlisted.example.test",
                outbound_https_allowed_origins=allowed_origins,
            )
        )

    with pytest.raises(ValueError, match="OTLP endpoint is blocked"):
        TelemetryService.from_settings(
            _settings(
                environment="production",
                otel_enabled=True,
                otel_exporter="otlp",
                otel_endpoint="https://unlisted.example.test/v1/traces",
                outbound_https_allowed_origins=allowed_origins,
            )
        )
