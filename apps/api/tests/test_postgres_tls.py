from __future__ import annotations

from pathlib import Path

import pytest

from hallu_defense.postgres_tls import (
    PostgresTlsConfigurationError,
    validate_postgres_tls,
)


def test_production_postgres_requires_verify_full_and_readable_matching_ca(
    tmp_path: Path,
) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={ca_path.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable"
    )

    validate_postgres_tls(
        dsn,
        environment="production",
        ca_cert_path=ca_path,
        kind_insecure_tls_enabled=False,
    )


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://runtime@db.example.test/app",
        "postgresql://runtime@db.example.test/app?sslmode=require",
        "postgresql://runtime@db.example.test/app?sslmode=verify-ca",
    ],
)
def test_production_postgres_rejects_non_verifying_tls(
    tmp_path: Path,
    dsn: str,
) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")

    with pytest.raises(PostgresTlsConfigurationError, match="sslmode=verify-full"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=ca_path,
            kind_insecure_tls_enabled=False,
        )


def test_production_postgres_rejects_mismatched_or_unreadable_ca(
    tmp_path: Path,
) -> None:
    configured = (tmp_path / "configured-ca.crt").resolve()
    different = (tmp_path / "different-ca.crt").resolve()
    configured.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={different.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable"
    )

    with pytest.raises(PostgresTlsConfigurationError, match="sslrootcert"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=configured,
            kind_insecure_tls_enabled=False,
        )


def test_exact_kind_postgres_exception_is_narrow_and_explicit() -> None:
    validate_postgres_tls(
        "postgresql://kind@hallu-defense-pgvector:5432/hallu_defense?sslmode=disable&gssencmode=disable",
        environment="production",
        ca_cert_path=None,
        kind_insecure_tls_enabled=True,
    )

    with pytest.raises(PostgresTlsConfigurationError, match="exact in-cluster"):
        validate_postgres_tls(
            "postgresql://kind@managed-db:5432/hallu_defense?sslmode=disable&gssencmode=disable",
            environment="production",
            ca_cert_path=None,
            kind_insecure_tls_enabled=True,
        )


def test_production_postgres_rejects_tls_below_v13(tmp_path: Path) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={ca_path.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.2&gssencmode=disable"
    )

    with pytest.raises(PostgresTlsConfigurationError, match="TLSv1.3"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=ca_path,
            kind_insecure_tls_enabled=False,
        )


def test_kind_postgres_exception_is_forbidden_in_staging_and_local() -> None:
    dsn = (
        "postgresql://kind@hallu-defense-pgvector:5432/hallu_defense"
        "?sslmode=disable&gssencmode=disable"
    )
    for environment in ("staging", "local"):
        with pytest.raises(PostgresTlsConfigurationError, match="Kind PostgreSQL TLS exception"):
            validate_postgres_tls(
                dsn,
                environment=environment,
                ca_cert_path=None,
                kind_insecure_tls_enabled=True,
            )


def test_production_postgres_rejects_gss_encryption_fallback(tmp_path: Path) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={ca_path.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3"
    )

    with pytest.raises(PostgresTlsConfigurationError, match="gssencmode=disable"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=ca_path,
            kind_insecure_tls_enabled=False,
        )


@pytest.mark.parametrize("from_environment", [False, True])
def test_kind_postgres_exception_rejects_hostaddr_override(
    monkeypatch: pytest.MonkeyPatch,
    from_environment: bool,
) -> None:
    dsn = (
        "postgresql://kind@hallu-defense-pgvector:5432/hallu_defense"
        "?sslmode=disable&gssencmode=disable"
    )
    if from_environment:
        monkeypatch.setenv("PGHOSTADDR", "203.0.113.10")
    else:
        dsn += "&hostaddr=203.0.113.10"

    with pytest.raises(PostgresTlsConfigurationError, match="hostaddr"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=None,
            kind_insecure_tls_enabled=True,
        )


@pytest.mark.parametrize("from_environment", [False, True])
def test_production_postgres_rejects_hostaddr_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    from_environment: bool,
) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={ca_path.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable"
    )
    if from_environment:
        monkeypatch.setenv("PGHOSTADDR", "203.0.113.10")
    else:
        dsn += "&hostaddr=203.0.113.10"

    with pytest.raises(PostgresTlsConfigurationError, match="hostaddr"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=ca_path,
            kind_insecure_tls_enabled=False,
        )


@pytest.mark.posix
def test_production_postgres_rejects_writable_ca_trust_file(tmp_path: Path) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    ca_path.chmod(0o666)
    dsn = (
        "postgresql://runtime@db.example.test/app"
        f"?sslmode=verify-full&sslrootcert={ca_path.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable"
    )

    with pytest.raises(PostgresTlsConfigurationError, match="writable"):
        validate_postgres_tls(
            dsn,
            environment="production",
            ca_cert_path=ca_path,
            kind_insecure_tls_enabled=False,
        )
