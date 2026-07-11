from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from pathlib import PurePosixPath

from psycopg import ProgrammingError
from psycopg.conninfo import conninfo_to_dict

PRODUCTION_LIKE_ENVIRONMENTS = frozenset({"production", "staging"})
KIND_POSTGRES_HOST = "hallu-defense-pgvector"


class PostgresTlsConfigurationError(ValueError):
    """Raised when a production PostgreSQL connection can bypass peer verification."""


def validate_postgres_tls(
    dsn: str,
    *,
    environment: str,
    ca_cert_path: Path | None,
    kind_insecure_tls_enabled: bool,
    trust_file_path: Path | None = None,
) -> None:
    """Validate PostgreSQL TLS without ever including the sensitive DSN in errors.

    ``ca_cert_path`` is the path encoded in ``sslrootcert`` inside the runtime
    container. ``trust_file_path`` optionally points at the equivalent host-side
    file for deployment preflight checks.
    """

    normalized_environment = environment.strip().lower()
    if normalized_environment not in PRODUCTION_LIKE_ENVIRONMENTS:
        if kind_insecure_tls_enabled:
            raise PostgresTlsConfigurationError(
                "The Kind PostgreSQL TLS exception is valid only in the exact production-profile Kind fixture."
            )
        return

    try:
        parameters = conninfo_to_dict(dsn)
    except (ProgrammingError, UnicodeError, ValueError) as exc:
        raise PostgresTlsConfigurationError(
            "The PostgreSQL DSN is invalid; its value was not disclosed."
        ) from exc

    if _parameter_text(parameters, "hostaddr") or os.getenv("PGHOSTADDR", "").strip():
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL forbid hostaddr and PGHOSTADDR overrides."
        )

    if kind_insecure_tls_enabled:
        _validate_kind_exception(parameters, environment=normalized_environment)
        return

    if _parameter_text(parameters, "sslmode").strip().lower() != "verify-full":
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL require sslmode=verify-full."
        )
    if _parameter_text(parameters, "ssl_min_protocol_version") != "TLSv1.3":
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL require ssl_min_protocol_version=TLSv1.3."
        )
    if _parameter_text(parameters, "gssencmode").strip().lower() != "disable":
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL require gssencmode=disable so GSS encryption cannot bypass TLS verification."
        )
    if ca_cert_path is None:
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL require HALLU_DEFENSE_POSTGRES_CA_CERT_PATH."
        )
    if not _is_absolute_path(ca_cert_path):
        raise PostgresTlsConfigurationError("HALLU_DEFENSE_POSTGRES_CA_CERT_PATH must be absolute.")
    configured_root = _parameter_text(parameters, "sslrootcert")
    if _portable_path(configured_root) != _portable_path(str(ca_cert_path)):
        raise PostgresTlsConfigurationError(
            "Production and staging PostgreSQL require sslrootcert to match HALLU_DEFENSE_POSTGRES_CA_CERT_PATH."
        )
    _validate_trust_file(trust_file_path or ca_cert_path)


def _validate_kind_exception(
    parameters: Mapping[str, object],
    *,
    environment: str,
) -> None:
    if environment != "production":
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception is forbidden in staging."
        )
    if _parameter_text(parameters, "host") != KIND_POSTGRES_HOST:
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception requires the exact in-cluster pgvector host."
        )
    if (_parameter_text(parameters, "port") or "5432") != "5432":
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception requires the exact pgvector port."
        )
    if _parameter_text(parameters, "sslmode").strip().lower() != "disable":
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception requires explicit sslmode=disable."
        )
    if _parameter_text(parameters, "gssencmode").strip().lower() != "disable":
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception requires gssencmode=disable."
        )
    if _parameter_text(parameters, "sslrootcert"):
        raise PostgresTlsConfigurationError(
            "The Kind PostgreSQL TLS exception must not mix an sslrootcert with disabled TLS."
        )


def _parameter_text(parameters: Mapping[str, object], name: str) -> str:
    value = parameters.get(name)
    if value is None:
        return ""
    if isinstance(value, (str, int)):
        return str(value)
    return ""


def _validate_trust_file(path: Path) -> None:
    if not path.is_absolute():
        raise PostgresTlsConfigurationError("The PostgreSQL CA trust file must be absolute.")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PostgresTlsConfigurationError("The PostgreSQL CA trust file is unavailable.") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PostgresTlsConfigurationError(
            "The PostgreSQL CA trust file must be a regular non-symlink file."
        )
    if not os.access(path, os.R_OK):
        raise PostgresTlsConfigurationError("The PostgreSQL CA trust file is not readable.")
    if os.name != "nt":
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PostgresTlsConfigurationError(
                "The PostgreSQL CA trust file must not be group- or world-writable."
            )
        owner = getattr(metadata, "st_uid", None)
        effective_uid_getter = getattr(os, "geteuid", None)
        if not callable(effective_uid_getter):
            raise PostgresTlsConfigurationError(
                "The PostgreSQL CA trust-file owner cannot be verified on this platform."
            )
        effective_uid = int(effective_uid_getter())
        if owner not in {0, effective_uid}:
            raise PostgresTlsConfigurationError(
                "The PostgreSQL CA trust file must be owned by root or the runtime user."
            )


def _is_absolute_path(path: Path) -> bool:
    return path.is_absolute() or PurePosixPath(_portable_path(str(path))).is_absolute()


def _portable_path(value: str) -> str:
    return value.replace("\\", "/")
