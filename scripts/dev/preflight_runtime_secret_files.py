from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from hallu_defense.runtime_secrets import RuntimeSecretError, read_runtime_secret_file
from hallu_defense.postgres_tls import (
    PostgresTlsConfigurationError,
    validate_postgres_tls,
)

SECRET_FILE_ENVIRONMENTS = (
    "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE",
    "HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE",
    "HALLU_DEFENSE_POSTGRES_DSN_FILE",
    "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE",
    "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH",
)
ONE_LINE_SECRET_FILE_ENVIRONMENTS = frozenset(
    {
        "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE",
        "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE",
    }
)
POSTGRES_DSN_FILE_ENVIRONMENTS = (
    "HALLU_DEFENSE_POSTGRES_DSN_FILE",
    "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE",
)
POSTGRES_CONTAINER_CA_PATH = Path("/run/hallu-defense/postgres/ca.crt")
EXPECTED_OWNER_UID = 0
EXPECTED_READER_GID = 10001
EXPECTED_MODE = 0o440
EXPECTED_PARENT_MODE = 0o750


class RuntimeSecretPreflightError(ValueError):
    pass


def validate_runtime_secret_paths(environ: Mapping[str, str]) -> tuple[Path, ...]:
    validated: list[Path] = []
    for variable_name in SECRET_FILE_ENVIRONMENTS:
        raw_path = environ.get(variable_name, "").strip()
        if not raw_path:
            raise RuntimeSecretPreflightError(f"{variable_name} must be set.")
        path = Path(raw_path)
        if not path.is_absolute():
            raise RuntimeSecretPreflightError(
                f"{variable_name} must reference an absolute host path."
            )
        if ".." in path.parts:
            raise RuntimeSecretPreflightError(
                f"{variable_name} must not contain parent-directory traversal."
            )
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise RuntimeSecretPreflightError(
                f"{variable_name} is unavailable."
            ) from exc
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeSecretPreflightError(
                f"{variable_name} must reference a regular non-symlink file."
            )
        if (
            metadata.st_uid != EXPECTED_OWNER_UID
            or metadata.st_gid != EXPECTED_READER_GID
        ):
            raise RuntimeSecretPreflightError(
                f"{variable_name} must be owned by root:{EXPECTED_READER_GID}."
            )
        if mode != EXPECTED_MODE:
            raise RuntimeSecretPreflightError(f"{variable_name} must use mode 0440.")
        _validate_secret_parent_chain(path, variable_name=variable_name)
        if variable_name in ONE_LINE_SECRET_FILE_ENVIRONMENTS:
            try:
                read_runtime_secret_file(str(path), variable_name=variable_name)
            except RuntimeSecretError as exc:
                raise RuntimeSecretPreflightError(str(exc)) from exc
        validated.append(path)
    return tuple(validated)


def validate_postgres_tls_inputs(environ: Mapping[str, str]) -> None:
    raw_ca_path = environ.get("HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH", "").strip()
    if not raw_ca_path:
        raise RuntimeSecretPreflightError(
            "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH must be set."
        )
    host_ca_path = Path(raw_ca_path)
    for variable_name in POSTGRES_DSN_FILE_ENVIRONMENTS:
        raw_dsn_path = environ.get(variable_name, "").strip()
        if not raw_dsn_path:
            raise RuntimeSecretPreflightError(f"{variable_name} must be set.")
        try:
            dsn = read_runtime_secret_file(raw_dsn_path, variable_name=variable_name)
            validate_postgres_tls(
                dsn,
                environment="production",
                ca_cert_path=POSTGRES_CONTAINER_CA_PATH,
                kind_insecure_tls_enabled=False,
                trust_file_path=host_ca_path,
            )
        except (RuntimeSecretError, PostgresTlsConfigurationError) as exc:
            raise RuntimeSecretPreflightError(str(exc)) from exc


def _validate_secret_parent_chain(path: Path, *, variable_name: str) -> None:
    current = path.parent
    direct_parent = True
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise RuntimeSecretPreflightError(
                f"{variable_name} has an unavailable parent directory."
            ) from exc
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeSecretPreflightError(
                f"{variable_name} parent chain must contain only real directories."
            )
        if metadata.st_uid != EXPECTED_OWNER_UID:
            raise RuntimeSecretPreflightError(
                f"{variable_name} parent directories must be root-owned."
            )
        if direct_parent:
            if metadata.st_gid != EXPECTED_READER_GID or mode != EXPECTED_PARENT_MODE:
                raise RuntimeSecretPreflightError(
                    f"{variable_name} direct parent must be root:{EXPECTED_READER_GID} mode 0750."
                )
        elif mode & 0o022:
            raise RuntimeSecretPreflightError(
                f"{variable_name} ancestor directories must not be group/other writable."
            )
        parent = current.parent
        if parent == current:
            return
        current = parent
        direct_parent = False


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    if os.name == "nt":
        print(
            json.dumps(
                {
                    "status": "error",
                    "reason": "production secret-file preflight requires a Linux/POSIX deployment host",
                },
                separators=(",", ":"),
            )
        )
        return 1
    try:
        validated = validate_runtime_secret_paths(os.environ)
        validate_postgres_tls_inputs(os.environ)
    except RuntimeSecretPreflightError as exc:
        print(
            json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":"))
        )
        return 1
    print(
        json.dumps(
            {"status": "ok", "validated_file_count": len(validated)},
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
