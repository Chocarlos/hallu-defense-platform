"""Skip-safe PostgreSQL backup/restore drill with encrypted S3 upload.

The enabled path uses:

- ``docker compose exec -T postgres pg_dump`` for the source dump.
- A Fernet key read through ``SecretManager``.
- A bounded in-process SigV4 upload to the S3-compatible endpoint.
- A scratch PostgreSQL database restored with ``pg_restore``.
- Row-count/checksum parity written to ``var/backup-drills/<timestamp>.json``.

By default the script is skipped. Unit tests inject a fake command runner,
secret manager, cipher, and S3 client, so no network, Vault, or Postgres is
needed to exercise the control flow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import PRODUCTION_LIKE_ENVIRONMENTS, Settings  # noqa: E402
from hallu_defense.services.data_lifecycle import POSTGRES_LIFECYCLE_TABLES  # noqa: E402
from hallu_defense.services.secrets import (  # noqa: E402
    SecretManager,
    create_secret_manager,
)
from scripts.dev.s3_sigv4 import (  # noqa: E402
    DEFAULT_REGION,
    S3SigV4Client,
    S3SigV4Config,
    S3SigV4Error,
)

ENABLED_ENV = "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED"
SECRET_NAME_ENV = "HALLU_DEFENSE_BACKUP_ENCRYPTION_SECRET_NAME"
DEFAULT_BACKUP_SECRET_NAME = "backup/encryption-key"

DEFAULT_POSTGRES_SERVICE = "postgres"
DEFAULT_POSTGRES_USER = "hallu"
DEFAULT_POSTGRES_DATABASE = "hallu_defense"
DEFAULT_OUTPUT_DIR = ROOT / "var" / "backup-drills"
DEFAULT_MINIO_BUCKET = "hallu-backups"
DEFAULT_MINIO_ALIAS = "hallu"
DEFAULT_MINIO_ENDPOINT = "http://127.0.0.1:9000"
DEFAULT_MINIO_ACCESS_KEY = "minioadmin"
DEFAULT_MINIO_SECRET_KEY = "minioadmin"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_BACKUP_BYTES = 1024 * 1024 * 1024
DEFAULT_MINIO_CREDENTIALS_SECRET_NAME = "backup/minio-credentials"
LOCAL_CREDENTIAL_ENVIRONMENTS = {"ci", "dev", "development", "local", "test"}

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
SAFE_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
BACKUP_PARITY_TABLES: tuple[str, ...] = tuple(table.name for table in POSTGRES_LIFECYCLE_TABLES)


class BackupRestoreDrillError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes = b""
    returncode: int = 0


class CommandRunner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout_seconds: int,
    ) -> CommandResult:
        ...


class PayloadCipher(Protocol):
    def encrypt(self, key: str, payload: bytes) -> bytes:
        ...

    def decrypt(self, key: str, payload: bytes) -> bytes:
        ...


class S3BytesClient(Protocol):
    def ensure_bucket(self, bucket: str, *, timeout_seconds: int) -> None: ...

    def upload_file(
        self,
        bucket: str,
        key: str,
        source: Path,
        *,
        timeout_seconds: int,
    ) -> None: ...

    def get_bytes(
        self,
        bucket: str,
        key: str,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> bytes: ...


class _FernetLike(Protocol):
    def encrypt(self, data: bytes) -> bytes:
        ...

    def decrypt(self, token: bytes) -> bytes:
        ...


class SubprocessCommandRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout_seconds: int,
    ) -> CommandResult:
        completed = subprocess.run(
            list(command),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        return CommandResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )


class FernetPayloadCipher:
    def encrypt(self, key: str, payload: bytes) -> bytes:
        _validate_fernet_key(key)
        return _fernet(key).encrypt(payload)

    def decrypt(self, key: str, payload: bytes) -> bytes:
        _validate_fernet_key(key)
        return _fernet(key).decrypt(payload)


@dataclass(frozen=True)
class BackupRestoreDrillConfig:
    enabled: bool
    docker_path: str
    postgres_service: str
    postgres_user: str
    source_database: str
    scratch_database: str
    output_dir: Path
    secret_name: str
    minio_bucket: str
    minio_alias: str
    minio_endpoint: str
    minio_access_key: str = field(repr=False)
    minio_secret_key: str = field(repr=False)
    minio_region: str
    minio_require_https: bool
    minio_allowed_origins: tuple[str, ...]
    minio_allow_private_endpoint: bool
    minio_ca_file: Path | None
    max_backup_bytes: int
    timeout_seconds: int


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    runner: CommandRunner | None = None,
    secret_manager: SecretManager | None = None,
    cipher: PayloadCipher | None = None,
    s3_client: S3BytesClient | None = None,
    timestamp: str | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the backup/restore drill",
            "report_path": None,
        }
    manager = secret_manager or _build_secret_manager(effective_env)
    config = _config_from_env(
        effective_env,
        timestamp=timestamp,
        secret_manager=manager,
    )
    return run_backup_restore_drill(
        config,
        runner=runner or SubprocessCommandRunner(),
        secret_manager=manager,
        cipher=cipher or FernetPayloadCipher(),
        s3_client=s3_client or _build_s3_client(config),
    )


def run_backup_restore_drill(
    config: BackupRestoreDrillConfig,
    *,
    runner: CommandRunner,
    secret_manager: SecretManager,
    cipher: PayloadCipher,
    s3_client: S3BytesClient,
) -> dict[str, object]:
    _validate_config(config)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    key = secret_manager.get_secret(config.secret_name).reveal()
    _validate_fernet_key(key)

    source_parity = _collect_parity(config, runner, database=config.source_database)
    dump = _run_checked(
        runner,
        _compose_exec(
            config,
            "pg_dump",
            "-U",
            config.postgres_user,
            "-d",
            config.source_database,
            "--format=custom",
            "--no-owner",
            "--no-acl",
        ),
        label="pg_dump",
        timeout_seconds=config.timeout_seconds,
    ).stdout
    if not dump:
        raise BackupRestoreDrillError("pg_dump returned an empty dump.")

    encrypted_dump = cipher.encrypt(key, dump)
    if not encrypted_dump or len(encrypted_dump) > config.max_backup_bytes:
        raise BackupRestoreDrillError("Encrypted backup exceeded its configured byte limit.")
    encrypted_path = config.output_dir / f"{_timestamp_from_scratch(config.scratch_database)}.dump.fernet"
    encrypted_path.write_bytes(encrypted_dump)
    object_key = f"postgres/{encrypted_path.name}"
    encrypted_sha256 = hashlib.sha256(encrypted_dump).hexdigest()
    _upload_to_minio(
        config,
        s3_client,
        encrypted_path=encrypted_path,
        object_key=object_key,
    )
    downloaded_dump = _download_from_minio(
        config,
        s3_client,
        object_key=object_key,
    )
    downloaded_sha256 = hashlib.sha256(downloaded_dump).hexdigest()
    if not hmac.compare_digest(encrypted_sha256, downloaded_sha256):
        raise BackupRestoreDrillError(
            "Downloaded MinIO backup checksum does not match the encrypted upload."
        )

    restored = False
    try:
        _run_checked(
            runner,
            _compose_exec(
                config,
                "dropdb",
                "-U",
                config.postgres_user,
                "--if-exists",
                config.scratch_database,
            ),
            label="drop scratch database",
            timeout_seconds=config.timeout_seconds,
        )
        _run_checked(
            runner,
            _compose_exec(
                config,
                "createdb",
                "-U",
                config.postgres_user,
                config.scratch_database,
            ),
            label="create scratch database",
            timeout_seconds=config.timeout_seconds,
        )
        # Restore only the object read back from MinIO. Using the local buffer
        # here would prove upload but not disaster recovery from object storage.
        decrypted_dump = cipher.decrypt(key, downloaded_dump)
        _run_checked(
            runner,
            _compose_exec(
                config,
                "pg_restore",
                "-U",
                config.postgres_user,
                "-d",
                config.scratch_database,
                "--no-owner",
                "--no-acl",
            ),
            input_bytes=decrypted_dump,
            label="pg_restore",
            timeout_seconds=config.timeout_seconds,
        )
        restored = True
        restored_parity = _collect_parity(config, runner, database=config.scratch_database)
    finally:
        _run_checked(
            runner,
            _compose_exec(
                config,
                "dropdb",
                "-U",
                config.postgres_user,
                "--if-exists",
                config.scratch_database,
            ),
            label="cleanup scratch database",
            timeout_seconds=config.timeout_seconds,
        )

    parity_report = _parity_report(source_parity, restored_parity if restored else {})
    report = {
        "status": "passed" if _parity_passed(parity_report) else "failed",
        "timestamp": _timestamp_from_scratch(config.scratch_database),
        "source_database": config.source_database,
        "scratch_database": config.scratch_database,
        "encrypted_dump_path": str(encrypted_path),
        "minio_bucket": config.minio_bucket,
        "minio_compatibility_alias": config.minio_alias,
        "minio_object_key": object_key,
        "encrypted_sha256": encrypted_sha256,
        "restored_from_object_storage": True,
        "secret_name": config.secret_name,
        "tables": parity_report,
        "parity_passed": _parity_passed(parity_report),
    }
    report_path = config.output_dir / f"{_timestamp_from_scratch(config.scratch_database)}.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return {**report, "report_path": str(report_path)}


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    runner: CommandRunner | None = None,
    secret_manager: SecretManager | None = None,
    cipher: PayloadCipher | None = None,
    s3_client: S3BytesClient | None = None,
) -> int:
    _ = argv
    try:
        result = run_from_env(
            env,
            runner=runner,
            secret_manager=secret_manager,
            cipher=cipher,
            s3_client=s3_client,
        )
    except Exception:
        print(
            _json_result(
                {
                    "status": "failed",
                    "error": "Backup/restore drill failed closed; no restore was accepted.",
                }
            )
        )
        return 1
    print(_json_result(result))
    return 0 if result.get("status") != "failed" else 1


def _collect_parity(
    config: BackupRestoreDrillConfig,
    runner: CommandRunner,
    *,
    database: str,
) -> dict[str, dict[str, object]]:
    parity: dict[str, dict[str, object]] = {}
    for table in BACKUP_PARITY_TABLES:
        output = _run_checked(
            runner,
            _compose_exec(
                config,
                "psql",
                "-U",
                config.postgres_user,
                "-d",
                database,
                "-At",
                "-c",
                _parity_sql(table),
            ),
            label=f"parity {database}.{table}",
            timeout_seconds=config.timeout_seconds,
        ).stdout.decode("utf-8", errors="replace").strip()
        parity[table] = _parse_parity_output(output, table=table)
    return parity


def _upload_to_minio(
    config: BackupRestoreDrillConfig,
    client: S3BytesClient,
    *,
    encrypted_path: Path,
    object_key: str,
) -> None:
    try:
        client.ensure_bucket(config.minio_bucket, timeout_seconds=config.timeout_seconds)
        client.upload_file(
            config.minio_bucket,
            object_key,
            encrypted_path,
            timeout_seconds=config.timeout_seconds,
        )
    except S3SigV4Error:
        raise BackupRestoreDrillError("S3-compatible backup upload failed.") from None


def _download_from_minio(
    config: BackupRestoreDrillConfig,
    client: S3BytesClient,
    *,
    object_key: str,
) -> bytes:
    try:
        payload = client.get_bytes(
            config.minio_bucket,
            object_key,
            max_bytes=config.max_backup_bytes,
            timeout_seconds=config.timeout_seconds,
        )
    except S3SigV4Error:
        raise BackupRestoreDrillError("S3-compatible backup download failed.") from None
    if not payload:
        raise BackupRestoreDrillError("MinIO returned an empty encrypted backup.")
    return payload


def _run_checked(
    runner: CommandRunner,
    command: Sequence[str],
    *,
    label: str,
    timeout_seconds: int,
    input_bytes: bytes | None = None,
) -> CommandResult:
    result = runner.run(command, input_bytes=input_bytes, timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise BackupRestoreDrillError(f"{label} failed with exit {result.returncode}: {stderr}")
    return result


def _compose_exec(config: BackupRestoreDrillConfig, *command: str) -> list[str]:
    return [
        config.docker_path,
        "compose",
        "exec",
        "-T",
        config.postgres_service,
        *command,
    ]


def _parity_sql(table: str) -> str:
    return (
        "SELECT count(*)::text || '|' || "
        "COALESCE(md5(string_agg(row_hash, '' ORDER BY row_hash)), 'empty') "
        f"FROM (SELECT md5(row_to_json(t)::text) AS row_hash FROM {table} AS t) AS rows"
    )


def _parse_parity_output(output: str, *, table: str) -> dict[str, object]:
    count_text, separator, checksum = output.partition("|")
    if separator != "|" or not count_text.isdecimal() or not checksum:
        raise BackupRestoreDrillError(f"Invalid parity output for table {table!r}.")
    return {"row_count": int(count_text), "checksum": checksum}


def _parity_report(
    source: Mapping[str, Mapping[str, object]],
    restored: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    report: dict[str, dict[str, object]] = {}
    for table in BACKUP_PARITY_TABLES:
        source_table = dict(source.get(table, {}))
        restored_table = dict(restored.get(table, {}))
        report[table] = {
            "source": source_table,
            "restored": restored_table,
            "matched": source_table == restored_table and bool(source_table),
        }
    return report


def _parity_passed(report: Mapping[str, Mapping[str, object]]) -> bool:
    return bool(report) and all(item.get("matched") is True for item in report.values())


def _config_from_env(
    env: Mapping[str, str],
    *,
    timestamp: str | None,
    secret_manager: SecretManager,
) -> BackupRestoreDrillConfig:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    environment = (_optional(env, "HALLU_DEFENSE_ENV") or "local").lower()
    if environment not in LOCAL_CREDENTIAL_ENVIRONMENTS | PRODUCTION_LIKE_ENVIRONMENTS:
        raise BackupRestoreDrillError("Runtime environment is not approved for this drill.")
    require_https = environment in PRODUCTION_LIKE_ENVIRONMENTS
    if require_https:
        if (_optional(env, "HALLU_DEFENSE_SECRETS_BACKEND") or "env").lower() != "vault":
            raise BackupRestoreDrillError(
                "Production and staging MinIO credentials require the Vault backend."
            )
        credentials_secret_name = (
            _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_CREDENTIALS_SECRET_NAME")
            or DEFAULT_MINIO_CREDENTIALS_SECRET_NAME
        )
        try:
            minio_access_key = secret_manager.get_secret(
                credentials_secret_name,
                field="access_key",
            ).reveal()
            minio_secret_key = secret_manager.get_secret(
                credentials_secret_name,
                field="secret_key",
            ).reveal()
        except Exception:
            raise BackupRestoreDrillError("MinIO credentials could not be loaded.") from None
    else:
        minio_access_key = (
            _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_ACCESS_KEY")
            or DEFAULT_MINIO_ACCESS_KEY
        )
        minio_secret_key = (
            _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_SECRET_KEY")
            or DEFAULT_MINIO_SECRET_KEY
        )
    scratch_database = _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_SCRATCH_DB") or (
        f"hallu_restore_{ts}"
    )
    return BackupRestoreDrillConfig(
        enabled=_enabled(env.get(ENABLED_ENV, "")),
        docker_path=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_DOCKER_PATH") or "docker",
        postgres_service=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_POSTGRES_SERVICE")
        or DEFAULT_POSTGRES_SERVICE,
        postgres_user=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_POSTGRES_USER")
        or DEFAULT_POSTGRES_USER,
        source_database=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_POSTGRES_DB")
        or DEFAULT_POSTGRES_DATABASE,
        scratch_database=scratch_database,
        output_dir=Path(
            _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_OUTPUT_DIR")
            or str(DEFAULT_OUTPUT_DIR)
        ).resolve(),
        secret_name=_optional(env, SECRET_NAME_ENV) or DEFAULT_BACKUP_SECRET_NAME,
        minio_bucket=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_BUCKET")
        or DEFAULT_MINIO_BUCKET,
        minio_alias=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_ALIAS")
        or DEFAULT_MINIO_ALIAS,
        minio_endpoint=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_ENDPOINT")
        or DEFAULT_MINIO_ENDPOINT,
        minio_access_key=minio_access_key,
        minio_secret_key=minio_secret_key,
        minio_region=_optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_REGION")
        or DEFAULT_REGION,
        minio_require_https=require_https,
        minio_allowed_origins=_origins_env(env),
        minio_allow_private_endpoint=environment in LOCAL_CREDENTIAL_ENVIRONMENTS,
        minio_ca_file=(
            Path(ca_path)
            if (ca_path := _optional(env, "HALLU_DEFENSE_BACKUP_DRILL_MINIO_CA_CERT_PATH"))
            else None
        ),
        max_backup_bytes=_int_env(
            env,
            "HALLU_DEFENSE_BACKUP_DRILL_MAX_BACKUP_BYTES",
            DEFAULT_MAX_BACKUP_BYTES,
        ),
        timeout_seconds=_int_env(env, "HALLU_DEFENSE_BACKUP_DRILL_TIMEOUT_SECONDS", 120),
    )


def _build_s3_client(config: BackupRestoreDrillConfig) -> S3SigV4Client:
    try:
        return S3SigV4Client(
            S3SigV4Config(
                endpoint=config.minio_endpoint,
                access_key=config.minio_access_key,
                secret_key=config.minio_secret_key,
                region=config.minio_region,
                require_https=config.minio_require_https,
                allowed_origins=config.minio_allowed_origins,
                allow_private_endpoint=config.minio_allow_private_endpoint,
                ca_file=config.minio_ca_file,
            )
        )
    except S3SigV4Error:
        raise BackupRestoreDrillError("MinIO-compatible S3 configuration is invalid.") from None


def _build_secret_manager(env: Mapping[str, str]) -> SecretManager:
    environment = (_optional(env, "HALLU_DEFENSE_ENV") or "local").lower()
    backend = (_optional(env, "HALLU_DEFENSE_SECRETS_BACKEND") or "env").lower()
    vault_addr = _optional(env, "HALLU_DEFENSE_VAULT_ADDR")
    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if backend != "vault":
            raise BackupRestoreDrillError(
                "Production and staging drills require the Vault secret backend."
            )
        if vault_addr is None or urlsplit(vault_addr).scheme != "https":
            raise BackupRestoreDrillError(
                "Production and staging drills require an HTTPS Vault endpoint."
            )
    settings = Settings(
        environment=environment,
        policy_version="backup-restore-drill",
        auth_required=False,
        allowed_workspace=ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        secrets_backend=backend,
        env_secret_prefix=_optional(env, "HALLU_DEFENSE_ENV_SECRET_PREFIX")
        or "HALLU_DEFENSE_SECRET_",
        vault_addr=vault_addr,
        vault_mount=_optional(env, "HALLU_DEFENSE_VAULT_MOUNT") or "secret",
        vault_namespace=_optional(env, "HALLU_DEFENSE_VAULT_NAMESPACE"),
        vault_token_env=_optional(env, "HALLU_DEFENSE_VAULT_TOKEN_ENV")
        or "HALLU_DEFENSE_VAULT_TOKEN",
        vault_timeout_seconds=_int_env(env, "HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS", 3),
    )
    return create_secret_manager(settings)


def _validate_config(config: BackupRestoreDrillConfig) -> None:
    for value, label in (
        (config.postgres_service, "postgres service"),
        (config.postgres_user, "postgres user"),
        (config.source_database, "source database"),
        (config.scratch_database, "scratch database"),
    ):
        if not SAFE_IDENTIFIER_RE.fullmatch(value):
            raise BackupRestoreDrillError(f"{label} must be a safe SQL identifier.")
    if config.scratch_database == config.source_database:
        raise BackupRestoreDrillError("scratch database must differ from source database.")
    if not SAFE_BUCKET_RE.fullmatch(config.minio_bucket):
        raise BackupRestoreDrillError("MinIO bucket must be DNS-safe.")
    if not SAFE_IDENTIFIER_RE.fullmatch(config.minio_alias):
        raise BackupRestoreDrillError("MinIO alias must be a safe identifier.")
    if config.max_backup_bytes <= 0:
        raise BackupRestoreDrillError("backup byte limit must be positive.")
    if config.timeout_seconds <= 0 or config.timeout_seconds > 600:
        raise BackupRestoreDrillError("timeout must be positive.")
    _build_s3_client(config)


def _validate_fernet_key(key: str) -> None:
    try:
        decoded = base64.urlsafe_b64decode(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise BackupRestoreDrillError("Backup encryption key must be a Fernet key.") from exc
    if len(decoded) != 32:
        raise BackupRestoreDrillError("Backup encryption key must decode to 32 bytes.")


def _fernet(key: str) -> _FernetLike:
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise BackupRestoreDrillError(
            "cryptography is required for Fernet backup encryption."
        ) from exc
    return Fernet(key.encode("ascii"))


def _timestamp_from_scratch(scratch_database: str) -> str:
    prefix = "hallu_restore_"
    if scratch_database.startswith(prefix):
        return scratch_database[len(prefix) :]
    return scratch_database


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _origins_env(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = _optional(env, "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS")
    if raw is None:
        return ()
    origins = tuple(item.strip() for item in raw.split(",") if item.strip())
    if len(origins) != len(set(origins)):
        raise BackupRestoreDrillError("Approved outbound origins must be unique.")
    return origins


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise BackupRestoreDrillError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise BackupRestoreDrillError(f"{name} must be positive.")
    return parsed


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
