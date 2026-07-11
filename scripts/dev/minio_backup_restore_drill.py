"""Opt-in tenant-scoped encrypted S3-compatible replica/restore drill.

The historical ``HALLU_DEFENSE_MINIO_*`` configuration contract remains
stable, while object operations use the repository's bounded SigV4 client.
No object payload is transported through subprocess stdout or a tool image.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
API_SRC = ROOT / "apps" / "api" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

from hallu_defense.config import PRODUCTION_LIKE_ENVIRONMENTS, Settings  # noqa: E402
from hallu_defense.services.minio_backup_drill import (  # noqa: E402
    MinioBackupDrillConfig,
    MinioBackupDrillError,
    MinioObject,
    MinioObjectStore,
    run_minio_backup_restore_drill,
)
from hallu_defense.services.secrets import (  # noqa: E402
    SecretManager,
    create_secret_manager,
)
from scripts.dev.s3_sigv4 import (  # noqa: E402
    DEFAULT_REGION,
    S3Object,
    S3SigV4Client,
    S3SigV4Config,
    S3SigV4Error,
)

ENABLED_ENV = "HALLU_DEFENSE_MINIO_BACKUP_RESTORE_DRILL_ENABLED"
TENANT_ENV = "HALLU_DEFENSE_MINIO_BACKUP_DRILL_TENANT_ID"
DEFAULT_ENDPOINT = "http://127.0.0.1:9000"
DEFAULT_SOURCE_BUCKET = "hallu-primary"
DEFAULT_REPLICA_BUCKET = "hallu-backup-replica"
DEFAULT_ACCESS_KEY = "minioadmin"
DEFAULT_SECRET_KEY = "minioadmin"
DEFAULT_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_CREDENTIALS_SECRET_NAME = "backup/minio-credentials"
LOCAL_CREDENTIAL_ENVIRONMENTS = {"ci", "dev", "development", "local", "test"}


class MinioDrillCommandError(MinioBackupDrillError):
    """Compatibility error type for the operational CLI boundary."""


class S3ClientProtocol(Protocol):
    def ensure_bucket(self, bucket: str, *, timeout_seconds: int) -> None: ...

    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str,
        max_response_bytes: int,
        timeout_seconds: int,
    ) -> Sequence[S3Object]: ...

    def download_file(
        self,
        bucket: str,
        key: str,
        destination: Path,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None: ...

    def upload_file(
        self,
        bucket: str,
        key: str,
        source: Path,
        *,
        timeout_seconds: int,
    ) -> None: ...

    def delete_prefix(
        self,
        bucket: str,
        *,
        prefix: str,
        timeout_seconds: int,
    ) -> None: ...

    def remove_bucket(self, bucket: str, *, timeout_seconds: int) -> None: ...


@dataclass(frozen=True)
class MinioClientConfig:
    endpoint: str
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    region: str = DEFAULT_REGION
    require_https: bool = False
    allowed_origins: tuple[str, ...] = ()
    allow_private_endpoint: bool = False
    ca_file: Path | None = None


class S3ObjectStore(MinioObjectStore):
    def __init__(
        self,
        config: MinioClientConfig,
        client: S3ClientProtocol | None = None,
    ) -> None:
        self._config = config
        try:
            self._client = client or S3SigV4Client(
                S3SigV4Config(
                    endpoint=config.endpoint,
                    access_key=config.access_key,
                    secret_key=config.secret_key,
                    region=config.region,
                    require_https=config.require_https,
                    allowed_origins=config.allowed_origins,
                    allow_private_endpoint=config.allow_private_endpoint,
                    ca_file=config.ca_file,
                )
            )
        except S3SigV4Error:
            raise MinioBackupDrillError("MinIO-compatible S3 client config is invalid.") from None

    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> Sequence[MinioObject]:
        try:
            objects = self._client.list_objects(
                bucket,
                prefix=prefix,
                max_response_bytes=max_output_bytes,
                timeout_seconds=timeout_seconds,
            )
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 object listing failed.") from None
        return tuple(MinioObject(key=item.key, size=item.size) for item in objects)

    def ensure_bucket(self, *, bucket: str, timeout_seconds: int) -> None:
        try:
            self._client.ensure_bucket(bucket, timeout_seconds=timeout_seconds)
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 bucket check failed.") from None

    def download(
        self,
        *,
        bucket: str,
        key: str,
        destination: Path,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None:
        try:
            self._client.download_file(
                bucket,
                key,
                destination,
                max_bytes=max_bytes,
                timeout_seconds=timeout_seconds,
            )
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 object download failed.") from None

    def upload(
        self,
        *,
        bucket: str,
        key: str,
        source: Path,
        timeout_seconds: int,
    ) -> None:
        try:
            self._client.upload_file(
                bucket,
                key,
                source,
                timeout_seconds=timeout_seconds,
            )
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 object upload failed.") from None

    def delete_prefix(
        self,
        *,
        bucket: str,
        prefix: str,
        timeout_seconds: int,
    ) -> None:
        try:
            self._client.delete_prefix(
                bucket,
                prefix=prefix,
                timeout_seconds=timeout_seconds,
            )
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 prefix cleanup failed.") from None

    def remove_bucket(self, *, bucket: str, timeout_seconds: int) -> None:
        try:
            self._client.remove_bucket(bucket, timeout_seconds=timeout_seconds)
        except S3SigV4Error:
            raise MinioDrillCommandError("S3 bucket cleanup failed.") from None


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    store: MinioObjectStore | None = None,
    secret_manager: SecretManager | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the MinIO backup/restore drill",
        }
    effective_run_id = run_id or _new_run_id()
    drill_config = _drill_config(effective_env, run_id=effective_run_id)
    manager = secret_manager or _build_secret_manager(effective_env)
    object_store = store or S3ObjectStore(
        _client_config(effective_env, secret_manager=manager)
    )
    return run_minio_backup_restore_drill(
        drill_config,
        store=object_store,
        secret_manager=manager,
    )


def main() -> int:
    try:
        result = run_from_env()
    except Exception:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": (
                        "MinIO-compatible backup/restore drill failed closed; "
                        "no restore was accepted."
                    ),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def _drill_config(env: Mapping[str, str], *, run_id: str) -> MinioBackupDrillConfig:
    tenant_id = _optional(env, TENANT_ENV)
    if tenant_id is None:
        raise MinioBackupDrillError(f"{TENANT_ENV} is required when the drill is enabled.")
    return MinioBackupDrillConfig(
        tenant_id=tenant_id,
        source_bucket=_optional(env, "HALLU_DEFENSE_MINIO_BACKUP_SOURCE_BUCKET")
        or DEFAULT_SOURCE_BUCKET,
        replica_bucket=_optional(env, "HALLU_DEFENSE_MINIO_BACKUP_REPLICA_BUCKET")
        or DEFAULT_REPLICA_BUCKET,
        tenant_prefix_root=_optional(env, "HALLU_DEFENSE_MINIO_BACKUP_TENANT_PREFIX_ROOT")
        or "tenants",
        synthetic_prefix_root=_optional(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_SYNTHETIC_PREFIX_ROOT",
        )
        or "__hallu_backup_drill__",
        run_id=run_id,
        secret_name=_optional(env, "HALLU_DEFENSE_BACKUP_ENCRYPTION_SECRET_NAME")
        or "backup/encryption-key",
        timeout_seconds=_int_env(env, "HALLU_DEFENSE_MINIO_BACKUP_TIMEOUT_SECONDS", 120),
        max_objects=_int_env(env, "HALLU_DEFENSE_MINIO_BACKUP_MAX_OBJECTS", 1000),
        max_object_bytes=_int_env(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_MAX_OBJECT_BYTES",
            1024 * 1024 * 1024,
        ),
        max_total_bytes=_int_env(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_MAX_TOTAL_BYTES",
            10 * 1024 * 1024 * 1024,
        ),
        max_listing_bytes=_int_env(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_MAX_LISTING_BYTES",
            DEFAULT_RESPONSE_BYTES,
        ),
        max_manifest_bytes=_int_env(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_MAX_MANIFEST_BYTES",
            DEFAULT_RESPONSE_BYTES,
        ),
        chunk_bytes=_int_env(
            env,
            "HALLU_DEFENSE_MINIO_BACKUP_CHUNK_BYTES",
            1024 * 1024,
        ),
    )


def _client_config(
    env: Mapping[str, str],
    *,
    secret_manager: SecretManager,
) -> MinioClientConfig:
    environment = (_optional(env, "HALLU_DEFENSE_ENV") or "local").lower()
    if environment not in LOCAL_CREDENTIAL_ENVIRONMENTS | PRODUCTION_LIKE_ENVIRONMENTS:
        raise MinioBackupDrillError("Runtime environment is not approved for this drill.")
    require_https = environment in PRODUCTION_LIKE_ENVIRONMENTS
    allow_private_endpoint = environment in LOCAL_CREDENTIAL_ENVIRONMENTS
    if require_https:
        if (_optional(env, "HALLU_DEFENSE_SECRETS_BACKEND") or "env").lower() != "vault":
            raise MinioBackupDrillError(
                "Production and staging MinIO credentials require the Vault backend."
            )
        secret_name = (
            _optional(env, "HALLU_DEFENSE_MINIO_BACKUP_CREDENTIALS_SECRET_NAME")
            or DEFAULT_CREDENTIALS_SECRET_NAME
        )
        try:
            access_key = secret_manager.get_secret(secret_name, field="access_key").reveal()
            secret_key = secret_manager.get_secret(secret_name, field="secret_key").reveal()
        except Exception:
            raise MinioBackupDrillError("MinIO credentials could not be loaded.") from None
    else:
        access_key = (
            _optional(env, "HALLU_DEFENSE_MINIO_BACKUP_ACCESS_KEY") or DEFAULT_ACCESS_KEY
        )
        secret_key = (
            _optional(env, "HALLU_DEFENSE_MINIO_BACKUP_SECRET_KEY") or DEFAULT_SECRET_KEY
        )
    ca_path = _optional(env, "HALLU_DEFENSE_MINIO_BACKUP_CA_CERT_PATH")
    config = MinioClientConfig(
        endpoint=_optional(env, "HALLU_DEFENSE_MINIO_BACKUP_ENDPOINT") or DEFAULT_ENDPOINT,
        access_key=access_key,
        secret_key=secret_key,
        region=_optional(env, "HALLU_DEFENSE_MINIO_BACKUP_REGION") or DEFAULT_REGION,
        require_https=require_https,
        allowed_origins=_origins_env(env),
        allow_private_endpoint=allow_private_endpoint,
        ca_file=Path(ca_path) if ca_path else None,
    )
    try:
        S3SigV4Client(
            S3SigV4Config(
                endpoint=config.endpoint,
                access_key=config.access_key,
                secret_key=config.secret_key,
                region=config.region,
                require_https=config.require_https,
                allowed_origins=config.allowed_origins,
                allow_private_endpoint=config.allow_private_endpoint,
                ca_file=config.ca_file,
            )
        )
    except S3SigV4Error:
        raise MinioBackupDrillError("MinIO endpoint or credentials are invalid.") from None
    return config


def _build_secret_manager(env: Mapping[str, str]) -> SecretManager:
    environment = (_optional(env, "HALLU_DEFENSE_ENV") or "local").lower()
    backend = (_optional(env, "HALLU_DEFENSE_SECRETS_BACKEND") or "env").lower()
    vault_addr = _optional(env, "HALLU_DEFENSE_VAULT_ADDR")
    if environment in PRODUCTION_LIKE_ENVIRONMENTS:
        if backend != "vault":
            raise MinioBackupDrillError(
                "Production and staging drills require the Vault secret backend."
            )
        if vault_addr is None or urlsplit(vault_addr).scheme != "https":
            raise MinioBackupDrillError(
                "Production and staging drills require an HTTPS Vault endpoint."
            )
    settings = Settings(
        environment=environment,
        policy_version="minio-backup-restore-drill",
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


def _new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{timestamp}-{secrets.token_hex(6)}"


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    return value.strip() if value is not None and value.strip() else None


def _origins_env(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = _optional(env, "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS")
    if raw is None:
        return ()
    origins = tuple(item.strip() for item in raw.split(",") if item.strip())
    if len(origins) != len(set(origins)):
        raise MinioBackupDrillError("Approved outbound origins must be unique.")
    return origins


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    raw = _optional(env, name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise MinioBackupDrillError(f"{name} must be an integer.") from None


if __name__ == "__main__":
    sys.exit(main())
