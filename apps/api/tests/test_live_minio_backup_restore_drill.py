from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from hallu_defense.services.minio_backup_drill import (
    MinioBackupDrillConfig,
    MinioBackupDrillError,
    MinioObject,
    run_minio_backup_restore_drill,
)
from scripts.dev import minio_backup_restore_drill as cli

LIVE_ENV = "HALLU_DEFENSE_MINIO_BACKUP_LIVE_SMOKE_ENABLED"


class CorruptingReplicaStore:
    def __init__(
        self,
        delegate: cli.S3ObjectStore,
        *,
        source_bucket: str,
        replica_bucket: str,
        workspace: Path,
    ) -> None:
        self.delegate = delegate
        self.source_bucket = source_bucket
        self.replica_bucket = replica_bucket
        self.workspace = workspace
        self.corrupted = False
        self.restore_uploads = 0

    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> Sequence[MinioObject]:
        return self.delegate.list_objects(
            bucket=bucket,
            prefix=prefix,
            max_output_bytes=max_output_bytes,
            timeout_seconds=timeout_seconds,
        )

    def ensure_bucket(self, *, bucket: str, timeout_seconds: int) -> None:
        self.delegate.ensure_bucket(bucket=bucket, timeout_seconds=timeout_seconds)

    def download(
        self,
        *,
        bucket: str,
        key: str,
        destination: Path,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None:
        if bucket == self.replica_bucket and key.endswith(".hdbk") and not self.corrupted:
            corrupt_path = self.workspace / "corrupt-replica.hdbk"
            self.delegate.download(
                bucket=bucket,
                key=key,
                destination=corrupt_path,
                max_bytes=max_bytes,
                timeout_seconds=timeout_seconds,
            )
            os.chmod(corrupt_path, 0o600)
            with corrupt_path.open("r+b", buffering=0) as stream:
                stream.seek(-17, os.SEEK_END)
                original = stream.read(1)
                if len(original) != 1:
                    raise AssertionError("encrypted replica was unexpectedly short")
                stream.seek(-1, os.SEEK_CUR)
                stream.write(bytes((original[0] ^ 1,)))
                stream.flush()
                os.fsync(stream.fileno())
            self.delegate.upload(
                bucket=bucket,
                key=key,
                source=corrupt_path,
                timeout_seconds=timeout_seconds,
            )
            corrupt_path.unlink(missing_ok=True)
            self.corrupted = True
        self.delegate.download(
            bucket=bucket,
            key=key,
            destination=destination,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
        )

    def upload(
        self,
        *,
        bucket: str,
        key: str,
        source: Path,
        timeout_seconds: int,
    ) -> None:
        if bucket == self.source_bucket and "/restore/" in key:
            self.restore_uploads += 1
        self.delegate.upload(
            bucket=bucket,
            key=key,
            source=source,
            timeout_seconds=timeout_seconds,
        )

    def delete_prefix(
        self,
        *,
        bucket: str,
        prefix: str,
        timeout_seconds: int,
    ) -> None:
        self.delegate.delete_prefix(
            bucket=bucket,
            prefix=prefix,
            timeout_seconds=timeout_seconds,
        )


@pytest.mark.skipif(
    os.getenv(LIVE_ENV, "").strip().lower() not in {"1", "true", "yes", "on"},
    reason=f"set {LIVE_ENV}=true to run the live MinIO drill",
)
def test_live_minio_replica_restore_is_tenant_scoped_and_rejects_corruption(
    tmp_path: Path,
) -> None:
    env: Mapping[str, str] = os.environ
    suffix = secrets.token_hex(6)
    source_bucket = f"hallu-drill-src-{suffix}"
    replica_bucket = f"hallu-drill-rep-{suffix}"
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    manager = cli._build_secret_manager(env)
    store = cli.S3ObjectStore(
        cli._client_config(env, secret_manager=manager),
    )
    os.chmod(tmp_path, 0o700)
    source_objects = {
        f"tenants/{tenant_a}/evidence/one.bin": b"tenant-a-live-object-one",
        f"tenants/{tenant_a}/reports/two.bin": b"tenant-a-live-object-two",
        f"tenants/{tenant_b}/sentinel.bin": b"tenant-b-isolation-sentinel",
    }
    try:
        store.ensure_bucket(bucket=source_bucket, timeout_seconds=60)
        store.ensure_bucket(bucket=replica_bucket, timeout_seconds=60)
        for index, (key, payload) in enumerate(source_objects.items()):
            seed_path = tmp_path / f"seed-{index}.bin"
            seed_path.write_bytes(payload)
            os.chmod(seed_path, 0o600)
            store.upload(
                bucket=source_bucket,
                key=key,
                source=seed_path,
                timeout_seconds=60,
            )
            seed_path.unlink()

        clean_result = run_minio_backup_restore_drill(
            _config(
                tenant_id=tenant_a,
                source_bucket=source_bucket,
                replica_bucket=replica_bucket,
                run_id="run-live-clean-abcdef",
            ),
            store=store,
            secret_manager=manager,
        )
        assert clean_result["status"] == "passed"
        assert clean_result["object_count"] == 2
        assert clean_result["restored_from_replica"] is True
        _assert_originals_unchanged(store, source_bucket, source_objects, tmp_path)
        _assert_synthetic_prefixes_empty(store, source_bucket, replica_bucket)

        corrupting = CorruptingReplicaStore(
            store,
            source_bucket=source_bucket,
            replica_bucket=replica_bucket,
            workspace=tmp_path,
        )
        with pytest.raises(MinioBackupDrillError, match="authentication failed"):
            run_minio_backup_restore_drill(
                _config(
                    tenant_id=tenant_a,
                    source_bucket=source_bucket,
                    replica_bucket=replica_bucket,
                    run_id="run-live-corrupt-abcdef",
                ),
                store=corrupting,
                secret_manager=manager,
            )
        assert corrupting.corrupted is True
        assert corrupting.restore_uploads == 0
        _assert_originals_unchanged(store, source_bucket, source_objects, tmp_path)
        _assert_synthetic_prefixes_empty(store, source_bucket, replica_bucket)
    finally:
        store.remove_bucket(bucket=replica_bucket, timeout_seconds=60)
        store.remove_bucket(bucket=source_bucket, timeout_seconds=60)

def _config(
    *,
    tenant_id: str,
    source_bucket: str,
    replica_bucket: str,
    run_id: str,
) -> MinioBackupDrillConfig:
    return MinioBackupDrillConfig(
        tenant_id=tenant_id,
        source_bucket=source_bucket,
        replica_bucket=replica_bucket,
        tenant_prefix_root="tenants",
        synthetic_prefix_root="__hallu_backup_drill__",
        run_id=run_id,
        timeout_seconds=60,
        max_objects=10,
        max_object_bytes=1024 * 1024,
        max_total_bytes=4 * 1024 * 1024,
        temp_parent=None,
    )


def _assert_originals_unchanged(
    store: cli.S3ObjectStore,
    source_bucket: str,
    expected: Mapping[str, bytes],
    workspace: Path,
) -> None:
    for index, (key, payload) in enumerate(expected.items()):
        downloaded = workspace / f"verify-{index}.bin"
        store.download(
            bucket=source_bucket,
            key=key,
            destination=downloaded,
            max_bytes=1024 * 1024,
            timeout_seconds=60,
        )
        assert _sha256(downloaded.read_bytes()) == _sha256(payload)
        downloaded.unlink()


def _assert_synthetic_prefixes_empty(
    store: cli.S3ObjectStore,
    source_bucket: str,
    replica_bucket: str,
) -> None:
    for bucket in (source_bucket, replica_bucket):
        assert store.list_objects(
            bucket=bucket,
            prefix="__hallu_backup_drill__/",
            max_output_bytes=64 * 1024,
            timeout_seconds=60,
        ) == []


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
