from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from hallu_defense.services.minio_backup_drill import (
    DEFAULT_CHUNK_BYTES,
    EnvelopeMetadata,
    ManifestEntry,
    MinioBackupDrillConfig,
    MinioBackupDrillError,
    MinioObject,
    decrypt_file_streaming,
    encrypt_file_streaming,
    run_minio_backup_restore_drill,
)
from hallu_defense.services.secrets import SecretValue


class FakeSecretManager:
    def __init__(self, value: str) -> None:
        self.value = value
        self.requests: list[tuple[str, str]] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requests.append((name, field))
        return SecretValue(name=name, _value=self.value)


class FakeMinioStore:
    def __init__(
        self,
        objects: dict[tuple[str, str], bytes],
        *,
        listed_objects: Sequence[MinioObject] | None = None,
        corrupt_replica: bool = False,
    ) -> None:
        self.objects = dict(objects)
        self.listed_objects = listed_objects
        self.corrupt_replica = corrupt_replica
        self.corruption_applied = False
        self.upload_history: list[tuple[str, str, bytes]] = []
        self.download_history: list[tuple[str, str, int, int]] = []
        self.delete_history: list[tuple[str, str, int]] = []
        self.ensure_history: list[tuple[str, int]] = []

    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> Sequence[MinioObject]:
        assert max_output_bytes > 0
        assert timeout_seconds > 0
        if self.listed_objects is not None:
            return self.listed_objects
        return [
            MinioObject(key=key, size=len(payload))
            for (object_bucket, key), payload in self.objects.items()
            if object_bucket == bucket and key.startswith(prefix)
        ]

    def ensure_bucket(self, *, bucket: str, timeout_seconds: int) -> None:
        self.ensure_history.append((bucket, timeout_seconds))

    def download(
        self,
        *,
        bucket: str,
        key: str,
        destination: Path,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None:
        payload = self.objects[(bucket, key)]
        if len(payload) > max_bytes:
            raise AssertionError("fake store received an unsafe download")
        if (
            self.corrupt_replica
            and not self.corruption_applied
            and bucket == "replica-bucket"
            and key.endswith(".hdbk")
        ):
            mutable = bytearray(payload)
            mutable[-17] ^= 1
            payload = bytes(mutable)
            self.corruption_applied = True
        destination.write_bytes(payload)
        self.download_history.append((bucket, key, max_bytes, timeout_seconds))

    def upload(
        self,
        *,
        bucket: str,
        key: str,
        source: Path,
        timeout_seconds: int,
    ) -> None:
        payload = source.read_bytes()
        self.objects[(bucket, key)] = payload
        self.upload_history.append((bucket, key, payload))

    def delete_prefix(
        self,
        *,
        bucket: str,
        prefix: str,
        timeout_seconds: int,
    ) -> None:
        self.delete_history.append((bucket, prefix, timeout_seconds))
        for identity in tuple(self.objects):
            if identity[0] == bucket and identity[1].startswith(prefix):
                del self.objects[identity]


def test_drill_encrypts_replica_restores_after_verification_and_cleans_prefixes() -> None:
    tenant_a_secret = b"alpha confidential evidence"
    tenant_a_second = b"second tenant-a object"
    tenant_b_secret = b"tenant-b must remain isolated"
    originals = {
        ("source-bucket", "tenants/tenant-a/evidence/a.json"): tenant_a_secret,
        ("source-bucket", "tenants/tenant-a/reports/b.txt"): tenant_a_second,
        ("source-bucket", "tenants/tenant-b/evidence/c.json"): tenant_b_secret,
    }
    store = FakeMinioStore(originals)
    secrets = FakeSecretManager(_encoded_key())

    result = run_minio_backup_restore_drill(
        _config(),
        store=store,
        secret_manager=secrets,
    )

    assert result["status"] == "passed"
    assert result["object_count"] == 2
    assert result["plaintext_bytes"] == len(tenant_a_secret) + len(tenant_a_second)
    assert result["restored_from_replica"] is True
    assert result["parity_passed"] is True
    assert secrets.requests == [("backup/encryption-key", "value")]
    assert store.ensure_history == [("replica-bucket", 30)]

    manifest_uploads = [item for item in store.upload_history if item[1].endswith("manifest.json")]
    assert len(manifest_uploads) == 1
    manifest_text = manifest_uploads[0][2].decode("utf-8")
    manifest = json.loads(manifest_text)
    assert len(manifest["objects"]) == 2
    for forbidden in (
        "tenant-a",
        "tenant-b",
        "evidence/a.json",
        "reports/b.txt",
        tenant_a_secret.decode(),
        tenant_a_second.decode(),
        tenant_b_secret.decode(),
        _encoded_key(),
    ):
        assert forbidden not in manifest_text
    assert all(set(item) == {
        "source_ref",
        "replica_key",
        "plaintext_size",
        "plaintext_sha256",
        "encrypted_size",
    } for item in manifest["objects"])

    assert store.objects == originals
    assert len([item for item in store.upload_history if "/restore/" in item[1]]) == 2
    assert len(store.delete_history) == 2
    assert store.delete_history[0][0] == "source-bucket"
    assert store.delete_history[1][0] == "replica-bucket"


def test_corrupt_replica_fails_before_any_restore_and_cleans_synthetic_data() -> None:
    original = b"authenticated payload that must not be restored after corruption"
    store = FakeMinioStore(
        {("source-bucket", "tenants/tenant-a/object.bin"): original},
        corrupt_replica=True,
    )

    with pytest.raises(MinioBackupDrillError, match="authentication failed"):
        run_minio_backup_restore_drill(
            _config(),
            store=store,
            secret_manager=FakeSecretManager(_encoded_key()),
        )

    assert store.corruption_applied is True
    assert not [item for item in store.upload_history if "/restore/" in item[1]]
    assert store.objects == {("source-bucket", "tenants/tenant-a/object.bin"): original}
    assert len(store.delete_history) == 2


def test_cross_tenant_listing_is_rejected_before_download_or_upload() -> None:
    store = FakeMinioStore(
        {},
        listed_objects=[MinioObject(key="tenants/tenant-b/foreign.bin", size=5)],
    )

    with pytest.raises(MinioBackupDrillError, match="tenant prefix boundary"):
        run_minio_backup_restore_drill(
            _config(),
            store=store,
            secret_manager=FakeSecretManager(_encoded_key()),
        )

    assert store.download_history == []
    assert store.upload_history == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"replica_bucket": "source-bucket"}, "must be distinct"),
        ({"tenant_id": "../tenant-a"}, "Tenant identifier"),
        ({"source_bucket": "Uppercase"}, "Source bucket"),
        ({"synthetic_prefix_root": "drill"}, "visibly reserved"),
        ({"secret_name": "backup/../key"}, "secret name"),
        ({"timeout_seconds": 0}, "timeout"),
        ({"max_objects": 0}, "object limit"),
        ({"chunk_bytes": 1024}, "chunk size"),
    ],
)
def test_unsafe_configuration_fails_before_secret_or_store_access(
    changes: dict[str, object],
    message: str,
) -> None:
    config_values = vars(_config()) | changes
    secrets = FakeSecretManager(_encoded_key())
    store = FakeMinioStore({})

    with pytest.raises(MinioBackupDrillError, match=message):
        run_minio_backup_restore_drill(
            MinioBackupDrillConfig(**config_values),
            store=store,
            secret_manager=secrets,
        )

    assert secrets.requests == []
    assert store.download_history == []
    assert store.upload_history == []


def test_listing_limits_fail_before_any_source_download() -> None:
    store = FakeMinioStore(
        {},
        listed_objects=[
            MinioObject(key="tenants/tenant-a/one.bin", size=10),
            MinioObject(key="tenants/tenant-a/two.bin", size=10),
        ],
    )
    config = MinioBackupDrillConfig(**(vars(_config()) | {"max_objects": 1}))

    with pytest.raises(MinioBackupDrillError, match="object limit"):
        run_minio_backup_restore_drill(
            config,
            store=store,
            secret_manager=FakeSecretManager(_encoded_key()),
        )

    assert store.download_history == []
    assert store.upload_history == []


def test_streaming_envelope_round_trip_and_tamper_rejection(tmp_path: Path) -> None:
    source = tmp_path / "large-source.bin"
    with source.open("wb") as stream:
        for index in range(48):
            stream.write(hashlib.sha256(str(index).encode()).digest() * 2048)
    payload_hash = _hash_path(source)
    source_ref = f"obj-sha256:{hashlib.sha256(b'source-ref').hexdigest()}"
    metadata = EnvelopeMetadata(
        source_ref=source_ref,
        plaintext_size=source.stat().st_size,
        plaintext_sha256=payload_hash,
    )
    encrypted = tmp_path / "object.hdbk"
    restored = tmp_path / "restored.bin"
    key = b"k" * 32

    encrypt_file_streaming(
        source,
        encrypted,
        key=key,
        metadata=metadata,
        chunk_bytes=DEFAULT_CHUNK_BYTES,
        nonce_factory=lambda size: b"n" * size,
    )
    expected = ManifestEntry(
        source_ref=source_ref,
        plaintext_size=source.stat().st_size,
        plaintext_sha256=payload_hash,
        encrypted_size=encrypted.stat().st_size,
        replica_key="__hallu_backup_drill__/opaque/object.hdbk",
    )

    actual = decrypt_file_streaming(
        encrypted,
        restored,
        key=key,
        expected=expected,
        chunk_bytes=DEFAULT_CHUNK_BYTES,
    )

    assert actual == metadata
    assert _hash_path(restored) == payload_hash
    restored.unlink()
    tampered = bytearray(encrypted.read_bytes())
    tampered[-1] ^= 1
    encrypted.write_bytes(tampered)
    with pytest.raises(MinioBackupDrillError, match="authentication failed"):
        decrypt_file_streaming(
            encrypted,
            restored,
            key=key,
            expected=expected,
            chunk_bytes=DEFAULT_CHUNK_BYTES,
        )
    assert not restored.exists()


def _config() -> MinioBackupDrillConfig:
    return MinioBackupDrillConfig(
        tenant_id="tenant-a",
        source_bucket="source-bucket",
        replica_bucket="replica-bucket",
        tenant_prefix_root="tenants",
        synthetic_prefix_root="__hallu_backup_drill__",
        run_id="run-20260709-abcdef",
        timeout_seconds=30,
    )


def _encoded_key() -> str:
    return base64.urlsafe_b64encode(b"x" * 32).decode("ascii")


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
