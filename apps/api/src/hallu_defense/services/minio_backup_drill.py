from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, TypeGuard

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from hallu_defense.services.secrets import SecretManager

ENVELOPE_MAGIC = b"HDBKOBJ\x00"
ENVELOPE_VERSION = 1
ENVELOPE_PREFIX = struct.Struct(">8sB12sI")
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_ENVELOPE_HEADER_BYTES = 4096
MANIFEST_FORMAT = "hallu-minio-backup-manifest"
MANIFEST_VERSION = 1
DEFAULT_SECRET_NAME = "backup/encryption-key"
DEFAULT_CHUNK_BYTES = 1024 * 1024
MIN_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 8 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 600
MAX_OBJECT_COUNT_LIMIT = 10_000
MAX_OBJECT_BYTES_LIMIT = 10 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES_LIMIT = 100 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES_LIMIT = 8 * 1024 * 1024

TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{5,95}$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$")
SOURCE_REF_RE = re.compile(r"^obj-sha256:[a-f0-9]{64}$")
SECRET_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,63})*$"
)


class MinioBackupDrillError(RuntimeError):
    pass


@dataclass(frozen=True)
class MinioObject:
    key: str
    size: int


@dataclass(frozen=True)
class MinioBackupDrillConfig:
    tenant_id: str
    source_bucket: str
    replica_bucket: str
    tenant_prefix_root: str
    synthetic_prefix_root: str
    run_id: str
    secret_name: str = DEFAULT_SECRET_NAME
    timeout_seconds: int = 120
    max_objects: int = 1000
    max_object_bytes: int = 1024 * 1024 * 1024
    max_total_bytes: int = 10 * 1024 * 1024 * 1024
    max_listing_bytes: int = 4 * 1024 * 1024
    max_manifest_bytes: int = 4 * 1024 * 1024
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    temp_parent: Path | None = None


class MinioObjectStore(Protocol):
    def list_objects(
        self,
        *,
        bucket: str,
        prefix: str,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> Sequence[MinioObject]: ...

    def ensure_bucket(self, *, bucket: str, timeout_seconds: int) -> None: ...

    def download(
        self,
        *,
        bucket: str,
        key: str,
        destination: Path,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None: ...

    def upload(
        self,
        *,
        bucket: str,
        key: str,
        source: Path,
        timeout_seconds: int,
    ) -> None: ...

    def delete_prefix(
        self,
        *,
        bucket: str,
        prefix: str,
        timeout_seconds: int,
    ) -> None: ...


@dataclass(frozen=True)
class ManifestEntry:
    source_ref: str
    replica_key: str
    plaintext_size: int
    plaintext_sha256: str
    encrypted_size: int

    def to_mapping(self) -> dict[str, object]:
        return {
            "source_ref": self.source_ref,
            "replica_key": self.replica_key,
            "plaintext_size": self.plaintext_size,
            "plaintext_sha256": self.plaintext_sha256,
            "encrypted_size": self.encrypted_size,
        }


@dataclass(frozen=True)
class EnvelopeMetadata:
    source_ref: str
    plaintext_size: int
    plaintext_sha256: str


def run_minio_backup_restore_drill(
    config: MinioBackupDrillConfig,
    *,
    store: MinioObjectStore,
    secret_manager: SecretManager,
) -> dict[str, object]:
    _validate_config(config)
    try:
        raw_key = secret_manager.get_secret(config.secret_name).reveal()
    except Exception:
        raise MinioBackupDrillError("Backup encryption key could not be loaded.") from None
    key = _decode_encryption_key(raw_key)
    del raw_key
    tenant_ref = _tenant_ref(config.tenant_id)
    source_prefix = f"{config.tenant_prefix_root}/{config.tenant_id}/"
    run_prefix = f"{config.synthetic_prefix_root}/{tenant_ref}/{config.run_id}"
    replica_prefix = f"{run_prefix}/replica"
    restore_prefix = f"{config.synthetic_prefix_root}/{tenant_ref}/{config.run_id}/restore"
    try:
        with _private_temporary_directory(config.temp_parent) as workspace:
            try:
                result = _execute_drill(
                    config,
                    store=store,
                    key=key,
                    workspace=workspace,
                    tenant_ref=tenant_ref,
                    source_prefix=source_prefix,
                    replica_prefix=replica_prefix,
                    restore_prefix=restore_prefix,
                )
            except MinioBackupDrillError:
                _cleanup_synthetic_prefixes(
                    config,
                    store=store,
                    run_prefix=run_prefix,
                    restore_prefix=restore_prefix,
                    suppress_errors=True,
                )
                raise
            except Exception:
                _cleanup_synthetic_prefixes(
                    config,
                    store=store,
                    run_prefix=run_prefix,
                    restore_prefix=restore_prefix,
                    suppress_errors=True,
                )
                raise MinioBackupDrillError("MinIO backup/restore drill failed.") from None
            _cleanup_synthetic_prefixes(
                config,
                store=store,
                run_prefix=run_prefix,
                restore_prefix=restore_prefix,
                suppress_errors=False,
            )
            return result
    finally:
        for index in range(len(key)):
            key[index] = 0


def _execute_drill(
    config: MinioBackupDrillConfig,
    *,
    store: MinioObjectStore,
    key: bytes | bytearray,
    workspace: Path,
    tenant_ref: str,
    source_prefix: str,
    replica_prefix: str,
    restore_prefix: str,
) -> dict[str, object]:
    objects = _validated_source_objects(
        config,
        store.list_objects(
            bucket=config.source_bucket,
            prefix=source_prefix,
            max_output_bytes=config.max_listing_bytes,
            timeout_seconds=config.timeout_seconds,
        ),
        source_prefix=source_prefix,
    )
    store.ensure_bucket(bucket=config.replica_bucket, timeout_seconds=config.timeout_seconds)
    expected_entries: list[ManifestEntry] = []
    seen_refs: set[str] = set()
    for index, item in enumerate(objects):
        source_ref = _source_ref(config.source_bucket, item.key)
        if source_ref in seen_refs:
            raise MinioBackupDrillError("Source reference collision detected.")
        seen_refs.add(source_ref)
        source_path = workspace / f"source-{index:05d}.bin"
        encrypted_path = workspace / f"replica-{index:05d}.hdbk"
        try:
            store.download(
                bucket=config.source_bucket,
                key=item.key,
                destination=source_path,
                max_bytes=config.max_object_bytes,
                timeout_seconds=config.timeout_seconds,
            )
            _secure_downloaded_file(source_path, max_bytes=config.max_object_bytes)
            plaintext_size, plaintext_sha256 = _hash_file(
                source_path,
                chunk_bytes=config.chunk_bytes,
                max_bytes=config.max_object_bytes,
            )
            if plaintext_size != item.size:
                raise MinioBackupDrillError("Source object size changed during the drill.")
            metadata = EnvelopeMetadata(
                source_ref=source_ref,
                plaintext_size=plaintext_size,
                plaintext_sha256=plaintext_sha256,
            )
            encrypt_file_streaming(
                source_path,
                encrypted_path,
                key=key,
                metadata=metadata,
                chunk_bytes=config.chunk_bytes,
            )
            encrypted_size = encrypted_path.stat().st_size
            replica_key = f"{replica_prefix}/{source_ref.removeprefix('obj-sha256:')}.hdbk"
            store.upload(
                bucket=config.replica_bucket,
                key=replica_key,
                source=encrypted_path,
                timeout_seconds=config.timeout_seconds,
            )
            expected_entries.append(
                ManifestEntry(
                    source_ref=source_ref,
                    replica_key=replica_key,
                    plaintext_size=plaintext_size,
                    plaintext_sha256=plaintext_sha256,
                    encrypted_size=encrypted_size,
                )
            )
        finally:
            source_path.unlink(missing_ok=True)
            encrypted_path.unlink(missing_ok=True)

    manifest_key = f"{replica_prefix}/manifest.json"
    manifest_path = workspace / "manifest-upload.json"
    manifest_bytes = _manifest_bytes(
        config,
        tenant_ref=tenant_ref,
        entries=expected_entries,
    )
    if len(manifest_bytes) > config.max_manifest_bytes:
        raise MinioBackupDrillError("Backup manifest exceeded its configured size limit.")
    _write_private_bytes(manifest_path, manifest_bytes)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    store.upload(
        bucket=config.replica_bucket,
        key=manifest_key,
        source=manifest_path,
        timeout_seconds=config.timeout_seconds,
    )
    manifest_path.unlink(missing_ok=True)

    downloaded_manifest_path = workspace / "manifest-restore.json"
    store.download(
        bucket=config.replica_bucket,
        key=manifest_key,
        destination=downloaded_manifest_path,
        max_bytes=config.max_manifest_bytes,
        timeout_seconds=config.timeout_seconds,
    )
    _secure_downloaded_file(downloaded_manifest_path, max_bytes=config.max_manifest_bytes)
    downloaded_manifest = _read_bounded(downloaded_manifest_path, config.max_manifest_bytes)
    if not hmac.compare_digest(
        manifest_sha256,
        hashlib.sha256(downloaded_manifest).hexdigest(),
    ):
        raise MinioBackupDrillError("Replica manifest integrity verification failed.")
    restored_entries = _parse_and_validate_manifest(
        downloaded_manifest,
        config=config,
        tenant_ref=tenant_ref,
        expected_entries=expected_entries,
    )
    downloaded_manifest_path.unlink(missing_ok=True)

    verified_paths: dict[str, Path] = {}
    for index, entry in enumerate(restored_entries):
        encrypted_path = workspace / f"downloaded-{index:05d}.hdbk"
        restored_path = workspace / f"verified-{index:05d}.bin"
        try:
            store.download(
                bucket=config.replica_bucket,
                key=entry.replica_key,
                destination=encrypted_path,
                max_bytes=config.max_object_bytes + MAX_ENVELOPE_HEADER_BYTES + 128,
                timeout_seconds=config.timeout_seconds,
            )
            _secure_downloaded_file(
                encrypted_path,
                max_bytes=config.max_object_bytes + MAX_ENVELOPE_HEADER_BYTES + 128,
            )
            if encrypted_path.stat().st_size != entry.encrypted_size:
                raise MinioBackupDrillError("Replica object size verification failed.")
            metadata = decrypt_file_streaming(
                encrypted_path,
                restored_path,
                key=key,
                expected=entry,
                chunk_bytes=config.chunk_bytes,
            )
            if metadata.source_ref != entry.source_ref:
                raise MinioBackupDrillError("Replica source reference verification failed.")
            verified_paths[entry.source_ref] = restored_path
        finally:
            encrypted_path.unlink(missing_ok=True)

    if len(verified_paths) != len(restored_entries):
        raise MinioBackupDrillError("Replica verification did not produce every source object.")

    restore_keys: dict[str, str] = {}
    for entry in restored_entries:
        restored_path = verified_paths[entry.source_ref]
        restore_key = (
            f"{restore_prefix}/{entry.source_ref.removeprefix('obj-sha256:')}.restore"
        )
        store.upload(
            bucket=config.source_bucket,
            key=restore_key,
            source=restored_path,
            timeout_seconds=config.timeout_seconds,
        )
        restore_keys[entry.source_ref] = restore_key

    for index, entry in enumerate(restored_entries):
        parity_path = workspace / f"parity-{index:05d}.bin"
        try:
            store.download(
                bucket=config.source_bucket,
                key=restore_keys[entry.source_ref],
                destination=parity_path,
                max_bytes=config.max_object_bytes,
                timeout_seconds=config.timeout_seconds,
            )
            _secure_downloaded_file(parity_path, max_bytes=config.max_object_bytes)
            parity_size, parity_hash = _hash_file(
                parity_path,
                chunk_bytes=config.chunk_bytes,
                max_bytes=config.max_object_bytes,
            )
            if parity_size != entry.plaintext_size or not hmac.compare_digest(
                parity_hash,
                entry.plaintext_sha256,
            ):
                raise MinioBackupDrillError("Restored object parity verification failed.")
        finally:
            parity_path.unlink(missing_ok=True)

    total_bytes = sum(entry.plaintext_size for entry in restored_entries)
    return {
        "status": "passed",
        "run_id": config.run_id,
        "tenant_ref": tenant_ref,
        "object_count": len(restored_entries),
        "plaintext_bytes": total_bytes,
        "manifest_sha256": manifest_sha256,
        "restored_from_replica": True,
        "parity_passed": True,
        "synthetic_prefixes_cleaned": True,
    }


def encrypt_file_streaming(
    source: Path,
    destination: Path,
    *,
    key: bytes | bytearray,
    metadata: EnvelopeMetadata,
    chunk_bytes: int,
    nonce_factory: Callable[[int], bytes] = os.urandom,
) -> None:
    _validate_aes_key(key)
    _validate_chunk_size(chunk_bytes)
    header = _envelope_header(metadata)
    nonce = nonce_factory(GCM_NONCE_BYTES)
    if len(nonce) != GCM_NONCE_BYTES:
        raise MinioBackupDrillError("Encryption nonce generator returned an invalid value.")
    prefix = ENVELOPE_PREFIX.pack(
        ENVELOPE_MAGIC,
        ENVELOPE_VERSION,
        nonce,
        len(header),
    )
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix + header)
    with source.open("rb", buffering=0) as source_stream:
        with _private_binary_writer(destination) as destination_stream:
            destination_stream.write(prefix)
            destination_stream.write(header)
            while True:
                chunk = source_stream.read(chunk_bytes)
                if not chunk:
                    break
                destination_stream.write(encryptor.update(chunk))
            destination_stream.write(encryptor.finalize())
            destination_stream.write(encryptor.tag)


def decrypt_file_streaming(
    source: Path,
    destination: Path,
    *,
    key: bytes | bytearray,
    expected: ManifestEntry,
    chunk_bytes: int,
) -> EnvelopeMetadata:
    _validate_aes_key(key)
    _validate_chunk_size(chunk_bytes)
    file_size = source.stat().st_size
    with source.open("rb", buffering=0) as source_stream:
        prefix = _read_exact(source_stream, ENVELOPE_PREFIX.size)
        magic, version, nonce, header_size = ENVELOPE_PREFIX.unpack(prefix)
        if magic != ENVELOPE_MAGIC or version != ENVELOPE_VERSION:
            raise MinioBackupDrillError("Replica object envelope version is unsupported.")
        if header_size <= 0 or header_size > MAX_ENVELOPE_HEADER_BYTES:
            raise MinioBackupDrillError("Replica object envelope header is invalid.")
        header = _read_exact(source_stream, header_size)
        metadata = _parse_envelope_header(header)
        _validate_envelope_against_manifest(metadata, expected)
        ciphertext_start = ENVELOPE_PREFIX.size + header_size
        ciphertext_size = file_size - ciphertext_start - GCM_TAG_BYTES
        if ciphertext_size < 0:
            raise MinioBackupDrillError("Replica object envelope is truncated.")
        source_stream.seek(file_size - GCM_TAG_BYTES)
        tag = _read_exact(source_stream, GCM_TAG_BYTES)
        source_stream.seek(ciphertext_start)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(prefix + header)
        digest = hashlib.sha256()
        plaintext_size = 0
        remaining = ciphertext_size
        try:
            with _private_binary_writer(destination) as destination_stream:
                while remaining:
                    chunk = source_stream.read(min(chunk_bytes, remaining))
                    if not chunk:
                        raise MinioBackupDrillError("Replica object ciphertext is truncated.")
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    plaintext_size += len(plaintext)
                    digest.update(plaintext)
                    destination_stream.write(plaintext)
                final_plaintext = decryptor.finalize()
                plaintext_size += len(final_plaintext)
                digest.update(final_plaintext)
                destination_stream.write(final_plaintext)
        except InvalidTag:
            raise MinioBackupDrillError(
                "Replica object authentication failed before restore."
            ) from None
    if plaintext_size != metadata.plaintext_size or not hmac.compare_digest(
        digest.hexdigest(),
        metadata.plaintext_sha256,
    ):
        destination.unlink(missing_ok=True)
        raise MinioBackupDrillError("Replica plaintext integrity verification failed.")
    return metadata


def _validated_source_objects(
    config: MinioBackupDrillConfig,
    raw_objects: Sequence[MinioObject],
    *,
    source_prefix: str,
) -> tuple[MinioObject, ...]:
    if not raw_objects:
        raise MinioBackupDrillError("Tenant source prefix did not contain any objects.")
    if len(raw_objects) > config.max_objects:
        raise MinioBackupDrillError("Tenant source prefix exceeded the object limit.")
    objects = sorted(raw_objects, key=lambda item: item.key)
    total_size = 0
    seen_keys: set[str] = set()
    for item in objects:
        if not _safe_object_key(item.key) or not item.key.startswith(source_prefix):
            raise MinioBackupDrillError("Object listing crossed the tenant prefix boundary.")
        if item.key in seen_keys:
            raise MinioBackupDrillError("Object listing returned a duplicate key.")
        seen_keys.add(item.key)
        if (
            not isinstance(item.size, int)
            or isinstance(item.size, bool)
            or item.size < 0
            or item.size > config.max_object_bytes
        ):
            raise MinioBackupDrillError("Source object exceeded the configured size limit.")
        total_size += item.size
        if total_size > config.max_total_bytes:
            raise MinioBackupDrillError("Tenant source prefix exceeded the total byte limit.")
    return tuple(objects)


def _manifest_bytes(
    config: MinioBackupDrillConfig,
    *,
    tenant_ref: str,
    entries: Sequence[ManifestEntry],
) -> bytes:
    payload = {
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "run_id": config.run_id,
        "tenant_ref": tenant_ref,
        "objects": [entry.to_mapping() for entry in entries],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_and_validate_manifest(
    payload: bytes,
    *,
    config: MinioBackupDrillConfig,
    tenant_ref: str,
    expected_entries: Sequence[ManifestEntry],
) -> tuple[ManifestEntry, ...]:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MinioBackupDrillError("Replica manifest is not valid UTF-8 JSON.") from None
    if not isinstance(decoded, Mapping):
        raise MinioBackupDrillError("Replica manifest must be a JSON object.")
    if (
        decoded.get("format") != MANIFEST_FORMAT
        or type(decoded.get("version")) is not int
        or decoded.get("version") != MANIFEST_VERSION
        or decoded.get("run_id") != config.run_id
        or decoded.get("tenant_ref") != tenant_ref
    ):
        raise MinioBackupDrillError("Replica manifest identity is invalid.")
    raw_entries = decoded.get("objects")
    if not isinstance(raw_entries, list) or len(raw_entries) > config.max_objects:
        raise MinioBackupDrillError("Replica manifest object list is invalid.")
    entries = tuple(_manifest_entry(item) for item in raw_entries)
    expected = [entry.to_mapping() for entry in expected_entries]
    actual = [entry.to_mapping() for entry in entries]
    if actual != expected:
        raise MinioBackupDrillError("Replica manifest does not match the source snapshot.")
    return entries


def _manifest_entry(value: object) -> ManifestEntry:
    if not isinstance(value, Mapping):
        raise MinioBackupDrillError("Replica manifest entry must be an object.")
    source_ref = value.get("source_ref")
    replica_key = value.get("replica_key")
    plaintext_size = value.get("plaintext_size")
    plaintext_sha256 = value.get("plaintext_sha256")
    encrypted_size = value.get("encrypted_size")
    if set(value) != {
        "source_ref",
        "replica_key",
        "plaintext_size",
        "plaintext_sha256",
        "encrypted_size",
    }:
        raise MinioBackupDrillError("Replica manifest entry fields are invalid.")
    if not isinstance(source_ref, str) or SOURCE_REF_RE.fullmatch(source_ref) is None:
        raise MinioBackupDrillError("Replica manifest source reference is invalid.")
    if not isinstance(replica_key, str) or not _safe_object_key(replica_key):
        raise MinioBackupDrillError("Replica manifest object key is invalid.")
    if (
        not isinstance(plaintext_size, int)
        or isinstance(plaintext_size, bool)
        or plaintext_size < 0
    ):
        raise MinioBackupDrillError("Replica manifest plaintext size is invalid.")
    if (
        not isinstance(encrypted_size, int)
        or isinstance(encrypted_size, bool)
        or encrypted_size <= 0
    ):
        raise MinioBackupDrillError("Replica manifest encrypted size is invalid.")
    if not _sha256_string(plaintext_sha256):
        raise MinioBackupDrillError("Replica manifest plaintext hash is invalid.")
    return ManifestEntry(
        source_ref=source_ref,
        replica_key=replica_key,
        plaintext_size=plaintext_size,
        plaintext_sha256=plaintext_sha256,
        encrypted_size=encrypted_size,
    )


def _envelope_header(metadata: EnvelopeMetadata) -> bytes:
    payload = {
        "format": "hallu-minio-backup-object",
        "version": ENVELOPE_VERSION,
        "source_ref": metadata.source_ref,
        "plaintext_size": metadata.plaintext_size,
        "plaintext_sha256": metadata.plaintext_sha256,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_ENVELOPE_HEADER_BYTES:
        raise MinioBackupDrillError("Encrypted object header exceeded its size limit.")
    return encoded


def _parse_envelope_header(payload: bytes) -> EnvelopeMetadata:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MinioBackupDrillError("Encrypted object header is invalid.") from None
    if not isinstance(decoded, Mapping):
        raise MinioBackupDrillError("Encrypted object header must be an object.")
    source_ref = decoded.get("source_ref")
    plaintext_size = decoded.get("plaintext_size")
    plaintext_sha256 = decoded.get("plaintext_sha256")
    if (
        set(decoded)
        != {"format", "version", "source_ref", "plaintext_size", "plaintext_sha256"}
        or
        decoded.get("format") != "hallu-minio-backup-object"
        or type(decoded.get("version")) is not int
        or decoded.get("version") != ENVELOPE_VERSION
        or not isinstance(source_ref, str)
        or SOURCE_REF_RE.fullmatch(source_ref) is None
        or not isinstance(plaintext_size, int)
        or isinstance(plaintext_size, bool)
        or plaintext_size < 0
        or not _sha256_string(plaintext_sha256)
    ):
        raise MinioBackupDrillError("Encrypted object header fields are invalid.")
    return EnvelopeMetadata(
        source_ref=source_ref,
        plaintext_size=plaintext_size,
        plaintext_sha256=plaintext_sha256,
    )


def _validate_envelope_against_manifest(
    metadata: EnvelopeMetadata,
    expected: ManifestEntry,
) -> None:
    if (
        metadata.source_ref != expected.source_ref
        or metadata.plaintext_size != expected.plaintext_size
        or not hmac.compare_digest(
            metadata.plaintext_sha256,
            expected.plaintext_sha256,
        )
    ):
        raise MinioBackupDrillError("Encrypted object header does not match the manifest.")


def _cleanup_synthetic_prefixes(
    config: MinioBackupDrillConfig,
    *,
    store: MinioObjectStore,
    run_prefix: str,
    restore_prefix: str,
    suppress_errors: bool,
) -> None:
    try:
        store.delete_prefix(
            bucket=config.source_bucket,
            prefix=f"{restore_prefix}/",
            timeout_seconds=config.timeout_seconds,
        )
        store.delete_prefix(
            bucket=config.replica_bucket,
            prefix=f"{run_prefix}/",
            timeout_seconds=config.timeout_seconds,
        )
    except Exception:
        if not suppress_errors:
            raise MinioBackupDrillError("Synthetic backup drill cleanup failed.") from None


def _validate_config(config: MinioBackupDrillConfig) -> None:
    if not isinstance(config.tenant_id, str) or TENANT_ID_RE.fullmatch(config.tenant_id) is None:
        raise MinioBackupDrillError("Tenant identifier is invalid.")
    if (
        not isinstance(config.source_bucket, str)
        or BUCKET_RE.fullmatch(config.source_bucket) is None
    ):
        raise MinioBackupDrillError("Source bucket name is invalid.")
    if (
        not isinstance(config.replica_bucket, str)
        or BUCKET_RE.fullmatch(config.replica_bucket) is None
    ):
        raise MinioBackupDrillError("Replica bucket name is invalid.")
    if config.source_bucket == config.replica_bucket:
        raise MinioBackupDrillError("Source and replica buckets must be distinct.")
    for prefix in (config.tenant_prefix_root, config.synthetic_prefix_root):
        if not isinstance(prefix, str) or PREFIX_RE.fullmatch(prefix) is None:
            raise MinioBackupDrillError("Configured object prefix is invalid.")
    if config.tenant_prefix_root == config.synthetic_prefix_root:
        raise MinioBackupDrillError("Tenant and synthetic prefix roots must be distinct.")
    if not config.synthetic_prefix_root.startswith("__"):
        raise MinioBackupDrillError("Synthetic prefix root must be visibly reserved.")
    if not isinstance(config.run_id, str) or RUN_ID_RE.fullmatch(config.run_id) is None:
        raise MinioBackupDrillError("Backup drill run identifier is invalid.")
    if (
        not isinstance(config.secret_name, str)
        or SECRET_NAME_RE.fullmatch(config.secret_name) is None
    ):
        raise MinioBackupDrillError("Backup encryption secret name is invalid.")
    if not _bounded_int(config.timeout_seconds, minimum=1, maximum=MAX_TIMEOUT_SECONDS):
        raise MinioBackupDrillError("Backup drill timeout is outside the allowed bounds.")
    if not _bounded_int(config.max_objects, minimum=1, maximum=MAX_OBJECT_COUNT_LIMIT):
        raise MinioBackupDrillError("Backup drill object limit is outside the allowed bounds.")
    object_bytes_valid = _bounded_int(
        config.max_object_bytes,
        minimum=1,
        maximum=MAX_OBJECT_BYTES_LIMIT,
    )
    if not object_bytes_valid:
        raise MinioBackupDrillError("Backup drill object byte limit is outside the allowed bounds.")
    total_bytes_valid = _bounded_int(
        config.max_total_bytes,
        minimum=1,
        maximum=MAX_TOTAL_BYTES_LIMIT,
    )
    if (
        not total_bytes_valid
        or not object_bytes_valid
        or config.max_total_bytes < config.max_object_bytes
    ):
        raise MinioBackupDrillError("Backup drill total byte limit is outside the allowed bounds.")
    if not _bounded_int(
        config.max_listing_bytes,
        minimum=1024,
        maximum=MAX_MANIFEST_BYTES_LIMIT,
    ):
        raise MinioBackupDrillError("Backup drill listing limit is outside the allowed bounds.")
    if not _bounded_int(
        config.max_manifest_bytes,
        minimum=1024,
        maximum=MAX_MANIFEST_BYTES_LIMIT,
    ):
        raise MinioBackupDrillError("Backup drill manifest limit is outside the allowed bounds.")
    _validate_chunk_size(config.chunk_bytes)
    if config.temp_parent is not None:
        if not config.temp_parent.is_absolute() or not config.temp_parent.is_dir():
            raise MinioBackupDrillError("Backup drill temporary parent is invalid.")


def _decode_encryption_key(raw_key: str) -> bytearray:
    try:
        decoded = base64.b64decode(
            raw_key.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        raise MinioBackupDrillError("Backup encryption key format is invalid.") from None
    if len(decoded) != 32:
        raise MinioBackupDrillError("Backup encryption key format is invalid.")
    return bytearray(decoded)


def _validate_aes_key(key: bytes | bytearray) -> None:
    if len(key) != 32:
        raise MinioBackupDrillError("AES-256-GCM requires a 32-byte key.")


def _validate_chunk_size(chunk_bytes: int) -> None:
    if not _bounded_int(chunk_bytes, minimum=MIN_CHUNK_BYTES, maximum=MAX_CHUNK_BYTES):
        raise MinioBackupDrillError("Streaming chunk size is outside the allowed bounds.")


def _bounded_int(value: object, *, minimum: int, maximum: int) -> TypeGuard[int]:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _tenant_ref(tenant_id: str) -> str:
    return f"tenant-sha256:{hashlib.sha256(tenant_id.encode('utf-8')).hexdigest()}"


def _source_ref(bucket: str, key: str) -> str:
    identity = f"{bucket}\x00{key}".encode("utf-8")
    return f"obj-sha256:{hashlib.sha256(identity).hexdigest()}"


def _safe_object_key(value: str) -> bool:
    if not value or value.startswith("/") or value.endswith("/"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _sha256_string(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _hash_file(path: Path, *, chunk_bytes: int, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(chunk_bytes)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise MinioBackupDrillError("Temporary object exceeded its byte limit.")
            digest.update(chunk)
    return total, digest.hexdigest()


def _secure_downloaded_file(path: Path, *, max_bytes: int) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise MinioBackupDrillError("Object download did not create a usable file.") from None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise MinioBackupDrillError("Object download destination is not a regular file.")
    try:
        os.chmod(path, 0o600)
        size = path.stat().st_size
    except OSError:
        raise MinioBackupDrillError("Object download file could not be secured.") from None
    if size > max_bytes:
        raise MinioBackupDrillError("Object download exceeded its byte limit.")


@contextmanager
def _private_temporary_directory(parent: Path | None) -> Iterator[Path]:
    try:
        with tempfile.TemporaryDirectory(
            prefix="hallu-minio-backup-drill-",
            dir=str(parent) if parent is not None else None,
        ) as raw_path:
            path = Path(raw_path)
            os.chmod(path, 0o700)
            if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o700:
                raise MinioBackupDrillError("Temporary directory permissions are insecure.")
            yield path
    except MinioBackupDrillError:
        raise
    except Exception:
        raise MinioBackupDrillError("Private temporary directory could not be created.") from None


@contextmanager
def _private_binary_writer(path: Path) -> Iterator[BinaryIO]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", buffering=0) as stream:
            descriptor = None
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        path.unlink(missing_ok=True)
        raise


def _write_private_bytes(path: Path, payload: bytes) -> None:
    with _private_binary_writer(path) as stream:
        stream.write(payload)


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    with path.open("rb", buffering=0) as stream:
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise MinioBackupDrillError("Replica manifest exceeded its byte limit.")
    return payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise MinioBackupDrillError("Replica object envelope is truncated.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
