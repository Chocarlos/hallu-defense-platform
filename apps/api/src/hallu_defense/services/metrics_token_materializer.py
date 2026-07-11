from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from hallu_defense.services.secret_token import validate_bearer_token
from hallu_defense.services.secrets import SecretManager

DEFAULT_METRICS_BEARER_TOKEN_FILE = Path(
    "/run/secrets/hallu_defense_metrics_bearer_token"
)
MIN_REFRESH_INTERVAL_SECONDS = 1.0
MAX_REFRESH_INTERVAL_SECONDS = 3600.0
SECURE_FILE_MODE = 0o600
INSECURE_DIRECTORY_BITS = 0o022


class MetricsTokenMaterializationError(RuntimeError):
    pass


class InsecureMetricsTokenDestinationError(MetricsTokenMaterializationError):
    pass


class StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float) -> bool: ...


class SecretFileWriter(Protocol):
    def write(self, payload: bytes) -> None: ...


class AtomicFileOperations(Protocol):
    def open_directory(self, path: Path) -> int: ...

    def directory_mode(self, directory_fd: int) -> int: ...

    def target_mode(self, directory_fd: int, name: str) -> int | None: ...

    def create_temp_file(self, directory_fd: int, name: str, mode: int) -> int: ...

    def chmod(self, file_fd: int, mode: int) -> None: ...

    def write(self, file_fd: int, payload: bytes) -> int: ...

    def fsync(self, file_fd: int) -> None: ...

    def close(self, file_fd: int) -> None: ...

    def replace(self, directory_fd: int, source: str, destination: str) -> None: ...

    def unlink(self, directory_fd: int, name: str) -> None: ...


class PosixAtomicFileOperations:
    def __init__(self) -> None:
        required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "fchmod")
        if os.name != "posix" or any(not hasattr(os, name) for name in required):
            raise MetricsTokenMaterializationError(
                "Metrics token materialization requires POSIX filesystem semantics."
            )
        self._o_directory = cast(int, getattr(os, "O_DIRECTORY"))
        self._o_nofollow = cast(int, getattr(os, "O_NOFOLLOW"))
        self._o_cloexec = cast(int, getattr(os, "O_CLOEXEC"))
        self._fchmod = cast(Callable[[int, int], None], getattr(os, "fchmod"))

    def open_directory(self, path: Path) -> int:
        flags = os.O_RDONLY | self._o_directory | self._o_nofollow | self._o_cloexec
        return os.open(path, flags)

    def directory_mode(self, directory_fd: int) -> int:
        return os.fstat(directory_fd).st_mode

    def target_mode(self, directory_fd: int, name: str) -> int | None:
        try:
            return os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return None

    def create_temp_file(self, directory_fd: int, name: str, mode: int) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | self._o_nofollow | self._o_cloexec
        return os.open(name, flags, mode, dir_fd=directory_fd)

    def chmod(self, file_fd: int, mode: int) -> None:
        self._fchmod(file_fd, mode)

    def write(self, file_fd: int, payload: bytes) -> int:
        return os.write(file_fd, payload)

    def fsync(self, file_fd: int) -> None:
        os.fsync(file_fd)

    def close(self, file_fd: int) -> None:
        os.close(file_fd)

    def replace(self, directory_fd: int, source: str, destination: str) -> None:
        os.replace(
            source,
            destination,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )

    def unlink(self, directory_fd: int, name: str) -> None:
        os.unlink(name, dir_fd=directory_fd)


class AtomicSecretFileWriter:
    def __init__(
        self,
        destination: Path,
        *,
        operations: AtomicFileOperations | None = None,
        temp_name_factory: Callable[[], str] | None = None,
    ) -> None:
        if not destination.is_absolute() or not destination.name:
            raise InsecureMetricsTokenDestinationError(
                "Metrics token destination must be an absolute file path."
            )
        self._destination = destination
        self._operations = operations or PosixAtomicFileOperations()
        self._temp_name_factory = temp_name_factory or (lambda: secrets.token_hex(16))

    def write(self, payload: bytes) -> None:
        if not payload:
            raise MetricsTokenMaterializationError("Metrics token payload is invalid.")
        directory_fd: int | None = None
        temp_fd: int | None = None
        temp_name: str | None = None
        try:
            directory_fd = self._operations.open_directory(self._destination.parent)
            self._validate_directory(directory_fd)
            self._validate_target(directory_fd)
            random_part = self._temp_name_factory()
            if not re.fullmatch(r"[A-Za-z0-9]+", random_part):
                raise MetricsTokenMaterializationError(
                    "Metrics token temporary file name is invalid."
                )
            temp_name = f".{self._destination.name}.{random_part}.tmp"
            temp_fd = self._operations.create_temp_file(
                directory_fd,
                temp_name,
                SECURE_FILE_MODE,
            )
            self._operations.chmod(temp_fd, SECURE_FILE_MODE)
            self._write_all(temp_fd, payload)
            self._operations.fsync(temp_fd)
            self._operations.close(temp_fd)
            temp_fd = None
            self._validate_target(directory_fd)
            self._operations.replace(
                directory_fd,
                temp_name,
                self._destination.name,
            )
            temp_name = None
            self._operations.fsync(directory_fd)
        except MetricsTokenMaterializationError:
            raise
        except Exception:
            raise MetricsTokenMaterializationError(
                "Metrics token file could not be materialized."
            ) from None
        finally:
            if temp_fd is not None:
                self._safe_close(temp_fd)
            if directory_fd is not None and temp_name is not None:
                self._safe_unlink(directory_fd, temp_name)
            if directory_fd is not None:
                self._safe_close(directory_fd)

    def _validate_directory(self, directory_fd: int) -> None:
        mode = self._operations.directory_mode(directory_fd)
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & INSECURE_DIRECTORY_BITS:
            raise InsecureMetricsTokenDestinationError(
                "Metrics token destination directory is insecure."
            )

    def _validate_target(self, directory_fd: int) -> None:
        mode = self._operations.target_mode(directory_fd, self._destination.name)
        if mode is None:
            return
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise InsecureMetricsTokenDestinationError(
                "Metrics token destination must be a regular file, not a symlink or directory."
            )

    def _write_all(self, file_fd: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = self._operations.write(file_fd, payload[offset:])
            if written <= 0:
                raise MetricsTokenMaterializationError(
                    "Metrics token file write did not complete."
                )
            offset += written

    def _safe_close(self, file_fd: int) -> None:
        try:
            self._operations.close(file_fd)
        except Exception:
            pass

    def _safe_unlink(self, directory_fd: int, name: str) -> None:
        try:
            self._operations.unlink(directory_fd, name)
        except Exception:
            pass


@dataclass(frozen=True)
class MetricsTokenMaterializationResult:
    rotated: bool


class MetricsBearerTokenMaterializer:
    def __init__(
        self,
        *,
        secret_manager: SecretManager,
        secret_name: str,
        writer: SecretFileWriter,
    ) -> None:
        if not secret_name.strip():
            raise MetricsTokenMaterializationError(
                "Metrics bearer token secret name is not configured."
            )
        self._secret_manager = secret_manager
        self._secret_name = secret_name
        self._writer = writer
        self._last_digest: bytes | None = None

    def materialize(self) -> MetricsTokenMaterializationResult:
        try:
            raw_value = self._secret_manager.get_secret(self._secret_name).reveal()
        except Exception:
            raise MetricsTokenMaterializationError(
                "Metrics bearer token could not be loaded."
            ) from None
        payload = _bearer_token_payload(raw_value)
        digest = hashlib.sha256(payload).digest()
        try:
            self._writer.write(payload)
        except Exception:
            raise MetricsTokenMaterializationError(
                "Metrics bearer token file update failed."
            ) from None
        rotated = self._last_digest is not None and digest != self._last_digest
        self._last_digest = digest
        return MetricsTokenMaterializationResult(rotated=rotated)

    def watch(
        self,
        *,
        interval_seconds: float,
        stop_signal: StopSignal,
        on_error: Callable[[], None] | None = None,
    ) -> None:
        _validate_refresh_interval(interval_seconds)
        while not stop_signal.is_set():
            try:
                self.materialize()
            except MetricsTokenMaterializationError:
                if on_error is not None:
                    on_error()
            if stop_signal.wait(interval_seconds):
                return


def _bearer_token_payload(raw_value: str) -> bytes:
    try:
        validate_bearer_token(raw_value)
    except ValueError:
        raise MetricsTokenMaterializationError(
            "Metrics bearer token has an invalid format."
        ) from None
    return raw_value.encode("ascii")


def _validate_refresh_interval(interval_seconds: float) -> None:
    if not MIN_REFRESH_INTERVAL_SECONDS <= interval_seconds <= MAX_REFRESH_INTERVAL_SECONDS:
        raise MetricsTokenMaterializationError(
            "Metrics token refresh interval is outside the allowed bounds."
        )
