from __future__ import annotations

import os
import stat
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.dev import materialize_metrics_bearer_token as materializer_cli
from hallu_defense.services.metrics_token_materializer import (
    MAX_REFRESH_INTERVAL_SECONDS,
    MIN_REFRESH_INTERVAL_SECONDS,
    AtomicSecretFileWriter,
    InsecureMetricsTokenDestinationError,
    MetricsBearerTokenMaterializer,
    MetricsTokenMaterializationError,
)
from hallu_defense.services.secrets import SecretValue
from hallu_defense.services.secret_token import MAX_BEARER_TOKEN_BYTES

DESTINATION = Path(
    "C:/run/secrets/hallu_defense_metrics_bearer_token"
    if os.name == "nt"
    else "/run/secrets/hallu_defense_metrics_bearer_token"
)
SECRET_NAME = "configured/metrics/credential"
SENSITIVE_VALUE = "sensitive-value-must-never-leak"
TOKEN_A = "a" * 32
TOKEN_B = "b" * 32
TOKEN_C = "c" * 32


def test_atomic_writer_fsyncs_and_replaces_with_mode_0600() -> None:
    operations = FakeAtomicFileOperations()
    operations.entries[DESTINATION.name] = FakeEntry(
        mode=stat.S_IFREG | 0o644,
        content=b"previous-token",
    )
    writer = AtomicSecretFileWriter(
        DESTINATION,
        operations=operations,
        temp_name_factory=lambda: "fixed",
    )

    writer.write(b"rotated-token")

    entry = operations.entries[DESTINATION.name]
    assert entry.content == b"rotated-token"
    assert stat.S_IMODE(entry.mode) == 0o600
    assert operations.events.index("fsync:11") < operations.events.index("replace")
    assert operations.events.index("replace") < operations.events.index("fsync:10")
    assert not any(name.endswith(".tmp") for name in operations.entries)


@pytest.mark.parametrize("target_kind", [stat.S_IFLNK, stat.S_IFDIR])
def test_atomic_writer_rejects_symlink_and_directory_targets(target_kind: int) -> None:
    operations = FakeAtomicFileOperations()
    operations.entries[DESTINATION.name] = FakeEntry(mode=target_kind | 0o700)
    writer = AtomicSecretFileWriter(DESTINATION, operations=operations)

    with pytest.raises(InsecureMetricsTokenDestinationError):
        writer.write(b"safe-token")

    assert "replace" not in operations.events


def test_atomic_writer_rejects_symlink_parent_and_insecure_directory() -> None:
    symlink_parent = FakeAtomicFileOperations(parent_symlink=True)
    with pytest.raises(MetricsTokenMaterializationError):
        AtomicSecretFileWriter(DESTINATION, operations=symlink_parent).write(b"safe-token")

    insecure_parent = FakeAtomicFileOperations(directory_mode=stat.S_IFDIR | 0o722)
    with pytest.raises(InsecureMetricsTokenDestinationError, match="directory is insecure"):
        AtomicSecretFileWriter(DESTINATION, operations=insecure_parent).write(b"safe-token")

    assert "replace" not in insecure_parent.events


def test_atomic_writer_failure_preserves_previous_file_and_redacts_cause() -> None:
    operations = FakeAtomicFileOperations(fail_temp_fsync=RuntimeError(SENSITIVE_VALUE))
    operations.entries[DESTINATION.name] = FakeEntry(
        mode=stat.S_IFREG | 0o600,
        content=b"previous-token",
    )
    writer = AtomicSecretFileWriter(
        DESTINATION,
        operations=operations,
        temp_name_factory=lambda: "fixed",
    )

    with pytest.raises(MetricsTokenMaterializationError) as exc_info:
        writer.write(b"replacement-token")

    assert operations.entries[DESTINATION.name].content == b"previous-token"
    assert not any(name.endswith(".tmp") for name in operations.entries)
    rendered = "".join(traceback.format_exception(exc_info.value))
    assert SENSITIVE_VALUE not in rendered


def test_materializer_uses_only_configured_secret_manager_value() -> None:
    manager = SequenceSecretManager([TOKEN_A])
    writer = RecordingSecretFileWriter()
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=manager,
        secret_name=SECRET_NAME,
        writer=writer,
    )

    result = materializer.materialize()

    assert result.rotated is False
    assert manager.requested_names == [SECRET_NAME]
    assert writer.current == TOKEN_A.encode()
    assert writer.writes == [TOKEN_A.encode()]


def test_watch_rotates_token_and_exits_cleanly() -> None:
    manager = SequenceSecretManager([TOKEN_A, TOKEN_B])
    writer = RecordingSecretFileWriter()
    stop_signal = CountingStopSignal(stop_after_waits=2)
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=manager,
        secret_name=SECRET_NAME,
        writer=writer,
    )

    materializer.watch(
        interval_seconds=MIN_REFRESH_INTERVAL_SECONDS,
        stop_signal=stop_signal,
    )

    assert writer.writes == [TOKEN_A.encode(), TOKEN_B.encode()]
    assert writer.current == TOKEN_B.encode()
    assert stop_signal.waits == [MIN_REFRESH_INTERVAL_SECONDS] * 2


def test_watch_retries_redacted_failure_without_losing_previous_value() -> None:
    manager = SequenceSecretManager(
        [TOKEN_A, RuntimeError(SENSITIVE_VALUE), TOKEN_C]
    )
    writer = RecordingSecretFileWriter()
    errors: list[str] = []
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=manager,
        secret_name=SECRET_NAME,
        writer=writer,
    )

    materializer.watch(
        interval_seconds=MIN_REFRESH_INTERVAL_SECONDS,
        stop_signal=CountingStopSignal(stop_after_waits=3),
        on_error=lambda: errors.append("refresh-failed"),
    )

    assert writer.writes == [TOKEN_A.encode(), TOKEN_C.encode()]
    assert writer.current == TOKEN_C.encode()
    assert errors == ["refresh-failed"]
    assert SENSITIVE_VALUE not in repr(errors)


@pytest.mark.parametrize(
    "interval",
    [MIN_REFRESH_INTERVAL_SECONDS - 0.01, MAX_REFRESH_INTERVAL_SECONDS + 0.01],
)
def test_watch_rejects_unbounded_refresh_interval(interval: float) -> None:
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=SequenceSecretManager([TOKEN_A]),
        secret_name=SECRET_NAME,
        writer=RecordingSecretFileWriter(),
    )

    with pytest.raises(MetricsTokenMaterializationError, match="allowed bounds"):
        materializer.watch(
            interval_seconds=interval,
            stop_signal=CountingStopSignal(stop_after_waits=1),
        )


def test_invalid_secret_never_appears_in_exception() -> None:
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=SequenceSecretManager([f"{SENSITIVE_VALUE}\n"]),
        secret_name=SECRET_NAME,
        writer=RecordingSecretFileWriter(),
    )

    with pytest.raises(MetricsTokenMaterializationError) as exc_info:
        materializer.materialize()

    assert SENSITIVE_VALUE not in str(exc_info.value)
    assert SENSITIVE_VALUE not in "".join(traceback.format_exception(exc_info.value))


@pytest.mark.parametrize(
    "invalid_token",
    ["x", " " * 32, "á" * 32, "x" * (MAX_BEARER_TOKEN_BYTES + 1)],
)
def test_materializer_rejects_invalid_rotated_token_without_overwriting_previous(
    invalid_token: str,
) -> None:
    writer = RecordingSecretFileWriter()
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=SequenceSecretManager([TOKEN_A, invalid_token]),
        secret_name=SECRET_NAME,
        writer=writer,
    )
    materializer.materialize()

    with pytest.raises(MetricsTokenMaterializationError, match="invalid format"):
        materializer.materialize()

    assert writer.current == TOKEN_A.encode()
    assert writer.writes == [TOKEN_A.encode()]


def test_writer_failure_message_is_redacted_even_when_it_uses_typed_exception() -> None:
    materializer = MetricsBearerTokenMaterializer(
        secret_manager=SequenceSecretManager([TOKEN_A]),
        secret_name=SECRET_NAME,
        writer=FailingSecretFileWriter(),
    )

    with pytest.raises(MetricsTokenMaterializationError) as exc_info:
        materializer.materialize()

    rendered = "".join(traceback.format_exception(exc_info.value))
    assert SENSITIVE_VALUE not in rendered


def test_cli_redacts_unexpected_secret_manager_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = StringIO()
    stderr = StringIO()
    manager = SequenceSecretManager([RuntimeError(SENSITIVE_VALUE)])
    monkeypatch.setattr(
        materializer_cli,
        "load_settings",
        lambda: SimpleNamespace(metrics_bearer_token_secret_name=SECRET_NAME),
    )
    monkeypatch.setattr(materializer_cli, "create_secret_manager", lambda _settings: manager)
    monkeypatch.setattr(
        materializer_cli,
        "AtomicSecretFileWriter",
        lambda _path: RecordingSecretFileWriter(),
    )

    exit_code = materializer_cli.main([], stdout=stdout, stderr=stderr)

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Metrics bearer token materialization failed.\n"
    assert SENSITIVE_VALUE not in stdout.getvalue() + stderr.getvalue()


def test_cli_watch_handles_clean_stop_without_reading_or_printing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = StringIO()
    stderr = StringIO()
    manager = SequenceSecretManager([SENSITIVE_VALUE])
    monkeypatch.setattr(
        materializer_cli,
        "load_settings",
        lambda: SimpleNamespace(metrics_bearer_token_secret_name=SECRET_NAME),
    )
    monkeypatch.setattr(materializer_cli, "create_secret_manager", lambda _settings: manager)
    monkeypatch.setattr(
        materializer_cli,
        "AtomicSecretFileWriter",
        lambda _path: RecordingSecretFileWriter(),
    )
    monkeypatch.setattr(
        materializer_cli,
        "_install_signal_handlers",
        lambda stop_signal: stop_signal.set(),
    )

    exit_code = materializer_cli.main(["--watch"], stdout=stdout, stderr=stderr)

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert stdout.getvalue() == (
        "Metrics bearer token watch started.\nMetrics bearer token watch stopped.\n"
    )
    assert manager.requested_names == []
    assert SENSITIVE_VALUE not in stdout.getvalue()


@dataclass
class FakeEntry:
    mode: int
    content: bytes = b""


class FakeAtomicFileOperations:
    def __init__(
        self,
        *,
        parent_symlink: bool = False,
        directory_mode: int = stat.S_IFDIR | 0o700,
        fail_temp_fsync: Exception | None = None,
    ) -> None:
        self.entries: dict[str, FakeEntry] = {}
        self.events: list[str] = []
        self._parent_symlink = parent_symlink
        self._directory_mode = directory_mode
        self._fail_temp_fsync = fail_temp_fsync
        self._fd_names: dict[int, str] = {}
        self._next_fd = 11

    def open_directory(self, path: Path) -> int:
        self.events.append(f"open-directory:{path}")
        if self._parent_symlink:
            raise OSError("parent is a symlink")
        return 10

    def directory_mode(self, directory_fd: int) -> int:
        assert directory_fd == 10
        return self._directory_mode

    def target_mode(self, directory_fd: int, name: str) -> int | None:
        assert directory_fd == 10
        entry = self.entries.get(name)
        return entry.mode if entry is not None else None

    def create_temp_file(self, directory_fd: int, name: str, mode: int) -> int:
        assert directory_fd == 10
        assert name not in self.entries
        file_fd = self._next_fd
        self._next_fd += 1
        self._fd_names[file_fd] = name
        self.entries[name] = FakeEntry(mode=stat.S_IFREG | mode)
        self.events.append(f"create:{name}")
        return file_fd

    def chmod(self, file_fd: int, mode: int) -> None:
        name = self._fd_names[file_fd]
        self.entries[name].mode = stat.S_IFREG | mode
        self.events.append(f"chmod:{mode:o}")

    def write(self, file_fd: int, payload: bytes) -> int:
        name = self._fd_names[file_fd]
        self.entries[name].content += payload
        self.events.append(f"write:{len(payload)}")
        return len(payload)

    def fsync(self, file_fd: int) -> None:
        self.events.append(f"fsync:{file_fd}")
        if file_fd != 10 and self._fail_temp_fsync is not None:
            raise self._fail_temp_fsync

    def close(self, file_fd: int) -> None:
        self.events.append(f"close:{file_fd}")

    def replace(self, directory_fd: int, source: str, destination: str) -> None:
        assert directory_fd == 10
        self.entries[destination] = self.entries.pop(source)
        self.events.append("replace")

    def unlink(self, directory_fd: int, name: str) -> None:
        assert directory_fd == 10
        self.entries.pop(name, None)
        self.events.append(f"unlink:{name}")


class SequenceSecretManager:
    def __init__(self, values: Sequence[str | Exception]) -> None:
        self._values = iter(values)
        self.requested_names: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert field == "value"
        self.requested_names.append(name)
        value = next(self._values)
        if isinstance(value, Exception):
            raise value
        return SecretValue(name=name, _value=value)


class RecordingSecretFileWriter:
    def __init__(self) -> None:
        self.current: bytes | None = None
        self.writes: list[bytes] = []

    def write(self, payload: bytes) -> None:
        self.current = payload
        self.writes.append(payload)


class FailingSecretFileWriter:
    def write(self, payload: bytes) -> None:
        del payload
        raise MetricsTokenMaterializationError(SENSITIVE_VALUE)


class CountingStopSignal:
    def __init__(self, *, stop_after_waits: int) -> None:
        self._stop_after_waits = stop_after_waits
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return len(self.waits) >= self._stop_after_waits

    def wait(self, timeout: float) -> bool:
        self.waits.append(timeout)
        return len(self.waits) >= self._stop_after_waits
