from __future__ import annotations

import os
import pathlib
import signal
import stat
import subprocess
import sys

try:
    import resource
except ModuleNotFoundError:  # pragma: no cover - container runtime is Linux
    resource = None  # type: ignore[assignment]

from sandbox_workspace import (
    MAX_PATH_BYTES,
    MAX_TOTAL_PATH_BYTES,
    MAX_WORKSPACE_PATHS,
    _directory_entries_no_follow,
    _open_directory_no_follow,
    _same_descriptor_snapshot,
    _same_file_identity,
    _supports_secure_directory_fds,
)

result_dir = pathlib.Path("/hallu-results")
stdout_path = result_dir / "stdout"
stderr_path = result_dir / "stderr"
done_path = result_dir / "done"
running_path = result_dir / "running"
stream_results = os.environ.get("HALLU_DEFENSE_SANDBOX_STREAM_RESULTS") == "1"
child: subprocess.Popen[bytes] | None = None
source_dir = pathlib.Path("/hallu-source")
workspace_dir = pathlib.Path("/workspace")
workspace_copy_stage = "not-started"


def validate_workspace_tree(
    root: pathlib.Path,
    *,
    max_files: int,
    max_bytes: int,
) -> None:
    file_count = 0
    total_bytes = 0
    path_count = 0
    total_path_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for name, metadata in _directory_entries_no_follow(
            root,
            directory,
            max_paths=MAX_WORKSPACE_PATHS,
        ):
            entry = directory / name
            relative = entry.relative_to(root).as_posix()
            relative_bytes = len(relative.encode("utf-8"))
            path_count += 1
            total_path_bytes += relative_bytes
            if relative_bytes > MAX_PATH_BYTES:
                raise ValueError("workspace path limit exceeded")
            if path_count > MAX_WORKSPACE_PATHS:
                raise ValueError("workspace path count limit exceeded")
            if total_path_bytes > MAX_TOTAL_PATH_BYTES:
                raise ValueError("workspace total path byte limit exceeded")
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("workspace links are forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(entry)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("workspace special files are forbidden")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > max_files:
                raise ValueError("workspace file limit exceeded")
            if total_bytes > max_bytes:
                raise ValueError("workspace byte limit exceeded")


def copy_workspace_tree(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    max_files: int,
    max_bytes: int,
) -> None:
    pending = [(source, destination)]
    file_count = 0
    total_bytes = 0
    path_count = 0
    total_path_bytes = 0
    while pending:
        source_directory, destination_directory = pending.pop()
        for name, metadata in _directory_entries_no_follow(
            source,
            source_directory,
            max_paths=MAX_WORKSPACE_PATHS,
        ):
            entry = source_directory / name
            relative = entry.relative_to(source)
            relative_text = relative.as_posix()
            relative_bytes = len(relative_text.encode("utf-8"))
            path_count += 1
            total_path_bytes += relative_bytes
            if relative_bytes > MAX_PATH_BYTES:
                raise ValueError("workspace path limit exceeded")
            if path_count > MAX_WORKSPACE_PATHS:
                raise ValueError("workspace path count limit exceeded")
            if total_path_bytes > MAX_TOTAL_PATH_BYTES:
                raise ValueError("workspace total path byte limit exceeded")
            target = destination_directory / entry.name
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("workspace links are forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=stat.S_IMODE(metadata.st_mode) | 0o700)
                pending.append((entry, target))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("workspace special files are forbidden")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > max_files:
                raise ValueError("workspace file limit exceeded")
            if total_bytes > max_bytes:
                raise ValueError("workspace byte limit exceeded")
            _copy_regular_file_no_follow(source, entry, target, metadata)
            target.chmod(stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)


def _copy_regular_file_no_follow(
    root: pathlib.Path,
    source: pathlib.Path,
    destination: pathlib.Path,
    expected: os.stat_result,
) -> None:
    relative = source.relative_to(root)
    if _supports_secure_directory_fds():
        parent_descriptor = _open_directory_no_follow(root, relative.parent)
        try:
            source_descriptor = os.open(
                relative.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    else:
        before_path = source.lstat()
        source_descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(source_descriptor)
        after_path = source.lstat()
        if not _same_file_identity(before_path, opened) or not _same_file_identity(
            opened,
            after_path,
        ):
            os.close(source_descriptor)
            raise ValueError("workspace file changed during copy open")
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise ValueError("workspace file changed before copy")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            stat.S_IMODE(expected.st_mode) | stat.S_IWUSR,
        )
        remaining = before.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(65_536, remaining))
            if not chunk:
                raise ValueError("workspace file changed during copy")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise ValueError("workspace copy made no progress")
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            raise ValueError("workspace file grew during copy")
        after = os.fstat(source_descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise ValueError("workspace file changed during copy")
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def create_working_copy(*, max_files: int, max_bytes: int) -> None:
    global workspace_copy_stage

    workspace_copy_stage = "mount-validation"
    if not source_dir.is_dir() or not workspace_dir.is_dir():
        raise ValueError("sandbox source or working directory is unavailable")
    if _directory_entries_no_follow(
        workspace_dir,
        workspace_dir,
        max_paths=1,
    ):
        raise ValueError("sandbox working directory must start empty")
    workspace_copy_stage = "source-validation"
    validate_workspace_tree(source_dir, max_files=max_files, max_bytes=max_bytes)
    workspace_copy_stage = "copy"
    copy_workspace_tree(
        source_dir,
        workspace_dir,
        max_files=max_files,
        max_bytes=max_bytes,
    )
    workspace_copy_stage = "copy-validation"
    validate_workspace_tree(workspace_dir, max_files=max_files, max_bytes=max_bytes)


def terminate_child(_signum: int, _frame: object) -> None:
    if child is not None and child.poll() is None:
        child.terminate()


def main() -> int:
    global child

    signal.signal(signal.SIGTERM, terminate_child)
    signal.signal(signal.SIGINT, terminate_child)
    if not stream_results:
        stdout_path.touch()
        stderr_path.touch()
        running_path.touch()
    exit_code = 125
    stage = "arguments"
    try:
        process_limit = int(sys.argv[1])
        max_workspace_files = int(sys.argv[2])
        max_workspace_bytes = int(sys.argv[3])
        command = sys.argv[4:]
        if not command:
            raise ValueError("missing command")
        if max_workspace_files <= 0 or max_workspace_bytes < 0:
            raise ValueError("invalid workspace limit")
        if resource is None:
            raise RuntimeError("sandbox process limits require a POSIX runtime")
        getrlimit = getattr(resource, "getrlimit", None)
        setrlimit = getattr(resource, "setrlimit", None)
        rlimit_nproc = getattr(resource, "RLIMIT_NPROC", None)
        rlim_infinity = getattr(resource, "RLIM_INFINITY", None)
        if (
            not callable(getrlimit)
            or not callable(setrlimit)
            or rlimit_nproc is None
            or rlim_infinity is None
        ):
            raise RuntimeError("sandbox process limits require POSIX resource support")
        _soft_limit, hard_limit = getrlimit(rlimit_nproc)
        effective_limit = (
            process_limit
            if hard_limit == rlim_infinity
            else min(process_limit, hard_limit)
        )
        if effective_limit <= 0:
            raise ValueError("invalid process limit")
        stage = "process-limit"
        setrlimit(rlimit_nproc, (effective_limit, effective_limit))
        stage = "workspace-copy"
        create_working_copy(
            max_files=max_workspace_files,
            max_bytes=max_workspace_bytes,
        )
        stage = "command"
        if stream_results:
            child = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
            exit_code = child.wait()
        else:
            with (
                stdout_path.open("wb", buffering=0) as stdout_file,
                stderr_path.open("wb", buffering=0) as stderr_file,
            ):
                child = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True,
                )
                exit_code = child.wait()
    except Exception as exc:
        if stage == "workspace-copy":
            stage = f"workspace-copy/{workspace_copy_stage}"
        message = f"sandbox runner failed during {stage}: {type(exc).__name__}\n"
        if stream_results:
            sys.stderr.write(message)
        else:
            with stderr_path.open("ab", buffering=0) as stderr_file:
                stderr_file.write(message.encode("utf-8"))
    finally:
        if not stream_results:
            running_path.replace(done_path)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
