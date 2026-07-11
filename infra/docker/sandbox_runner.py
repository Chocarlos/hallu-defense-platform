from __future__ import annotations

import os
import pathlib
import resource
import signal
import shutil
import stat
import subprocess
import sys

result_dir = pathlib.Path("/hallu-results")
stdout_path = result_dir / "stdout"
stderr_path = result_dir / "stderr"
done_path = result_dir / "done"
running_path = result_dir / "running"
stream_results = os.environ.get("HALLU_DEFENSE_SANDBOX_STREAM_RESULTS") == "1"
if not stream_results:
    stdout_path.touch()
    stderr_path.touch()
    running_path.touch()
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
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in directory.iterdir():
            metadata = entry.lstat()
            if entry.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
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


def copy_workspace_tree(source: pathlib.Path, destination: pathlib.Path) -> None:
    pending = [(source, destination)]
    while pending:
        source_directory, destination_directory = pending.pop()
        for entry in source_directory.iterdir():
            metadata = entry.lstat()
            target = destination_directory / entry.name
            if entry.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise ValueError("workspace links are forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=stat.S_IMODE(metadata.st_mode) | 0o700)
                pending.append((entry, target))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("workspace special files are forbidden")
            shutil.copyfile(entry, target, follow_symlinks=False)
            target.chmod(stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)


def create_working_copy(*, max_files: int, max_bytes: int) -> None:
    global workspace_copy_stage

    workspace_copy_stage = "mount-validation"
    if not source_dir.is_dir() or not workspace_dir.is_dir():
        raise ValueError("sandbox source or working directory is unavailable")
    if any(workspace_dir.iterdir()):
        raise ValueError("sandbox working directory must start empty")
    workspace_copy_stage = "source-validation"
    validate_workspace_tree(source_dir, max_files=max_files, max_bytes=max_bytes)
    workspace_copy_stage = "copy"
    copy_workspace_tree(source_dir, workspace_dir)
    workspace_copy_stage = "copy-validation"
    validate_workspace_tree(workspace_dir, max_files=max_files, max_bytes=max_bytes)


def terminate_child(_signum: int, _frame: object) -> None:
    if child is not None and child.poll() is None:
        child.terminate()


signal.signal(signal.SIGTERM, terminate_child)
signal.signal(signal.SIGINT, terminate_child)
exit_code = 125
stage = "arguments"
try:
    process_limit = int(sys.argv[1])
    max_workspace_files = int(sys.argv[2])
    max_workspace_bytes = int(sys.argv[3])
    command = sys.argv[4:]
    if not command:
        raise ValueError("missing command")
    if max_workspace_files <= 0 or max_workspace_bytes <= 0:
        raise ValueError("invalid workspace limit")
    _soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
    effective_limit = (
        process_limit
        if hard_limit == resource.RLIM_INFINITY
        else min(process_limit, hard_limit)
    )
    if effective_limit <= 0:
        raise ValueError("invalid process limit")
    stage = "process-limit"
    resource.setrlimit(resource.RLIMIT_NPROC, (effective_limit, effective_limit))
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
            stderr_file.write(
                message.encode(
                    "utf-8"
                )
            )
finally:
    if not stream_results:
        running_path.replace(done_path)
raise SystemExit(exit_code)
