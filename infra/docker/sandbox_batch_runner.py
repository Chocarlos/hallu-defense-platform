from __future__ import annotations

import ctypes
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Sequence

from sandbox_workspace import (
    MAX_PATH_BYTES,
    MAX_TOTAL_PATH_BYTES,
    MAX_WORKSPACE_BYTES,
    MAX_WORKSPACE_PATHS,
    _directory_entries_no_follow,
    regular_file_sha256,
    workspace_fingerprint,
)

TIMEOUT_RETURN_CODE = 124
MAX_COMMANDS = 10
MAX_COMMAND_ARGUMENTS = 256
MAX_COMMAND_BYTES = 32 * 1024
MAX_OUTPUT_CHARS = 100_000
MAX_ARTIFACTS = 10_000
ARTIFACT_ROOTS = ("artifacts", "reports")
MAX_DESCENDANT_SCAN = 4_096
_subreaper_enabled = False


def artifact_snapshot(root: pathlib.Path) -> dict[str, tuple[int, str]]:
    snapshot: dict[str, tuple[int, str]] = {}
    path_count = 0
    total_path_bytes = 0
    total_file_bytes = 0
    for root_name in ARTIFACT_ROOTS:
        artifact_root = root / root_name
        if not artifact_root.exists():
            continue
        root_metadata = artifact_root.lstat()
        if artifact_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            raise ValueError("artifact root must be a real directory")
        pending = [artifact_root]
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
                    raise ValueError("artifact path limit exceeded")
                if path_count > MAX_WORKSPACE_PATHS:
                    raise ValueError("artifact path count limit exceeded")
                if total_path_bytes > MAX_TOTAL_PATH_BYTES:
                    raise ValueError("artifact total path byte limit exceeded")
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & 0x400
                ):
                    raise ValueError("artifact links are forbidden")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(entry)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("artifact special files are forbidden")
                total_file_bytes += metadata.st_size
                if total_file_bytes > MAX_WORKSPACE_BYTES:
                    raise ValueError("artifact byte limit exceeded")
                snapshot[relative] = (
                    metadata.st_size,
                    regular_file_sha256(root, entry, metadata),
                )
                if len(snapshot) > MAX_ARTIFACTS:
                    raise ValueError("artifact inventory limit exceeded")
    return snapshot


def _drain_bounded_pipe(
    stream: object,
    chunks: list[bytes],
    byte_limit: int,
) -> None:
    read = getattr(stream, "read")
    captured = 0
    while True:
        chunk = read(65_536)
        if not chunk:
            return
        if not isinstance(chunk, bytes):
            raise RuntimeError("sandbox output pipe was not binary")
        if captured < byte_limit:
            bounded_chunk = chunk[: byte_limit - captured]
            chunks.append(bounded_chunk)
            captured += len(bounded_chunk)


def _drain_bounded_pipe_safely(
    stream: object,
    chunks: list[bytes],
    byte_limit: int,
    errors: list[BaseException],
) -> None:
    try:
        _drain_bounded_pipe(stream, chunks, byte_limit)
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            getattr(stream, "close")()
        except BaseException as exc:
            errors.append(exc)


def _decode_bounded(chunks: list[bytes], output_caps: int) -> str:
    return b"".join(chunks).decode("utf-8", errors="replace")[:output_caps]


def execute_command(
    command: Sequence[str],
    *,
    cwd: pathlib.Path,
    timeout: float,
    output_caps: int,
) -> dict[str, object]:
    _ensure_child_subreaper()
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise RuntimeError("sandbox output pipes were unavailable")
    byte_limit = output_caps * 4 + 4
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_errors: list[BaseException] = []
    stderr_errors: list[BaseException] = []
    stdout_thread = threading.Thread(
        target=_drain_bounded_pipe_safely,
        args=(process.stdout, stdout_chunks, byte_limit, stdout_errors),
        daemon=True,
        name="sandbox-batch-stdout-drain",
    )
    stderr_thread = threading.Thread(
        target=_drain_bounded_pipe_safely,
        args=(process.stderr, stderr_chunks, byte_limit, stderr_errors),
        daemon=True,
        name="sandbox-batch-stderr-drain",
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    cleanup_errors: list[BaseException] = []
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = TIMEOUT_RETURN_CODE
    finally:
        for force in (False, True):
            try:
                _terminate_process_group(process, force=force)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if process.poll() is None:
            try:
                process.wait(timeout=1)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            _terminate_descendant_processes()
        except BaseException as exc:
            cleanup_errors.append(exc)
    pipe_deadline = time.monotonic() + 1.0
    for thread in (stdout_thread, stderr_thread):
        thread.join(max(0.0, pipe_deadline - time.monotonic()))
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        cleanup_errors.append(RuntimeError("sandbox output pipes could not be closed"))
    if stdout_errors or stderr_errors:
        raise RuntimeError("sandbox output pipe capture failed") from (
            stdout_errors + stderr_errors
        )[0]
    if cleanup_errors:
        raise RuntimeError("sandbox subprocess cleanup failed") from cleanup_errors[0]
    stderr = _decode_bounded(stderr_chunks, output_caps)
    if timed_out:
        timeout_message = f"sandbox command timed out after {timeout} second(s)\n"
        stderr = (stderr + timeout_message)[-output_caps:]
    return {
        "returncode": returncode,
        "stdout": _decode_bounded(stdout_chunks, output_caps),
        "stderr": stderr,
        "timed_out": timed_out,
    }


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    force: bool,
) -> None:
    if os.name == "nt":
        if process.poll() is None:
            if force:
                process.kill()
            else:
                process.terminate()
        return
    selected_signal = getattr(signal, "SIGKILL", 9) if force else signal.SIGTERM
    kill_process_group = getattr(os, "killpg", None)
    if not callable(kill_process_group):
        raise RuntimeError("sandbox process-group cleanup requires POSIX support")
    try:
        kill_process_group(process.pid, selected_signal)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            return


def _ensure_child_subreaper() -> None:
    global _subreaper_enabled

    if os.name == "nt" or _subreaper_enabled:
        return
    if not sys.platform.startswith("linux"):
        raise RuntimeError("sandbox descendant cleanup requires Linux")
    pr_set_child_subreaper = 36
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(pr_set_child_subreaper, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "could not enable sandbox child subreaper")
    _subreaper_enabled = True


def _terminate_descendant_processes() -> None:
    if os.name == "nt":
        return
    for selected_signal in (signal.SIGTERM, getattr(signal, "SIGKILL", 9)):
        for _attempt in range(10):
            descendants = _descendant_process_ids(os.getpid())
            if not descendants:
                _reap_exited_children()
                return
            for process_id in descendants:
                try:
                    os.kill(process_id, selected_signal)
                except ProcessLookupError:
                    continue
            _reap_exited_children()
            time.sleep(0.02)
    survivors = _descendant_process_ids(os.getpid())
    _reap_exited_children()
    if survivors:
        raise RuntimeError("sandbox command left descendant processes running")


def _descendant_process_ids(root_process_id: int) -> list[int]:
    parent_by_process: dict[int, int] = {}
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            scanned += 1
            if scanned > MAX_DESCENDANT_SCAN:
                raise RuntimeError(
                    "sandbox process inventory exceeded its safety limit"
                )
            process_id = int(entry.name)
            if process_id == root_process_id:
                continue
            try:
                with open(
                    f"/proc/{process_id}/status",
                    encoding="ascii",
                    errors="replace",
                ) as status_file:
                    status_text = status_file.read(16_384)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            parent_line = next(
                (line for line in status_text.splitlines() if line.startswith("PPid:")),
                "",
            )
            try:
                parent_by_process[process_id] = int(parent_line.split()[1])
            except (IndexError, ValueError):
                continue

    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for process_id, parent_id in parent_by_process.items():
            if process_id in descendants:
                continue
            if parent_id == root_process_id or parent_id in descendants:
                descendants.add(process_id)
                changed = True
    return sorted(descendants, reverse=True)


def _reap_exited_children() -> None:
    wait_nohang = int(getattr(os, "WNOHANG", 1))
    while True:
        try:
            process_id, _status = os.waitpid(-1, wait_nohang)
        except ChildProcessError:
            return
        if process_id == 0:
            return


def parse_commands(raw: str) -> list[list[str]]:
    decoded = json.loads(raw)
    if (
        not isinstance(decoded, list)
        or not 1 <= len(decoded) <= MAX_COMMANDS
        or not all(
            isinstance(command, list)
            and command
            and len(command) <= MAX_COMMAND_ARGUMENTS
            and sum(
                len(argument.encode("utf-8"))
                for argument in command
                if isinstance(argument, str)
            )
            <= MAX_COMMAND_BYTES
            and all(
                isinstance(argument, str) and argument and "\x00" not in argument
                for argument in command
            )
            for command in decoded
        )
    ):
        raise ValueError("invalid sandbox command batch")
    return decoded


def main() -> None:
    if len(sys.argv) != 4:
        raise ValueError("invalid sandbox batch runner arguments")
    timeout = float(sys.argv[1])
    output_caps = int(sys.argv[2])
    if timeout <= 0 or not 0 < output_caps <= MAX_OUTPUT_CHARS:
        raise ValueError("invalid sandbox batch limits")
    commands = parse_commands(sys.argv[3])
    workspace = pathlib.Path.cwd().resolve()
    if workspace != pathlib.Path("/workspace"):
        raise ValueError("sandbox batch must execute in /workspace")
    pre_snapshot_fingerprint = workspace_fingerprint(workspace)
    before = artifact_snapshot(workspace)
    executions = [
        execute_command(
            command,
            cwd=workspace,
            timeout=timeout,
            output_caps=output_caps,
        )
        for command in commands
    ]
    after = artifact_snapshot(workspace)
    post_snapshot_fingerprint = workspace_fingerprint(workspace)
    artifacts = sorted(
        path for path, signature in after.items() if before.get(path) != signature
    )
    print(
        json.dumps(
            {
                "schema_version": "sandbox_execution_batch.v3",
                "pre_snapshot_fingerprint": pre_snapshot_fingerprint,
                "post_snapshot_fingerprint": post_snapshot_fingerprint,
                "executions": executions,
                "artifacts": artifacts,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
