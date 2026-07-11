from __future__ import annotations

import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from typing import BinaryIO

from sandbox_workspace import regular_file_sha256, workspace_fingerprint

TIMEOUT_RETURN_CODE = 124
MAX_COMMANDS = 10
MAX_ARTIFACTS = 10_000
ARTIFACT_ROOTS = ("artifacts", "reports")


def artifact_snapshot(root: pathlib.Path) -> dict[str, tuple[int, str]]:
    snapshot: dict[str, tuple[int, str]] = {}
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
            for entry in directory.iterdir():
                metadata = entry.lstat()
                if entry.is_symlink():
                    raise ValueError("artifact links are forbidden")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(entry)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("artifact special files are forbidden")
                relative = entry.relative_to(root).as_posix()
                snapshot[relative] = (
                    metadata.st_size,
                    regular_file_sha256(entry, metadata),
                )
                if len(snapshot) > MAX_ARTIFACTS:
                    raise ValueError("artifact inventory limit exceeded")
    return snapshot


def read_bounded(stream: BinaryIO, output_caps: int) -> str:
    stream.seek(0)
    raw = stream.read(output_caps * 4 + 4)
    return raw.decode("utf-8", errors="replace")[:output_caps]


def execute_command(
    command: Sequence[str],
    *,
    cwd: pathlib.Path,
    timeout: float,
    output_caps: int,
) -> dict[str, object]:
    with (
        tempfile.TemporaryFile(dir="/tmp") as stdout_file,
        tempfile.TemporaryFile(dir="/tmp") as stderr_file,
    ):
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process, force=False)
            _terminate_process_group(process, force=True)
            process.wait(timeout=1)
            returncode = TIMEOUT_RETURN_CODE
        else:
            _terminate_process_group(process, force=False)
            _terminate_process_group(process, force=True)
        stderr = read_bounded(stderr_file, output_caps)
        if timed_out:
            timeout_message = f"sandbox command timed out after {timeout} second(s)\n"
            stderr = (stderr + timeout_message)[-output_caps:]
        return {
            "returncode": returncode,
            "stdout": read_bounded(stdout_file, output_caps),
            "stderr": stderr,
            "timed_out": timed_out,
        }


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    force: bool,
) -> None:
    selected_signal = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.killpg(process.pid, selected_signal)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            return


def parse_commands(raw: str) -> list[list[str]]:
    decoded = json.loads(raw)
    if (
        not isinstance(decoded, list)
        or not 1 <= len(decoded) <= MAX_COMMANDS
        or not all(
            isinstance(command, list)
            and command
            and all(
                isinstance(argument, str)
                and argument
                and "\x00" not in argument
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
    if timeout <= 0 or output_caps <= 0:
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
