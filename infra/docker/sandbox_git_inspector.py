"""Emit bounded Git inspection JSON from inside an isolated sandbox.

This process receives no application secrets and is expected to run with network
denied, a process limit, a memory limit, and the repository as its working
directory.  It deliberately never imports application code.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

SCHEMA_VERSION = "sandbox_git_inspection.v1"
MAX_LIST_ENTRIES = 2_000
MAX_LIST_ITEM_CHARS = 4_096
MAX_ERROR_ENTRIES = 16
MAX_ERROR_CHARS = 1_000
MIN_OUTPUT_BYTES = 1_024
MAX_OUTPUT_BYTES = 100_000
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 5.0
MAX_CONFIG_ENTRIES = 2_000
MAX_CONFIG_KEY_CHARS = 4_096
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

COMMON_GIT_ARGS = (
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.filemode=false",
    "-c",
    "core.autocrlf=input",
    "-c",
    "core.safecrlf=false",
    "-c",
    "safe.directory=*",
    "-c",
    "diff.external=",
    "-c",
    "submodule.recurse=false",
    "-c",
    "core.quotePath=false",
)

COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "status",
        ("status", "--short", "--untracked-files=all", "--ignore-submodules=all"),
    ),
    (
        "unstaged_files",
        (
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--name-only",
        ),
    ),
    (
        "staged_files",
        (
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--name-only",
        ),
    ),
    (
        "unstaged_diff_stat",
        (
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--stat",
        ),
    ),
    (
        "staged_diff_stat",
        (
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--stat",
        ),
    ),
    (
        "unstaged_patch",
        (
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--unified=0",
        ),
    ),
    (
        "staged_patch",
        (
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--ignore-submodules=all",
            "--unified=0",
        ),
    ),
)


class InspectorInputError(ValueError):
    pass


def _empty_payload(*, is_repository: bool) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "is_repository": is_repository,
        "status": [],
        "unstaged_files": [],
        "staged_files": [],
        "unstaged_diff_stat": "",
        "staged_diff_stat": "",
        "unstaged_patch": "",
        "staged_patch": "",
        "errors": [],
    }


def inspect_repository(
    *,
    root: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> dict[str, object]:
    payload = _empty_payload(is_repository=False)
    git_metadata = root / ".git"
    try:
        git_info = os.lstat(git_metadata)
    except FileNotFoundError:
        return payload
    if _is_link_or_reparse(git_info) or not stat.S_ISDIR(git_info.st_mode):
        payload["errors"] = [
            {
                "command": "repository_guard",
                "error": ".git must be a real in-repository directory",
            }
        ]
        return payload

    payload["is_repository"] = True
    git_path = shutil.which("git", path=os.environ.get("PATH") or os.defpath)
    if git_path is None:
        payload["errors"] = [
            {"command": "git", "error": "git executable is unavailable in sandbox"}
        ]
        return payload

    errors: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="hallu-git-inspector-") as scratch_name:
        scratch = Path(scratch_name)
        guard_error = _repository_config_guard(
            git_path,
            git_metadata=git_metadata,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )
        if guard_error is not None:
            payload["errors"] = [
                {
                    "command": "repository_guard",
                    "error": guard_error,
                }
            ]
            return payload
        for field_name, command_args in COMMANDS:
            result = _run_git(
                git_path,
                command_args,
                root=root,
                scratch=scratch,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
            if result["error"] is not None and len(errors) < MAX_ERROR_ENTRIES:
                errors.append(
                    {
                        "command": f"git {field_name}",
                        "error": _bounded_error(str(result["error"])),
                    }
                )
            output = str(result["stdout"])
            if field_name in {"status", "unstaged_files", "staged_files"}:
                payload[field_name] = _bounded_lines(
                    output,
                    field_name=field_name,
                    errors=errors,
                )
            else:
                payload[field_name] = output
    payload["errors"] = errors[:MAX_ERROR_ENTRIES]
    return payload


def _repository_config_guard(
    git_path: str,
    *,
    git_metadata: Path,
    scratch: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> str | None:
    for config_name in ("config", "config.worktree"):
        config_path = git_metadata / config_name
        try:
            metadata = os.lstat(config_path)
        except FileNotFoundError:
            continue
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            return "repository Git configuration must be regular non-link files"
        result = _run_git(
            git_path,
            (
                "config",
                "--file",
                str(config_path),
                "--no-includes",
                "--null",
                "--name-only",
                "--list",
            ),
            root=scratch,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            bind_repository=False,
            use_common_args=False,
        )
        if result["error"] is not None:
            return "repository Git configuration could not be validated"
        try:
            keys = _parse_config_keys(str(result["stdout"]))
        except InspectorInputError:
            return "repository Git configuration has an invalid bounded format"
        if any(_is_executable_config_key(key) for key in keys):
            return "repository Git configuration contains executable directives"
    return None


def _parse_config_keys(output: str) -> tuple[str, ...]:
    if "\ufffd" in output or (output and not output.endswith("\x00")):
        raise InspectorInputError("invalid Git configuration key output")
    keys = tuple(item for item in output.split("\x00") if item)
    if len(keys) > MAX_CONFIG_ENTRIES or any(
        len(key) > MAX_CONFIG_KEY_CHARS
        or "\r" in key
        or "\n" in key
        or not key.strip()
        for key in keys
    ):
        raise InspectorInputError("Git configuration key inventory exceeded its limit")
    return keys


def _is_executable_config_key(raw_key: str) -> bool:
    key = raw_key.strip().lower()
    if key == "include.path" or (
        key.startswith("includeif.") and key.endswith(".path")
    ):
        return True
    if key.startswith("filter.") and key.endswith(
        (".clean", ".smudge", ".process")
    ):
        return True
    return key == "diff.external" or (
        key.startswith("diff.") and key.endswith((".command", ".textconv"))
    )


def _run_git(
    git_path: str,
    command_args: Sequence[str],
    *,
    root: Path,
    scratch: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
    bind_repository: bool = True,
    use_common_args: bool = True,
) -> dict[str, object]:
    command = [
        git_path,
        *(COMMON_GIT_ARGS if use_common_args else ()),
        *command_args,
    ]
    environment = {
        "HOME": str(scratch),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.path.dirname(git_path) + os.pathsep + os.defpath,
        "USERPROFILE": str(scratch),
        "XDG_CONFIG_HOME": str(scratch),
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    if bind_repository:
        git_directory = root / ".git"
        environment.update(
            {
                "GIT_DIR": str(git_directory),
                "GIT_COMMON_DIR": str(git_directory),
                "GIT_WORK_TREE": str(root),
            }
        )
    for key in ("SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=os.name != "nt",
        )
        timed_out = False
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_tree(process)
            return_code = process.wait(timeout=1)

        stdout, stdout_truncated = _read_bounded_file(stdout_file, output_limit_bytes)
        stderr, stderr_truncated = _read_bounded_file(stderr_file, output_limit_bytes)
    error: str | None = None
    if timed_out:
        error = "command timed out"
    elif return_code != 0:
        error = stderr.strip() or f"command exited with code {return_code}"
    if stdout_truncated or stderr_truncated:
        suffix = "command output exceeded its safety limit"
        error = f"{error}; {suffix}" if error else suffix
    return {"stdout": stdout, "error": error}


def _terminate_process_tree(process: subprocess.Popen[object]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        process.kill()


def _read_bounded_file(file: object, limit: int) -> tuple[str, bool]:
    seek = getattr(file, "seek")
    read = getattr(file, "read")
    seek(0)
    content = read(limit + 1)
    if not isinstance(content, bytes):
        raise RuntimeError("temporary Git output was not bytes")
    truncated = len(content) > limit
    return content[:limit].decode("utf-8", errors="replace"), truncated


def _bounded_lines(
    output: str,
    *,
    field_name: str,
    errors: list[dict[str, str]],
) -> list[str]:
    raw_lines = [line for line in output.splitlines() if line]
    truncated = len(raw_lines) > MAX_LIST_ENTRIES
    lines: list[str] = []
    for line in raw_lines[:MAX_LIST_ENTRIES]:
        if "\x00" in line or len(line) > MAX_LIST_ITEM_CHARS:
            truncated = True
            continue
        lines.append(line)
    if truncated and len(errors) < MAX_ERROR_ENTRIES:
        errors.append(
            {
                "command": f"git {field_name}",
                "error": "path inventory exceeded its safety limit",
            }
        )
    return lines


def _bounded_error(value: str) -> str:
    sanitized = value.replace("\x00", "?").replace("\r", " ").replace("\n", " ").strip()
    return (sanitized or "Git inspection failed")[:MAX_ERROR_CHARS]


def _is_link_or_reparse(path_info: os.stat_result) -> bool:
    attributes = getattr(path_info, "st_file_attributes", 0)
    return stat.S_ISLNK(path_info.st_mode) or bool(
        attributes & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _validated_inputs(argv: Sequence[str]) -> tuple[float, int]:
    if len(argv) != 2:
        raise InspectorInputError("expected timeout and output limit")
    try:
        timeout_seconds = float(argv[0])
        output_limit_bytes = int(argv[1])
    except ValueError as exc:
        raise InspectorInputError("timeout and output limit must be numeric") from exc
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise InspectorInputError("timeout is outside the safety range")
    if not MIN_OUTPUT_BYTES <= output_limit_bytes <= MAX_OUTPUT_BYTES:
        raise InspectorInputError("output limit is outside the safety range")
    return timeout_seconds, output_limit_bytes


def main(argv: Sequence[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        timeout_seconds, output_limit_bytes = _validated_inputs(effective_argv)
        payload = inspect_repository(
            root=Path.cwd(),
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )
    except Exception as exc:
        payload = _empty_payload(is_repository=False)
        payload["errors"] = [
            {
                "command": "inspector",
                "error": _bounded_error(type(exc).__name__),
            }
        ]
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
