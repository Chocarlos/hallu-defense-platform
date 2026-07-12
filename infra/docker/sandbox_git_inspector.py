"""Emit bounded Git inspection JSON from inside an isolated sandbox.

This process receives no application secrets and is expected to run with network
denied, a process limit, a memory limit, and the repository as its working
directory.  It deliberately never imports application code.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections.abc import Sequence
from pathlib import Path

from sandbox_workspace import _directory_entries_no_follow, workspace_fingerprint

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
MAX_INDEX_ENTRIES = 50_000
MAX_INDEX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PATH_BYTES = 4_096
MAX_PATH_INVENTORY_BYTES = 100_000
MAX_GIT_CONTROL_BYTES = 64 * 1024 * 1024
MAX_GIT_INDEX_BYTES = 16 * 1024 * 1024
MAX_GIT_CONFIG_BYTES = 2 * 1024 * 1024
MAX_LOOSE_OBJECT_BYTES = 16 * 1024 * 1024
MAX_HEAD_OBJECTS = 50_000
MAX_HEAD_OBJECT_BYTES = 64 * 1024 * 1024
MAX_ATTRIBUTE_OUTPUT_BYTES = 2 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
BLOCKED_ATTRIBUTES = (
    "diff",
    "binary",
    "text",
    "filter",
    "eol",
    "working-tree-encoding",
    "ident",
    "crlf",
)
MAX_ATTRIBUTE_BATCH_PATHS = 512
MAX_ATTRIBUTE_BATCH_INPUT_BYTES = 192 * 1024
_WINDOWS_CREATE_SUSPENDED = 0x00000004

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
    "core.ignoreCase=false",
    "-c",
    "core.precomposeUnicode=false",
    "-c",
    "core.symlinks=false",
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
    "-c",
    "color.ui=false",
    "-c",
    "color.diff=false",
    "-c",
    "color.status=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.mnemonicPrefix=false",
)

INDEX_GIT_ARGS = COMMON_GIT_ARGS
CANONICAL_DIFF_ARGS = (
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--full-index",
    "--ignore-submodules=all",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--text",
)

COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "status",
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ),
    ),
    (
        "unstaged_files",
        (
            "diff",
            *CANONICAL_DIFF_ARGS,
            "--name-only",
            "-z",
        ),
    ),
    (
        "staged_files",
        (
            "diff",
            "--cached",
            *CANONICAL_DIFF_ARGS,
            "--name-only",
            "-z",
        ),
    ),
    (
        "unstaged_diff_stat",
        (
            "diff",
            *CANONICAL_DIFF_ARGS,
            "--stat",
        ),
    ),
    (
        "staged_diff_stat",
        (
            "diff",
            "--cached",
            *CANONICAL_DIFF_ARGS,
            "--stat",
        ),
    ),
    (
        "unstaged_patch",
        (
            "diff",
            *CANONICAL_DIFF_ARGS,
            "--unified=0",
        ),
    ),
    (
        "staged_patch",
        (
            "diff",
            "--cached",
            *CANONICAL_DIFF_ARGS,
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
        "workspace_fingerprint_before": "",
        "workspace_fingerprint_after": "",
        "git_control_fingerprint_before": "",
        "git_control_fingerprint_after": "",
        "config_keys": [],
        "index_flags": {
            "assume_unchanged": [],
            "skip_worktree": [],
            "fsmonitor_valid": [],
        },
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
    payload["workspace_fingerprint_before"] = workspace_fingerprint(root)
    payload["git_control_fingerprint_before"] = _git_control_fingerprint(git_metadata)
    errors: list[dict[str, str]] = []
    try:
        config_error, preflight_config_keys = _repository_static_config_guard(
            git_metadata
        )
        payload["config_keys"] = list(preflight_config_keys)
        preflight_error = config_error or _repository_pre_git_guard(root, git_metadata)
    except InspectorInputError as exc:
        preflight_error = str(exc)
    if preflight_error is not None:
        errors.append({"command": "repository_guard", "error": preflight_error})
        return _finalize_payload(payload, root, git_metadata, errors)

    git_path = shutil.which("git", path=os.environ.get("PATH") or os.defpath)
    if git_path is None:
        errors.append(
            {"command": "git", "error": "git executable is unavailable in sandbox"}
        )
        return _finalize_payload(payload, root, git_metadata, errors)

    with tempfile.TemporaryDirectory(prefix="hallu-git-inspector-") as scratch_name:
        scratch = Path(scratch_name)
        guard_error, verified_config_keys = _repository_config_guard(
            git_path,
            git_metadata=git_metadata,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )
        if guard_error is not None:
            errors.append({"command": "repository_guard", "error": guard_error})
            return _finalize_payload(payload, root, git_metadata, errors)
        if verified_config_keys != preflight_config_keys:
            errors.append(
                {
                    "command": "repository_guard",
                    "error": "repository Git configuration key inventory changed during inspection",
                }
            )
            return _finalize_payload(payload, root, git_metadata, errors)

        guard_error = _prepare_private_index(git_metadata, scratch)
        if guard_error is not None:
            errors.append({"command": "repository_guard", "error": guard_error})
            return _finalize_payload(payload, root, git_metadata, errors)

        index_flags, guard_error = _repository_index_guard(
            git_path,
            root=root,
            git_metadata=git_metadata,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
        )
        payload["index_flags"] = index_flags
        if guard_error is not None:
            errors.append({"command": "repository_guard", "error": guard_error})
            return _finalize_payload(payload, root, git_metadata, errors)

        tracked_result = _run_git(
            git_path,
            ("ls-files", "--stage", "-z"),
            root=root,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=MAX_INDEX_OUTPUT_BYTES,
            common_args=INDEX_GIT_ARGS,
        )
        if tracked_result["error"] is not None:
            errors.append(
                {
                    "command": "repository_guard",
                    "error": "tracked path inventory could not be validated",
                }
            )
            return _finalize_payload(payload, root, git_metadata, errors)
        try:
            tracked_paths = _parse_stage_paths(
                str(tracked_result["stdout"]),
            )
        except InspectorInputError:
            errors.append(
                {
                    "command": "repository_guard",
                    "error": "tracked path inventory has an invalid bounded format",
                }
            )
            return _finalize_payload(payload, root, git_metadata, errors)
        guard_error = _repository_attributes_guard(
            git_path,
            paths=tracked_paths,
            root=root,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
        )
        if guard_error is not None:
            errors.append({"command": "repository_guard", "error": guard_error})
            return _finalize_payload(payload, root, git_metadata, errors)

        refresh_result = _run_git(
            git_path,
            ("update-index", "-z", "--index-info"),
            root=root,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=MAX_INDEX_OUTPUT_BYTES,
            common_args=INDEX_GIT_ARGS,
            stdin_bytes=str(tracked_result["stdout"]).encode("utf-8"),
        )
        if (
            refresh_result["returncode"] != 0
            or refresh_result["timed_out"] is True
            or refresh_result["output_truncated"] is True
        ):
            errors.append(
                {
                    "command": "repository_guard",
                    "error": "private repository index could not be fully refreshed",
                }
            )
            return _finalize_payload(payload, root, git_metadata, errors)

        command_by_name = dict(COMMANDS)
        for field_name in ("status", "unstaged_files", "staged_files"):
            result = _run_git(
                git_path,
                command_by_name[field_name],
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
            if field_name == "status":
                try:
                    payload[field_name] = _parse_nul_status(output)
                except InspectorInputError:
                    errors.append(
                        {
                            "command": "git status",
                            "error": "status inventory has an invalid bounded format",
                        }
                    )
            else:
                try:
                    payload[field_name] = _parse_nul_paths(output)
                except InspectorInputError:
                    errors.append(
                        {
                            "command": f"git {field_name}",
                            "error": "path inventory has an invalid bounded format",
                        }
                    )
        if errors:
            return _finalize_payload(payload, root, git_metadata, errors)

        for field_name in (
            "unstaged_diff_stat",
            "staged_diff_stat",
            "unstaged_patch",
            "staged_patch",
        ):
            result = _run_git(
                git_path,
                command_by_name[field_name],
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
            payload[field_name] = str(result["stdout"])
    return _finalize_payload(payload, root, git_metadata, errors)


def _repository_pre_git_guard(root: Path, git_metadata: Path) -> str | None:
    structural_error = _repository_structure_guard(root)
    if structural_error is not None:
        return structural_error
    try:
        os.lstat(git_metadata / "modules")
    except FileNotFoundError:
        pass
    else:
        return "repository submodule control metadata is forbidden: .git/modules"
    for relative in (
        Path("objects") / "info" / "alternates",
        Path("objects") / "info" / "http-alternates",
    ):
        try:
            os.lstat(git_metadata / relative)
        except FileNotFoundError:
            continue
        return (
            f"repository Git alternate object store is forbidden: {relative.as_posix()}"
        )

    exclude_path = git_metadata / "info" / "exclude"
    try:
        exclude_text = _read_regular_file_bounded(
            exclude_path,
            max_bytes=MAX_GIT_CONFIG_BYTES,
        ).decode("utf-8")
    except FileNotFoundError:
        pass
    except UnicodeDecodeError:
        return "repository Git exclude file must be bounded UTF-8 text"
    else:
        if any(
            line.strip() and not line.lstrip().startswith("#")
            for line in exclude_text.splitlines()
        ):
            return "repository Git info/exclude patterns are forbidden"

    index_path = git_metadata / "index"
    index_missing = False
    try:
        index_bytes = _read_regular_file_bounded(
            index_path,
            max_bytes=MAX_GIT_INDEX_BYTES,
        )
    except FileNotFoundError:
        index_missing = True
    else:
        index_error = _git_index_guard(index_bytes)
        if index_error is not None:
            return index_error
    head_error = _head_tree_guard(git_metadata)
    if head_error is not None:
        return head_error
    if index_missing:
        return "repository Git index is required for inspection"
    return None


def _head_tree_guard(git_metadata: Path) -> str | None:
    try:
        head_text = (
            _read_regular_file_bounded(
                git_metadata / "HEAD",
                max_bytes=4_096,
            )
            .decode("ascii")
            .strip()
        )
    except (FileNotFoundError, UnicodeDecodeError):
        return "repository HEAD must be bounded canonical text"
    object_id: str | None
    if head_text.startswith("ref: "):
        ref_name = head_text[5:]
        if (
            not ref_name.startswith("refs/")
            or "\\" in ref_name
            or any(part in {"", ".", ".."} for part in ref_name.split("/"))
        ):
            return "repository HEAD reference is unsafe"
        try:
            object_id = (
                _read_regular_file_bounded(
                    git_metadata / Path(*ref_name.split("/")),
                    max_bytes=256,
                )
                .decode("ascii")
                .strip()
            )
        except FileNotFoundError:
            object_id = _packed_ref_object_id(git_metadata, ref_name)
        except UnicodeDecodeError:
            return "repository HEAD reference must be ASCII"
    else:
        object_id = head_text
    if object_id is None:
        return None
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id) is None:
        return "repository HEAD object id is invalid"

    try:
        object_type, commit = _read_loose_git_object(git_metadata, object_id)
    except FileNotFoundError:
        return "repository packed HEAD object graph cannot be preflighted safely"
    except InspectorInputError as exc:
        return str(exc)
    if object_type != "commit":
        return "repository HEAD must resolve to a commit object"
    tree_line = next(
        (line for line in commit.split(b"\n") if line.startswith(b"tree ")),
        None,
    )
    if tree_line is None:
        return "repository HEAD commit is missing its tree"
    try:
        tree_id = tree_line[5:].decode("ascii")
    except UnicodeDecodeError:
        return "repository HEAD tree id is invalid"
    if len(tree_id) != len(object_id) or not all(
        character in "0123456789abcdef" for character in tree_id
    ):
        return "repository HEAD tree id is invalid"
    budget = [1, len(commit), 0, 0]
    return _head_tree_object_guard(
        git_metadata,
        tree_id,
        object_id_bytes=len(object_id) // 2,
        relative_prefix="",
        budget=budget,
        seen=set(),
        depth=0,
    )


def _packed_ref_object_id(git_metadata: Path, ref_name: str) -> str | None:
    try:
        packed_refs = _read_regular_file_bounded(
            git_metadata / "packed-refs",
            max_bytes=MAX_GIT_CONFIG_BYTES,
        ).decode("ascii")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError as exc:
        raise InspectorInputError("repository packed refs must be ASCII") from exc
    for line in packed_refs.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        try:
            object_id, candidate_ref = line.split(" ", 1)
        except ValueError as exc:
            raise InspectorInputError("repository packed refs are invalid") from exc
        if candidate_ref == ref_name:
            return object_id
    return None


def _read_loose_git_object(
    git_metadata: Path,
    object_id: str,
) -> tuple[str, bytes]:
    compressed = _read_regular_file_bounded(
        git_metadata / "objects" / object_id[:2] / object_id[2:],
        max_bytes=MAX_LOOSE_OBJECT_BYTES,
    )
    decompressor = zlib.decompressobj()
    try:
        decoded = decompressor.decompress(compressed, MAX_LOOSE_OBJECT_BYTES + 1)
        if decompressor.unconsumed_tail:
            raise InspectorInputError("repository loose object exceeded its byte limit")
        if len(decoded) > MAX_LOOSE_OBJECT_BYTES:
            raise InspectorInputError("repository loose object exceeded its byte limit")
        decoded += decompressor.flush(MAX_LOOSE_OBJECT_BYTES + 1 - len(decoded))
    except zlib.error as exc:
        raise InspectorInputError(
            "repository loose object compression is invalid"
        ) from exc
    if len(decoded) > MAX_LOOSE_OBJECT_BYTES or not decompressor.eof:
        raise InspectorInputError("repository loose object exceeded its byte limit")
    header, separator, body = decoded.partition(b"\x00")
    if not separator:
        raise InspectorInputError("repository loose object header is invalid")
    try:
        object_type_bytes, size_bytes = header.split(b" ", 1)
        object_type = object_type_bytes.decode("ascii")
        declared_size = int(size_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InspectorInputError("repository loose object header is invalid") from exc
    if declared_size != len(body):
        raise InspectorInputError("repository loose object size is invalid")
    return object_type, body


def _head_tree_object_guard(
    git_metadata: Path,
    tree_id: str,
    *,
    object_id_bytes: int,
    relative_prefix: str,
    budget: list[int],
    seen: set[str],
    depth: int,
) -> str | None:
    if depth > 100 or tree_id in seen:
        return "repository HEAD tree graph is recursive or too deep"
    next_seen = {*seen, tree_id}
    try:
        object_type, tree = _read_loose_git_object(git_metadata, tree_id)
    except FileNotFoundError:
        return "repository packed HEAD tree cannot be preflighted safely"
    except InspectorInputError as exc:
        return str(exc)
    if object_type != "tree":
        return "repository HEAD tree reference has an invalid object type"
    budget[0] += 1
    budget[1] += len(tree)
    if budget[0] > MAX_HEAD_OBJECTS or budget[1] > MAX_HEAD_OBJECT_BYTES:
        return "repository HEAD tree graph exceeded its safety limit"

    offset = 0
    child_trees: list[tuple[str, str]] = []
    while offset < len(tree):
        space = tree.find(b" ", offset)
        terminator = tree.find(b"\x00", space + 1)
        object_end = terminator + 1 + object_id_bytes
        if space < 0 or terminator < 0 or object_end > len(tree):
            return "repository HEAD tree entry is truncated"
        try:
            mode = int(tree[offset:space], 8)
            name = tree[space + 1 : terminator].decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return "repository HEAD tree entry is not canonical UTF-8"
        if not name or "/" in name or name in {".", ".."}:
            return "repository HEAD tree entry path is unsafe"
        object_id = tree[terminator + 1 : object_end].hex()
        relative = f"{relative_prefix}/{name}" if relative_prefix else name
        budget[2] += 1
        budget[3] += len(relative.encode("utf-8"))
        if budget[2] > MAX_INDEX_ENTRIES or budget[3] > MAX_INDEX_OUTPUT_BYTES:
            return "repository HEAD tree paths exceeded their safety limit"
        if mode & 0o170000 == 0o160000:
            return "repository HEAD contains a forbidden gitlink/submodule"
        if name.casefold() == ".gitmodules":
            return "repository HEAD contains forbidden .gitmodules metadata"
        if mode & 0o170000 == 0o040000:
            child_trees.append((object_id, relative))
        elif mode & 0o170000 not in {0o100000, 0o120000}:
            return "repository HEAD contains an unsupported entry mode"
        offset = object_end

    for child_id, child_prefix in child_trees:
        error = _head_tree_object_guard(
            git_metadata,
            child_id,
            object_id_bytes=object_id_bytes,
            relative_prefix=child_prefix,
            budget=budget,
            seen=next_seen,
            depth=depth + 1,
        )
        if error is not None:
            return error
    return None


def _repository_structure_guard(root: Path) -> str | None:
    pending = [root]
    path_count = 0
    total_path_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            entries = _directory_entries_no_follow(
                root,
                directory,
                max_paths=75_000,
            )
        except (OSError, ValueError) as exc:
            raise InspectorInputError(
                "repository structure could not be enumerated safely"
            ) from exc
        for name, metadata in entries:
            path_count += 1
            if path_count > 75_000:
                raise InspectorInputError(
                    "repository structure path count exceeded its safety limit"
                )
            path = directory / name
            relative = path.relative_to(root).as_posix()
            relative_bytes = len(relative.encode("utf-8"))
            total_path_bytes += relative_bytes
            if relative_bytes > MAX_PATH_BYTES:
                raise InspectorInputError(
                    "repository structure path exceeded its safety limit"
                )
            if total_path_bytes > 64 * 1024 * 1024:
                raise InspectorInputError(
                    "repository structure path bytes exceeded their safety limit"
                )
            normalized_name = name.casefold()
            if normalized_name == ".gitmodules":
                return "repository submodule metadata is forbidden: .gitmodules"
            if normalized_name == ".git" and relative != ".git":
                return "nested Git repositories and worktree pointers are forbidden"
            if _is_link_or_reparse(metadata):
                raise InspectorInputError(
                    "repository structure contains a link or reparse point"
                )
            if stat.S_ISDIR(metadata.st_mode):
                if relative != ".git":
                    pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise InspectorInputError(
                    "repository structure contains a special file"
                )
    return None


def _repository_static_config_guard(
    git_metadata: Path,
) -> tuple[str | None, tuple[str, ...]]:
    all_keys: set[str] = set()
    contains_submodule_section = False
    for config_name in ("config", "config.worktree"):
        try:
            config_text = _read_regular_file_bounded(
                git_metadata / config_name,
                max_bytes=MAX_GIT_CONFIG_BYTES,
            ).decode("utf-8")
        except FileNotFoundError:
            continue
        except UnicodeDecodeError as exc:
            raise InspectorInputError(
                "repository Git configuration must be bounded UTF-8 text"
            ) from exc
        keys, has_submodule = _parse_static_config_keys(config_text)
        all_keys.update(keys)
        if len(all_keys) > MAX_CONFIG_ENTRIES:
            raise InspectorInputError(
                "repository Git configuration key inventory exceeded its limit"
            )
        contains_submodule_section = contains_submodule_section or has_submodule

    ordered_keys = tuple(sorted(all_keys))
    if contains_submodule_section:
        return (
            "repository Git configuration contains forbidden submodule metadata",
            ordered_keys,
        )
    inventory_key = next(
        (
            key
            for key in ordered_keys
            if key in {"core.attributesfile", "core.excludesfile"}
        ),
        None,
    )
    if inventory_key is not None:
        return (
            "repository Git configuration alters pre-inspection inventory: "
            f"{inventory_key}",
            ordered_keys,
        )
    executable = next(
        (key for key in ordered_keys if _is_executable_config_key(key)),
        None,
    )
    if executable is not None:
        return (
            "repository Git configuration contains executable directives",
            ordered_keys,
        )
    affecting = next(
        (key for key in ordered_keys if _is_diff_affecting_config_key(key)),
        None,
    )
    if affecting is not None:
        return (
            "repository Git configuration alters canonical inspection semantics: "
            f"{affecting}",
            ordered_keys,
        )
    return None, ordered_keys


def _parse_static_config_keys(config_text: str) -> tuple[tuple[str, ...], bool]:
    if "\x00" in config_text:
        raise InspectorInputError("repository Git configuration contains NUL bytes")
    if config_text.startswith("\ufeff"):
        raise InspectorInputError(
            "repository Git configuration must not contain a byte-order mark"
        )
    section_prefix = ""
    contains_submodule_section = False
    keys: set[str] = set()
    section_pattern = re.compile(
        r'^\[([A-Za-z0-9-]+)(?:\s+"((?:[^"\\]|\\["\\])*)")?\]'
        r"(?:\s*[#;].*)?$"
    )
    key_pattern = re.compile(r"^([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)*)")
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if raw_line.rstrip().endswith("\\"):
            raise InspectorInputError(
                "repository Git configuration continuations are forbidden"
            )
        if line.startswith("["):
            match = section_pattern.fullmatch(line)
            if match is None:
                raise InspectorInputError(
                    "repository Git configuration has a non-canonical section"
                )
            section = match.group(1).lower()
            subsection = match.group(2)
            if subsection is not None:
                subsection = subsection.replace(r"\\", "\\").replace(r"\"", '"')
                section_prefix = f"{section}.{subsection.lower()}"
            else:
                section_prefix = section
            contains_submodule_section = (
                contains_submodule_section or section == "submodule"
            )
            continue
        match = key_pattern.match(line)
        if match is None:
            raise InspectorInputError(
                "repository Git configuration has a non-canonical key"
            )
        raw_key = match.group(1).lower()
        remainder = line[match.end() :]
        if remainder and not (remainder[0].isspace() or remainder.startswith("=")):
            raise InspectorInputError(
                "repository Git configuration has a non-canonical key"
            )
        canonical_key = (
            f"{section_prefix}.{raw_key}"
            if section_prefix and "." not in raw_key
            else raw_key
        )
        if len(canonical_key) > MAX_CONFIG_KEY_CHARS:
            raise InspectorInputError(
                "repository Git configuration key inventory exceeded its limit"
            )
        keys.add(canonical_key)
        if len(keys) > MAX_CONFIG_ENTRIES:
            raise InspectorInputError(
                "repository Git configuration key inventory exceeded its limit"
            )
    return tuple(sorted(keys)), contains_submodule_section


def _git_index_guard(index_bytes: bytes) -> str | None:
    if len(index_bytes) < 32 or index_bytes[:4] != b"DIRC":
        return "repository Git index has an unsupported bounded format"
    version = int.from_bytes(index_bytes[4:8], "big")
    entry_count = int.from_bytes(index_bytes[8:12], "big")
    if version not in {2, 3, 4} or entry_count > MAX_INDEX_ENTRIES:
        return "repository Git index has an unsupported version or entry count"
    offset = 12
    previous_path = b""
    for _entry_index in range(entry_count):
        entry_start = offset
        if offset + 62 > len(index_bytes):
            return "repository Git index entry is truncated"
        mode = int.from_bytes(index_bytes[offset + 24 : offset + 28], "big")
        flags = int.from_bytes(index_bytes[offset + 60 : offset + 62], "big")
        offset += 62
        if version >= 3 and flags & 0x4000:
            if offset + 2 > len(index_bytes):
                return "repository Git extended index entry is truncated"
            offset += 2
        if version == 4:
            try:
                strip_count, offset = _decode_index_v4_varint(index_bytes, offset)
            except InspectorInputError as exc:
                return str(exc)
            terminator = index_bytes.find(b"\x00", offset)
            if terminator < 0 or strip_count > len(previous_path):
                return "repository Git v4 index path is invalid"
            previous_path = (
                previous_path[: len(previous_path) - strip_count]
                + index_bytes[offset:terminator]
            )
            offset = terminator + 1
        else:
            path_length = flags & 0x0FFF
            if path_length == 0x0FFF:
                terminator = index_bytes.find(b"\x00", offset)
                if terminator < 0:
                    return "repository Git index path is unterminated"
            else:
                terminator = offset + path_length
                if terminator >= len(index_bytes) or index_bytes[terminator] != 0:
                    return "repository Git index path length is invalid"
            previous_path = index_bytes[offset:terminator]
            entry_length = terminator + 1 - entry_start
            offset = entry_start + ((entry_length + 7) & ~7)
            if offset <= entry_start or offset > len(index_bytes):
                return "repository Git index entry padding is invalid"
        if mode & 0o170000 == 0o160000:
            return "repository Git index contains a forbidden gitlink/submodule"
        if flags & 0x3000:
            return "repository Git index contains unmerged stages"
        if any(
            component.lower() == b".gitmodules"
            for component in previous_path.split(b"/")
        ):
            return "repository Git index contains forbidden .gitmodules metadata"

    checksum_start = len(index_bytes) - 20
    while offset + 8 <= checksum_start:
        signature = index_bytes[offset : offset + 4]
        extension_size = int.from_bytes(index_bytes[offset + 4 : offset + 8], "big")
        extension_end = offset + 8 + extension_size
        if extension_end > checksum_start:
            return "repository Git index extension is invalid"
        if signature == b"link":
            return "repository split index is forbidden"
        offset = extension_end
    if offset != checksum_start:
        return "repository Git index checksum format is unsupported"
    return None


def _decode_index_v4_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for _index in range(10):
        if offset >= len(data):
            raise InspectorInputError("repository Git v4 index varint is truncated")
        byte = data[offset]
        offset += 1
        value = (value << 7) + (byte & 0x7F)
        if not byte & 0x80:
            return value, offset
        value += 1
    raise InspectorInputError("repository Git v4 index varint exceeded its limit")


def _read_regular_file_bounded(path: Path, *, max_bytes: int) -> bytes:
    expected = os.lstat(path)
    if _is_link_or_reparse(expected) or not stat.S_ISREG(expected.st_mode):
        raise InspectorInputError(
            "repository Git control file must be regular and non-link"
        )
    if expected.st_size > max_bytes:
        raise InspectorInputError("repository Git control file exceeded its byte limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise InspectorInputError(
                "repository Git control file changed before bounded read"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise InspectorInputError(
                    "repository Git control file changed during bounded read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InspectorInputError(
                "repository Git control file grew during bounded read"
            )
        after = os.fstat(descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise InspectorInputError(
                "repository Git control file changed during bounded read"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _repository_config_guard(
    git_path: str,
    *,
    git_metadata: Path,
    scratch: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> tuple[str | None, tuple[str, ...]]:
    all_keys: set[str] = set()
    for config_name in ("config", "config.worktree"):
        config_path = git_metadata / config_name
        try:
            metadata = os.lstat(config_path)
        except FileNotFoundError:
            continue
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            return "repository Git configuration must be regular non-link files", ()
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
            return "repository Git configuration could not be validated", ()
        try:
            keys = _parse_config_keys(str(result["stdout"]))
        except InspectorInputError:
            return "repository Git configuration has an invalid bounded format", ()
        all_keys.update(key.strip().lower() for key in keys)
        if len(all_keys) > MAX_CONFIG_ENTRIES:
            return "repository Git configuration key inventory exceeded its limit", ()
    ordered_keys = tuple(sorted(all_keys))
    executable = next(
        (key for key in ordered_keys if _is_executable_config_key(key)),
        None,
    )
    if executable is not None:
        return (
            "repository Git configuration contains executable directives",
            ordered_keys,
        )
    affecting = next(
        (key for key in ordered_keys if _is_diff_affecting_config_key(key)),
        None,
    )
    if affecting is not None:
        return (
            "repository Git configuration alters canonical inspection semantics: "
            f"{affecting}",
            ordered_keys,
        )
    return None, ordered_keys


def _prepare_private_index(git_metadata: Path, scratch: Path) -> str | None:
    source = git_metadata / "index"
    destination = scratch / "index"
    try:
        expected = os.lstat(source)
    except FileNotFoundError:
        return None
    if _is_link_or_reparse(expected) or not stat.S_ISREG(expected.st_mode):
        return "repository Git index must be a regular non-link file"
    if expected.st_size > MAX_GIT_CONTROL_BYTES:
        return "repository Git index exceeded its byte limit"

    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        source_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        source_descriptor = os.open(source, source_flags)
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            return "repository Git index changed before private inspection"
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        remaining = before.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(65_536, remaining))
            if not chunk:
                return "repository Git index changed during private inspection"
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    return "repository Git index private copy made no progress"
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            return "repository Git index grew during private inspection"
        after = os.fstat(source_descriptor)
        if not _same_descriptor_snapshot(before, after):
            return "repository Git index changed during private inspection"
    except OSError:
        return "repository Git index could not be copied for private inspection"
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
    return None


def _parse_config_keys(output: str) -> tuple[str, ...]:
    if "\ufffd" in output or (output and not output.endswith("\x00")):
        raise InspectorInputError("invalid Git configuration key output")
    keys = tuple(item for item in output.split("\x00") if item)
    if len(keys) > MAX_CONFIG_ENTRIES or any(
        len(key) > MAX_CONFIG_KEY_CHARS or "\r" in key or "\n" in key or not key.strip()
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
    if key.startswith("filter.") and key.endswith((".clean", ".smudge", ".process")):
        return True
    return key == "diff.external" or (
        key.startswith("diff.") and key.endswith((".command", ".textconv"))
    )


def _is_diff_affecting_config_key(raw_key: str) -> bool:
    key = raw_key.strip().lower()
    if key.startswith(
        (
            "diff.",
            "color.",
            "filter.",
            "pager.",
            "status.",
            "submodule.",
        )
    ):
        return True
    if key in {"interactive.difffilter", "include.path"} or (
        key.startswith("includeif.") and key.endswith(".path")
    ):
        return True
    return key in {
        "core.attributesfile",
        "core.abbrev",
        "core.autocrlf",
        "core.checkstat",
        "core.eol",
        "core.fsmonitor",
        "core.fsmonitorhookversion",
        "core.ignorestat",
        "core.pager",
        "core.quotepath",
        "core.safecrlf",
        "core.trustctime",
        "core.untrackedcache",
        "core.whitespace",
    }


def _repository_index_guard(
    git_path: str,
    *,
    root: Path,
    git_metadata: Path,
    scratch: Path,
    timeout_seconds: float,
) -> tuple[dict[str, list[str]], str | None]:
    checks = (
        ("assume_unchanged", "-v"),
        ("skip_worktree", "-t"),
    )
    flags: dict[str, list[str]] = {
        "assume_unchanged": [],
        "skip_worktree": [],
        "fsmonitor_valid": [],
    }
    if _regular_file_contains_marker(git_metadata / "index", b"FSMN"):
        flags["fsmonitor_valid"] = [".git/index"]
        return flags, "repository index contains hidden-state flags: fsmonitor_valid"
    for flag_name, option in checks:
        result = _run_git(
            git_path,
            ("ls-files", option, "-z"),
            root=root,
            scratch=scratch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=MAX_INDEX_OUTPUT_BYTES,
            common_args=INDEX_GIT_ARGS,
        )
        if result["error"] is not None:
            return flags, "repository index flags could not be validated"
        try:
            tagged = _parse_tagged_paths(str(result["stdout"]))
        except InspectorInputError:
            return flags, "repository index flags have an invalid bounded format"
        for tag, path in tagged:
            selected = (
                tag in {"S", "s"} if flag_name == "skip_worktree" else tag.islower()
            )
            if selected:
                flags[flag_name].append(path)
        if flags[flag_name]:
            return (
                flags,
                f"repository index contains hidden-state flags: {flag_name}",
            )
    return flags, None


def _regular_file_contains_marker(path: Path, marker: bytes) -> bool:
    try:
        expected = os.lstat(path)
    except FileNotFoundError:
        return False
    if _is_link_or_reparse(expected) or not stat.S_ISREG(expected.st_mode):
        raise InspectorInputError("Git index must be a regular non-link file")
    if expected.st_size > MAX_GIT_CONTROL_BYTES:
        raise InspectorInputError("Git index exceeded its byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise InspectorInputError("Git index changed before inspection")
        overlap = b""
        remaining = before.st_size
        found = False
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise InspectorInputError("Git index changed during inspection")
            if marker in overlap + chunk:
                found = True
            overlap = (
                (overlap + chunk)[-(len(marker) - 1) :] if len(marker) > 1 else b""
            )
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InspectorInputError("Git index grew during inspection")
        after = os.fstat(descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise InspectorInputError("Git index changed during inspection")
        return found
    finally:
        os.close(descriptor)


def _parse_tagged_paths(output: str) -> tuple[tuple[str, str], ...]:
    records = _parse_nul_records(output, max_entries=MAX_INDEX_ENTRIES)
    tagged: list[tuple[str, str]] = []
    for record in records:
        if len(record) < 3 or record[1] != " ":
            raise InspectorInputError("invalid tagged path record")
        tag = record[0]
        if len(tag) != 1 or not tag.isalpha():
            raise InspectorInputError("invalid tagged path status")
        path = record[2:]
        _validate_git_path(path)
        tagged.append((tag, path))
    return tuple(tagged)


def _parse_nul_paths(
    output: str,
    *,
    max_entries: int = MAX_LIST_ENTRIES,
    max_total_bytes: int = MAX_PATH_INVENTORY_BYTES,
) -> list[str]:
    records = _parse_nul_records(output, max_entries=max_entries)
    total_bytes = 0
    paths: list[str] = []
    for path in records:
        path_bytes = _validate_git_path(path)
        total_bytes += path_bytes
        if total_bytes > max_total_bytes:
            raise InspectorInputError("path inventory byte limit exceeded")
        paths.append(path)
    return paths


def _parse_nul_status(output: str) -> list[str]:
    records = _parse_nul_records(output, max_entries=MAX_LIST_ENTRIES)
    total_path_bytes = 0
    status: list[str] = []
    for record in records:
        if len(record) < 4 or record[2] != " ":
            raise InspectorInputError("invalid porcelain status record")
        code = record[:2]
        if any(character not in " MADRCU?!T" for character in code):
            raise InspectorInputError("invalid porcelain status code")
        path = record[3:]
        total_path_bytes += _validate_git_path(path)
        if total_path_bytes > MAX_PATH_INVENTORY_BYTES:
            raise InspectorInputError("status path inventory byte limit exceeded")
        status.append(record)
    return status


def _parse_stage_paths(output: str) -> list[str]:
    records = _parse_nul_records(output, max_entries=MAX_INDEX_ENTRIES)
    total_path_bytes = 0
    paths: list[str] = []
    for record in records:
        try:
            header, path = record.split("\t", 1)
        except ValueError as exc:
            raise InspectorInputError("invalid staged path record") from exc
        fields = header.split(" ")
        if len(fields) != 3:
            raise InspectorInputError("invalid staged path metadata")
        mode_text, object_id, stage_text = fields
        try:
            mode = int(mode_text, 8)
        except ValueError as exc:
            raise InspectorInputError("invalid staged path mode") from exc
        if (
            mode & 0o170000 not in {0o100000, 0o120000}
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id) is None
            or set(object_id) == {"0"}
            or stage_text != "0"
        ):
            raise InspectorInputError("unsupported staged path metadata")
        total_path_bytes += _validate_git_path(path)
        if total_path_bytes > MAX_INDEX_OUTPUT_BYTES:
            raise InspectorInputError("staged path inventory byte limit exceeded")
        paths.append(path)
    if paths != sorted(set(paths)):
        raise InspectorInputError("staged path inventory is not canonical")
    return paths


def _parse_nul_records(output: str, *, max_entries: int) -> tuple[str, ...]:
    if "\ufffd" in output or (output and not output.endswith("\x00")):
        raise InspectorInputError("invalid NUL-delimited Git output")
    records = tuple(item for item in output.split("\x00") if item)
    if len(records) > max_entries:
        raise InspectorInputError("Git output entry limit exceeded")
    return records


def _validate_git_path(path: str) -> int:
    if (
        not path
        or path.startswith("/")
        or path != path.strip()
        or "\\" in path
        or '"' in path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise InspectorInputError("unsafe or non-canonical Git path")
    encoded = path.encode("utf-8")
    if len(encoded) > MAX_PATH_BYTES:
        raise InspectorInputError("Git path byte limit exceeded")
    return len(encoded)


def _repository_attributes_guard(
    git_path: str,
    *,
    paths: list[str],
    root: Path,
    scratch: Path,
    timeout_seconds: float,
) -> str | None:
    if not paths:
        return None
    batch: list[str] = []
    batch_bytes = 0
    for path in [*paths, ""]:
        encoded_size = len(path.encode("utf-8")) + 1 if path else 0
        if batch and (
            len(batch) >= MAX_ATTRIBUTE_BATCH_PATHS
            or batch_bytes + encoded_size > MAX_ATTRIBUTE_BATCH_INPUT_BYTES
            or not path
        ):
            guard_error = _repository_attributes_batch_guard(
                git_path,
                paths=batch,
                root=root,
                scratch=scratch,
                timeout_seconds=timeout_seconds,
            )
            if guard_error is not None:
                return guard_error
            batch = []
            batch_bytes = 0
        if path:
            batch.append(path)
            batch_bytes += encoded_size
    return None


def _repository_attributes_batch_guard(
    git_path: str,
    *,
    paths: list[str],
    root: Path,
    scratch: Path,
    timeout_seconds: float,
) -> str | None:
    encoded_paths = b"".join(path.encode("utf-8") + b"\x00" for path in paths)
    result = _run_git(
        git_path,
        ("check-attr", "-z", "--stdin", *BLOCKED_ATTRIBUTES),
        root=root,
        scratch=scratch,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=MAX_ATTRIBUTE_OUTPUT_BYTES,
        stdin_bytes=encoded_paths,
    )
    if result["error"] is not None:
        return "repository attributes could not be validated"
    try:
        fields = _parse_nul_records(
            str(result["stdout"]),
            max_entries=len(paths) * len(BLOCKED_ATTRIBUTES) * 3,
        )
    except InspectorInputError:
        return "repository attributes have an invalid bounded format"
    if len(fields) != len(paths) * len(BLOCKED_ATTRIBUTES) * 3:
        return "repository attributes returned an unexpected result count"
    expected_paths = set(paths)
    for index in range(0, len(fields), 3):
        path, attribute, value = fields[index : index + 3]
        if path not in expected_paths or attribute not in BLOCKED_ATTRIBUTES:
            return "repository attributes returned an invalid result"
        if value != "unspecified":
            return f"repository attributes alter canonical diff semantics: {attribute}"
    return None


def _finalize_payload(
    payload: dict[str, object],
    root: Path,
    git_metadata: Path,
    errors: list[dict[str, str]],
) -> dict[str, object]:
    workspace_after = workspace_fingerprint(root)
    control_after = _git_control_fingerprint(git_metadata)
    payload["workspace_fingerprint_after"] = workspace_after
    payload["git_control_fingerprint_after"] = control_after
    if (
        workspace_after != payload["workspace_fingerprint_before"]
        or control_after != payload["git_control_fingerprint_before"]
    ) and len(errors) < MAX_ERROR_ENTRIES:
        errors.append(
            {
                "command": "repository_guard",
                "error": "repository Git control surface changed during inspection",
            }
        )
    payload["errors"] = errors[:MAX_ERROR_ENTRIES]
    return payload


def _git_control_fingerprint(git_metadata: Path) -> str:
    digest = hashlib.sha256()
    total_bytes = 0
    candidates = (
        git_metadata / "HEAD",
        git_metadata / "config",
        git_metadata / "config.worktree",
        git_metadata / "index",
        git_metadata / "packed-refs",
        git_metadata / "info" / "attributes",
        git_metadata / "info" / "exclude",
        git_metadata / "objects" / "info" / "alternates",
        git_metadata / "objects" / "info" / "http-alternates",
    )
    for path in candidates:
        relative = path.relative_to(git_metadata).as_posix()
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            digest.update(b"M\x00" + relative.encode("utf-8") + b"\x00")
            continue
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise InspectorInputError(
                "Git control files must be regular non-link files"
            )
        total_bytes += metadata.st_size
        if total_bytes > MAX_GIT_CONTROL_BYTES:
            raise InspectorInputError("Git control surface exceeded its byte limit")
        digest.update(b"F\x00" + relative.encode("utf-8") + b"\x00")
        digest.update(str(metadata.st_size).encode("ascii") + b"\x00")
        _update_digest_from_regular_file(digest, path, metadata)
        digest.update(b"\x00")
    return digest.hexdigest()


def _update_digest_from_regular_file(
    digest: object,
    path: Path,
    expected: os.stat_result,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise InspectorInputError("Git control file changed before fingerprinting")
        remaining = before.st_size
        update = getattr(digest, "update")
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise InspectorInputError(
                    "Git control file changed while fingerprinting"
                )
            update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InspectorInputError("Git control file grew while fingerprinting")
        after = os.fstat(descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise InspectorInputError("Git control file changed while fingerprinting")
    finally:
        os.close(descriptor)


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
    common_args: Sequence[str] | None = None,
    stdin_bytes: bytes | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    selected_common_args = (
        tuple(common_args)
        if common_args is not None
        else (COMMON_GIT_ARGS if use_common_args else ())
    )
    command = [
        git_path,
        *selected_common_args,
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
                "GIT_INDEX_FILE": str(scratch / "index"),
                "GIT_WORK_TREE": str(root),
            }
        )
    for key in ("SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    windows_job = _create_windows_kill_job()
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=_WINDOWS_CREATE_SUSPENDED if os.name == "nt" else 0,
        )
    except BaseException:
        _close_windows_handle(windows_job)
        raise
    try:
        _assign_process_to_windows_job(windows_job, process)
        _resume_windows_process(process)
    except BaseException:
        process.kill()
        process.wait()
        _close_windows_handle(windows_job)
        raise
    return _collect_git_process_result(
        process,
        deadline=deadline,
        output_limit_bytes=output_limit_bytes,
        stdin_bytes=stdin_bytes,
        windows_job=windows_job,
    )


def _collect_git_process_result(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    output_limit_bytes: int,
    stdin_bytes: bytes | None,
    windows_job: int | None,
) -> dict[str, object]:
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_truncated = [False]
    stderr_truncated = [False]
    stdout_errors: list[BaseException] = []
    stderr_errors: list[BaseException] = []
    stdin_errors: list[BaseException] = []
    pipe_threads: tuple[threading.Thread, ...] = ()
    timed_out = False
    return_code = -1
    primary_error: BaseException | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Git output pipes were unavailable")
        stdout_thread = threading.Thread(
            target=_drain_bounded_pipe_safely,
            args=(
                process.stdout,
                stdout_chunks,
                output_limit_bytes,
                stdout_truncated,
                stdout_errors,
            ),
            daemon=True,
            name="sandbox-git-stdout-drain",
        )
        stderr_thread = threading.Thread(
            target=_drain_bounded_pipe_safely,
            args=(
                process.stderr,
                stderr_chunks,
                output_limit_bytes,
                stderr_truncated,
                stderr_errors,
            ),
            daemon=True,
            name="sandbox-git-stderr-drain",
        )
        stdout_thread.start()
        pipe_threads = (stdout_thread,)
        stderr_thread.start()
        pipe_threads = (stdout_thread, stderr_thread)
        if stdin_bytes is not None:
            if process.stdin is None:
                raise RuntimeError("Git input pipe was unavailable")
            stdin_thread = threading.Thread(
                target=_write_git_stdin_safely,
                args=(process.stdin, stdin_bytes, stdin_errors),
                daemon=True,
                name="sandbox-git-stdin-writer",
            )
            stdin_thread.start()
            pipe_threads = (stdout_thread, stderr_thread, stdin_thread)
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    except BaseException as exc:
        primary_error = exc
    cleanup_errors = _cleanup_git_process_capture(
        process,
        windows_job,
        pipe_threads,
    )
    if primary_error is not None:
        if cleanup_errors:
            primary_error.add_note(
                "Git subprocess cleanup also failed "
                f"({type(cleanup_errors[0]).__name__})."
            )
        raise primary_error
    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
    error: str | None = None
    if timed_out:
        error = "command timed out"
    elif return_code != 0:
        error = stderr.strip() or f"command exited with code {return_code}"
    if stdout_truncated[0] or stderr_truncated[0]:
        suffix = "command output exceeded its safety limit"
        error = f"{error}; {suffix}" if error else suffix
    if stdout_errors or stderr_errors:
        suffix = "command output pipe capture failed"
        error = f"{error}; {suffix}" if error else suffix
    if stdin_errors:
        suffix = "command input pipe write failed"
        error = f"{error}; {suffix}" if error else suffix
    if cleanup_errors:
        suffix = "command cleanup failed"
        error = f"{error}; {suffix}" if error else suffix
    return {
        "stdout": stdout,
        "error": error,
        "returncode": return_code,
        "timed_out": timed_out,
        "output_truncated": stdout_truncated[0] or stderr_truncated[0],
    }


def _cleanup_git_process_capture(
    process: subprocess.Popen[bytes],
    job_handle: int | None,
    pipe_threads: Sequence[threading.Thread],
) -> list[BaseException]:
    errors: list[BaseException] = []
    try:
        _terminate_process_tree(process, job_handle)
    except BaseException as exc:
        errors.append(exc)
    try:
        _close_windows_handle(job_handle)
    except BaseException as exc:
        errors.append(exc)
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=0.5)
            except BaseException as exc:
                errors.append(exc)
    pipe_deadline = time.monotonic() + 1.0
    for thread in pipe_threads:
        thread.join(max(0.0, pipe_deadline - time.monotonic()))
    if any(thread.is_alive() for thread in pipe_threads):
        errors.append(RuntimeError("Git output pipes could not be closed"))
    for index, stream in enumerate((process.stdout, process.stderr)):
        pipe_thread = pipe_threads[index] if index < len(pipe_threads) else None
        if (pipe_thread is None or not pipe_thread.is_alive()) and stream is not None:
            try:
                stream.close()
            except OSError as exc:
                errors.append(exc)
    stdin_thread = pipe_threads[2] if len(pipe_threads) > 2 else None
    if process.stdin is not None and (
        stdin_thread is None or not stdin_thread.is_alive()
    ):
        try:
            process.stdin.close()
        except OSError as exc:
            errors.append(exc)
    return errors


def _drain_bounded_pipe_safely(
    stream: object,
    chunks: list[bytes],
    limit: int,
    truncated: list[bool],
    errors: list[BaseException],
) -> None:
    try:
        _drain_bounded_pipe(stream, chunks, limit, truncated)
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            getattr(stream, "close")()
        except BaseException as exc:
            errors.append(exc)


def _write_git_stdin_safely(
    stream: object,
    payload: bytes,
    errors: list[BaseException],
) -> None:
    write = getattr(stream, "write")
    view = memoryview(payload)
    try:
        while view:
            written = write(view[:65_536])
            if not isinstance(written, int) or written <= 0:
                raise RuntimeError("Git input pipe made no progress")
            view = view[written:]
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            getattr(stream, "close")()
        except BaseException as exc:
            errors.append(exc)


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    job_handle: int | None,
) -> None:
    if job_handle is not None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not kernel32.TerminateJobObject(ctypes.c_void_p(job_handle), 1):
            error_number = ctypes.get_last_error()
            raise ctypes.WinError(error_number or 1)
        return
    kill_process_group = getattr(os, "killpg", None)
    kill_signal = getattr(signal, "SIGKILL", 9)
    try:
        if not callable(kill_process_group):
            raise ProcessLookupError
        kill_process_group(process.pid, kill_signal)
    except ProcessLookupError:
        return
    except OSError:
        if process.poll() is None:
            process.kill()
        raise


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", ctypes.c_ulong),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", ctypes.c_ulong),
        ("affinity", ctypes.c_size_t),
        ("priority_class", ctypes.c_ulong),
        ("scheduling_class", ctypes.c_ulong),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _JobObjectBasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


def _create_windows_kill_job() -> int | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.restype = ctypes.c_void_p
    handle = create_job(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    information = _JobObjectExtendedLimitInformation()
    information.basic_limit_information.limit_flags = 0x00002000
    if not kernel32.SetInformationJobObject(
        ctypes.c_void_p(handle),
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise error
    return int(handle)


def _assign_process_to_windows_job(
    job_handle: int | None,
    process: subprocess.Popen[bytes],
) -> None:
    if job_handle is None:
        return
    process_handle = int(getattr(process, "_handle"))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.AssignProcessToJobObject(
        ctypes.c_void_p(job_handle),
        ctypes.c_void_p(process_handle),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        return
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    resume_process = ntdll.NtResumeProcess
    resume_process.argtypes = [ctypes.c_void_p]
    resume_process.restype = ctypes.c_long
    status = int(resume_process(ctypes.c_void_p(int(getattr(process, "_handle")))))
    if status < 0:
        raise RuntimeError(
            f"could not resume Git (NTSTATUS 0x{status & 0xFFFFFFFF:08x})"
        )


def _close_windows_handle(job_handle: int | None) -> None:
    if job_handle is None:
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.CloseHandle(ctypes.c_void_p(job_handle)):
        raise ctypes.WinError(ctypes.get_last_error() or 1)


def _drain_bounded_pipe(
    stream: object,
    chunks: list[bytes],
    limit: int,
    truncated: list[bool],
) -> None:
    read = getattr(stream, "read")
    captured = 0
    while True:
        chunk = read(65_536)
        if not chunk:
            return
        if not isinstance(chunk, bytes):
            raise RuntimeError("Git output pipe was not binary")
        available = max(0, limit - captured)
        if available:
            bounded_chunk = chunk[:available]
            chunks.append(bounded_chunk)
            captured += len(bounded_chunk)
        if len(chunk) > available:
            truncated[0] = True


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    if (
        stat.S_IFMT(first.st_mode) != stat.S_IFMT(second.st_mode)
        or stat.S_IMODE(first.st_mode) != stat.S_IMODE(second.st_mode)
        or first.st_size != second.st_size
    ):
        return False
    first_inode = (getattr(first, "st_dev", 0), getattr(first, "st_ino", 0))
    second_inode = (getattr(second, "st_dev", 0), getattr(second, "st_ino", 0))
    if first_inode != (0, 0) and second_inode != (0, 0):
        return first_inode == second_inode
    return first.st_mtime_ns == second.st_mtime_ns


def _same_descriptor_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
        and stat.S_IMODE(first.st_mode) == stat.S_IMODE(second.st_mode)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


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
