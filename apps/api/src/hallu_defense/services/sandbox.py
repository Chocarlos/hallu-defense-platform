from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import stat
import tempfile
from contextlib import contextmanager
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    Authority,
    Evidence,
    EvidenceKind,
    Freshness,
    RepoChecksRunRequest,
    SandboxRun,
    StalenessClass,
    VerdictStatus,
)
from hallu_defense.services.sandbox_exec import (
    MAX_SANDBOX_WORKSPACE_BYTES,
    MAX_SANDBOX_WORKSPACE_FILES,
    MAX_SANDBOX_WORKSPACE_PATHS,
    MAX_SANDBOX_PATH_BYTES,
    MAX_SANDBOX_TOTAL_PATH_BYTES,
    SANDBOX_GIT_INSPECTOR_PATH,
    SandboxBatchExecutionBackend,
    SandboxExecutionBackend,
    SandboxExecutionError,
    build_sandbox_execution_backend,
)
from hallu_defense.services.text import bounded, tokenize

ALLOWED_EXECUTABLES = {"python", "pytest", "npm", "node"}
ARTIFACT_DIRS = {"artifacts", "reports"}
INSPECTION_EVIDENCE_SOURCE = "sandbox://inspection"
INSPECTION_SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "node_modules",
    "reports",
    "venv",
}
MAX_INSPECTION_BYTES = 500_000
MAX_INSPECTION_FILES = 2_000
MAX_INSPECTION_SYMBOLS = 1_000
MAX_CHANGED_LINES = 1_000
MAX_CHANGED_LINE_CHARS = 500
MAX_ARTIFACT_FILES = 10_000
MAX_GIT_LIST_ENTRIES = 2_000
MAX_GIT_ERROR_ENTRIES = 16
MAX_GIT_ERROR_CHARS = 1_000
MIN_GIT_INSPECTOR_CONTROL_CHARS = 32_768
MAX_GIT_INSPECTOR_CONTROL_CHARS = 1_600_000
SANDBOX_GIT_INSPECTION_SCHEMA = "sandbox_git_inspection.v1"
HOST_GIT_INSPECTOR_ENV_KEYS = {
    "PATH",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
}
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
INSPECTION_FILE_SUFFIXES = {
    ".c",
    ".cpp",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".kt",
    ".md",
    ".py",
    ".rs",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
DESTRUCTIVE_PATTERNS = [
    re.compile(pattern, re.I)
    for pattern in [
        r"\b(rm|rmdir|del|erase|remove-item|move-item)\b",
        r"\bgit\s+(clean|reset\s+--hard|checkout\s+--)\b",
        r"\bshutil\.rmtree\b",
        r"\bos\.(remove|unlink|rmdir)\b",
        r"\.unlink\s*\(",
        r"\.rmdir\s*\(",
    ]
]
NETWORK_PATTERNS = [
    re.compile(pattern, re.I)
    for pattern in [
        r"\b(curl|wget|ssh|scp|ftp|telnet|nc|ncat)\b",
        r"\b(npm\s+install|npm\s+publish|pip\s+install)\b",
        r"\b(socket|urllib|requests|httpx|aiohttp|fetch)\b",
        r"https?://",
    ]
]
SENSITIVE_ENV_RE = re.compile(r"(api[_-]?key|secret|token|password)", re.I)
DIFF_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_lines>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_lines>\d+))? @@"
)
GIT_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
JS_IDENTIFIER_RE = r"[A-Za-z_$][\w$]*"
JS_CLASS_RE = re.compile(rf"^\s*(?:export\s+default\s+|export\s+)?class\s+({JS_IDENTIFIER_RE})\b")
JS_FUNCTION_RE = re.compile(rf"^\s*(?:export\s+)?(?:async\s+)?function\s+({JS_IDENTIFIER_RE})\s*\(")
JS_ARROW_RE = re.compile(
    rf"^\s*(?:export\s+)?(?:const|let|var)\s+({JS_IDENTIFIER_RE})\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|{JS_IDENTIFIER_RE})\s*=>"
)
JS_FUNCTION_EXPR_RE = re.compile(
    rf"^\s*(?:export\s+)?(?:const|let|var)\s+({JS_IDENTIFIER_RE})\s*(?::[^=]+)?=\s*(?:async\s+)?function\b"
)
JS_METHOD_RE = re.compile(
    rf"^\s*(?:(?:public|private|protected|static|async|readonly|override)\s+)*({JS_IDENTIFIER_RE})\s*\([^)]*\)\s*(?::[^\{{]+)?\{{?"
)
JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "constructor"}
COMMAND_TARGET_VALUE_FLAGS = {"-k", "-m", "--grep", "--testnamepattern", "--test-name-pattern"}
COMMAND_TARGET_STOPWORDS = {
    "build",
    "check",
    "compile",
    "lint",
    "node",
    "npm",
    "pytest",
    "python",
    "run",
    "test",
    "tests",
    "typecheck",
    "unittest",
}
VALIDATION_COMMAND_KINDS = {"test", "build", "typecheck", "lint", "check"}


class SandboxError(ValueError):
    pass


class _SandboxFileTooLarge(OSError):
    pass


class SandboxRunner:
    def __init__(
        self,
        settings: Settings,
        execution_backend: SandboxExecutionBackend | None = None,
    ) -> None:
        self._settings = settings
        self._execution_backend = execution_backend or build_sandbox_execution_backend(settings)

    def run(self, request: RepoChecksRunRequest) -> SandboxRun:
        repo_path = self._resolve_repo(request.repo_ref)
        self._require_supported_network_policy(request.network_policy)
        source_fingerprint = _workspace_fingerprint(repo_path)
        parsed_commands = [
            self._parse_command(command, repo_path, request.network_policy)
            for command in request.commands
        ]
        if _workspace_fingerprint(repo_path) != source_fingerprint:
            raise SandboxError("source workspace changed during sandbox command policy inspection")

        if isinstance(self._execution_backend, SandboxBatchExecutionBackend):
            inspection_report = self._batch_inspection_report(
                repo_path,
                source_fingerprint=source_fingerprint,
            )
            try:
                batch = self._execution_backend.execute_batch(
                    parsed_commands,
                    cwd=repo_path,
                    source_cwd=repo_path,
                    env=self._sandbox_env(request.network_policy),
                    timeout=self._settings.max_command_seconds,
                    output_caps=self._settings.max_output_chars,
                )
            except SandboxExecutionError as exc:
                raise SandboxError(str(exc)) from exc
            if len(batch.executions) != len(parsed_commands):
                raise SandboxError("sandbox batch backend returned an unexpected result count")
            if batch.pre_snapshot_fingerprint != source_fingerprint:
                raise SandboxError(
                    "sandbox execution snapshot does not match the requested source workspace"
                )
            completed_commands = list(batch.executions)
            artifacts = sorted(set(batch.artifacts))
        else:
            with _ephemeral_working_copy(repo_path, source_fingerprint) as working_copy:
                before_artifacts = self._artifact_snapshot(working_copy)
                inspection_report = self._inspection_report(
                    working_copy,
                    source_repo_path=repo_path,
                )
                completed_commands = []
                for args in parsed_commands:
                    try:
                        completed_commands.append(
                            self._execution_backend.execute(
                                args,
                                cwd=working_copy,
                                source_cwd=repo_path,
                                env=self._sandbox_env(request.network_policy),
                                timeout=self._settings.max_command_seconds,
                                output_caps=self._settings.max_output_chars,
                            )
                        )
                    except SandboxExecutionError as exc:
                        raise SandboxError(str(exc)) from exc
                artifacts = self._changed_artifacts(working_copy, before_artifacts)

        if _workspace_fingerprint(repo_path) != source_fingerprint:
            raise SandboxError("source workspace changed during the isolated sandbox run")

        exit_codes = [item.returncode for item in completed_commands]
        stdout = [
            bounded(item.stdout, self._settings.max_output_chars) for item in completed_commands
        ]
        stderr = [
            bounded(item.stderr, self._settings.max_output_chars) for item in completed_commands
        ]

        git_report = inspection_report.get("git")
        git_failed = (
            isinstance(git_report, dict)
            and git_report.get("is_repository") is True
            and bool(git_report.get("errors"))
        )
        return SandboxRun(
            repo_ref=str(repo_path),
            commands=request.commands,
            exit_codes=exit_codes,
            stdout=stdout,
            stderr=stderr,
            artifacts=artifacts,
            evidence=self._evidence_from_run(
                request, parsed_commands, exit_codes, stdout, stderr, inspection_report
            ),
            network_policy=request.network_policy,
            verdict=VerdictStatus.SUPPORTED
            if exit_codes and all(code == 0 for code in exit_codes) and not git_failed
            else VerdictStatus.CONTRADICTED,
        )

    def _require_supported_network_policy(self, network_policy: str) -> None:
        if network_policy != "deny":
            raise SandboxError(
                "allowlisted network policy requires an exact destination allowlist "
                "and an approved execution grant; allowlisted egress is not enabled"
            )

    def _resolve_repo(self, repo_ref: str) -> Path:
        configured_allowed = Path(os.path.abspath(self._settings.allowed_workspace))
        try:
            _require_real_directory(configured_allowed, label="configured workspace")
        except OSError as exc:
            raise SandboxError("configured workspace is unavailable") from exc
        allowed = configured_allowed.resolve(strict=True)
        candidate = Path(os.path.abspath(allowed / repo_ref))
        try:
            candidate.relative_to(allowed)
        except ValueError as exc:
            raise SandboxError("repo_ref escapes the configured workspace") from exc
        try:
            _guard_existing_path(allowed, candidate, expected="directory")
        except FileNotFoundError:
            raise SandboxError("repo_ref must point to an existing directory") from None
        return candidate.resolve(strict=True)

    def _parse_command(
        self,
        command: str,
        repo_path: Path,
        network_policy: str,
    ) -> list[str]:
        args = shlex.split(command, posix=os.name != "nt")
        if not args:
            raise SandboxError("command cannot be empty")
        executable_path = Path(args[0])
        if executable_path.name != args[0]:
            raise SandboxError("command executable must be referenced by name, not by path")
        executable = executable_path.name.lower()
        if executable.endswith(".exe"):
            executable = executable[:-4]
        if executable not in ALLOWED_EXECUTABLES:
            raise SandboxError(f"command executable '{args[0]}' is not allowlisted")
        policy_text = "\n".join([command, *self._script_policy_inputs(args, repo_path)])
        self._enforce_command_policy(policy_text, network_policy)
        return args

    def _script_policy_inputs(self, args: list[str], repo_path: Path) -> list[str]:
        inputs: list[str] = []
        for raw_arg in args[1:]:
            arg = raw_arg.strip("\"'")
            if arg.startswith("-") or not arg.lower().endswith((".py", ".js", ".mjs", ".cjs")):
                continue
            script_path = Path(os.path.abspath(repo_path / arg))
            try:
                script_path.relative_to(repo_path)
            except ValueError as exc:
                raise SandboxError("command script path escapes the repository workspace") from exc
            try:
                inputs.append(
                    _read_text_no_follow(
                        repo_path,
                        script_path,
                        max_bytes=100_000,
                        errors="ignore",
                    )
                )
            except FileNotFoundError:
                continue
            except _SandboxFileTooLarge as exc:
                raise SandboxError(
                    "command script exceeds the policy inspection size limit"
                ) from exc
        return inputs

    def _enforce_command_policy(self, policy_text: str, network_policy: str) -> None:
        for pattern in DESTRUCTIVE_PATTERNS:
            if pattern.search(policy_text):
                raise SandboxError("command is blocked by destructive-operation policy")
        if network_policy == "deny":
            for pattern in NETWORK_PATTERNS:
                if pattern.search(policy_text):
                    raise SandboxError("command is blocked because sandbox network policy is deny")

    def _sandbox_env(self, network_policy: str) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if not SENSITIVE_ENV_RE.search(key)}
        env["HALLU_DEFENSE_NETWORK_POLICY"] = network_policy
        return env

    def _artifact_snapshot(self, repo_path: Path) -> dict[str, tuple[int, str]]:
        snapshot: dict[str, tuple[int, str]] = {}
        total_bytes = 0
        path_budget = [0, 0]
        for artifact_dir in ARTIFACT_DIRS:
            root = repo_path / artifact_dir
            try:
                root_info = os.lstat(root)
            except FileNotFoundError:
                continue
            if _stat_is_link_or_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
                raise SandboxError(
                    f"sandbox artifact directory {artifact_dir!r} must be a real directory"
                )
            for path, path_info in _walk_regular_files_no_follow(
                repo_path,
                root,
                reject_links=True,
                path_budget=path_budget,
            ):
                if len(snapshot) >= MAX_ARTIFACT_FILES:
                    raise SandboxError("sandbox artifact inventory exceeded its safety limit")
                total_bytes += path_info.st_size
                if total_bytes > MAX_SANDBOX_WORKSPACE_BYTES:
                    raise SandboxError("sandbox artifact bytes exceeded their safety limit")
                snapshot[path.relative_to(repo_path).as_posix()] = (
                    path_info.st_size,
                    _file_content_digest_no_follow(
                        repo_path,
                        path,
                        expected=path_info,
                        max_bytes=MAX_SANDBOX_WORKSPACE_BYTES,
                    ),
                )
        return snapshot

    def _changed_artifacts(
        self,
        repo_path: Path,
        before: dict[str, tuple[int, str]],
    ) -> list[str]:
        after = self._artifact_snapshot(repo_path)
        return sorted(path for path, signature in after.items() if before.get(path) != signature)

    def _inspection_report(
        self,
        repo_path: Path,
        *,
        source_repo_path: Path,
    ) -> dict[str, object]:
        static_report = self._static_inspection(repo_path)
        return {
            "schema_version": "sandbox_inspection.v1",
            "git": self._git_inspection(
                repo_path,
                static_report,
                source_repo_path=source_repo_path,
            ),
            "static": static_report,
        }

    def _batch_inspection_report(
        self,
        source_repo_path: Path,
        *,
        source_fingerprint: str,
    ) -> dict[str, object]:
        """Inspect only snapshots whose content is bound to the command snapshot."""

        with _ephemeral_working_copy(
            source_repo_path,
            source_fingerprint,
        ) as inspection_snapshot:
            static_report = self._static_inspection(inspection_snapshot)
            git_path = inspection_snapshot / ".git"
            try:
                git_info = os.lstat(git_path)
            except FileNotFoundError:
                git_report = _no_git_inspection()
            else:
                if _stat_is_link_or_reparse(git_info) or not stat.S_ISDIR(git_info.st_mode):
                    raise SandboxError(
                        "repository .git metadata must be a real in-repository directory"
                    )
                try:
                    inspector = self._run_isolated_git_inspector(
                        source_repo_path,
                        source_repo_path=source_repo_path,
                        expected_source_fingerprint=source_fingerprint,
                    )
                except SandboxError as exc:
                    git_report = _failed_git_inspection(str(exc))
                else:
                    git_report = self._git_report_from_inspector(
                        static_report,
                        inspector,
                    )
        return {
            "schema_version": "sandbox_inspection.v1",
            "git": git_report,
            "static": static_report,
        }

    def _evidence_from_run(
        self,
        request: RepoChecksRunRequest,
        parsed_commands: list[list[str]],
        exit_codes: list[int],
        stdout: list[str],
        stderr: list[str],
        inspection_report: dict[str, object],
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
        retrieved_at = datetime.now(timezone.utc)
        for index, command in enumerate(request.commands):
            exit_code = exit_codes[index] if index < len(exit_codes) else -1
            stdout_text = stdout[index] if index < len(stdout) else ""
            stderr_text = stderr[index] if index < len(stderr) else ""
            args = parsed_commands[index] if index < len(parsed_commands) else []
            evidence.append(
                Evidence(
                    evidence_id=f"ev_sandbox_cmd_{index + 1:03d}",
                    kind=EvidenceKind.COMMAND_OUTPUT,
                    source_ref=f"sandbox://command/{index + 1}",
                    content="\n".join(
                        [
                            f"command: {command}",
                            f"exit_code: {exit_code}",
                            "stdout:",
                            stdout_text.rstrip(),
                            "stderr:",
                            stderr_text.rstrip(),
                        ]
                    ),
                    structured_content={
                        "command": command,
                        **self._command_metadata(command, args),
                        "exit_code": exit_code,
                        "stdout": stdout_text,
                        "stderr": stderr_text,
                        "network_policy": request.network_policy,
                    },
                    authority=Authority.INTERNAL,
                    freshness=Freshness(
                        retrieved_at=retrieved_at,
                        staleness_class=StalenessClass.FRESH,
                    ),
                )
            )
        evidence.append(
            Evidence(
                evidence_id="ev_sandbox_inspection",
                kind=EvidenceKind.REPO_FILE,
                source_ref=INSPECTION_EVIDENCE_SOURCE,
                content=json.dumps(inspection_report, sort_keys=True),
                structured_content=inspection_report,
                authority=Authority.INTERNAL,
                freshness=Freshness(
                    retrieved_at=retrieved_at,
                    staleness_class=StalenessClass.FRESH,
                ),
            )
        )
        return evidence

    def _command_metadata(self, command: str, args: list[str]) -> dict[str, object]:
        executable = self._normalized_executable(args[0]) if args else ""
        target_args = self._command_target_args(args)
        return {
            "schema_version": "sandbox_command.v1",
            "argv": args,
            "executable": executable,
            "command_kind": self._command_kind(args),
            "command_target_args": target_args,
            "command_target_tokens": self._target_tokens([command, *target_args]),
            "is_targeted": bool(target_args),
        }

    def _command_kind(self, args: list[str]) -> str:
        if not args:
            return "unknown"
        executable = self._normalized_executable(args[0])
        lowered = [arg.lower() for arg in args]
        if executable == "pytest":
            return "test"
        if executable == "python":
            if len(lowered) > 2 and lowered[1] == "-m" and lowered[2] in {"pytest", "unittest"}:
                return "test"
            return "script"
        if executable == "npm":
            return self._npm_command_kind(lowered[1:])
        if executable == "node":
            return "script"
        return "unknown"

    def _npm_command_kind(self, args: list[str]) -> str:
        words = [arg for arg in args if arg != "--"]
        if not words:
            return "script"
        script = words[1] if words[0] == "run" and len(words) > 1 else words[0]
        if script == "test" or "test" in script:
            return "test"
        if any(value in script for value in ("build", "compile")):
            return "build"
        if any(value in script for value in ("typecheck", "tsc")):
            return "typecheck"
        if any(value in script for value in ("lint", "ruff")):
            return "lint"
        if "check" in script:
            return "check"
        return "script"

    def _command_target_args(self, args: list[str]) -> list[str]:
        if len(args) <= 1:
            return []
        target_args: list[str] = []
        include_next = False
        after_double_dash = False
        skip_indexes = self._command_word_indexes(args)
        for index, raw_arg in enumerate(args[1:], start=1):
            arg = raw_arg.strip("\"'")
            lowered = arg.lower()
            if index in skip_indexes:
                continue
            if include_next:
                if arg:
                    target_args.append(arg)
                include_next = False
                continue
            if arg == "--":
                after_double_dash = True
                continue
            if lowered in COMMAND_TARGET_VALUE_FLAGS:
                include_next = True
                continue
            if arg.startswith("-") and not after_double_dash:
                continue
            if after_double_dash or self._is_target_arg(arg):
                target_args.append(arg)
        return target_args

    def _command_word_indexes(self, args: list[str]) -> set[int]:
        lowered = [arg.lower() for arg in args]
        skip_indexes = {0}
        executable = self._normalized_executable(args[0]) if args else ""
        if (
            executable == "python"
            and len(lowered) > 2
            and lowered[1] == "-m"
            and lowered[2] in {"pytest", "unittest"}
        ):
            skip_indexes.update({1, 2})
        if executable == "npm" and len(lowered) > 1:
            skip_indexes.add(1)
            if lowered[1] == "run" and len(lowered) > 2:
                if lowered[2] in VALIDATION_COMMAND_KINDS:
                    skip_indexes.add(2)
        return skip_indexes

    def _is_target_arg(self, arg: str) -> bool:
        lowered = arg.lower()
        if lowered in COMMAND_TARGET_STOPWORDS:
            return False
        if lowered in VALIDATION_COMMAND_KINDS:
            return False
        return bool(self._target_tokens([arg]))

    def _target_tokens(self, values: list[str]) -> list[str]:
        tokens: set[str] = set()
        for value in values:
            for token in tokenize(value):
                tokens.add(token)
                tokens.update(part for part in re.split(r"[./:=_-]+", token) if len(part) > 2)
        tokens.difference_update(COMMAND_TARGET_STOPWORDS)
        tokens.difference_update(VALIDATION_COMMAND_KINDS)
        return sorted(tokens)

    def _normalized_executable(self, raw_executable: str) -> str:
        executable = Path(raw_executable).name.lower()
        return executable[:-4] if executable.endswith(".exe") else executable

    def _git_inspection(
        self,
        repo_path: Path,
        static_report: dict[str, object],
        *,
        source_repo_path: Path,
    ) -> dict[str, object]:
        git_path = repo_path / ".git"
        try:
            git_info = os.lstat(git_path)
        except FileNotFoundError:
            return _no_git_inspection()
        if _stat_is_link_or_reparse(git_info) or not stat.S_ISDIR(git_info.st_mode):
            raise SandboxError("repository .git metadata must be a real in-repository directory")

        try:
            inspector = self._run_isolated_git_inspector(
                repo_path,
                source_repo_path=source_repo_path,
            )
        except SandboxError as exc:
            return _failed_git_inspection(str(exc))
        return self._git_report_from_inspector(static_report, inspector)

    def _git_report_from_inspector(
        self,
        static_report: dict[str, object],
        inspector: dict[str, object],
    ) -> dict[str, object]:
        errors = cast(list[dict[str, str]], inspector["errors"])
        diagnostics = {
            "inspection_fingerprints": {
                field_name: inspector[field_name]
                for field_name in (
                    "workspace_fingerprint_before",
                    "workspace_fingerprint_after",
                    "git_control_fingerprint_before",
                    "git_control_fingerprint_after",
                )
            },
            "config_keys": cast(list[str], inspector["config_keys"]),
            "index_flags": cast(dict[str, list[str]], inspector["index_flags"]),
            "errors": errors,
        }
        if errors:
            return {
                "is_repository": True,
                "status": [],
                "diff_files": [],
                "diff_stat": "",
                "changed_ranges": [],
                "changed_lines": [],
                "changed_symbols": [],
                **diagnostics,
            }

        status = "\n".join(cast(list[str], inspector["status"]))
        unstaged_files = cast(list[str], inspector["unstaged_files"])
        staged_files = cast(list[str], inspector["staged_files"])
        diff_stat = cast(str, inspector["unstaged_diff_stat"])
        cached_diff_stat = cast(str, inspector["staged_diff_stat"])
        unstaged_patch = cast(str, inspector["unstaged_patch"])
        staged_patch = cast(str, inspector["staged_patch"])

        diff_files = sorted({*unstaged_files, *staged_files})
        diff_stat_parts = [part for part in [diff_stat.strip(), cached_diff_stat.strip()] if part]
        changed_ranges = [
            *self._changed_ranges_from_patch(
                unstaged_patch,
                "working_tree",
                expected_paths=set(unstaged_files),
            ),
            *self._changed_ranges_from_patch(
                staged_patch,
                "index",
                expected_paths=set(staged_files),
            ),
        ]
        changed_lines = [
            *self._changed_lines_from_patch(
                unstaged_patch,
                "working_tree",
                expected_paths=set(unstaged_files),
            ),
            *self._changed_lines_from_patch(
                staged_patch,
                "index",
                expected_paths=set(staged_files),
            ),
        ]

        return {
            "is_repository": True,
            "status": self._nonempty_lines(status),
            "diff_files": diff_files,
            "diff_stat": "\n".join(diff_stat_parts),
            "changed_ranges": changed_ranges,
            "changed_lines": changed_lines,
            "changed_symbols": self._changed_symbols(static_report, changed_ranges),
            **diagnostics,
        }

    def _run_isolated_git_inspector(
        self,
        repo_path: Path,
        *,
        source_repo_path: Path,
        expected_source_fingerprint: str | None = None,
    ) -> dict[str, object]:
        inspector_path = getattr(
            self._execution_backend,
            "git_inspector_path",
            SANDBOX_GIT_INSPECTOR_PATH,
        )
        inspector_python = getattr(
            self._execution_backend,
            "git_inspector_python",
            "python",
        )
        per_command_timeout = max(
            0.25,
            min(2.0, self._settings.max_command_seconds / 8),
        )
        per_output_bytes = max(
            1_024,
            min(100_000, self._settings.max_output_chars // 8),
        )
        control_output_chars = min(
            MAX_GIT_INSPECTOR_CONTROL_CHARS,
            max(MIN_GIT_INSPECTOR_CONTROL_CHARS, per_output_bytes * 16),
        )
        inspector_env = {
            "CI": "true",
            "HALLU_DEFENSE_NETWORK_POLICY": "deny",
            "PYTHONUNBUFFERED": "1",
        }
        host_environment = getattr(
            self._execution_backend,
            "git_inspector_environment",
            {},
        )
        if not isinstance(host_environment, dict) or any(
            key not in HOST_GIT_INSPECTOR_ENV_KEYS or not isinstance(value, str) or "\x00" in value
            for key, value in host_environment.items()
        ):
            raise SandboxError("isolated Git inspector environment is invalid")
        inspector_env.update(cast(dict[str, str], host_environment))
        inspector_command = [
            str(inspector_python),
            str(inspector_path),
            f"{per_command_timeout:.6f}",
            str(per_output_bytes),
        ]
        try:
            if expected_source_fingerprint is not None:
                if not isinstance(
                    self._execution_backend,
                    SandboxBatchExecutionBackend,
                ):
                    raise SandboxError("snapshot-bound Git inspection requires a batch backend")
                batch = self._execution_backend.execute_batch(
                    [inspector_command],
                    cwd=repo_path,
                    source_cwd=source_repo_path,
                    env=inspector_env,
                    timeout=self._settings.max_command_seconds,
                    output_caps=control_output_chars,
                )
                if (
                    batch.pre_snapshot_fingerprint != expected_source_fingerprint
                    or batch.post_snapshot_fingerprint != expected_source_fingerprint
                    or len(batch.executions) != 1
                    or batch.artifacts
                ):
                    raise SandboxError(
                        "Git inspection snapshot does not match the requested source workspace"
                    )
                completed = batch.executions[0]
            else:
                completed = self._execution_backend.execute(
                    inspector_command,
                    cwd=repo_path,
                    source_cwd=source_repo_path,
                    env=inspector_env,
                    timeout=self._settings.max_command_seconds,
                    output_caps=control_output_chars,
                )
        except SandboxExecutionError as exc:
            detail = bounded(str(exc), MAX_GIT_ERROR_CHARS)
            raise SandboxError(
                f"isolated Git inspector could not execute: {detail}"
            ) from exc
        if completed.timed_out:
            raise SandboxError("isolated Git inspector timed out")
        if completed.returncode != 0:
            raise SandboxError("isolated Git inspector failed")
        try:
            decoded = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError("isolated Git inspector returned invalid JSON") from exc
        return _validate_git_inspection_payload(decoded)

    def _static_inspection(self, repo_path: Path) -> dict[str, object]:
        symbols: list[dict[str, object]] = []
        javascript_symbols: list[dict[str, object]] = []
        parse_errors: list[dict[str, str]] = []
        inspectable_files = self._iter_inspectable_files(repo_path)

        for path in [item for item in inspectable_files if item.suffix.lower() == ".py"]:
            rel_path = path.relative_to(repo_path).as_posix()
            try:
                content = _read_text_no_follow(
                    repo_path,
                    path,
                    max_bytes=MAX_INSPECTION_BYTES,
                )
                tree = ast.parse(content, filename=rel_path)
            except _SandboxFileTooLarge:
                parse_errors.append(
                    {"path": rel_path, "error": "file too large for static inspection"}
                )
                continue
            except (OSError, SyntaxError, UnicodeDecodeError) as exc:
                parse_errors.append({"path": rel_path, "error": f"{type(exc).__name__}: {exc}"})
                continue

            visitor = _PythonSymbolVisitor(rel_path)
            visitor.visit(tree)
            remaining = MAX_INSPECTION_SYMBOLS - len(symbols)
            if remaining <= 0:
                break
            symbols.extend(visitor.symbols[:remaining])

        for path in [
            item for item in inspectable_files if item.suffix.lower() in JAVASCRIPT_SUFFIXES
        ]:
            remaining = MAX_INSPECTION_SYMBOLS - len(javascript_symbols)
            if remaining <= 0:
                break
            rel_path = path.relative_to(repo_path).as_posix()
            try:
                content = _read_text_no_follow(
                    repo_path,
                    path,
                    max_bytes=MAX_INSPECTION_BYTES,
                    errors="ignore",
                )
            except _SandboxFileTooLarge:
                parse_errors.append(
                    {"path": rel_path, "error": "file too large for static inspection"}
                )
                continue
            except OSError as exc:
                parse_errors.append({"path": rel_path, "error": f"{type(exc).__name__}: {exc}"})
                continue
            javascript_symbols.extend(self._javascript_symbols(rel_path, content)[:remaining])

        return {
            "files": [
                path.relative_to(repo_path).as_posix()
                for path in inspectable_files[:MAX_INSPECTION_FILES]
            ],
            "python_symbols": symbols,
            "javascript_symbols": javascript_symbols,
            "parse_errors": parse_errors,
            "truncated": len(inspectable_files) > MAX_INSPECTION_FILES
            or len(symbols) >= MAX_INSPECTION_SYMBOLS
            or len(javascript_symbols) >= MAX_INSPECTION_SYMBOLS,
        }

    def _javascript_symbols(self, rel_path: str, content: str) -> list[dict[str, object]]:
        language = (
            "typescript" if Path(rel_path).suffix.lower() in {".ts", ".tsx"} else "javascript"
        )
        symbols: list[dict[str, object]] = []
        brace_depth = 0
        current_class: str | None = None
        class_start_depth = 0

        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "*", "/*")):
                continue

            if current_class is not None:
                method_match = JS_METHOD_RE.match(line)
                if method_match is not None:
                    method_name = method_match.group(1)
                    if method_name not in JS_KEYWORDS:
                        symbols.append(
                            self._symbol_record(
                                rel_path,
                                "method",
                                method_name,
                                lineno,
                                f"{current_class}.{method_name}",
                                language,
                            )
                        )

            class_match = JS_CLASS_RE.match(line)
            if class_match is not None:
                class_name = class_match.group(1)
                symbols.append(
                    self._symbol_record(rel_path, "class", class_name, lineno, class_name, language)
                )
                current_class = class_name
                class_start_depth = brace_depth

            for regex, kind in [
                (JS_FUNCTION_RE, "function"),
                (JS_ARROW_RE, "arrow_function"),
                (JS_FUNCTION_EXPR_RE, "function"),
            ]:
                match = regex.match(line)
                if match is None:
                    continue
                name = match.group(1)
                symbols.append(self._symbol_record(rel_path, kind, name, lineno, name, language))
                break

            brace_depth += line.count("{") - line.count("}")
            if current_class is not None and brace_depth <= class_start_depth:
                current_class = None

        return symbols

    def _symbol_record(
        self,
        path: str,
        kind: str,
        name: str,
        lineno: int,
        qualified_name: str,
        language: str,
    ) -> dict[str, object]:
        return {
            "path": path,
            "kind": kind,
            "name": name,
            "qualified_name": qualified_name,
            "lineno": lineno,
            "language": language,
        }

    def _iter_inspectable_files(self, repo_path: Path) -> list[Path]:
        return sorted(
            path
            for path, _path_info in _walk_regular_files_no_follow(
                repo_path,
                repo_path,
                reject_links=False,
                skip_directories=INSPECTION_SKIP_DIRS,
            )
            if path.suffix.lower() in INSPECTION_FILE_SUFFIXES
        )

    def _nonempty_lines(self, value: str) -> list[str]:
        return [line for line in value.splitlines() if line.strip()]

    def _changed_ranges_from_patch(
        self,
        patch_text: str,
        source: str,
        *,
        expected_paths: set[str],
    ) -> list[dict[str, object]]:
        ranges: list[dict[str, object]] = []
        current_path: str | None = None
        old_path: str | None = None
        in_hunk = False
        self._require_canonical_patch_text(patch_text)
        for line in patch_text.splitlines():
            if line.startswith("diff --git "):
                self._require_canonical_diff_header(line)
                current_path = None
                old_path = None
                in_hunk = False
                continue
            if not in_hunk and line.startswith("--- "):
                old_path = self._canonical_patch_path(
                    line[4:],
                    prefix="a/",
                    expected_paths=expected_paths,
                )
                continue
            if not in_hunk and line.startswith("+++ "):
                new_path = self._canonical_patch_path(
                    line[4:],
                    prefix="b/",
                    expected_paths=expected_paths,
                )
                current_path = new_path if new_path is not None else old_path
                if current_path is None:
                    raise SandboxError("canonical Git patch is missing a file path")
                continue
            if current_path is None:
                continue
            hunk_match = DIFF_HUNK_RE.match(line)
            if hunk_match is None:
                continue
            in_hunk = True
            old_lines = int(hunk_match.group("old_lines") or "1")
            new_lines = int(hunk_match.group("new_lines") or "1")
            ranges.append(
                {
                    "path": current_path,
                    "old_start": int(hunk_match.group("old_start")),
                    "old_lines": old_lines,
                    "new_start": int(hunk_match.group("new_start")),
                    "new_lines": new_lines,
                    "source": source,
                }
            )
        return ranges

    def _changed_lines_from_patch(
        self,
        patch_text: str,
        source: str,
        *,
        expected_paths: set[str],
    ) -> list[dict[str, object]]:
        lines: list[dict[str, object]] = []
        current_path: str | None = None
        old_path: str | None = None
        old_lineno = 0
        new_lineno = 0
        in_hunk = False
        self._require_canonical_patch_text(patch_text)
        for line in patch_text.splitlines():
            if line.startswith("diff --git "):
                self._require_canonical_diff_header(line)
                current_path = None
                old_path = None
                in_hunk = False
                continue
            if not in_hunk and line.startswith("--- "):
                old_path = self._canonical_patch_path(
                    line[4:],
                    prefix="a/",
                    expected_paths=expected_paths,
                )
                continue
            if not in_hunk and line.startswith("+++ "):
                new_path = self._canonical_patch_path(
                    line[4:],
                    prefix="b/",
                    expected_paths=expected_paths,
                )
                current_path = new_path if new_path is not None else old_path
                if current_path is None:
                    raise SandboxError("canonical Git patch is missing a file path")
                continue
            if current_path is None:
                continue
            hunk_match = DIFF_HUNK_RE.match(line)
            if hunk_match is not None:
                old_lineno = int(hunk_match.group("old_start"))
                new_lineno = int(hunk_match.group("new_start"))
                in_hunk = True
                continue
            if not in_hunk or line.startswith("\\"):
                continue
            if line.startswith("+") and not line.startswith("+++"):
                lines.append(
                    {
                        "path": current_path,
                        "lineno": new_lineno,
                        "kind": "added",
                        "text": bounded(line[1:], MAX_CHANGED_LINE_CHARS),
                        "source": source,
                    }
                )
                new_lineno += 1
            elif line.startswith("-") and not line.startswith("---"):
                lines.append(
                    {
                        "path": current_path,
                        "old_lineno": old_lineno,
                        "kind": "removed",
                        "text": bounded(line[1:], MAX_CHANGED_LINE_CHARS),
                        "source": source,
                    }
                )
                old_lineno += 1
            else:
                old_lineno += 1
                new_lineno += 1
            if len(lines) >= MAX_CHANGED_LINES:
                break
        return lines

    def _require_canonical_patch_text(self, patch_text: str) -> None:
        if "\x1b" in patch_text or "\x00" in patch_text:
            raise SandboxError("canonical Git patch contains control sequences")

    def _require_canonical_diff_header(self, line: str) -> None:
        if not line.startswith("diff --git a/") or " b/" not in line:
            raise SandboxError("canonical Git patch has an invalid diff header")

    def _canonical_patch_path(
        self,
        raw_path: str,
        *,
        prefix: str,
        expected_paths: set[str],
    ) -> str | None:
        if "\t" in raw_path:
            raw_path, suffix = raw_path.split("\t", 1)
            if suffix:
                raise SandboxError("canonical Git patch path contains an unexpected suffix")
        if raw_path == "/dev/null":
            return None
        if not raw_path.startswith(prefix):
            raise SandboxError("canonical Git patch has a non-canonical path prefix")
        path = raw_path[len(prefix) :]
        if path not in expected_paths:
            raise SandboxError(
                "canonical Git patch path does not match the NUL-delimited inventory"
            )
        return path

    def _changed_symbols(
        self,
        static_report: dict[str, object],
        changed_ranges: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        def symbol_lineno(item: dict[str, object]) -> int:
            lineno = item.get("lineno")
            return lineno if isinstance(lineno, int) else 0

        symbols_by_path: dict[str, list[dict[str, object]]] = {}
        for raw_symbol in [
            *self._raw_symbols(static_report.get("python_symbols")),
            *self._raw_symbols(static_report.get("javascript_symbols")),
        ]:
            path = raw_symbol.get("path")
            lineno = raw_symbol.get("lineno")
            if not isinstance(path, str) or not isinstance(lineno, int):
                continue
            symbols_by_path.setdefault(path, []).append(raw_symbol)

        for symbols in symbols_by_path.values():
            symbols.sort(key=symbol_lineno)

        changed_symbols: dict[tuple[str, str], dict[str, object]] = {}
        for changed_range in changed_ranges:
            path = changed_range.get("path")
            new_start = changed_range.get("new_start")
            new_lines = changed_range.get("new_lines")
            if (
                not isinstance(path, str)
                or not isinstance(new_start, int)
                or not isinstance(new_lines, int)
            ):
                continue
            symbols = symbols_by_path.get(path, [])
            if not symbols:
                continue
            new_end = new_start + max(new_lines - 1, 0)
            symbol = self._nearest_changed_symbol(symbols, new_start, new_end)
            if symbol is None:
                continue
            qualified_name = symbol.get("qualified_name")
            if not isinstance(qualified_name, str):
                continue
            key = (path, qualified_name)
            existing = changed_symbols.get(key)
            if existing is None:
                changed_symbols[key] = {
                    **symbol,
                    "changed_ranges": [changed_range],
                }
            else:
                ranges = existing.get("changed_ranges")
                if isinstance(ranges, list):
                    ranges.append(changed_range)
        return sorted(
            changed_symbols.values(),
            key=lambda item: (str(item.get("path", "")), str(item.get("qualified_name", ""))),
        )

    def _nearest_changed_symbol(
        self,
        symbols: list[dict[str, object]],
        new_start: int,
        new_end: int,
    ) -> dict[str, object] | None:
        preceding: dict[str, object] | None = None
        for symbol in symbols:
            lineno = symbol.get("lineno")
            if not isinstance(lineno, int):
                continue
            if new_start <= lineno <= new_end:
                return symbol
            if lineno <= new_start:
                preceding = symbol
            if lineno > new_end:
                break
        return preceding

    def _raw_symbols(self, value: object) -> list[dict[str, object]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]


def _no_git_inspection() -> dict[str, object]:
    return {
        "is_repository": False,
        "status": [],
        "diff_files": [],
        "diff_stat": "",
        "changed_ranges": [],
        "changed_lines": [],
        "changed_symbols": [],
        "inspection_fingerprints": {},
        "config_keys": [],
        "index_flags": {
            "assume_unchanged": [],
            "skip_worktree": [],
            "fsmonitor_valid": [],
        },
        "errors": [],
    }


def _failed_git_inspection(error_type: str) -> dict[str, object]:
    return {
        "is_repository": True,
        "status": [],
        "diff_files": [],
        "diff_stat": "",
        "changed_ranges": [],
        "changed_lines": [],
        "changed_symbols": [],
        "inspection_fingerprints": {},
        "config_keys": [],
        "index_flags": {
            "assume_unchanged": [],
            "skip_worktree": [],
            "fsmonitor_valid": [],
        },
        "errors": [
            {
                "command": "isolated_git_inspector",
                "error": bounded(error_type, MAX_GIT_ERROR_CHARS),
            }
        ],
    }


def _validate_git_inspection_payload(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SandboxError("isolated Git inspector response must be an object")
    expected_keys = {
        "schema_version",
        "is_repository",
        "workspace_fingerprint_before",
        "workspace_fingerprint_after",
        "git_control_fingerprint_before",
        "git_control_fingerprint_after",
        "config_keys",
        "index_flags",
        "status",
        "unstaged_files",
        "staged_files",
        "unstaged_diff_stat",
        "staged_diff_stat",
        "unstaged_patch",
        "staged_patch",
        "errors",
    }
    if set(value) != expected_keys:
        raise SandboxError("isolated Git inspector response has an invalid schema")
    if value.get("schema_version") != SANDBOX_GIT_INSPECTION_SCHEMA:
        raise SandboxError("isolated Git inspector schema version is unsupported")
    if value.get("is_repository") is not True:
        raise SandboxError("isolated Git inspector did not confirm the repository")

    normalized: dict[str, object] = {
        "schema_version": SANDBOX_GIT_INSPECTION_SCHEMA,
        "is_repository": True,
    }
    for field_name in (
        "workspace_fingerprint_before",
        "workspace_fingerprint_after",
        "git_control_fingerprint_before",
        "git_control_fingerprint_after",
    ):
        fingerprint = value.get(field_name)
        if not isinstance(fingerprint, str) or GIT_FINGERPRINT_RE.fullmatch(fingerprint) is None:
            raise SandboxError(f"isolated Git inspector returned invalid {field_name}")
        normalized[field_name] = fingerprint

    raw_config_keys = value.get("config_keys")
    if (
        not isinstance(raw_config_keys, list)
        or len(raw_config_keys) > MAX_GIT_LIST_ENTRIES
        or not all(
            isinstance(item, str)
            and item == item.strip().lower()
            and 0 < len(item) <= 4_096
            and "\x00" not in item
            and "\r" not in item
            and "\n" not in item
            for item in raw_config_keys
        )
        or raw_config_keys != sorted(set(raw_config_keys))
    ):
        raise SandboxError("isolated Git inspector returned invalid config keys")
    normalized["config_keys"] = list(raw_config_keys)

    raw_index_flags = value.get("index_flags")
    expected_index_flags = {
        "assume_unchanged",
        "skip_worktree",
        "fsmonitor_valid",
    }
    if not isinstance(raw_index_flags, dict) or set(raw_index_flags) != expected_index_flags:
        raise SandboxError("isolated Git inspector returned invalid index flags")
    index_flags: dict[str, list[str]] = {}
    for flag_name in sorted(expected_index_flags):
        raw_paths = raw_index_flags.get(flag_name)
        if (
            not isinstance(raw_paths, list)
            or len(raw_paths) > MAX_GIT_LIST_ENTRIES
            or raw_paths != sorted(set(raw_paths))
            or not all(
                isinstance(path, str) and _valid_git_payload_path(path) for path in raw_paths
            )
        ):
            raise SandboxError(f"isolated Git inspector returned invalid {flag_name} paths")
        index_flags[flag_name] = list(raw_paths)
    normalized["index_flags"] = index_flags

    for field_name in ("status", "unstaged_files", "staged_files"):
        raw_items = value.get(field_name)
        if (
            not isinstance(raw_items, list)
            or len(raw_items) > MAX_GIT_LIST_ENTRIES
            or not all(
                isinstance(item, str)
                and len(item) <= 4_096
                and "\x00" not in item
                and "\r" not in item
                and "\n" not in item
                for item in raw_items
            )
        ):
            raise SandboxError(f"isolated Git inspector returned invalid {field_name} entries")
        normalized[field_name] = list(raw_items)
        if field_name != "status" and not all(_valid_git_payload_path(item) for item in raw_items):
            raise SandboxError(f"isolated Git inspector returned unsafe {field_name} paths")

    for field_name in (
        "unstaged_diff_stat",
        "staged_diff_stat",
        "unstaged_patch",
        "staged_patch",
    ):
        raw_text = value.get(field_name)
        if (
            not isinstance(raw_text, str)
            or len(raw_text.encode("utf-8")) > 100_000
            or "\x00" in raw_text
        ):
            raise SandboxError(f"isolated Git inspector returned invalid {field_name} output")
        normalized[field_name] = raw_text

    raw_errors = value.get("errors")
    if not isinstance(raw_errors, list) or len(raw_errors) > MAX_GIT_ERROR_ENTRIES:
        raise SandboxError("isolated Git inspector returned invalid errors")
    errors: list[dict[str, str]] = []
    for raw_error in raw_errors:
        if not isinstance(raw_error, dict) or set(raw_error) != {"command", "error"}:
            raise SandboxError("isolated Git inspector returned an invalid error record")
        command = raw_error.get("command")
        error = raw_error.get("error")
        if (
            not isinstance(command, str)
            or not command
            or len(command) > 256
            or not isinstance(error, str)
            or not error
            or len(error) > MAX_GIT_ERROR_CHARS
            or "\x00" in command
            or "\x00" in error
        ):
            raise SandboxError("isolated Git inspector returned an invalid error record")
        errors.append({"command": command, "error": error})
    normalized["errors"] = errors
    fingerprints_changed = (
        normalized["workspace_fingerprint_before"] != normalized["workspace_fingerprint_after"]
        or normalized["git_control_fingerprint_before"]
        != normalized["git_control_fingerprint_after"]
    )
    if (fingerprints_changed or any(index_flags.values())) and not errors:
        raise SandboxError("isolated Git inspector omitted a required repository guard error")
    return normalized


def _valid_git_payload_path(path: str) -> bool:
    return (
        bool(path)
        and path == path.strip()
        and not path.startswith("/")
        and "\\" not in path
        and '"' not in path
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in path)
        and all(part not in {"", ".", ".."} for part in path.split("/"))
        and len(path.encode("utf-8")) <= 4_096
    )


def _stat_is_link_or_reparse(path_info: object) -> bool:
    mode = getattr(path_info, "st_mode", 0)
    attributes = getattr(path_info, "st_file_attributes", 0)
    return stat.S_ISLNK(mode) or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _require_real_directory(path: Path, *, label: str) -> os.stat_result:
    path_info = os.lstat(path)
    if _stat_is_link_or_reparse(path_info) or not stat.S_ISDIR(path_info.st_mode):
        raise SandboxError(f"{label} must be a real directory, not a symlink or reparse point")
    return path_info


def _relative_path_no_resolve(root: Path, path: Path) -> Path:
    absolute_root = Path(os.path.abspath(root))
    absolute_path = Path(os.path.abspath(path))
    try:
        return absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise SandboxError("sandbox path escapes the repository workspace") from exc


def _guard_existing_path(root: Path, path: Path, *, expected: str) -> os.stat_result:
    _require_real_directory(root, label="repository workspace")
    relative = _relative_path_no_resolve(root, path)
    current = root
    if not relative.parts:
        path_info = os.lstat(root)
    else:
        path_info = os.lstat(root)
        for index, part in enumerate(relative.parts):
            current = current / part
            path_info = os.lstat(current)
            if _stat_is_link_or_reparse(path_info):
                raise SandboxError(
                    "sandbox path contains a symlink or reparse point: "
                    f"{current.relative_to(root).as_posix()}"
                )
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(path_info.st_mode):
                raise SandboxError("sandbox path has a non-directory parent")
    if expected == "directory" and not stat.S_ISDIR(path_info.st_mode):
        raise SandboxError("sandbox path must be a real directory")
    if expected == "file" and not stat.S_ISREG(path_info.st_mode):
        raise SandboxError("sandbox path must be a real regular file")
    return path_info


def _supports_secure_directory_fds() -> bool:
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.scandir in os.supports_fd
    )


def _open_directory_no_follow(root: Path, relative: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(root, flags)
    try:
        for part in relative.parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_entries_no_follow(
    root: Path,
    directory: Path,
) -> list[tuple[str, os.stat_result]]:
    def bounded_entries(
        entries: Iterable[os.DirEntry[str]],
    ) -> list[tuple[str, os.stat_result]]:
        result: list[tuple[str, os.stat_result]] = []
        for entry in entries:
            if len(result) >= MAX_SANDBOX_WORKSPACE_PATHS:
                raise SandboxError("sandbox workspace path count exceeded its safety limit")
            name = entry.name
            if len(name.encode("utf-8")) > MAX_SANDBOX_PATH_BYTES:
                raise SandboxError("sandbox path exceeded its safety limit")
            result.append((name, entry.stat(follow_symlinks=False)))
        return result

    relative = _relative_path_no_resolve(root, directory)
    if _supports_secure_directory_fds():
        descriptor = _open_directory_no_follow(root, relative)
        try:
            with os.scandir(descriptor) as entries:
                return bounded_entries(entries)
        finally:
            os.close(descriptor)

    before = _guard_existing_path(root, directory, expected="directory")
    with os.scandir(directory) as entries:
        result = bounded_entries(entries)
    after = _guard_existing_path(root, directory, expected="directory")
    if not _same_file_identity(before, after):
        raise SandboxError("sandbox directory changed during inspection")
    return result


def _walk_regular_files_no_follow(
    root: Path,
    start: Path,
    *,
    reject_links: bool,
    skip_directories: set[str] | None = None,
    path_budget: list[int] | None = None,
) -> Iterator[tuple[Path, os.stat_result]]:
    _guard_existing_path(root, start, expected="directory")
    skipped = skip_directories or set()
    directories = [start]
    budget = path_budget if path_budget is not None else [0, 0]
    if len(budget) != 2 or any(value < 0 for value in budget):
        raise SandboxError("sandbox traversal path budget is invalid")
    while directories:
        directory = directories.pop()
        for name, path_info in _directory_entries_no_follow(root, directory):
            path = directory / name
            relative = path.relative_to(root)
            relative_bytes = _bounded_relative_path_bytes(relative)
            budget[0] += 1
            budget[1] += relative_bytes
            if budget[0] > MAX_SANDBOX_WORKSPACE_PATHS:
                raise SandboxError("sandbox tree path count exceeded its safety limit")
            if budget[1] > MAX_SANDBOX_TOTAL_PATH_BYTES:
                raise SandboxError("sandbox tree path byte size exceeded its safety limit")
            if _stat_is_link_or_reparse(path_info):
                if reject_links:
                    raise SandboxError(
                        "sandbox artifact tree contains a symlink or reparse point: "
                        f"{path.relative_to(root).as_posix()}"
                    )
                continue
            if stat.S_ISDIR(path_info.st_mode):
                if name not in skipped:
                    directories.append(path)
            elif stat.S_ISREG(path_info.st_mode):
                yield path, path_info
            else:
                raise SandboxError(f"sandbox tree contains a special file: {relative.as_posix()}")


def _bounded_relative_path_bytes(relative: Path) -> int:
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SandboxError("sandbox relative path is invalid")
    encoded_length = len(relative.as_posix().encode("utf-8"))
    if encoded_length > MAX_SANDBOX_PATH_BYTES:
        raise SandboxError("sandbox path exceeded its safety limit")
    return encoded_length


def _read_text_no_follow(
    root: Path,
    path: Path,
    *,
    max_bytes: int,
    errors: str = "strict",
) -> str:
    return _read_bytes_no_follow(root, path, max_bytes=max_bytes).decode(
        "utf-8",
        errors=errors,
    )


def _read_bytes_no_follow(
    root: Path,
    path: Path,
    *,
    max_bytes: int,
) -> bytes:
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    relative = _relative_path_no_resolve(root, path)
    if not relative.parts:
        raise SandboxError("sandbox file path must not be the repository root")

    descriptor: int
    parent_descriptor: int | None = None
    if _supports_secure_directory_fds():
        parent_descriptor = _open_directory_no_follow(root, relative.parent)
        try:
            descriptor = os.open(
                relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    else:
        before = _guard_existing_path(root, path, expected="file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        after = _guard_existing_path(root, path, expected="file")
        if not _same_file_identity(before, opened) or not _same_file_identity(opened, after):
            os.close(descriptor)
            raise SandboxError("sandbox file changed during no-follow open")

    try:
        path_info = os.fstat(descriptor)
        if not stat.S_ISREG(path_info.st_mode):
            raise SandboxError("sandbox path must be a regular file")
        if path_info.st_size > max_bytes:
            raise _SandboxFileTooLarge(str(path))
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            raise _SandboxFileTooLarge(str(path))
        after_read = os.fstat(descriptor)
        if not _same_descriptor_snapshot(path_info, after_read):
            raise SandboxError("sandbox file changed during bounded read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _workspace_fingerprint(root: Path) -> str:
    """Return a bounded content fingerprint while rejecting unsafe tree entries."""

    _require_real_directory(root, label="repository workspace")
    digest = hashlib.sha256()
    directories = [root]
    file_count = 0
    total_bytes = 0
    path_count = 0
    total_path_bytes = 0
    while directories:
        directory = directories.pop()
        entries = sorted(_directory_entries_no_follow(root, directory), key=lambda item: item[0])
        for name, path_info in entries:
            path = directory / name
            relative_path = path.relative_to(root)
            relative = relative_path.as_posix()
            path_count += 1
            total_path_bytes += _bounded_relative_path_bytes(relative_path)
            if path_count > MAX_SANDBOX_WORKSPACE_PATHS:
                raise SandboxError("sandbox workspace path count exceeded its safety limit")
            if total_path_bytes > MAX_SANDBOX_TOTAL_PATH_BYTES:
                raise SandboxError("sandbox workspace path byte size exceeded its safety limit")
            if _stat_is_link_or_reparse(path_info):
                raise SandboxError(
                    f"sandbox source workspace contains a symlink or reparse point: {relative}"
                )
            if stat.S_ISDIR(path_info.st_mode):
                directories.append(path)
                digest.update(b"D\0" + relative.encode("utf-8") + b"\0")
                continue
            if not stat.S_ISREG(path_info.st_mode):
                raise SandboxError(f"sandbox source workspace contains a special file: {relative}")
            file_count += 1
            total_bytes += path_info.st_size
            if file_count > MAX_SANDBOX_WORKSPACE_FILES:
                raise SandboxError("sandbox workspace file count exceeded its safety limit")
            if total_bytes > MAX_SANDBOX_WORKSPACE_BYTES:
                raise SandboxError("sandbox workspace byte size exceeded its safety limit")
            digest.update(b"F\0" + relative.encode("utf-8") + b"\0")
            digest.update(str(path_info.st_size).encode("ascii") + b"\0")
            _update_digest_from_file_no_follow(
                digest,
                root,
                path,
                expected=path_info,
                max_bytes=(MAX_SANDBOX_WORKSPACE_BYTES - (total_bytes - path_info.st_size)),
            )
            digest.update(b"\0")
    return digest.hexdigest()


def _file_content_digest_no_follow(
    root: Path,
    path: Path,
    *,
    expected: os.stat_result,
    max_bytes: int,
) -> str:
    digest = hashlib.sha256()
    _update_digest_from_file_no_follow(
        digest,
        root,
        path,
        expected=expected,
        max_bytes=max_bytes,
    )
    return digest.hexdigest()


def _update_digest_from_file_no_follow(
    digest: object,
    root: Path,
    path: Path,
    *,
    expected: os.stat_result,
    max_bytes: int,
) -> None:
    relative = _relative_path_no_resolve(root, path)
    if not relative.parts or max_bytes < 0:
        raise SandboxError("sandbox fingerprint path or limit is invalid")
    if _supports_secure_directory_fds():
        parent_descriptor = _open_directory_no_follow(root, relative.parent)
        try:
            descriptor = os.open(
                relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    else:
        before_path = _guard_existing_path(root, path, expected="file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        after_path = _guard_existing_path(root, path, expected="file")
        if not _same_file_identity(before_path, opened) or not _same_file_identity(
            opened,
            after_path,
        ):
            os.close(descriptor)
            raise SandboxError("sandbox file changed during fingerprint open")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
            or before.st_size > max_bytes
        ):
            raise SandboxError("sandbox file changed before fingerprinting")
        update = getattr(digest, "update")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise SandboxError("sandbox file changed during fingerprinting")
            update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SandboxError("sandbox file grew during fingerprinting")
        after = os.fstat(descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise SandboxError("sandbox file changed during fingerprinting")
    finally:
        os.close(descriptor)


@contextmanager
def _ephemeral_working_copy(
    source: Path,
    source_fingerprint: str,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="hallu-sandbox-run-") as temp_dir:
        working_copy = Path(temp_dir) / "workspace"
        try:
            _copy_workspace_tree_no_follow(source, working_copy)
        except OSError as exc:
            raise SandboxError("sandbox source snapshot could not be created") from exc
        if _workspace_fingerprint(source) != source_fingerprint:
            raise SandboxError("source workspace changed while creating its sandbox snapshot")
        if _workspace_fingerprint(working_copy) != source_fingerprint:
            raise SandboxError("sandbox working copy does not match the source snapshot")
        _make_ephemeral_copy_writable(working_copy)
        yield working_copy


def _copy_workspace_tree_no_follow(source: Path, destination: Path) -> None:
    """Copy a bounded source tree without following mutable path components."""

    _require_real_directory(source, label="sandbox source workspace")
    destination.mkdir(mode=0o700)
    directories = [source]
    path_count = 0
    total_path_bytes = 0
    file_count = 0
    total_file_bytes = 0
    while directories:
        directory = directories.pop()
        for name, path_info in sorted(
            _directory_entries_no_follow(source, directory),
            key=lambda item: item[0],
        ):
            source_path = directory / name
            relative = source_path.relative_to(source)
            path_count += 1
            total_path_bytes += _bounded_relative_path_bytes(relative)
            if path_count > MAX_SANDBOX_WORKSPACE_PATHS:
                raise SandboxError("sandbox workspace path count exceeded its safety limit")
            if total_path_bytes > MAX_SANDBOX_TOTAL_PATH_BYTES:
                raise SandboxError("sandbox workspace path byte size exceeded its safety limit")
            if _stat_is_link_or_reparse(path_info):
                raise SandboxError(
                    "sandbox source workspace contains a symlink or reparse point: "
                    f"{relative.as_posix()}"
                )
            destination_path = destination / relative
            if stat.S_ISDIR(path_info.st_mode):
                destination_path.mkdir(mode=stat.S_IMODE(path_info.st_mode) | 0o700)
                directories.append(source_path)
                continue
            if not stat.S_ISREG(path_info.st_mode):
                raise SandboxError(
                    f"sandbox source workspace contains a special file: {relative.as_posix()}"
                )
            file_count += 1
            total_file_bytes += path_info.st_size
            if file_count > MAX_SANDBOX_WORKSPACE_FILES:
                raise SandboxError("sandbox workspace file count exceeded its safety limit")
            if total_file_bytes > MAX_SANDBOX_WORKSPACE_BYTES:
                raise SandboxError("sandbox workspace byte size exceeded its safety limit")
            _copy_regular_file_no_follow(
                source,
                source_path,
                destination_path,
                expected=path_info,
            )


def _copy_regular_file_no_follow(
    root: Path,
    source: Path,
    destination: Path,
    *,
    expected: os.stat_result,
) -> None:
    relative = _relative_path_no_resolve(root, source)
    if _supports_secure_directory_fds():
        parent_descriptor = _open_directory_no_follow(root, relative.parent)
        try:
            source_descriptor = os.open(
                relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    else:
        before_path = _guard_existing_path(root, source, expected="file")
        source_descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(source_descriptor)
        after_path = _guard_existing_path(root, source, expected="file")
        if not _same_file_identity(before_path, opened) or not _same_file_identity(
            opened,
            after_path,
        ):
            os.close(source_descriptor)
            raise SandboxError("sandbox file changed during no-follow copy open")

    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file_identity(expected, before)
            or before.st_size != expected.st_size
        ):
            raise SandboxError("sandbox file changed before snapshot copy")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            stat.S_IMODE(expected.st_mode) | 0o600,
        )
        remaining = before.st_size
        while remaining:
            chunk = os.read(source_descriptor, min(65_536, remaining))
            if not chunk:
                raise SandboxError("sandbox file changed during snapshot copy")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise SandboxError("sandbox snapshot copy could not make progress")
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_descriptor, 1):
            raise SandboxError("sandbox file grew during snapshot copy")
        after = os.fstat(source_descriptor)
        if not _same_descriptor_snapshot(before, after):
            raise SandboxError("sandbox file changed during snapshot copy")
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def _make_ephemeral_copy_writable(root: Path) -> None:
    """Allow the fixed container UID to mutate only the hidden temporary copy."""

    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = Path(current) / name
            path.chmod(stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) | 0o666)
        for name in directories:
            path = Path(current) / name
            path.chmod(stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) | 0o777)
    root.chmod(stat.S_IMODE(root.stat().st_mode) | 0o777)


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


class _PythonSymbolVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.symbols: list[dict[str, object]] = []
        self._scope: list[tuple[str, str]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._add_symbol("class", node.name, node.lineno)
        self._scope.append((node.name, "class"))
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node.name, node.lineno, is_async=False)
        self.generic_visit(node)
        self._scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node.name, node.lineno, is_async=True)
        self.generic_visit(node)
        self._scope.pop()

    def _visit_function(self, name: str, lineno: int, *, is_async: bool) -> None:
        kind = "async_function" if is_async else "function"
        if any(scope_kind == "class" for _, scope_kind in self._scope):
            kind = "async_method" if is_async else "method"
        self._add_symbol(kind, name, lineno)
        self._scope.append((name, kind))

    def _add_symbol(self, kind: str, name: str, lineno: int) -> None:
        parent = ".".join(scope_name for scope_name, _ in self._scope)
        qualified_name = ".".join([parent, name]) if parent else name
        self.symbols.append(
            {
                "path": self.path,
                "kind": kind,
                "name": name,
                "qualified_name": qualified_name,
                "lineno": lineno,
            }
        )
