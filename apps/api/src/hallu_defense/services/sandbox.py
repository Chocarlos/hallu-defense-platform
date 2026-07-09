from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

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
    SandboxExecutionBackend,
    SandboxExecutionError,
    build_sandbox_execution_backend,
)
from hallu_defense.services.text import bounded, tokenize

ALLOWED_EXECUTABLES = {"python", "pytest", "npm", "node"}
ARTIFACT_DIRS = {"artifacts", "reports"}
INSPECTION_REPORT_PATH = "reports/sandbox-inspection.json"
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
DIFF_FILE_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
DIFF_HUNK_RE = re.compile(r"^@@ -(?P<old_start>\d+)(?:,(?P<old_lines>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_lines>\d+))? @@")
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
JS_IDENTIFIER_RE = r"[A-Za-z_$][\w$]*"
JS_CLASS_RE = re.compile(
    rf"^\s*(?:export\s+default\s+|export\s+)?class\s+({JS_IDENTIFIER_RE})\b"
)
JS_FUNCTION_RE = re.compile(
    rf"^\s*(?:export\s+)?(?:async\s+)?function\s+({JS_IDENTIFIER_RE})\s*\("
)
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
        before_artifacts = self._artifact_snapshot(repo_path)
        exit_codes: list[int] = []
        stdout: list[str] = []
        stderr: list[str] = []
        parsed_commands: list[list[str]] = []

        for command in request.commands:
            args = self._parse_command(command, repo_path, request.network_policy)
            parsed_commands.append(args)
            try:
                completed = self._execution_backend.execute(
                    args,
                    cwd=repo_path,
                    env=self._sandbox_env(request.network_policy),
                    timeout=self._settings.max_command_seconds,
                    output_caps=self._settings.max_output_chars,
                )
            except SandboxExecutionError as exc:
                raise SandboxError(str(exc)) from exc
            exit_codes.append(completed.returncode)
            stdout.append(bounded(completed.stdout, self._settings.max_output_chars))
            stderr.append(bounded(completed.stderr, self._settings.max_output_chars))

        inspection_report = self._write_inspection_report(repo_path)

        return SandboxRun(
            repo_ref=str(repo_path),
            commands=request.commands,
            exit_codes=exit_codes,
            stdout=stdout,
            stderr=stderr,
            artifacts=self._changed_artifacts(repo_path, before_artifacts),
            evidence=self._evidence_from_run(request, parsed_commands, exit_codes, stdout, stderr, inspection_report),
            network_policy=request.network_policy,
            verdict=VerdictStatus.SUPPORTED
            if exit_codes and all(code == 0 for code in exit_codes)
            else VerdictStatus.CONTRADICTED,
        )

    def _resolve_repo(self, repo_ref: str) -> Path:
        candidate = (self._settings.allowed_workspace / repo_ref).resolve()
        allowed = self._settings.allowed_workspace.resolve()
        try:
            candidate.relative_to(allowed)
        except ValueError as exc:
            raise SandboxError("repo_ref escapes the configured workspace") from exc
        if not candidate.exists() or not candidate.is_dir():
            raise SandboxError("repo_ref must point to an existing directory")
        return candidate

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
            script_path = (repo_path / arg).resolve()
            try:
                script_path.relative_to(repo_path)
            except ValueError as exc:
                raise SandboxError("command script path escapes the repository workspace") from exc
            if script_path.exists() and script_path.is_file():
                inputs.append(script_path.read_text(encoding="utf-8", errors="ignore")[:100_000])
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
        env = {
            key: value
            for key, value in os.environ.items()
            if not SENSITIVE_ENV_RE.search(key)
        }
        env["HALLU_DEFENSE_NETWORK_POLICY"] = network_policy
        return env

    def _artifact_snapshot(self, repo_path: Path) -> dict[str, tuple[int, int]]:
        snapshot: dict[str, tuple[int, int]] = {}
        for artifact_dir in ARTIFACT_DIRS:
            root = repo_path / artifact_dir
            if not root.exists() or not root.is_dir():
                continue
            for path in root.rglob("*"):
                if path.is_file():
                    stat = path.stat()
                    snapshot[path.relative_to(repo_path).as_posix()] = (stat.st_mtime_ns, stat.st_size)
        return snapshot

    def _changed_artifacts(
        self,
        repo_path: Path,
        before: dict[str, tuple[int, int]],
    ) -> list[str]:
        after = self._artifact_snapshot(repo_path)
        return sorted(
            path
            for path, signature in after.items()
            if before.get(path) != signature
        )

    def _write_inspection_report(self, repo_path: Path) -> dict[str, object]:
        report_path = repo_path / INSPECTION_REPORT_PATH
        report_path.parent.mkdir(parents=True, exist_ok=True)
        static_report = self._static_inspection(repo_path)
        payload: dict[str, object] = {
            "schema_version": "sandbox_inspection.v1",
            "git": self._git_inspection(repo_path, static_report),
            "static": static_report,
        }
        report_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return payload

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
                    freshness=Freshness(staleness_class=StalenessClass.FRESH),
                )
            )
        evidence.append(
            Evidence(
                evidence_id="ev_sandbox_inspection",
                kind=EvidenceKind.REPO_FILE,
                source_ref=INSPECTION_REPORT_PATH,
                content=json.dumps(inspection_report, sort_keys=True),
                structured_content=inspection_report,
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
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
        if executable == "python" and len(lowered) > 2 and lowered[1] == "-m" and lowered[2] in {"pytest", "unittest"}:
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

    def _git_inspection(self, repo_path: Path, static_report: dict[str, object]) -> dict[str, object]:
        if not (repo_path / ".git").exists():
            return {
                "is_repository": False,
                "status": [],
                "diff_files": [],
                "diff_stat": "",
                "changed_ranges": [],
                "changed_lines": [],
                "changed_symbols": [],
                "errors": [],
            }

        errors: list[dict[str, str]] = []
        status = self._git_output(repo_path, ["status", "--short"], errors)
        unstaged_files = self._git_output(repo_path, ["diff", "--name-only"], errors)
        staged_files = self._git_output(repo_path, ["diff", "--cached", "--name-only"], errors)
        diff_stat = self._git_output(repo_path, ["diff", "--stat"], errors)
        cached_diff_stat = self._git_output(repo_path, ["diff", "--cached", "--stat"], errors)
        unstaged_patch = self._git_output(repo_path, ["diff", "--unified=0", "--no-ext-diff"], errors)
        staged_patch = self._git_output(repo_path, ["diff", "--cached", "--unified=0", "--no-ext-diff"], errors)

        diff_files = sorted({*self._nonempty_lines(unstaged_files), *self._nonempty_lines(staged_files)})
        diff_stat_parts = [part for part in [diff_stat.strip(), cached_diff_stat.strip()] if part]
        changed_ranges = [
            *self._changed_ranges_from_patch(unstaged_patch, "working_tree"),
            *self._changed_ranges_from_patch(staged_patch, "index"),
        ]
        changed_lines = [
            *self._changed_lines_from_patch(unstaged_patch, "working_tree"),
            *self._changed_lines_from_patch(staged_patch, "index"),
        ]

        return {
            "is_repository": True,
            "status": self._nonempty_lines(status),
            "diff_files": diff_files,
            "diff_stat": "\n".join(diff_stat_parts),
            "changed_ranges": changed_ranges,
            "changed_lines": changed_lines,
            "changed_symbols": self._changed_symbols(static_report, changed_ranges),
            "errors": errors,
        }

    def _git_output(self, repo_path: Path, args: list[str], errors: list[dict[str, str]]) -> str:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=repo_path,
                text=True,
                capture_output=True,
                timeout=min(self._settings.max_command_seconds, 5),
                check=False,
            )
        except FileNotFoundError:
            errors.append({"command": f"git {' '.join(args)}", "error": "git executable not found"})
            return ""
        except subprocess.TimeoutExpired:
            errors.append({"command": f"git {' '.join(args)}", "error": "git command timed out"})
            return ""
        if completed.returncode != 0:
            errors.append(
                {
                    "command": f"git {' '.join(args)}",
                    "error": bounded(completed.stderr, self._settings.max_output_chars).strip(),
                }
            )
            return ""
        return bounded(completed.stdout, self._settings.max_output_chars)

    def _static_inspection(self, repo_path: Path) -> dict[str, object]:
        symbols: list[dict[str, object]] = []
        javascript_symbols: list[dict[str, object]] = []
        parse_errors: list[dict[str, str]] = []
        inspectable_files = self._iter_inspectable_files(repo_path)

        for path in [item for item in inspectable_files if item.suffix.lower() == ".py"]:
            rel_path = path.relative_to(repo_path).as_posix()
            try:
                if path.stat().st_size > MAX_INSPECTION_BYTES:
                    parse_errors.append({"path": rel_path, "error": "file too large for static inspection"})
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel_path)
            except (OSError, SyntaxError, UnicodeDecodeError) as exc:
                parse_errors.append({"path": rel_path, "error": f"{type(exc).__name__}: {exc}"})
                continue

            visitor = _PythonSymbolVisitor(rel_path)
            visitor.visit(tree)
            remaining = MAX_INSPECTION_SYMBOLS - len(symbols)
            if remaining <= 0:
                break
            symbols.extend(visitor.symbols[:remaining])

        for path in [item for item in inspectable_files if item.suffix.lower() in JAVASCRIPT_SUFFIXES]:
            remaining = MAX_INSPECTION_SYMBOLS - len(javascript_symbols)
            if remaining <= 0:
                break
            rel_path = path.relative_to(repo_path).as_posix()
            try:
                if path.stat().st_size > MAX_INSPECTION_BYTES:
                    parse_errors.append({"path": rel_path, "error": "file too large for static inspection"})
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                parse_errors.append({"path": rel_path, "error": f"{type(exc).__name__}: {exc}"})
                continue
            javascript_symbols.extend(self._javascript_symbols(rel_path, content)[:remaining])

        return {
            "files": [path.relative_to(repo_path).as_posix() for path in inspectable_files[:MAX_INSPECTION_FILES]],
            "python_symbols": symbols,
            "javascript_symbols": javascript_symbols,
            "parse_errors": parse_errors,
            "truncated": len(inspectable_files) > MAX_INSPECTION_FILES
            or len(symbols) >= MAX_INSPECTION_SYMBOLS
            or len(javascript_symbols) >= MAX_INSPECTION_SYMBOLS,
        }

    def _javascript_symbols(self, rel_path: str, content: str) -> list[dict[str, object]]:
        language = "typescript" if Path(rel_path).suffix.lower() in {".ts", ".tsx"} else "javascript"
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
        files: list[Path] = []
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in INSPECTION_FILE_SUFFIXES:
                continue
            try:
                resolved = path.resolve()
                resolved.relative_to(repo_path)
                rel_parts = path.relative_to(repo_path).parts
            except ValueError:
                continue
            if any(part in INSPECTION_SKIP_DIRS for part in rel_parts[:-1]):
                continue
            files.append(path)
        return sorted(files)

    def _nonempty_lines(self, value: str) -> list[str]:
        return [line for line in value.splitlines() if line.strip()]

    def _changed_ranges_from_patch(self, patch_text: str, source: str) -> list[dict[str, object]]:
        ranges: list[dict[str, object]] = []
        current_path: str | None = None
        for line in patch_text.splitlines():
            file_match = DIFF_FILE_RE.match(line)
            if file_match is not None:
                current_path = file_match.group(2)
                continue
            if current_path is None:
                continue
            hunk_match = DIFF_HUNK_RE.match(line)
            if hunk_match is None:
                continue
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

    def _changed_lines_from_patch(self, patch_text: str, source: str) -> list[dict[str, object]]:
        lines: list[dict[str, object]] = []
        current_path: str | None = None
        old_lineno = 0
        new_lineno = 0
        in_hunk = False
        for line in patch_text.splitlines():
            file_match = DIFF_FILE_RE.match(line)
            if file_match is not None:
                current_path = file_match.group(2)
                in_hunk = False
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
            if not isinstance(path, str) or not isinstance(new_start, int) or not isinstance(new_lines, int):
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
