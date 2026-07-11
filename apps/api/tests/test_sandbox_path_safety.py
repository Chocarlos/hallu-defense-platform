from __future__ import annotations

import json
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import hallu_defense.services.sandbox as sandbox_module
from hallu_defense.config import Settings
from hallu_defense.domain.models import RepoChecksRunRequest, VerdictStatus
from hallu_defense.services.sandbox import (
    SANDBOX_GIT_INSPECTION_SCHEMA,
    SANDBOX_GIT_INSPECTOR_PATH,
    SandboxError,
    SandboxRunner,
    _stat_is_link_or_reparse,
)
from hallu_defense.services.sandbox_exec import (
    ExecutionResult,
    SandboxExecutionBatchResult,
)


class RecordingBackend:
    def __init__(
        self,
        *,
        inspector_result: ExecutionResult | None = None,
    ) -> None:
        self.inspector_result = inspector_result or ExecutionResult(
            returncode=0,
            stdout=json.dumps(_valid_inspector_payload(), separators=(",", ":")),
            stderr="",
        )
        self.calls: list[tuple[list[str], Path, Path, dict[str, str]]] = []
        self.output_caps: list[int] = []

    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        del timeout
        normalized = list(argv)
        self.calls.append((normalized, cwd, source_cwd, dict(env)))
        self.output_caps.append(output_caps)
        if SANDBOX_GIT_INSPECTOR_PATH in normalized:
            return self.inspector_result
        return ExecutionResult(returncode=0, stdout="command-ok\n", stderr="")


class SameMetadataArtifactMutationBackend(RecordingBackend):
    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        if SANDBOX_GIT_INSPECTOR_PATH in argv:
            return super().execute(
                argv,
                cwd=cwd,
                source_cwd=source_cwd,
                env=env,
                timeout=timeout,
                output_caps=output_caps,
            )
        target = cwd / "artifacts" / "result.txt"
        before = target.stat()
        target.write_text("new", encoding="utf-8")
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        return ExecutionResult(returncode=0, stdout="artifact-mutated\n", stderr="")


class LocalSnapshotTestBackend:
    @property
    def git_inspector_path(self) -> str:
        return str(
            Path(__file__).resolve().parents[3]
            / "infra"
            / "docker"
            / "sandbox_git_inspector.py"
        )

    @property
    def git_inspector_python(self) -> str:
        return sys.executable

    @property
    def git_inspector_environment(self) -> dict[str, str]:
        environment = {"PATH": os.environ.get("PATH", os.defpath)}
        for key in ("SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
            if value := os.environ.get(key):
                environment[key] = value
        return environment

    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        del output_caps
        assert cwd.resolve() != source_cwd.resolve()
        try:
            completed = subprocess.run(
                list(argv),
                cwd=cwd,
                env=dict(env),
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                returncode=124,
                stdout=_coerce_test_output(exc.stdout),
                stderr=_coerce_test_output(exc.stderr),
                timed_out=True,
            )
        return ExecutionResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class MismatchedSnapshotBatchBackend:
    def execute_batch(
        self,
        commands: Sequence[Sequence[str]],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> SandboxExecutionBatchResult:
        del cwd, source_cwd, env, timeout, output_caps
        return SandboxExecutionBatchResult(
            executions=tuple(
                ExecutionResult(returncode=0, stdout="", stderr="")
                for _command in commands
            ),
            pre_snapshot_fingerprint="0" * 64,
            post_snapshot_fingerprint="0" * 64,
        )


class PostMismatchedSnapshotBatchBackend:
    def execute_batch(
        self,
        commands: Sequence[Sequence[str]],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> SandboxExecutionBatchResult:
        del source_cwd, env, timeout, output_caps
        pre_fingerprint = sandbox_module._workspace_fingerprint(cwd)
        post_fingerprint = (
            ("1" if pre_fingerprint[0] != "1" else "0") + pre_fingerprint[1:]
        )
        return SandboxExecutionBatchResult(
            executions=tuple(
                ExecutionResult(returncode=0, stdout="", stderr="")
                for _command in commands
            ),
            pre_snapshot_fingerprint=pre_fingerprint,
            post_snapshot_fingerprint=post_fingerprint,
        )


def _settings(workspace: Path) -> Settings:
    return Settings(
        environment="test",
        policy_version="test",
        auth_required=False,
        allowed_workspace=workspace,
        max_command_seconds=10,
        max_output_chars=20_000,
        sandbox_backend="docker",
    )


def _request(repo_name: str = "repo") -> RepoChecksRunRequest:
    return RepoChecksRunRequest(
        repo_ref=repo_name,
        commands=["python probe.py"],
        network_policy="deny",
    )


def _repo(workspace: Path) -> Path:
    repo = workspace / "repo"
    repo.mkdir()
    (repo / "probe.py").write_text("print('ok')\n", encoding="utf-8")
    return repo


def _valid_inspector_payload() -> dict[str, object]:
    return {
        "schema_version": SANDBOX_GIT_INSPECTION_SCHEMA,
        "is_repository": True,
        "status": [" M probe.py"],
        "unstaged_files": ["probe.py"],
        "staged_files": [],
        "unstaged_diff_stat": " probe.py | 1 +",
        "staged_diff_stat": "",
        "unstaged_patch": (
            "diff --git a/probe.py b/probe.py\n"
            "@@ -1,0 +2 @@\n"
            "+print('changed')\n"
        ),
        "staged_patch": "",
        "errors": [],
    }


def _symlink_or_skip(target: Path, link: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")


def test_reparse_attribute_is_rejected_without_platform_privileges() -> None:
    fake_info = type(
        "FakeStat",
        (),
        {
            "st_mode": stat.S_IFREG | 0o600,
            "st_file_attributes": 0x400,
        },
    )()

    assert _stat_is_link_or_reparse(fake_info) is True


def test_runner_rejects_symlinked_repository_directory(tmp_path: Path) -> None:
    real_repo = _repo(tmp_path)
    _symlink_or_skip(real_repo, tmp_path / "linked-repo", directory=True)
    runner = SandboxRunner(_settings(tmp_path), execution_backend=RecordingBackend())

    with pytest.raises(SandboxError, match="symlink|reparse"):
        runner.run(_request("linked-repo"))


def test_allowlisted_network_policy_fails_closed_before_any_execution(
    tmp_path: Path,
) -> None:
    _repo(tmp_path)
    backend = RecordingBackend()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=backend)

    with pytest.raises(SandboxError, match="exact destination allowlist.*approved"):
        runner.run(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python probe.py"],
                network_policy="allowlisted",
            )
        )

    assert backend.calls == []


def test_snapshot_fails_closed_when_workspace_file_bound_is_exceeded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "second.txt").write_text("second\n", encoding="utf-8")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_FILES", 1)
    backend = RecordingBackend()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=backend)

    with pytest.raises(SandboxError, match="file count exceeded"):
        runner.run(_request())

    assert backend.calls == []


def test_snapshot_fails_closed_when_workspace_byte_bound_is_exceeded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _repo(tmp_path)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 4)
    backend = RecordingBackend()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=backend)

    with pytest.raises(SandboxError, match="byte size exceeded"):
        runner.run(_request())

    assert backend.calls == []


def test_batch_evidence_rejects_a_snapshot_that_differs_from_api_source(
    tmp_path: Path,
) -> None:
    _repo(tmp_path)
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=MismatchedSnapshotBatchBackend(),
    )

    with pytest.raises(SandboxError, match="snapshot does not match"):
        runner.run(_request())


def test_batch_git_inspection_rejects_post_snapshot_mutation(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".git").mkdir()
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=PostMismatchedSnapshotBatchBackend(),
    )

    run = runner.run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["errors"][0]["command"] == "isolated_git_inspector"


def test_container_and_api_workspace_fingerprint_algorithms_match(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    nested = repo / "nested"
    nested.mkdir()
    (nested / "binary.bin").write_bytes(b"\x00\xffsnapshot\n")
    (repo / "empty").mkdir()
    module_path = (
        Path(__file__).resolve().parents[3]
        / "infra"
        / "docker"
        / "sandbox_workspace.py"
    )
    spec = importlib.util.spec_from_file_location("sandbox_workspace_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.workspace_fingerprint(repo) == sandbox_module._workspace_fingerprint(repo)


def test_runner_rejects_symlinked_command_script(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "probe.py").unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    _symlink_or_skip(outside, repo / "probe.py", directory=False)
    backend = RecordingBackend()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=backend)

    with pytest.raises(SandboxError, match="symlink|reparse"):
        runner.run(_request())

    assert backend.calls == []


def test_runner_rejects_symlinked_reports_directory_without_external_write(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    outside = tmp_path / "outside-reports"
    outside.mkdir()
    _symlink_or_skip(outside, repo / "reports", directory=True)
    backend = RecordingBackend()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=backend)

    with pytest.raises(SandboxError, match="artifact directory|symlink|reparse"):
        runner.run(_request())

    assert not (outside / "sandbox-inspection.json").exists()
    assert backend.calls == []


def test_runner_rejects_symlinked_report_file_without_overwriting_target(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    reports = repo / "reports"
    reports.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-overwrite\n", encoding="utf-8")
    _symlink_or_skip(victim, reports / "sandbox-inspection.json", directory=False)
    runner = SandboxRunner(_settings(tmp_path), execution_backend=RecordingBackend())

    with pytest.raises(SandboxError, match="symlink|reparse"):
        runner.run(_request())

    assert victim.read_text(encoding="utf-8") == "do-not-overwrite\n"


def test_runner_rejects_symlink_inside_artifact_tree(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    artifacts = repo / "artifacts"
    artifacts.mkdir()
    outside = tmp_path / "outside-artifact.txt"
    outside.write_text("outside\n", encoding="utf-8")
    _symlink_or_skip(outside, artifacts / "linked.txt", directory=False)
    runner = SandboxRunner(_settings(tmp_path), execution_backend=RecordingBackend())

    with pytest.raises(SandboxError, match="symlink|reparse"):
        runner.run(_request())


def test_artifact_inventory_detects_same_size_restored_mtime_change(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    artifacts = repo / "artifacts"
    artifacts.mkdir()
    target = artifacts / "result.txt"
    target.write_text("old", encoding="utf-8")
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=SameMetadataArtifactMutationBackend(),
    )

    run = runner.run(_request())

    assert "artifacts/result.txt" in run.artifacts
    assert target.read_text(encoding="utf-8") == "old"


def test_snapshot_rejects_symlinked_source_file(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    outside = tmp_path / "outside_source.py"
    outside.write_text("def outside_secret_symbol():\n    pass\n", encoding="utf-8")
    _symlink_or_skip(outside, repo / "linked_source.py", directory=False)
    runner = SandboxRunner(_settings(tmp_path), execution_backend=RecordingBackend())

    with pytest.raises(SandboxError, match="symlink|reparse"):
        runner.run(_request())


def test_inspection_is_in_memory_and_never_overwrites_source_report(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    reports = repo / "reports"
    reports.mkdir()
    report = reports / "sandbox-inspection.json"
    report.write_text("old\n", encoding="utf-8")
    runner = SandboxRunner(_settings(tmp_path), execution_backend=RecordingBackend())

    run = runner.run(_request())

    assert report.read_text(encoding="utf-8") == "old\n"
    assert run.evidence[-1].source_ref == "sandbox://inspection"
    assert run.evidence[-1].structured_content["schema_version"] == "sandbox_inspection.v1"
    assert "reports/sandbox-inspection.json" not in run.artifacts
    assert run.verdict is VerdictStatus.SUPPORTED


def test_python_obfuscated_delete_and_write_cannot_mutate_source_workspace(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    victim = repo / "protected.txt"
    victim.write_text("immutable-python\n", encoding="utf-8")
    (repo / "mutate.py").write_text(
        "from pathlib import Path\n"
        "target = Path('protected.txt')\n"
        "getattr(target, 'un' + 'link')()\n"
        "with open('protected.txt', 'w', encoding='utf-8') as stream:\n"
        "    stream.write('working-copy-only')\n",
        encoding="utf-8",
    )
    before = _tree_bytes(repo)
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=LocalSnapshotTestBackend(),
    )

    run = runner.run(
        RepoChecksRunRequest(
            repo_ref="repo",
            commands=["python mutate.py"],
            network_policy="deny",
        )
    )

    assert run.exit_codes == [0]
    assert _tree_bytes(repo) == before
    assert victim.read_text(encoding="utf-8") == "immutable-python\n"


def test_node_obfuscated_unlink_and_open_write_cannot_mutate_source_workspace(
    tmp_path: Path,
) -> None:
    if shutil.which("node") is None:
        pytest.skip("node executable is unavailable")
    repo = _repo(tmp_path)
    victim = repo / "protected-node.txt"
    victim.write_text("immutable-node\n", encoding="utf-8")
    (repo / "mutate.js").write_text(
        "const fs = require('f' + 's');\n"
        "fs['un' + 'linkSync']('protected-node.txt');\n"
        "const fd = fs['open' + 'Sync']('protected-node.txt', 'w');\n"
        "fs['write' + 'Sync'](fd, 'working-copy-only');\n"
        "fs['close' + 'Sync'](fd);\n",
        encoding="utf-8",
    )
    before = _tree_bytes(repo)
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=LocalSnapshotTestBackend(),
    )

    run = runner.run(
        RepoChecksRunRequest(
            repo_ref="repo",
            commands=["node mutate.js"],
            network_policy="deny",
        )
    )

    assert run.exit_codes == [0]
    assert _tree_bytes(repo) == before
    assert victim.read_text(encoding="utf-8") == "immutable-node\n"


def test_git_inspection_uses_backend_and_never_executes_git_in_api_process(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".git").mkdir()
    backend = RecordingBackend()
    settings = _settings(tmp_path)
    runner = SandboxRunner(settings, execution_backend=backend)

    run = runner.run(_request())

    assert len(backend.calls) == 2
    inspector_argv, inspector_cwd, inspector_source, inspector_env = next(
        call for call in backend.calls if SANDBOX_GIT_INSPECTOR_PATH in call[0]
    )
    assert inspector_argv[0] == "python"
    assert SANDBOX_GIT_INSPECTOR_PATH in inspector_argv
    assert all(call[0][0] != "git" for call in backend.calls)
    assert inspector_cwd != repo
    assert inspector_source == repo
    assert inspector_env == {
        "CI": "true",
        "HALLU_DEFENSE_NETWORK_POLICY": "deny",
        "PYTHONUNBUFFERED": "1",
    }
    assert max(backend.output_caps) > settings.max_output_chars
    assert run.verdict is VerdictStatus.SUPPORTED
    assert run.evidence[-1].structured_content["git"]["errors"] == []


@pytest.mark.parametrize(
    "inspector_result",
    [
        ExecutionResult(returncode=0, stdout="{", stderr=""),
        ExecutionResult(returncode=1, stdout="", stderr="failed"),
        ExecutionResult(returncode=124, stdout="", stderr="timeout", timed_out=True),
    ],
)
def test_git_inspector_failure_cannot_produce_supported_evidence(
    tmp_path: Path,
    inspector_result: ExecutionResult,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".git").mkdir()
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=RecordingBackend(inspector_result=inspector_result),
    )

    run = runner.run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["is_repository"] is True
    assert git_report["errors"]


def test_local_test_inspector_rejects_executable_repository_config(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable is unavailable")
    repo = _repo(tmp_path)
    marker = tmp_path / "git-config-executed.txt"
    malicious = _malicious_git_helper(tmp_path, marker)
    _run_git(git, repo, "init")
    _run_git(git, repo, "config", "user.email", "sandbox@example.invalid")
    _run_git(git, repo, "config", "user.name", "Sandbox Test")
    _run_git(git, repo, "add", "probe.py")
    _run_git(git, repo, "commit", "-m", "baseline")
    _run_git(git, repo, "config", "core.fsmonitor", str(malicious))
    _run_git(git, repo, "config", "diff.external", str(malicious))
    (repo / "probe.py").write_text("print('changed')\n", encoding="utf-8")
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=LocalSnapshotTestBackend(),
    )

    run = runner.run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert git_report["is_repository"] is True
    assert git_report["errors"][0]["command"] == "repository_guard"
    assert run.verdict is VerdictStatus.CONTRADICTED
    assert not marker.exists()
    assert not (repo / "%SystemDrive%").exists()


@pytest.mark.parametrize(
    "config_key",
    [
        "include.path",
        "includeIf.gitdir:/.path",
        "filter.evil.clean",
        "filter.evil.smudge",
        "filter.evil.process",
        "diff.evil.command",
        "diff.evil.textconv",
    ],
)
def test_local_test_inspector_rejects_all_executable_config_families(
    tmp_path: Path,
    config_key: str,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable is unavailable")
    repo = _repo(tmp_path)
    marker = tmp_path / "git-config-executed.txt"
    malicious = _malicious_git_helper(tmp_path, marker)
    _run_git(git, repo, "init")
    _run_git(git, repo, "config", "user.email", "sandbox@example.invalid")
    _run_git(git, repo, "config", "user.name", "Sandbox Test")
    _run_git(git, repo, "add", "probe.py")
    _run_git(git, repo, "commit", "-m", "baseline")
    _run_git(git, repo, "config", config_key, str(malicious))
    (repo / "probe.py").write_text("print('changed')\n", encoding="utf-8")
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=LocalSnapshotTestBackend(),
    )

    run = runner.run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert git_report["errors"][0]["command"] == "repository_guard"
    assert run.verdict is VerdictStatus.CONTRADICTED
    assert not marker.exists()


def test_local_test_inspector_normalizes_crlf_and_reports_only_the_changed_line(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable is unavailable")
    repo = _repo(tmp_path)
    service = repo / "service.py"
    service.write_bytes(b"def fetch():\r\n    return 'old'\r\n")
    _run_git(git, repo, "init")
    _run_git(git, repo, "config", "user.email", "sandbox@example.invalid")
    _run_git(git, repo, "config", "user.name", "Sandbox Test")
    _run_git(
        git,
        repo,
        "-c",
        "core.autocrlf=true",
        "-c",
        "core.safecrlf=false",
        "add",
        "probe.py",
        "service.py",
    )
    _run_git(git, repo, "commit", "-m", "baseline")
    service.write_bytes(b"def fetch():\r\n    return 'new'\r\n")
    runner = SandboxRunner(
        _settings(tmp_path),
        execution_backend=LocalSnapshotTestBackend(),
    )

    run = runner.run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert git_report["errors"] == []
    assert any(
        changed_range["path"] == "service.py"
        and changed_range["new_start"] == 2
        and changed_range["new_lines"] == 1
        for changed_range in git_report["changed_ranges"]
    )
    assert not (repo / "%SystemDrive%").exists()


def _run_git(git: str, repo: Path, *args: str) -> None:
    completed = subprocess.run(
        [git, *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)


def _malicious_git_helper(root: Path, marker: Path) -> Path:
    if os.name == "nt":
        helper = root / "malicious-git-config.cmd"
        helper.write_text(
            f"@echo off\r\n>\"{marker}\" echo executed\r\nexit /b 0\r\n",
            encoding="utf-8",
        )
    else:
        helper = root / "malicious-git-config.sh"
        helper.write_text(
            f"#!/bin/sh\nprintf executed > '{marker}'\nexit 0\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
    return helper


def _coerce_test_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
