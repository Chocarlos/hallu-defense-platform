from __future__ import annotations

import importlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import stat
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from hallu_defense.config import Settings
from hallu_defense.domain.models import RepoChecksRunRequest, VerdictStatus
from hallu_defense.services.sandbox import (
    SandboxError,
    SandboxRunner,
    _validate_git_inspection_payload,
)
from hallu_defense.services.sandbox_exec import ExecutionResult


ROOT = Path(__file__).resolve().parents[3]
DOCKER_HELPERS = ROOT / "infra" / "docker"
PROCESS_TEST_EXECUTABLE = getattr(sys, "_base_executable", sys.executable)
INSPECTOR = DOCKER_HELPERS / "sandbox_git_inspector.py"


class LocalSnapshotBackend:
    @property
    def git_inspector_path(self) -> str:
        return str(INSPECTOR)

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
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return ExecutionResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _git() -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    return executable


def _run_git(repo: Path, *args: str, allow_failure: bool = False) -> None:
    completed = subprocess.run(
        [_git(), *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0 and not allow_failure:
        raise AssertionError(completed.stderr)


def _repo(tmp_path: Path, *, changed_path: str = "tracked.py") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "probe.py").write_text("print('ok')\n", encoding="utf-8")
    target = repo / changed_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("old = 1\n", encoding="utf-8")
    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "sandbox@example.invalid")
    _run_git(repo, "config", "user.name", "Sandbox Test")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "baseline")
    return repo


def _runner(tmp_path: Path) -> SandboxRunner:
    return SandboxRunner(
        Settings(
            environment="test",
            policy_version="test",
            auth_required=False,
            allowed_workspace=tmp_path,
            max_command_seconds=10,
            max_output_chars=20_000,
            sandbox_backend="docker",
        ),
        execution_backend=LocalSnapshotBackend(),
    )


def _request() -> RepoChecksRunRequest:
    return RepoChecksRunRequest(
        repo_ref="repo",
        commands=["python probe.py"],
        network_policy="deny",
    )


def _git_state_snapshot(repo: Path) -> tuple[tuple[tuple[str, str, int, bytes], ...], str]:
    git_metadata = repo / ".git"
    entries: list[tuple[str, str, int, bytes]] = []
    digest = hashlib.sha256()
    for path in sorted(git_metadata.rglob("*"), key=lambda item: item.as_posix()):
        metadata = os.lstat(path)
        relative = path.relative_to(git_metadata).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            content = b""
        elif stat.S_ISREG(metadata.st_mode):
            kind = "file"
            content = path.read_bytes()
        else:
            raise AssertionError(f"unexpected Git control entry: {relative}")
        entry = (relative, kind, stat.S_IMODE(metadata.st_mode), content)
        entries.append(entry)
        digest.update(relative.encode("utf-8") + b"\x00")
        digest.update(kind.encode("ascii") + b"\x00")
        digest.update(str(entry[2]).encode("ascii") + b"\x00")
        digest.update(content)
        digest.update(b"\x00")
    return tuple(entries), digest.hexdigest()


@pytest.mark.parametrize(
    ("update_args", "flag_name"),
    [
        (("--assume-unchanged", "tracked.py"), "assume_unchanged"),
        (("--skip-worktree", "tracked.py"), "skip_worktree"),
        (("--fsmonitor",), "fsmonitor_valid"),
    ],
)
def test_hidden_git_index_state_fails_closed_before_diff_evidence(
    tmp_path: Path,
    update_args: tuple[str, ...],
    flag_name: str,
) -> None:
    repo = _repo(tmp_path)
    _run_git(repo, "update-index", *update_args)
    (repo / "tracked.py").write_text("hidden = 2\n", encoding="utf-8")

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["diff_files"] == []
    assert git_report["index_flags"][flag_name]
    assert git_report["errors"][0]["command"] == "repository_guard"
    assert "hidden-state flags" in git_report["errors"][0]["error"]


@pytest.mark.parametrize(
    "hazard",
    [
        "gitlink",
        "head_gitlink_deleted_from_index",
        "head_gitlink_missing_index",
        "head_gitmodules_missing_index",
        "gitmodules",
        "uppercase_gitmodules",
        "indexed_gitmodules",
        "indexed_uppercase_gitmodules",
        "git_modules_directory",
        "submodule_config",
        "legacy_submodule_config",
        "nested_git_directory",
        "uppercase_nested_git_directory",
        "nested_gitfile",
        "alternates",
        "http_alternates",
        "core_excludes_file",
        "core_attributes_file",
        "config_bom_core_excludes",
        "config_include",
        "config_include_if",
        "info_exclude",
    ],
)
def test_repository_hazards_fail_before_any_git_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hazard: str,
) -> None:
    repo = _repo(tmp_path)
    if hazard in {
        "gitlink",
        "head_gitlink_deleted_from_index",
        "head_gitlink_missing_index",
    }:
        head = subprocess.run(
            [_git(), "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        _run_git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{head},vendor/module",
        )
        if hazard in {"head_gitlink_deleted_from_index", "head_gitlink_missing_index"}:
            _run_git(repo, "commit", "-m", "gitlink baseline")
            _run_git(repo, "update-index", "--force-remove", "vendor/module")
        if hazard == "head_gitlink_missing_index":
            (repo / ".git" / "index").unlink()
    elif hazard == "head_gitmodules_missing_index":
        gitmodules = repo / ".gitmodules"
        gitmodules.write_text(
            '[submodule "vendor/module"]\n\tpath = vendor/module\n',
            encoding="utf-8",
        )
        _run_git(repo, "add", ".gitmodules")
        _run_git(repo, "commit", "-m", "gitmodules baseline")
        gitmodules.unlink()
        (repo / ".git" / "index").unlink()
    elif hazard in {"gitmodules", "uppercase_gitmodules"}:
        gitmodules_name = ".gitmodules" if hazard == "gitmodules" else ".GITMODULES"
        (repo / gitmodules_name).write_text(
            '[submodule "vendor/module"]\n\tpath = vendor/module\n',
            encoding="utf-8",
        )
    elif hazard in {"indexed_gitmodules", "indexed_uppercase_gitmodules"}:
        name = ".gitmodules" if hazard == "indexed_gitmodules" else ".GITMODULES"
        gitmodules = repo / name
        gitmodules.write_text(
            '[submodule "vendor/module"]\n\tpath = vendor/module\n',
            encoding="utf-8",
        )
        _run_git(repo, "add", name)
        gitmodules.unlink()
    elif hazard == "git_modules_directory":
        (repo / ".git" / "modules").mkdir()
    elif hazard in {"submodule_config", "legacy_submodule_config"}:
        key = (
            "submodule.vendor/module.url"
            if hazard == "submodule_config"
            else "submodule.vendor.url"
        )
        _run_git(repo, "config", key, "https://example.invalid/module.git")
    elif hazard in {
        "nested_git_directory",
        "uppercase_nested_git_directory",
        "nested_gitfile",
    }:
        (repo / ".gitignore").write_text("vendor/\n", encoding="utf-8")
        nested = repo / "vendor"
        nested.mkdir()
        if hazard in {"nested_git_directory", "uppercase_nested_git_directory"}:
            git_name = ".git" if hazard == "nested_git_directory" else ".GIT"
            (nested / git_name).mkdir()
        else:
            (nested / ".git").write_text(
                "gitdir: ../../outside-worktree\n",
                encoding="utf-8",
            )
    elif hazard in {"alternates", "http_alternates"}:
        alternate_name = "alternates" if hazard == "alternates" else "http-alternates"
        (repo / ".git" / "objects" / "info" / alternate_name).write_text(
            "../attacker-objects\n",
            encoding="utf-8",
        )
    elif hazard in {"core_excludes_file", "core_attributes_file"}:
        key = "core.excludesFile" if hazard == "core_excludes_file" else "core.attributesFile"
        _run_git(repo, "config", key, ".git/attacker-rules")
    elif hazard == "config_bom_core_excludes":
        config = repo / ".git" / "config"
        config.write_text(
            "\ufeff"
            + config.read_text(encoding="utf-8")
            + "\n[core]\n\texcludesFile = .git/attacker-rules\n",
            encoding="utf-8",
        )
    elif hazard in {"config_include", "config_include_if"}:
        key = "include.path" if hazard == "config_include" else "includeIf.gitdir:/.path"
        _run_git(repo, "config", key, ".git/attacker-config")
    elif hazard == "info_exclude":
        (repo / ".git" / "info" / "exclude").write_text(
            "hidden.py\n",
            encoding="utf-8",
        )
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(hazard)

    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    git_calls: list[tuple[object, ...]] = []

    def forbidden_git(*args: object, **_kwargs: object) -> dict[str, object]:
        git_calls.append(args)
        raise AssertionError("Git was invoked before repository preflight")

    monkeypatch.setattr(inspector, "_run_git", forbidden_git)

    payload = inspector.inspect_repository(
        root=repo,
        timeout_seconds=1,
        output_limit_bytes=100_000,
    )

    assert git_calls == []
    assert payload["status"] == []
    assert payload["unstaged_files"] == []
    assert payload["staged_files"] == []
    assert payload["errors"][0]["command"] == "repository_guard"
    if hazard == "core_attributes_file":
        assert "core.attributesfile" in payload["config_keys"]
    if hazard == "core_excludes_file":
        assert "core.excludesfile" in payload["config_keys"]


def test_unmerged_index_stages_fail_before_git_and_emit_no_source_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    branch = subprocess.run(
        [_git(), "branch", "--show-current"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    _run_git(repo, "checkout", "-b", "conflicting-side")
    (repo / "tracked.py").write_text("side = 2\n", encoding="utf-8")
    _run_git(repo, "add", "tracked.py")
    _run_git(repo, "commit", "-m", "side")
    _run_git(repo, "checkout", branch)
    (repo / "tracked.py").write_text("main = 3\n", encoding="utf-8")
    _run_git(repo, "add", "tracked.py")
    _run_git(repo, "commit", "-m", "main")
    _run_git(repo, "merge", "conflicting-side", allow_failure=True)

    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    git_calls: list[tuple[object, ...]] = []

    def forbidden_git(*args: object, **_kwargs: object) -> dict[str, object]:
        git_calls.append(args)
        raise AssertionError("Git was invoked for an unmerged source index")

    monkeypatch.setattr(inspector, "_run_git", forbidden_git)
    payload = inspector.inspect_repository(
        root=repo,
        timeout_seconds=1,
        output_limit_bytes=100_000,
    )

    assert git_calls == []
    assert "unmerged stages" in payload["errors"][0]["error"]
    for field in (
        "status",
        "unstaged_files",
        "staged_files",
        "unstaged_diff_stat",
        "staged_diff_stat",
        "unstaged_patch",
        "staged_patch",
    ):
        assert payload[field] in ([], "")


def test_same_size_restored_mtime_change_is_detected_with_private_stat_zero_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    target = repo / "tracked.py"
    committed = target.stat()
    source_index = repo / ".git" / "index"
    index_before = source_index.read_bytes()
    index_metadata_before = source_index.stat()
    target.write_text("new = 2\n", encoding="utf-8")
    os.utime(target, ns=(committed.st_atime_ns, committed.st_mtime_ns))
    changed = target.stat()
    assert changed.st_size == committed.st_size
    assert changed.st_mtime_ns == committed.st_mtime_ns

    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    payload = inspector.inspect_repository(
        root=repo,
        timeout_seconds=2,
        output_limit_bytes=100_000,
    )

    assert payload["errors"] == []
    assert payload["unstaged_files"] == ["tracked.py"]
    assert "+new = 2" in payload["unstaged_patch"]
    assert source_index.read_bytes() == index_before
    index_metadata_after = source_index.stat()
    assert index_metadata_after.st_size == index_metadata_before.st_size
    assert index_metadata_after.st_mtime_ns == index_metadata_before.st_mtime_ns


def test_repeated_inspection_preserves_every_source_git_byte_and_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    (repo / "tracked.py").write_text("new = 2\n", encoding="utf-8")
    before, before_hash = _git_state_snapshot(repo)
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")

    first = inspector.inspect_repository(
        root=repo,
        timeout_seconds=2,
        output_limit_bytes=100_000,
    )
    middle, middle_hash = _git_state_snapshot(repo)
    second = inspector.inspect_repository(
        root=repo,
        timeout_seconds=2,
        output_limit_bytes=100_000,
    )
    after, after_hash = _git_state_snapshot(repo)

    assert first["errors"] == second["errors"] == []
    assert first["unstaged_files"] == second["unstaged_files"] == ["tracked.py"]
    assert before == middle == after
    assert before_hash == middle_hash == after_hash


def test_static_config_key_inventory_accepts_exact_limits_and_rejects_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    exact_inventory = "[safe]\n" + "".join(
        f"key{index}\n" for index in range(inspector.MAX_CONFIG_ENTRIES)
    )

    keys, has_submodule = inspector._parse_static_config_keys(exact_inventory)

    assert len(keys) == inspector.MAX_CONFIG_ENTRIES
    assert has_submodule is False
    with pytest.raises(inspector.InspectorInputError, match="inventory exceeded"):
        inspector._parse_static_config_keys(
            exact_inventory + f"key{inspector.MAX_CONFIG_ENTRIES}\n"
        )

    exact_key = "a" * (inspector.MAX_CONFIG_KEY_CHARS - len("safe."))
    keys, _has_submodule = inspector._parse_static_config_keys(f"[safe]\n{exact_key}\n")
    assert len(keys[0]) == inspector.MAX_CONFIG_KEY_CHARS
    with pytest.raises(inspector.InspectorInputError, match="inventory exceeded"):
        inspector._parse_static_config_keys(f"[safe]\n{exact_key}a\n")


@pytest.mark.parametrize(
    ("config_key", "config_value"),
    [
        ("core.fsmonitor", "true"),
        ("core.abbrev", "4"),
        ("core.untrackedCache", "true"),
        ("core.attributesFile", "attributes"),
        ("color.ui", "always"),
        ("color.diff.meta", "red"),
        ("diff.noprefix", "true"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.srcPrefix", "source/"),
        ("diff.dstPrefix", "target/"),
        ("diff.external", "true"),
        ("diff.driver.binary", "true"),
        ("diff.driver.textconv", "true"),
        ("interactive.diffFilter", "true"),
    ],
)
def test_diff_affecting_repository_config_is_blocked_without_execution(
    tmp_path: Path,
    config_key: str,
    config_value: str,
) -> None:
    repo = _repo(tmp_path)
    _run_git(repo, "config", config_key, config_value)
    (repo / "tracked.py").write_text("changed = 2\n", encoding="utf-8")

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["errors"][0]["command"] == "repository_guard"
    assert "configuration" in git_report["errors"][0]["error"]
    assert config_key.lower() in git_report["config_keys"]
    if config_key.lower() == "core.attributesfile":
        assert "core.attributesfile" in git_report["errors"][0]["error"]


@pytest.mark.parametrize("attribute", ["-diff", "binary", "diff=driver"])
@pytest.mark.parametrize("nested", [False, True])
def test_diff_affecting_attributes_are_blocked_at_root_and_nested_paths(
    tmp_path: Path,
    attribute: str,
    nested: bool,
) -> None:
    changed_path = "nested/tracked.py" if nested else "tracked.py"
    repo = _repo(tmp_path, changed_path=changed_path)
    attributes = repo / ("nested/.gitattributes" if nested else ".gitattributes")
    attributes.write_text(f"tracked.py {attribute}\n", encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "attributes")
    (repo / changed_path).write_text("changed = 2\n", encoding="utf-8")

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["diff_files"] == []
    assert git_report["changed_ranges"] == []
    assert git_report["errors"][0]["command"] == "repository_guard"
    assert "attributes alter canonical diff semantics" in git_report["errors"][0]["error"]


def test_ident_attribute_cannot_hide_a_tracked_worktree_change(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".gitattributes").write_text("tracked.py ident\n", encoding="utf-8")
    (repo / "tracked.py").write_text("value = '$Id$'\n", encoding="utf-8")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-m", "ident baseline")
    (repo / "tracked.py").write_text(
        "value = '$Id: attacker-controlled $'\n",
        encoding="utf-8",
    )

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.CONTRADICTED
    assert git_report["diff_files"] == []
    assert git_report["changed_lines"] == []
    assert git_report["changed_symbols"] == []
    assert "ident" in git_report["errors"][0]["error"]


def test_canonical_patch_parser_binds_ambiguous_space_path_to_nul_inventory(
    tmp_path: Path,
) -> None:
    changed_path = "foo b/target.py"
    repo = _repo(tmp_path, changed_path=changed_path)
    (repo / changed_path).write_text("changed = 2\n", encoding="utf-8")

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]

    assert run.verdict is VerdictStatus.SUPPORTED
    assert git_report["errors"] == []
    assert git_report["diff_files"] == [changed_path]
    assert {item["path"] for item in git_report["changed_lines"]} == {changed_path}
    assert not any(item["path"] == "target.py" for item in git_report["changed_lines"])


def test_git_fingerprints_and_config_inventory_are_exposed_and_stable(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / "tracked.py").write_text("changed = 2\n", encoding="utf-8")

    run = _runner(tmp_path).run(_request())
    git_report = run.evidence[-1].structured_content["git"]
    fingerprints = git_report["inspection_fingerprints"]

    assert (
        fingerprints["workspace_fingerprint_before"] == fingerprints["workspace_fingerprint_after"]
    )
    assert (
        fingerprints["git_control_fingerprint_before"]
        == fingerprints["git_control_fingerprint_after"]
    )
    assert all(len(value) == 64 for value in fingerprints.values())
    assert git_report["config_keys"] == sorted(set(git_report["config_keys"]))
    assert "user.email" in git_report["config_keys"]


def test_payload_validator_rejects_fingerprint_drift_without_guard_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    payload = inspector.inspect_repository(
        root=repo,
        timeout_seconds=1,
        output_limit_bytes=100_000,
    )
    payload["workspace_fingerprint_after"] = "f" * 64
    payload["errors"] = []

    with pytest.raises(SandboxError, match="omitted a required"):
        _validate_git_inspection_payload(payload)


def test_guard_error_discards_all_diff_evidence_even_when_payload_contains_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    payload = inspector.inspect_repository(
        root=repo,
        timeout_seconds=1,
        output_limit_bytes=100_000,
    )
    payload.update(
        {
            "workspace_fingerprint_after": "f" * 64,
            "status": [" M tracked.py"],
            "unstaged_files": ["tracked.py"],
            "unstaged_diff_stat": " tracked.py | 1 +",
            "unstaged_patch": (
                "diff --git a/tracked.py b/tracked.py\n"
                "--- a/tracked.py\n"
                "+++ b/tracked.py\n"
                "@@ -1 +1 @@\n"
                "-old = 1\n"
                "+changed = 2\n"
            ),
            "errors": [
                {
                    "command": "repository_guard",
                    "error": "repository Git control surface changed during inspection",
                }
            ],
        }
    )
    normalized = _validate_git_inspection_payload(payload)

    report = _runner(tmp_path)._git_report_from_inspector({}, normalized)

    assert report["diff_files"] == []
    assert report["diff_stat"] == ""
    assert report["changed_ranges"] == []
    assert report["changed_lines"] == []
    assert report["changed_symbols"] == []
    assert report["errors"] == payload["errors"]


def test_git_subprocess_output_is_streamed_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        (
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 1000000); "
            "sys.stderr.buffer.write(b'y' * 1000000)",
        ),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=10,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
    )

    assert result["stdout"] == "x" * 128
    assert "output exceeded its safety limit" in str(result["error"])


def test_git_subprocess_cleans_inherited_pipe_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    marker = tmp_path / "git-descendant-survived.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {descendant!r}])"
    started_at = time.monotonic()

    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        ("-c", leader),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=2,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
    )

    assert result["error"] is None
    assert time.monotonic() - started_at < 1.5
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


def test_git_subprocess_timeout_cleans_descendant_and_pipe_threads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    marker = tmp_path / "git-timeout-descendant-survived.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); time.sleep(30)"
    )
    started_at = time.monotonic()

    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        ("-c", leader),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=0.2,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
    )

    assert result["timed_out"] is True
    assert time.monotonic() - started_at < 2.0
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


def test_git_subprocess_timeout_bounds_nonconsuming_stdin_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    started_at = time.monotonic()

    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        ("-c", "import time; time.sleep(30)"),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=0.2,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
        stdin_bytes=b"x" * 1_000_000,
    )

    assert result["timed_out"] is True
    assert time.monotonic() - started_at < 2.0
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


@pytest.mark.windows
def test_git_subprocess_fails_closed_on_job_assignment_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")

    def fail_assignment(*_args: object) -> None:
        raise OSError("synthetic Git Job assignment failure")

    monkeypatch.setattr(inspector, "_assign_process_to_windows_job", fail_assignment)
    started_at = time.monotonic()

    with pytest.raises(OSError, match="synthetic Git Job assignment failure"):
        inspector._run_git(
            PROCESS_TEST_EXECUTABLE,
            ("-c", "import time; time.sleep(30)"),
            root=tmp_path,
            scratch=tmp_path,
            timeout_seconds=2,
            output_limit_bytes=128,
            bind_repository=False,
            use_common_args=False,
        )

    assert time.monotonic() - started_at < 2.0
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


@pytest.mark.windows
def test_git_subprocess_propagates_job_termination_error_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    calls = 0
    marker = tmp_path / "git-termination-error-descendant.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {descendant!r}])"

    def fail_termination(_process: object, _job_handle: int | None) -> None:
        nonlocal calls
        calls += 1
        raise OSError("synthetic Git Job termination failure")

    monkeypatch.setattr(inspector, "_terminate_process_tree", fail_termination)
    started_at = time.monotonic()

    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        ("-c", leader),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=2,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
    )

    assert "command cleanup failed" in str(result["error"])
    assert calls == 1
    assert time.monotonic() - started_at < 2.0
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


def test_git_subprocess_fails_closed_on_pipe_capture_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")

    def fail_drain(*_args: object) -> None:
        raise OSError("synthetic Git pipe read failure")

    monkeypatch.setattr(inspector, "_drain_bounded_pipe", fail_drain)

    result = inspector._run_git(
        PROCESS_TEST_EXECUTABLE,
        ("-c", "print('MUST_CAPTURE')"),
        root=tmp_path,
        scratch=tmp_path,
        timeout_seconds=2,
        output_limit_bytes=128,
        bind_repository=False,
        use_common_args=False,
    )

    assert result["stdout"] == ""
    assert "pipe capture failed" in str(result["error"])
    assert not any(thread.name.startswith("sandbox-git-") for thread in threading.enumerate())


def test_inspector_commands_pin_the_canonical_diff_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    inspector = importlib.import_module("sandbox_git_inspector")
    required = {
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--text",
        "--no-ext-diff",
        "--no-textconv",
        "--full-index",
    }

    for field_name, argv in inspector.COMMANDS:
        if field_name == "status":
            continue
        assert required.issubset(argv)
    assert (
        json.loads(json.dumps(inspector._empty_payload(is_repository=True)))["schema_version"]
        == "sandbox_git_inspection.v1"
    )
