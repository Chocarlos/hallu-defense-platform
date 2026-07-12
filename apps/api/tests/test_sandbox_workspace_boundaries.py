from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import hallu_defense.services.sandbox as sandbox_module
import hallu_defense.services.sandbox_exec as sandbox_exec_module
from hallu_defense.services.sandbox import SandboxError, SandboxRunner
from hallu_defense.services.sandbox_exec import SandboxExecutionError


ROOT = Path(__file__).resolve().parents[3]
DOCKER_HELPERS = ROOT / "infra" / "docker"
PROCESS_TEST_EXECUTABLE = getattr(sys, "_base_executable", sys.executable)


def _load_helper(module_name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        module_name,
        DOCKER_HELPERS / filename,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    helper_path = str(DOCKER_HELPERS)
    inserted = helper_path not in sys.path
    if inserted:
        sys.path.insert(0, helper_path)
    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(helper_path)
    return module


def test_api_fingerprint_accepts_exact_byte_limit_with_trailing_zero_byte_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "payload.bin").write_bytes(b"1234")
    (tmp_path / "zero.bin").write_bytes(b"")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 4)

    fingerprint = sandbox_module._workspace_fingerprint(tmp_path)

    assert len(fingerprint) == 64


def test_api_fingerprint_rejects_one_byte_over_exact_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "payload.bin").write_bytes(b"12345")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 4)

    with pytest.raises(SandboxError, match="byte size exceeded"):
        sandbox_module._workspace_fingerprint(tmp_path)


def test_api_fingerprint_counts_zero_byte_files_and_empty_directories_as_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "empty-dir").mkdir()
    (tmp_path / "zero.bin").write_bytes(b"")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_PATHS", 2)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 0)

    assert len(sandbox_module._workspace_fingerprint(tmp_path)) == 64
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_PATHS", 1)
    with pytest.raises(SandboxError, match="path count exceeded"):
        sandbox_module._workspace_fingerprint(tmp_path)


def test_api_fingerprint_enforces_per_path_and_aggregate_path_byte_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = tmp_path / "aa"
    second = tmp_path / "bbb"
    first.write_bytes(b"")
    second.write_bytes(b"")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 0)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_PATH_BYTES", 3)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_TOTAL_PATH_BYTES", 5)

    assert len(sandbox_module._workspace_fingerprint(tmp_path)) == 64
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_TOTAL_PATH_BYTES", 4)
    with pytest.raises(SandboxError, match="path byte size exceeded"):
        sandbox_module._workspace_fingerprint(tmp_path)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_TOTAL_PATH_BYTES", 5)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_PATH_BYTES", 2)
    with pytest.raises(SandboxError, match="path exceeded"):
        sandbox_module._workspace_fingerprint(tmp_path)


def test_container_and_api_fingerprints_match_at_zero_byte_and_mode_boundaries(
    tmp_path: Path,
) -> None:
    workspace_helper = _load_helper(
        "sandbox_workspace_boundaries",
        "sandbox_workspace.py",
    )
    (tmp_path / "empty-dir").mkdir()
    (tmp_path / "zero.bin").write_bytes(b"")
    executable = tmp_path / "probe.py"
    executable.write_bytes(b"print('ok')\n")
    if os.name != "nt":
        executable.chmod(0o750)

    assert workspace_helper.workspace_fingerprint(
        tmp_path,
        max_files=2,
        max_bytes=executable.stat().st_size,
        max_paths=3,
        max_path_bytes=len("empty-dir"),
        max_total_path_bytes=sum(len(value) for value in ("empty-dir", "zero.bin", "probe.py")),
    ) == sandbox_module._workspace_fingerprint(tmp_path)


def test_executable_mode_is_normalized_in_cross_platform_fingerprints(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not expose POSIX executable mode semantics")
    workspace_helper = _load_helper(
        "sandbox_workspace_executable_mode",
        "sandbox_workspace.py",
    )
    target = tmp_path / "probe.sh"
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    target.chmod(0o600)
    api_before = sandbox_module._workspace_fingerprint(tmp_path)
    container_before = workspace_helper.workspace_fingerprint(tmp_path)

    target.chmod(0o700)

    api_after = sandbox_module._workspace_fingerprint(tmp_path)
    container_after = workspace_helper.workspace_fingerprint(tmp_path)
    assert api_before == container_before
    assert api_after == container_after
    assert api_after == api_before


def test_container_fingerprint_rejects_path_count_and_path_bytes_over_limit(
    tmp_path: Path,
) -> None:
    workspace_helper = _load_helper(
        "sandbox_workspace_limits",
        "sandbox_workspace.py",
    )
    (tmp_path / "a").mkdir()
    (tmp_path / "bb").write_bytes(b"")

    with pytest.raises(ValueError, match="path count"):
        workspace_helper.workspace_fingerprint(
            tmp_path,
            max_files=1,
            max_bytes=0,
            max_paths=1,
        )
    with pytest.raises(ValueError, match="path limit"):
        workspace_helper.workspace_fingerprint(
            tmp_path,
            max_files=1,
            max_bytes=0,
            max_path_bytes=1,
        )
    with pytest.raises(ValueError, match="total path byte"):
        workspace_helper.workspace_fingerprint(
            tmp_path,
            max_files=1,
            max_bytes=0,
            max_total_path_bytes=2,
        )


def test_windows_path_ctime_is_not_compared_to_descriptor_write_time() -> None:
    workspace_helper = _load_helper(
        "sandbox_workspace_windows_ctime",
        "sandbox_workspace.py",
    )
    git_inspector = _load_helper(
        "sandbox_git_inspector_windows_ctime",
        "sandbox_git_inspector.py",
    )
    common = {
        "st_dev": 0,
        "st_ino": 0,
        "st_mode": stat.S_IFREG | 0o600,
        "st_size": 4,
        "st_mtime_ns": 100,
    }
    path_snapshot = SimpleNamespace(**common, st_ctime_ns=111)
    descriptor_before = SimpleNamespace(**common, st_ctime_ns=222)
    descriptor_same = SimpleNamespace(**common, st_ctime_ns=222)
    descriptor_changed = SimpleNamespace(**common, st_ctime_ns=223)
    descriptor_mode_changed = SimpleNamespace(
        **{**common, "st_mode": stat.S_IFREG | 0o400},
        st_ctime_ns=222,
    )
    descriptor_size_changed = SimpleNamespace(
        **{**common, "st_size": 5},
        st_ctime_ns=222,
    )
    descriptor_mtime_changed = SimpleNamespace(
        **{**common, "st_mtime_ns": 101},
        st_ctime_ns=222,
    )

    assert sandbox_module._same_file_identity(path_snapshot, descriptor_before)
    assert workspace_helper._same_file_identity(path_snapshot, descriptor_before)
    assert git_inspector._same_file_identity(path_snapshot, descriptor_before)
    for helper in (sandbox_module, workspace_helper, git_inspector):
        assert helper._same_file_identity(path_snapshot, descriptor_changed)
        assert not helper._same_file_identity(
            SimpleNamespace(**{**common, "st_dev": 1, "st_ino": 2}, st_ctime_ns=1),
            SimpleNamespace(
                **{
                    **common,
                    "st_dev": 1,
                    "st_ino": 2,
                    "st_mode": stat.S_IFREG | 0o400,
                },
                st_ctime_ns=2,
            ),
        )
        assert not helper._same_file_identity(
            path_snapshot,
            descriptor_size_changed,
        )
    assert sandbox_module._same_descriptor_snapshot(
        descriptor_before,
        descriptor_same,
    )
    assert workspace_helper._same_descriptor_snapshot(
        descriptor_before,
        descriptor_same,
    )
    assert git_inspector._same_descriptor_snapshot(
        descriptor_before,
        descriptor_same,
    )
    assert not sandbox_module._same_descriptor_snapshot(
        descriptor_before,
        descriptor_changed,
    )
    assert not workspace_helper._same_descriptor_snapshot(
        descriptor_before,
        descriptor_mode_changed,
    )
    for changed in (
        descriptor_changed,
        descriptor_mode_changed,
        descriptor_size_changed,
        descriptor_mtime_changed,
    ):
        assert not sandbox_module._same_descriptor_snapshot(descriptor_before, changed)
        assert not workspace_helper._same_descriptor_snapshot(
            descriptor_before,
            changed,
        )
        assert not git_inspector._same_descriptor_snapshot(
            descriptor_before,
            changed,
        )


def test_default_process_runner_streams_and_discards_output_after_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_exec_module, "MAX_DOCKER_CLI_OUTPUT_BYTES", 1024)

    completed = sandbox_exec_module._run_docker(
        [
            PROCESS_TEST_EXECUTABLE,
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 1000000); "
            "sys.stderr.buffer.write(b'y' * 1000000)",
        ],
        timeout=10,
    )

    assert completed.returncode == 0
    assert completed.stdout == "x" * 1024
    assert completed.stderr == "y" * 1024


def test_batch_command_output_limit_rejects_exact_limit_plus_one() -> None:
    assert sandbox_exec_module._validated_batch_commands(
        [["python", "probe.py"]],
        timeout=1,
        output_caps=sandbox_exec_module.MAX_SANDBOX_OUTPUT_CHARS,
    ) == [["python", "probe.py"]]

    with pytest.raises(SandboxExecutionError, match="positive and bounded"):
        sandbox_exec_module._validated_batch_commands(
            [["python", "probe.py"]],
            timeout=1,
            output_caps=sandbox_exec_module.MAX_SANDBOX_OUTPUT_CHARS + 1,
        )


def test_batch_decoder_rejects_artifact_path_over_byte_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_exec_module, "MAX_SANDBOX_PATH_BYTES", 8)
    payload = {
        "schema_version": "sandbox_execution_batch.v3",
        "pre_snapshot_fingerprint": "0" * 64,
        "post_snapshot_fingerprint": "1" * 64,
        "executions": [{"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}],
        "artifacts": ["artifacts/too-long.txt"],
    }

    with pytest.raises(SandboxExecutionError, match="unsafe artifact path"):
        sandbox_exec_module.decode_sandbox_execution_batch(
            json.dumps(payload),
            expected_count=1,
            output_caps=100,
        )


def test_default_process_runner_timeout_output_remains_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_exec_module, "MAX_DOCKER_CLI_OUTPUT_BYTES", 512)

    with pytest.raises(subprocess.TimeoutExpired) as captured:
        sandbox_exec_module._run_docker(
            [
                PROCESS_TEST_EXECUTABLE,
                "-c",
                "import sys, time; sys.stdout.buffer.write(b'x' * 1000000); "
                "sys.stdout.flush(); time.sleep(30)",
            ],
            timeout=0.2,
        )

    assert isinstance(captured.value.output, str)
    assert len(captured.value.output) <= 512


def test_default_process_runner_cleans_inherited_pipe_descendant(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "docker-descendant-survived.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {descendant!r}])"
    started_at = time.monotonic()

    completed = sandbox_exec_module._run_docker(
        [PROCESS_TEST_EXECUTABLE, "-c", leader],
        timeout=2,
    )

    assert completed.returncode == 0
    assert time.monotonic() - started_at < 1.5
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-docker-") for thread in threading.enumerate())


def test_default_process_runner_timeout_cleans_descendant_and_pipe_threads(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "docker-timeout-descendant-survived.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); time.sleep(30)"
    )
    started_at = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        sandbox_exec_module._run_docker(
            [PROCESS_TEST_EXECUTABLE, "-c", leader],
            timeout=0.2,
        )

    assert time.monotonic() - started_at < 2.0
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-docker-") for thread in threading.enumerate())


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object regression")
def test_default_process_runner_fails_closed_on_job_assignment_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_assignment(*_args: object) -> None:
        raise OSError("synthetic Job assignment failure")

    monkeypatch.setattr(
        sandbox_exec_module,
        "_assign_process_to_windows_job",
        fail_assignment,
    )
    started_at = time.monotonic()

    with pytest.raises(OSError, match="synthetic Job assignment failure"):
        sandbox_exec_module._run_docker(
            [PROCESS_TEST_EXECUTABLE, "-c", "import time; time.sleep(30)"],
            timeout=2,
        )

    assert time.monotonic() - started_at < 2.0
    assert not any(thread.name.startswith("sandbox-docker-") for thread in threading.enumerate())


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object regression")
def test_default_process_runner_propagates_job_termination_error_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = 0
    marker = tmp_path / "docker-termination-error-descendant.txt"
    descendant = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    leader = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {descendant!r}])"

    def fail_termination(_process: object, _job_handle: int | None) -> None:
        nonlocal calls
        calls += 1
        raise OSError("synthetic Job termination failure")

    monkeypatch.setattr(
        sandbox_exec_module,
        "_terminate_owned_process_tree",
        fail_termination,
    )
    started_at = time.monotonic()

    with pytest.raises(SandboxExecutionError, match="cleanup failed") as raised:
        sandbox_exec_module._run_docker(
            [PROCESS_TEST_EXECUTABLE, "-c", leader],
            timeout=2,
        )

    assert isinstance(raised.value.__cause__, OSError)
    assert calls == 1
    assert time.monotonic() - started_at < 2.0
    time.sleep(0.7)
    assert not marker.exists()
    assert not any(thread.name.startswith("sandbox-docker-") for thread in threading.enumerate())


def test_default_process_runner_fails_closed_on_pipe_capture_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_drain(*_args: object) -> None:
        raise OSError("synthetic Docker pipe read failure")

    monkeypatch.setattr(sandbox_exec_module, "_drain_bounded_pipe", fail_drain)

    with pytest.raises(SandboxExecutionError, match="pipe capture failed") as raised:
        sandbox_exec_module._run_docker(
            [PROCESS_TEST_EXECUTABLE, "-c", "print('MUST_CAPTURE')"],
            timeout=2,
        )

    assert isinstance(raised.value.__cause__, OSError)
    assert not any(thread.name.startswith("sandbox-docker-") for thread in threading.enumerate())


def test_batch_runner_streams_large_output_without_temporary_file_growth(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    batch_runner = _load_helper(
        "sandbox_batch_runner_boundaries",
        "sandbox_batch_runner.py",
    )

    result = batch_runner.execute_command(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 1000000); "
            "sys.stderr.buffer.write(b'y' * 1000000)",
        ],
        cwd=tmp_path,
        timeout=10,
        output_caps=128,
    )

    assert result == {
        "returncode": 0,
        "stdout": "x" * 128,
        "stderr": "y" * 128,
        "timed_out": False,
    }


def test_batch_runner_fails_closed_on_pipe_capture_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    batch_runner = _load_helper(
        "sandbox_batch_runner_pipe_error",
        "sandbox_batch_runner.py",
    )

    def fail_drain(*_args: object) -> None:
        raise OSError("synthetic batch pipe read failure")

    monkeypatch.setattr(batch_runner, "_drain_bounded_pipe", fail_drain)

    with pytest.raises(RuntimeError, match="pipe capture failed") as raised:
        batch_runner.execute_command(
            [PROCESS_TEST_EXECUTABLE, "-c", "print('MUST_CAPTURE')"],
            cwd=tmp_path,
            timeout=2,
            output_caps=128,
        )

    assert isinstance(raised.value.__cause__, OSError)
    assert not any(thread.name.startswith("sandbox-batch-") for thread in threading.enumerate())


def test_runner_and_artifact_walkers_do_not_use_materializing_path_iterdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    runner = _load_helper("sandbox_runner_scandir", "sandbox_runner.py")
    batch_runner = _load_helper("sandbox_batch_runner_scandir", "sandbox_batch_runner.py")
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    artifacts = source / "artifacts"
    artifacts.mkdir()
    (artifacts / "result.txt").write_text("result", encoding="utf-8")

    def forbidden_iterdir(_path: Path) -> object:
        raise AssertionError("Path.iterdir materializes os.listdir output")

    monkeypatch.setattr(Path, "iterdir", forbidden_iterdir)

    runner.validate_workspace_tree(source, max_files=1, max_bytes=6)
    runner.copy_workspace_tree(source, destination, max_files=1, max_bytes=6)
    assert batch_runner.artifact_snapshot(source)["artifacts/result.txt"][0] == 6


def test_linux_batch_runner_reaps_detached_descendant_before_snapshot(
    tmp_path: Path,
) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux subreaper behavior is exercised in the sandbox container")
    marker = tmp_path / "detached-survived.txt"
    helper_path = str(DOCKER_HELPERS)
    grandchild = (
        "import pathlib,time; time.sleep(0.4); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    command = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, start_new_session=True)"
    )
    driver = (
        "import json,sys,time; "
        f"sys.path.insert(0, {helper_path!r}); "
        "import sandbox_batch_runner as runner; "
        f"result=runner.execute_command([sys.executable, '-c', {command!r}], "
        f"cwd=__import__('pathlib').Path({str(tmp_path)!r}), timeout=5, output_caps=1000); "
        "time.sleep(0.8); "
        f"print(json.dumps({{'result': result, 'marker': __import__('pathlib').Path({str(marker)!r}).exists()}}))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", driver],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["result"]["returncode"] == 0
    assert payload["marker"] is False
    time.sleep(0.1)
    assert not marker.exists()


def test_container_workspace_copy_rejects_source_identity_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    runner = _load_helper("sandbox_runner_boundaries", "sandbox_runner.py")
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    target = source / "target.txt"
    target.write_text("original", encoding="utf-8")
    expected = target.lstat()
    replacement = source / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")
    target.unlink()
    replacement.replace(target)

    with pytest.raises(ValueError, match="changed before copy"):
        runner._copy_regular_file_no_follow(
            source,
            target,
            destination / "target.txt",
            expected,
        )


def test_container_regular_file_hash_rejects_source_identity_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    workspace_helper = _load_helper(
        "sandbox_workspace_hash_identity",
        "sandbox_workspace.py",
    )
    target = tmp_path / "target.txt"
    target.write_text("original", encoding="utf-8")
    expected = target.lstat()
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")
    target.unlink()
    replacement.replace(target)

    with pytest.raises(ValueError, match="changed before fingerprinting"):
        workspace_helper.regular_file_sha256(tmp_path, target, expected)


def test_fallback_artifact_snapshot_enforces_aggregate_exact_byte_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "payload.bin").write_bytes(b"1234")
    (artifacts / "zero.bin").write_bytes(b"")
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 4)
    runner = object.__new__(SandboxRunner)

    snapshot = runner._artifact_snapshot(tmp_path)

    assert snapshot["artifacts/payload.bin"][0] == 4
    assert snapshot["artifacts/zero.bin"][0] == 0
    (artifacts / "over.bin").write_bytes(b"x")
    with pytest.raises(SandboxError, match="artifact bytes exceeded"):
        runner._artifact_snapshot(tmp_path)


def test_fallback_artifact_snapshot_shares_path_budget_across_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for root_name, file_name in (("artifacts", "a"), ("reports", "b")):
        artifact_root = tmp_path / root_name
        artifact_root.mkdir()
        (artifact_root / file_name).write_bytes(b"")
    runner = object.__new__(SandboxRunner)
    relative_paths = ("artifacts/a", "reports/b")
    exact_path_bytes = sum(len(path.encode("utf-8")) for path in relative_paths)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_BYTES", 0)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_PATHS", 2)
    monkeypatch.setattr(
        sandbox_module,
        "MAX_SANDBOX_TOTAL_PATH_BYTES",
        exact_path_bytes,
    )

    assert sorted(runner._artifact_snapshot(tmp_path)) == list(relative_paths)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_PATHS", 1)
    with pytest.raises(SandboxError, match="path count exceeded"):
        runner._artifact_snapshot(tmp_path)
    monkeypatch.setattr(sandbox_module, "MAX_SANDBOX_WORKSPACE_PATHS", 2)
    monkeypatch.setattr(
        sandbox_module,
        "MAX_SANDBOX_TOTAL_PATH_BYTES",
        exact_path_bytes - 1,
    )
    with pytest.raises(SandboxError, match="path byte size exceeded"):
        runner._artifact_snapshot(tmp_path)


def test_container_workspace_copy_accepts_zero_byte_at_exact_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(DOCKER_HELPERS))
    runner = _load_helper("sandbox_runner_zero_boundary", "sandbox_runner.py")
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    (source / "zero.bin").write_bytes(b"")

    runner.copy_workspace_tree(
        source,
        destination,
        max_files=1,
        max_bytes=0,
    )

    copied = destination / "zero.bin"
    assert copied.is_file()
    assert copied.stat().st_size == 0
