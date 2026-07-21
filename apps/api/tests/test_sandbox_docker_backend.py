from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hallu_defense.config import SandboxConfigurationError, Settings, validate_sandbox_settings
from hallu_defense.services.sandbox_exec import (
    SANDBOX_GIT_INSPECTOR_PATH,
    DockerContainerBackend,
    SandboxExecutionConfigurationError,
    SandboxExecutionError,
    build_sandbox_execution_backend,
    decode_sandbox_execution_batch,
)
from scripts.dev import live_docker_sandbox_smoke


def test_live_smoke_subprocess_capture_is_utf8_and_decode_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(live_docker_sandbox_smoke.subprocess, "run", fake_run)

    completed = live_docker_sandbox_smoke._run(["docker", "version"], timeout=5)

    assert completed.stdout == "ok"
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"
    assert captured["text"] is True
    assert captured["capture_output"] is True


class RecordingDockerRunner:
    def __init__(self, *, timeout_on_run: bool = False) -> None:
        self.timeout_on_run = timeout_on_run
        self.calls: list[tuple[list[str], float | None]] = []

    def __call__(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), timeout))
        if argv[:2] == ["docker", "run"] and self.timeout_on_run:
            cidfile = Path(_option_value(argv, "--cidfile"))
            cidfile.write_text("container-123\n", encoding="utf-8")
            raise subprocess.TimeoutExpired(
                cmd=list(argv),
                timeout=timeout or 0,
                output="partial stdout\n",
                stderr="partial stderr\n",
            )
        if argv[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(list(argv), 0, "container-123\n", "")
        commands = json.loads(argv[-1])
        payload = {
            "schema_version": "sandbox_execution_batch.v3",
            "pre_snapshot_fingerprint": "0" * 64,
            "post_snapshot_fingerprint": "1" * 64,
            "executions": [
                {
                    "returncode": 0,
                    "stdout": "docker ok\n",
                    "stderr": "",
                    "timed_out": False,
                }
                for _command in commands
            ],
            "artifacts": [],
        }
        return subprocess.CompletedProcess(
            list(argv),
            0,
            json.dumps(payload, separators=(",", ":")),
            "",
        )


def test_batch_v3_allows_normal_command_to_change_ephemeral_snapshot() -> None:
    payload = {
        "schema_version": "sandbox_execution_batch.v3",
        "pre_snapshot_fingerprint": "0" * 64,
        "post_snapshot_fingerprint": "1" * 64,
        "executions": [{"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}],
        "artifacts": [],
    }

    result = decode_sandbox_execution_batch(
        json.dumps(payload),
        expected_count=1,
        output_caps=100,
    )

    assert result.pre_snapshot_fingerprint == "0" * 64
    assert result.post_snapshot_fingerprint == "1" * 64


@pytest.mark.parametrize(
    "payload",
    [
        {
            "schema_version": "sandbox_execution_batch.v2",
            "snapshot_fingerprint": "0" * 64,
            "executions": [],
            "artifacts": [],
        },
        {
            "schema_version": "sandbox_execution_batch.v3",
            "pre_snapshot_fingerprint": "0" * 64,
            "executions": [],
            "artifacts": [],
        },
        {
            "schema_version": "sandbox_execution_batch.v3",
            "pre_snapshot_fingerprint": "0" * 64,
            "post_snapshot_fingerprint": "A" * 64,
            "executions": [],
            "artifacts": [],
        },
    ],
)
def test_batch_decoder_rejects_results_without_exact_v3_fingerprints(
    payload: dict[str, object],
) -> None:
    with pytest.raises(SandboxExecutionError):
        decode_sandbox_execution_batch(
            json.dumps(payload),
            expected_count=0,
            output_caps=100,
        )


def test_host_subprocess_backend_is_rejected_even_outside_production(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, sandbox_backend="host")

    with pytest.raises(SandboxConfigurationError, match="cannot enforce.*network"):
        validate_sandbox_settings(settings)
    with pytest.raises(
        SandboxExecutionConfigurationError,
        match="cannot enforce.*network",
    ):
        build_sandbox_execution_backend(settings)


def test_docker_backend_builds_pinned_isolation_argv_without_shell(tmp_path: Path) -> None:
    source = tmp_path / "source repo"
    source.mkdir()
    recording_runner = RecordingDockerRunner()
    backend = DockerContainerBackend(
        image="hallu-defense-sandbox:ci",
        docker_path="docker",
        memory_mb=512,
        cpus=1.0,
        pids_limit=256,
        timeout_grace_seconds=2,
        runner=recording_runner,
    )

    result = backend.execute(
        ["python", "probe.py"],
        cwd=source,
        source_cwd=source,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny", "API_KEY": "secret-value"},
        timeout=5,
        output_caps=100,
    )

    assert result.returncode == 0
    assert recording_runner.calls
    argv, timeout = recording_runner.calls[0]
    assert timeout == 10
    assert all(isinstance(part, str) for part in argv)
    assert "--network=none" in argv
    assert "--rm" in argv
    assert "--read-only" in argv
    assert _option_value(argv, "--tmpfs") == ("/tmp:rw,nosuid,nodev,size=64m,mode=1777")
    assert _option_value(argv, "--cap-drop") == "ALL"
    assert _option_value(argv, "--security-opt") == "no-new-privileges"
    assert _option_value(argv, "--pids-limit") == "256"
    assert _option_value(argv, "--memory") == "512m"
    assert _option_value(argv, "--cpus") == "1.0"
    assert _option_value(argv, "--user") == "10001"
    assert _option_value(argv, "--workdir") == "/workspace"
    assert argv.count("--mount") == 2
    source_mount, workspace_mount = _option_values(argv, "--mount")
    assert source_mount.startswith("type=bind,source=")
    assert source_mount.endswith("target=/hallu-source,readonly")
    assert workspace_mount == ("type=tmpfs,target=/workspace,tmpfs-size=536870912,tmpfs-mode=1777")
    assert "sandbox_runner.py" in "\n".join(argv)
    assert "sandbox_batch_runner.py" in "\n".join(argv)
    serialized = "\n".join(argv)
    assert "API_KEY" not in serialized
    assert "secret-value" not in serialized


def test_docker_backend_batches_commands_in_one_bounded_container(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    recording_runner = RecordingDockerRunner()
    backend = DockerContainerBackend(
        image="hallu-defense-sandbox:ci",
        runner=recording_runner,
    )

    result = backend.execute_batch(
        [["python", "first.py"], ["node", "second.js"]],
        cwd=source,
        source_cwd=source,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        timeout=5,
        output_caps=1000,
    )

    assert [item.returncode for item in result.executions] == [0, 0]
    docker_runs = [call for call in recording_runner.calls if call[0][:2] == ["docker", "run"]]
    assert len(docker_runs) == 1
    argv, outer_timeout = docker_runs[0]
    assert outer_timeout == 15
    assert json.loads(argv[-1]) == [
        ["python", "first.py"],
        ["node", "second.js"],
    ]


def test_docker_backend_mounts_git_source_read_only_and_copy_as_bounded_tmpfs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    backend = DockerContainerBackend(image="hallu-defense-sandbox:ci")

    argv = backend.build_run_argv(
        ["python", SANDBOX_GIT_INSPECTOR_PATH, "0.625", "1024"],
        cwd=source,
        source_cwd=source,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
    )

    source_mount, workspace_mount = _option_values(argv, "--mount")
    assert source_mount.endswith("target=/hallu-source,readonly")
    assert workspace_mount == ("type=tmpfs,target=/workspace,tmpfs-size=536870912,tmpfs-mode=1777")


def test_docker_backend_rejects_caller_supplied_writable_working_copy(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    backend = DockerContainerBackend(image="hallu-defense-sandbox:ci")

    working_copy = tmp_path / "working"
    working_copy.mkdir()

    with pytest.raises(SandboxExecutionError, match="owns the ephemeral working copy"):
        backend.build_run_argv(
            ["python", "probe.py"],
            cwd=working_copy,
            source_cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        )


def test_docker_backend_timeout_kills_recorded_container(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    recording_runner = RecordingDockerRunner(timeout_on_run=True)
    backend = DockerContainerBackend(
        image="hallu-defense-sandbox:ci",
        timeout_grace_seconds=3,
        runner=recording_runner,
    )

    with pytest.raises(SandboxExecutionError, match="orchestration deadline"):
        backend.execute(
            ["python", "slow.py"],
            cwd=source,
            source_cwd=source,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=1,
            output_caps=500,
        )

    assert recording_runner.calls[1] == (["docker", "kill", "container-123"], 3)


@pytest.mark.parametrize("backend_name", ["docker"])
def test_sandbox_settings_reject_non_kubernetes_backend_in_production_and_staging(
    tmp_path: Path,
    backend_name: str,
) -> None:
    for environment in ("production", "staging"):
        settings = _settings(
            tmp_path,
            environment=environment,
            sandbox_backend=backend_name,
        )

        with pytest.raises(SandboxConfigurationError, match="SANDBOX_BACKEND=kubernetes"):
            validate_sandbox_settings(settings)
        with pytest.raises(
            SandboxExecutionConfigurationError,
            match="SANDBOX_BACKEND=kubernetes",
        ):
            build_sandbox_execution_backend(settings)


def test_sandbox_settings_accept_docker_backend_for_local_ci_only(tmp_path: Path) -> None:
    settings = _settings(tmp_path, environment="test", sandbox_backend="docker")

    validate_sandbox_settings(settings)
    backend = build_sandbox_execution_backend(settings)

    assert isinstance(backend, DockerContainerBackend)


def _option_value(argv: list[str], option: str) -> str:
    index = argv.index(option)
    return argv[index + 1]


def _option_values(argv: list[str], option: str) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv) if value == option]


def _settings(
    tmp_path: Path,
    *,
    environment: str = "test",
    sandbox_backend: str = "docker",
) -> Settings:
    return Settings(
        environment=environment,
        policy_version="test",
        auth_required=False,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        sandbox_backend=sandbox_backend,
    )
