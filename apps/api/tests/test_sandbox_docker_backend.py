from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hallu_defense.config import SandboxConfigurationError, Settings, validate_sandbox_settings
from hallu_defense.domain.models import RepoChecksRunRequest
from hallu_defense.services.sandbox import SandboxRunner
from hallu_defense.services.sandbox_exec import (
    DOCKER_TIMEOUT_RETURN_CODE,
    DockerContainerBackend,
    HostSubprocessBackend,
    SandboxExecutionConfigurationError,
    build_sandbox_execution_backend,
)


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
        return subprocess.CompletedProcess(list(argv), 0, "docker ok\n", "")


def test_host_subprocess_backend_keeps_sandbox_runner_compatibility(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    runner = SandboxRunner(_settings(tmp_path), execution_backend=HostSubprocessBackend())

    run = runner.run(RepoChecksRunRequest(repo_ref="repo", commands=["python --version"]))

    assert run.exit_codes == [0]
    assert run.evidence[0].structured_content["argv"] == ["python", "--version"]
    assert run.evidence[1].structured_content["schema_version"] == "sandbox_inspection.v1"


def test_docker_backend_builds_pinned_isolation_argv_without_shell(tmp_path: Path) -> None:
    repo = tmp_path / "repo with spaces"
    repo.mkdir()
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
        cwd=repo,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny", "API_KEY": "secret-value"},
        timeout=5,
        output_caps=100,
    )

    assert result.returncode == 0
    assert recording_runner.calls
    argv, timeout = recording_runner.calls[0]
    assert timeout == 5
    assert all(isinstance(part, str) for part in argv)
    assert "--network=none" in argv
    assert "--rm" in argv
    assert "--read-only" in argv
    assert _option_value(argv, "--tmpfs") == "/tmp"
    assert _option_value(argv, "--cap-drop") == "ALL"
    assert _option_value(argv, "--security-opt") == "no-new-privileges"
    assert _option_value(argv, "--pids-limit") == "256"
    assert _option_value(argv, "--memory") == "512m"
    assert _option_value(argv, "--cpus") == "1.0"
    assert _option_value(argv, "--user") == "10001"
    assert _option_value(argv, "--workdir") == "/workspace"
    assert argv.count("--mount") == 1
    mount = _option_value(argv, "--mount")
    assert mount.startswith("type=bind,source=")
    assert "target=/workspace" in mount
    assert "readonly" not in mount
    assert argv[-3:] == ["hallu-defense-sandbox:ci", "python", "probe.py"]
    serialized = "\n".join(argv)
    assert "API_KEY" not in serialized
    assert "secret-value" not in serialized


def test_docker_backend_timeout_kills_recorded_container(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    recording_runner = RecordingDockerRunner(timeout_on_run=True)
    backend = DockerContainerBackend(
        image="hallu-defense-sandbox:ci",
        timeout_grace_seconds=3,
        runner=recording_runner,
    )

    result = backend.execute(
        ["python", "slow.py"],
        cwd=repo,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        timeout=1,
        output_caps=500,
    )

    assert result.returncode == DOCKER_TIMEOUT_RETURN_CODE
    assert result.timed_out is True
    assert "partial stdout" in result.stdout
    assert "docker kill completed" in result.stderr
    assert recording_runner.calls[1] == (["docker", "kill", "container-123"], 3)


def test_sandbox_settings_reject_host_backend_in_production_and_staging(tmp_path: Path) -> None:
    for environment in ("production", "staging"):
        settings = _settings(tmp_path, environment=environment, sandbox_backend="host")

        with pytest.raises(SandboxConfigurationError, match="SANDBOX_BACKEND=docker"):
            validate_sandbox_settings(settings)
        with pytest.raises(SandboxExecutionConfigurationError, match="SANDBOX_BACKEND=docker"):
            build_sandbox_execution_backend(settings)


def test_sandbox_settings_accept_docker_backend_in_staging(tmp_path: Path) -> None:
    settings = _settings(tmp_path, environment="staging", sandbox_backend="docker")

    validate_sandbox_settings(settings)
    backend = build_sandbox_execution_backend(settings)

    assert isinstance(backend, DockerContainerBackend)


def _option_value(argv: list[str], option: str) -> str:
    index = argv.index(option)
    return argv[index + 1]


def _settings(
    tmp_path: Path,
    *,
    environment: str = "test",
    sandbox_backend: str = "host",
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
