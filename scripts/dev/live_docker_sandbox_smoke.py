"""Opt-in live smoke for the Docker sandbox execution backend."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import Settings  # noqa: E402
from hallu_defense.domain.models import RepoChecksRunRequest  # noqa: E402
from hallu_defense.services.sandbox import SandboxRunner  # noqa: E402
from hallu_defense.services.sandbox_exec import DockerContainerBackend  # noqa: E402

ENABLED_ENV = "HALLU_DEFENSE_LIVE_DOCKER_SANDBOX_SMOKE_ENABLED"
IMAGE_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE"
DOCKER_PATH_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_PATH"
MEMORY_MB_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB"
CPUS_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_CPUS"
PIDS_LIMIT_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT"
TIMEOUT_GRACE_ENV = "HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS"


class LiveDockerSandboxSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveDockerSandboxSmokeConfig:
    docker_path: str = "docker"
    image: str = "hallu-defense-sandbox:ci"
    memory_mb: int = 512
    cpus: float = 1.0
    pids_limit: int = 256
    timeout_grace_seconds: float = 2.0


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live Docker sandbox smoke",
        }

    config = _config_from_env(effective_env)
    docker_check = _docker_available(config)
    if docker_check is not None:
        return docker_check

    _run_checked(
        [
            config.docker_path,
            "build",
            "-f",
            "infra/docker/sandbox.Dockerfile",
            "-t",
            config.image,
            ".",
        ],
        timeout=300,
    )

    var_dir = ROOT / "var"
    var_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hallu-live-docker-sandbox-", dir=var_dir) as temp_dir:
        workspace = Path(temp_dir)
        repo = workspace / "repo"
        repo.mkdir(parents=True)
        _make_writable_for_container(repo)
        _write_probe_scripts(repo)

        runner = SandboxRunner(_settings(config, workspace, max_command_seconds=3))
        network_run = runner.run(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python network_probe.py"],
                network_policy="allow",
            )
        )
        outside_write_run = runner.run(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python outside_write_probe.py"],
                network_policy="deny",
            )
        )
        artifact_run = runner.run(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python artifact_probe.py"],
                network_policy="deny",
            )
        )

        timeout_runner = SandboxRunner(_settings(config, workspace, max_command_seconds=1))
        timeout_run = timeout_runner.run(
            RepoChecksRunRequest(
                repo_ref="repo",
                commands=["python timeout_probe.py"],
                network_policy="deny",
            )
        )

        limits = _inspect_limits(config, repo)

    _assert_run(network_run.exit_codes == [0], "outbound network probe did not fail closed")
    _assert_run("network denied" in "".join(network_run.stdout), "network-deny evidence missing")
    _assert_run(outside_write_run.exit_codes == [0], "outside-workspace write probe succeeded")
    _assert_run("outside write denied" in "".join(outside_write_run.stdout), "outside-write evidence missing")
    _assert_run(artifact_run.exit_codes == [0], "artifact probe failed")
    _assert_run("artifacts/live-smoke.txt" in artifact_run.artifacts, "artifact was not captured")
    _assert_run(timeout_run.exit_codes == [124], "timeout path did not return 124")
    _assert_run("docker kill" in "".join(timeout_run.stderr), "timeout path did not report docker kill")

    return {
        "status": "passed",
        "image": config.image,
        "network_denied": True,
        "outside_workspace_write_denied": True,
        "artifact_captured": "artifacts/live-smoke.txt",
        "timeout_killed": True,
        "limits": limits,
    }


def _config_from_env(env: Mapping[str, str]) -> LiveDockerSandboxSmokeConfig:
    return LiveDockerSandboxSmokeConfig(
        docker_path=env.get(DOCKER_PATH_ENV, "docker"),
        image=env.get(IMAGE_ENV, "hallu-defense-sandbox:ci"),
        memory_mb=int(env.get(MEMORY_MB_ENV, "512")),
        cpus=float(env.get(CPUS_ENV, "1.0")),
        pids_limit=int(env.get(PIDS_LIMIT_ENV, "256")),
        timeout_grace_seconds=float(env.get(TIMEOUT_GRACE_ENV, "2")),
    )


def _docker_available(config: LiveDockerSandboxSmokeConfig) -> dict[str, object] | None:
    if Path(config.docker_path).exists():
        docker_executable: str | None = config.docker_path
    else:
        docker_executable = shutil.which(config.docker_path)
    if docker_executable is None:
        return {
            "status": "skipped",
            "reason": f"Docker executable {config.docker_path!r} is not available on PATH",
        }
    try:
        completed = _run(
            [config.docker_path, "version", "--format", "{{.Server.Version}}"],
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "skipped",
            "reason": f"Docker is not available: {type(exc).__name__}",
        }
    if completed.returncode != 0:
        return {
            "status": "skipped",
            "reason": completed.stderr.strip() or "Docker daemon is not reachable",
        }
    return None


def _settings(
    config: LiveDockerSandboxSmokeConfig,
    workspace: Path,
    *,
    max_command_seconds: int,
) -> Settings:
    return Settings(
        environment="local",
        policy_version="live-docker-sandbox-smoke",
        auth_required=False,
        allowed_workspace=workspace,
        max_command_seconds=max_command_seconds,
        max_output_chars=4000,
        sandbox_backend="docker",
        sandbox_docker_image=config.image,
        sandbox_docker_path=config.docker_path,
        sandbox_docker_memory_mb=config.memory_mb,
        sandbox_docker_cpus=config.cpus,
        sandbox_docker_pids_limit=config.pids_limit,
        sandbox_docker_timeout_grace_seconds=config.timeout_grace_seconds,
    )


def _write_probe_scripts(repo: Path) -> None:
    (repo / "network_probe.py").write_text(
        "import socket\n"
        "import sys\n"
        "sock = socket.socket()\n"
        "sock.settimeout(1)\n"
        "try:\n"
        "    sock.connect(('1.1.1.1', 53))\n"
        "except OSError:\n"
        "    print('network denied')\n"
        "    sys.exit(0)\n"
        "print('network reachable')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    (repo / "outside_write_probe.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "try:\n"
        "    Path('/outside-workspace.txt').write_text('blocked', encoding='utf-8')\n"
        "except OSError:\n"
        "    print('outside write denied')\n"
        "    sys.exit(0)\n"
        "print('outside write unexpectedly succeeded')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    (repo / "artifact_probe.py").write_text(
        "from pathlib import Path\n"
        "Path('artifacts').mkdir(exist_ok=True)\n"
        "Path('artifacts/live-smoke.txt').write_text('captured', encoding='utf-8')\n"
        "print('artifact written')\n",
        encoding="utf-8",
    )
    (repo / "timeout_probe.py").write_text(
        "import time\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )


def _inspect_limits(config: LiveDockerSandboxSmokeConfig, repo: Path) -> dict[str, object]:
    backend = DockerContainerBackend(
        image=config.image,
        docker_path=config.docker_path,
        memory_mb=config.memory_mb,
        cpus=config.cpus,
        pids_limit=config.pids_limit,
        timeout_grace_seconds=config.timeout_grace_seconds,
    )
    argv = backend.build_run_argv(
        ["python", "-c", "import time; time.sleep(60)"],
        cwd=repo,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
    )
    argv.insert(2, "-d")
    started = _run_checked(argv, timeout=10)
    container_id = started.stdout.strip()
    try:
        inspected = _run_checked([config.docker_path, "inspect", container_id], timeout=10)
        payload = json.loads(inspected.stdout)
        if not isinstance(payload, list) or not payload:
            raise LiveDockerSandboxSmokeError("docker inspect returned an empty payload")
        host_config = payload[0].get("HostConfig")
        if not isinstance(host_config, dict):
            raise LiveDockerSandboxSmokeError("docker inspect missing HostConfig")
        limits = {
            "network_mode": host_config.get("NetworkMode"),
            "readonly_rootfs": host_config.get("ReadonlyRootfs"),
            "pids_limit": host_config.get("PidsLimit"),
            "memory": host_config.get("Memory"),
            "nano_cpus": host_config.get("NanoCpus"),
            "cap_drop": host_config.get("CapDrop"),
            "security_opt": host_config.get("SecurityOpt"),
        }
        _assert_run(limits["network_mode"] == "none", "inspect NetworkMode is not none")
        _assert_run(limits["readonly_rootfs"] is True, "inspect ReadonlyRootfs is not true")
        _assert_run(limits["pids_limit"] == config.pids_limit, "inspect PidsLimit mismatch")
        _assert_run(
            limits["memory"] == config.memory_mb * 1024 * 1024,
            "inspect Memory limit mismatch",
        )
        expected_nano_cpus = int(config.cpus * 1_000_000_000)
        _assert_run(limits["nano_cpus"] == expected_nano_cpus, "inspect NanoCpus mismatch")
        _assert_run(limits["cap_drop"] == ["ALL"], "inspect CapDrop mismatch")
        security_opt = limits["security_opt"]
        _assert_run(
            isinstance(security_opt, list) and "no-new-privileges" in security_opt,
            "inspect SecurityOpt missing no-new-privileges",
        )
        return limits
    finally:
        if container_id:
            _run([config.docker_path, "kill", container_id], timeout=10)


def _run_checked(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = _run(argv, timeout=timeout)
    if completed.returncode != 0:
        raise LiveDockerSandboxSmokeError(
            f"command failed: {argv[0]} {argv[1]}: {completed.stderr.strip()}"
        )
    return completed


def _run(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _make_writable_for_container(path: Path) -> None:
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _assert_run(condition: bool, message: str) -> None:
    if not condition:
        raise LiveDockerSandboxSmokeError(message)


def main() -> None:
    result = run_from_env()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
