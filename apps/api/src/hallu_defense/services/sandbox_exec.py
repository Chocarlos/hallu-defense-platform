from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hallu_defense.config import PRODUCTION_LIKE_ENVIRONMENTS, Settings
from hallu_defense.services.text import bounded

SANDBOX_BACKEND_DOCKER = "docker"
SANDBOX_BACKEND_HOST = "host"
DOCKER_WORKDIR = "/workspace"
DOCKER_USER = "10001"
DOCKER_TIMEOUT_RETURN_CODE = 124

_CONTAINER_ENV_DEFAULTS = {
    "CI": "true",
    "HOME": "/tmp",
    "PYTHONUNBUFFERED": "1",
}
_CONTAINER_ENV_ALLOWLIST = {
    "CI",
    "HALLU_DEFENSE_NETWORK_POLICY",
    "PYTHONUNBUFFERED",
}


class SandboxExecutionConfigurationError(ValueError):
    pass


class SandboxExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class SandboxExecutionBackend(Protocol):
    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        """Execute one already-parsed command and return bounded process output."""


class DockerCommandRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a Docker CLI argv list. Used for injected unit-test fakes."""


class HostSubprocessBackend:
    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        try:
            completed = subprocess.run(
                list(argv),
                cwd=cwd,
                env=dict(env),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = bounded(_coerce_output(exc.stdout), output_caps)
            stderr = bounded(
                "\n".join(
                    part
                    for part in [
                        _coerce_output(exc.stderr).rstrip(),
                        f"host sandbox command timed out after {timeout} second(s)",
                    ]
                    if part
                )
                + "\n",
                output_caps,
            )
            return ExecutionResult(
                returncode=DOCKER_TIMEOUT_RETURN_CODE,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )
        return ExecutionResult(
            returncode=completed.returncode,
            stdout=bounded(completed.stdout, output_caps),
            stderr=bounded(completed.stderr, output_caps),
            timed_out=False,
        )


class DockerContainerBackend:
    def __init__(
        self,
        *,
        image: str,
        docker_path: str = "docker",
        memory_mb: int = 512,
        cpus: float = 1.0,
        pids_limit: int = 256,
        timeout_grace_seconds: float = 2.0,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        if not image.strip():
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE must not be empty."
            )
        if not docker_path.strip():
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_PATH must not be empty."
            )
        if memory_mb <= 0:
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB must be positive."
            )
        if cpus <= 0:
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_CPUS must be positive."
            )
        if pids_limit <= 0:
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT must be positive."
            )
        if timeout_grace_seconds <= 0:
            raise SandboxExecutionConfigurationError(
                "HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS must be positive."
            )

        self._image = image.strip()
        self._docker_path = docker_path.strip()
        self._memory_mb = memory_mb
        self._cpus = cpus
        self._pids_limit = pids_limit
        self._timeout_grace_seconds = timeout_grace_seconds
        self._runner = runner or _run_docker

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        runner: DockerCommandRunner | None = None,
    ) -> DockerContainerBackend:
        return cls(
            image=settings.sandbox_docker_image,
            docker_path=settings.sandbox_docker_path,
            memory_mb=settings.sandbox_docker_memory_mb,
            cpus=settings.sandbox_docker_cpus,
            pids_limit=settings.sandbox_docker_pids_limit,
            timeout_grace_seconds=settings.sandbox_docker_timeout_grace_seconds,
            runner=runner,
        )

    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="hallu-sandbox-") as temp_dir:
            cidfile = Path(temp_dir) / "container.cid"
            run_argv = self.build_run_argv(argv, cwd=cwd, env=env, cidfile=cidfile)
            try:
                completed = self._runner(run_argv, timeout=timeout)
            except FileNotFoundError as exc:
                raise SandboxExecutionError("docker executable was not found") from exc
            except subprocess.TimeoutExpired as exc:
                stderr_parts = [
                    _coerce_output(exc.stderr).rstrip(),
                    f"docker sandbox command timed out after {timeout} second(s)",
                    self._kill_container(cidfile, output_caps).rstrip(),
                ]
                return ExecutionResult(
                    returncode=DOCKER_TIMEOUT_RETURN_CODE,
                    stdout=bounded(_coerce_output(exc.stdout), output_caps),
                    stderr=bounded("\n".join(part for part in stderr_parts if part) + "\n", output_caps),
                    timed_out=True,
                )

        return ExecutionResult(
            returncode=completed.returncode,
            stdout=bounded(completed.stdout, output_caps),
            stderr=bounded(completed.stderr, output_caps),
            timed_out=False,
        )

    def build_run_argv(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        cidfile: Path | None = None,
    ) -> list[str]:
        run_argv = [
            self._docker_path,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self._pids_limit),
            "--memory",
            f"{self._memory_mb}m",
            "--cpus",
            str(self._cpus),
            "--user",
            DOCKER_USER,
            "--mount",
            f"type=bind,source={cwd.resolve()},target={DOCKER_WORKDIR}",
            "--workdir",
            DOCKER_WORKDIR,
        ]
        if cidfile is not None:
            run_argv.extend(["--cidfile", str(cidfile)])
        for key, value in sorted(self._container_env(env).items()):
            run_argv.extend(["--env", f"{key}={value}"])
        run_argv.extend([self._image, *list(argv)])
        return run_argv

    def _container_env(self, env: Mapping[str, str]) -> dict[str, str]:
        container_env = dict(_CONTAINER_ENV_DEFAULTS)
        for key in _CONTAINER_ENV_ALLOWLIST:
            value = env.get(key)
            if value is not None:
                container_env[key] = value
        return container_env

    def _kill_container(self, cidfile: Path, output_caps: int) -> str:
        try:
            container_id = cidfile.read_text(encoding="utf-8").strip()
        except OSError:
            return "docker kill skipped because the container id was unavailable"
        if not container_id:
            return "docker kill skipped because the container id was empty"
        try:
            completed = self._runner(
                [self._docker_path, "kill", container_id],
                timeout=self._timeout_grace_seconds,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return f"docker kill failed: {type(exc).__name__}"
        if completed.returncode != 0:
            stderr = bounded(completed.stderr, output_caps).strip()
            return f"docker kill failed with exit code {completed.returncode}: {stderr}"
        return "docker kill completed"


def build_sandbox_execution_backend(settings: Settings) -> SandboxExecutionBackend:
    backend = settings.sandbox_backend.strip().lower()
    if (
        settings.environment.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS
        and backend == SANDBOX_BACKEND_HOST
    ):
        raise SandboxExecutionConfigurationError(
            "Production and staging must set HALLU_DEFENSE_SANDBOX_BACKEND=docker."
        )
    if backend == SANDBOX_BACKEND_HOST:
        return HostSubprocessBackend()
    if backend == SANDBOX_BACKEND_DOCKER:
        return DockerContainerBackend.from_settings(settings)
    raise SandboxExecutionConfigurationError(
        "HALLU_DEFENSE_SANDBOX_BACKEND must be host or docker."
    )


def _run_docker(
    argv: Sequence[str],
    *,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _coerce_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
