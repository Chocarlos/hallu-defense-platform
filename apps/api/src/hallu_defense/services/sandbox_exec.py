from __future__ import annotations

import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast, runtime_checkable

from hallu_defense.config import PRODUCTION_LIKE_ENVIRONMENTS, Settings
from hallu_defense.services.text import bounded

SANDBOX_BACKEND_DOCKER = "docker"
SANDBOX_BACKEND_KUBERNETES = "kubernetes"
DOCKER_WORKDIR = "/workspace"
DOCKER_SOURCE_DIR = "/hallu-source"
DOCKER_USER = "10001"
SANDBOX_TIMEOUT_RETURN_CODE = 124
DOCKER_TIMEOUT_RETURN_CODE = SANDBOX_TIMEOUT_RETURN_CODE
SANDBOX_GIT_INSPECTOR_PATH = "/opt/hallu-defense/sandbox_git_inspector.py"
SANDBOX_RUNNER_PATH = "/opt/hallu-defense/sandbox_runner.py"
SANDBOX_BATCH_RUNNER_PATH = "/opt/hallu-defense/sandbox_batch_runner.py"
MAX_SANDBOX_WORKSPACE_FILES = 50_000
MAX_SANDBOX_WORKSPACE_BYTES = 512 * 1024 * 1024
MAX_SANDBOX_WORKSPACE_PATHS = 75_000
MAX_SANDBOX_PATH_BYTES = 4_096
MAX_SANDBOX_TOTAL_PATH_BYTES = 64 * 1024 * 1024
MAX_SANDBOX_COMMANDS = 10
MAX_SANDBOX_COMMAND_ARGUMENTS = 256
MAX_SANDBOX_COMMAND_BYTES = 32 * 1024
MAX_SANDBOX_OUTPUT_CHARS = 100_000
MAX_SANDBOX_BATCH_CONTROL_CHARS = 1_048_576
MAX_SANDBOX_ARTIFACTS = 10_000
MAX_DOCKER_CLI_OUTPUT_BYTES = MAX_SANDBOX_BATCH_CONTROL_CHARS * 4 + 4
SANDBOX_STREAM_RESULTS_ENV = "HALLU_DEFENSE_SANDBOX_STREAM_RESULTS"
SANDBOX_SNAPSHOT_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_CREATE_SUSPENDED = 0x00000004

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


@dataclass(frozen=True)
class SandboxExecutionBatchResult:
    executions: tuple[ExecutionResult, ...]
    pre_snapshot_fingerprint: str
    post_snapshot_fingerprint: str
    artifacts: tuple[str, ...] = ()


class SandboxExecutionBackend(Protocol):
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
        """Execute one already-parsed command and return bounded process output."""


@runtime_checkable
class SandboxBatchExecutionBackend(Protocol):
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
        """Execute all commands against one ephemeral working copy."""


class DockerCommandRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a Docker CLI argv list. Used for injected unit-test fakes."""


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
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        batch = self.execute_batch(
            [argv],
            cwd=cwd,
            source_cwd=source_cwd,
            env=env,
            timeout=timeout,
            output_caps=output_caps,
        )
        return batch.executions[0]

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
        normalized_commands = _validated_batch_commands(
            commands,
            timeout=timeout,
            output_caps=output_caps,
        )
        resolved_cwd = cwd.resolve(strict=True)
        resolved_source = source_cwd.resolve(strict=True)
        if resolved_cwd != resolved_source:
            raise SandboxExecutionError(
                "Docker backend owns the ephemeral working copy; cwd must be the source repository."
            )
        serialized_commands = json.dumps(
            normalized_commands,
            separators=(",", ":"),
        )
        control_output_caps = min(
            MAX_SANDBOX_BATCH_CONTROL_CHARS,
            max(65_536, output_caps * len(normalized_commands) * 4),
        )
        outer_timeout = timeout * len(normalized_commands) + max(
            5.0,
            min(30.0, timeout),
        )
        completed = self._execute_control_command(
            [
                "python",
                SANDBOX_BATCH_RUNNER_PATH,
                f"{timeout:.6f}",
                str(output_caps),
                serialized_commands,
            ],
            cwd=resolved_cwd,
            source_cwd=resolved_source,
            env=env,
            timeout=outer_timeout,
            output_caps=control_output_caps,
        )
        if completed.timed_out:
            raise SandboxExecutionError("Docker sandbox batch exceeded its orchestration deadline.")
        if completed.returncode != 0:
            raise SandboxExecutionError("Docker sandbox batch orchestration failed.")
        return decode_sandbox_execution_batch(
            completed.stdout,
            expected_count=len(normalized_commands),
            output_caps=output_caps,
        )

    def _execute_control_command(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="hallu-sandbox-") as temp_dir:
            cidfile = Path(temp_dir) / "container.cid"
            run_argv = self.build_run_argv(
                argv,
                cwd=cwd,
                source_cwd=source_cwd,
                env=env,
                cidfile=cidfile,
            )
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
                    stderr=bounded(
                        "\n".join(part for part in stderr_parts if part) + "\n", output_caps
                    ),
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
        source_cwd: Path,
        env: Mapping[str, str],
        cidfile: Path | None = None,
    ) -> list[str]:
        resolved_workspace = cwd.resolve(strict=True)
        resolved_source = source_cwd.resolve(strict=True)
        if resolved_workspace != resolved_source:
            raise SandboxExecutionError(
                "Docker backend owns the ephemeral working copy; cwd must be the source repository."
            )
        source_mount = f"type=bind,source={resolved_source},target={DOCKER_SOURCE_DIR},readonly"
        workspace_mount = (
            f"type=tmpfs,target={DOCKER_WORKDIR},"
            f"tmpfs-size={MAX_SANDBOX_WORKSPACE_BYTES},tmpfs-mode=1777"
        )
        run_argv = [
            self._docker_path,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
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
            source_mount,
            "--mount",
            workspace_mount,
            "--workdir",
            DOCKER_WORKDIR,
        ]
        if cidfile is not None:
            run_argv.extend(["--cidfile", str(cidfile)])
        container_env = self._container_env(env)
        container_env[SANDBOX_STREAM_RESULTS_ENV] = "1"
        for key, value in sorted(container_env.items()):
            run_argv.extend(["--env", f"{key}={value}"])
        run_argv.extend(
            [
                self._image,
                "python",
                SANDBOX_RUNNER_PATH,
                str(self._pids_limit),
                str(MAX_SANDBOX_WORKSPACE_FILES),
                str(MAX_SANDBOX_WORKSPACE_BYTES),
                *list(argv),
            ]
        )
        return run_argv

    def _container_env(self, env: Mapping[str, str]) -> dict[str, str]:
        return sanitized_container_environment(env)

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


def _validated_batch_commands(
    commands: Sequence[Sequence[str]],
    *,
    timeout: float,
    output_caps: int,
) -> list[list[str]]:
    if timeout <= 0 or not 0 < output_caps <= MAX_SANDBOX_OUTPUT_CHARS:
        raise SandboxExecutionError("sandbox execution limits must be positive and bounded")
    if not commands or len(commands) > MAX_SANDBOX_COMMANDS:
        raise SandboxExecutionError("sandbox batch must contain between 1 and 10 commands")
    normalized = [list(command) for command in commands]
    for command in normalized:
        if (
            not command
            or len(command) > MAX_SANDBOX_COMMAND_ARGUMENTS
            or any(not argument or "\x00" in argument for argument in command)
            or sum(len(argument.encode("utf-8")) for argument in command)
            > MAX_SANDBOX_COMMAND_BYTES
        ):
            raise SandboxExecutionError("sandbox command exceeded its safety limit")
    return normalized


def decode_sandbox_execution_batch(
    raw: str,
    *,
    expected_count: int,
    output_caps: int,
) -> SandboxExecutionBatchResult:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise SandboxExecutionError("sandbox batch returned invalid JSON") from None
    if not isinstance(payload, Mapping):
        raise SandboxExecutionError("sandbox batch returned a non-object result")
    if set(payload) != {
        "schema_version",
        "pre_snapshot_fingerprint",
        "post_snapshot_fingerprint",
        "executions",
        "artifacts",
    }:
        raise SandboxExecutionError("sandbox batch returned unexpected fields")
    if payload.get("schema_version") != "sandbox_execution_batch.v3":
        raise SandboxExecutionError("sandbox batch returned an unsupported schema")
    fingerprints: dict[str, str] = {}
    for field_name in ("pre_snapshot_fingerprint", "post_snapshot_fingerprint"):
        fingerprint = payload.get(field_name)
        if (
            not isinstance(fingerprint, str)
            or SANDBOX_SNAPSHOT_FINGERPRINT_RE.fullmatch(fingerprint) is None
        ):
            raise SandboxExecutionError(f"sandbox batch returned an invalid {field_name}")
        fingerprints[field_name] = fingerprint
    raw_executions = payload.get("executions")
    if not isinstance(raw_executions, list) or len(raw_executions) != expected_count:
        raise SandboxExecutionError("sandbox batch returned an unexpected result count")
    executions: list[ExecutionResult] = []
    for item in raw_executions:
        if not isinstance(item, Mapping) or set(item) != {
            "returncode",
            "stdout",
            "stderr",
            "timed_out",
        }:
            raise SandboxExecutionError("sandbox batch returned an invalid command result")
        returncode = item.get("returncode")
        stdout = item.get("stdout")
        stderr = item.get("stderr")
        timed_out = item.get("timed_out")
        if (
            not isinstance(returncode, int)
            or isinstance(returncode, bool)
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
            or not isinstance(timed_out, bool)
            or len(stdout) > output_caps
            or len(stderr) > output_caps
        ):
            raise SandboxExecutionError("sandbox batch returned an invalid command value")
        executions.append(
            ExecutionResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
            )
        )
    raw_artifacts = payload.get("artifacts")
    if (
        not isinstance(raw_artifacts, list)
        or len(raw_artifacts) > MAX_SANDBOX_ARTIFACTS
        or not all(isinstance(item, str) for item in raw_artifacts)
    ):
        raise SandboxExecutionError("sandbox batch returned an invalid artifact inventory")
    artifacts: list[str] = []
    total_artifact_path_bytes = 0
    for artifact in cast(list[str], raw_artifacts):
        path = PurePosixPath(artifact)
        path_bytes = len(artifact.encode("utf-8"))
        total_artifact_path_bytes += path_bytes
        if (
            not artifact
            or path_bytes > MAX_SANDBOX_PATH_BYTES
            or total_artifact_path_bytes > MAX_SANDBOX_TOTAL_PATH_BYTES
            or artifact.startswith("/")
            or "\\" in artifact
            or "\x00" in artifact
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in {"artifacts", "reports"}
        ):
            raise SandboxExecutionError("sandbox batch returned an unsafe artifact path")
        artifacts.append(artifact)
    if artifacts != sorted(set(artifacts)):
        raise SandboxExecutionError("sandbox batch artifact inventory must be unique and sorted")
    return SandboxExecutionBatchResult(
        executions=tuple(executions),
        pre_snapshot_fingerprint=fingerprints["pre_snapshot_fingerprint"],
        post_snapshot_fingerprint=fingerprints["post_snapshot_fingerprint"],
        artifacts=tuple(artifacts),
    )


def build_sandbox_execution_backend(settings: Settings) -> SandboxExecutionBackend:
    backend = settings.sandbox_backend.strip().lower()
    if (
        settings.environment.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS
        and backend != SANDBOX_BACKEND_KUBERNETES
    ):
        raise SandboxExecutionConfigurationError(
            "Production and staging require "
            "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation."
        )
    if backend == SANDBOX_BACKEND_DOCKER:
        return DockerContainerBackend.from_settings(settings)
    if backend == SANDBOX_BACKEND_KUBERNETES:
        from hallu_defense.services.sandbox_kubernetes import KubernetesJobBackend

        return KubernetesJobBackend.from_settings(settings)
    raise SandboxExecutionConfigurationError(
        "HALLU_DEFENSE_SANDBOX_BACKEND must be docker or kubernetes; "
        "host subprocess execution cannot enforce sandbox network isolation."
    )


def sanitized_container_environment(env: Mapping[str, str]) -> dict[str, str]:
    container_env = dict(_CONTAINER_ENV_DEFAULTS)
    for key in _CONTAINER_ENV_ALLOWLIST:
        value = env.get(key)
        if value is not None:
            container_env[key] = value
    return container_env


def is_git_inspector_command(argv: Sequence[str]) -> bool:
    return len(argv) >= 2 and argv[0] == "python" and argv[1] == SANDBOX_GIT_INSPECTOR_PATH


def _run_docker(
    argv: Sequence[str],
    *,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    deadline = time.monotonic() + timeout if timeout is not None else None
    windows_job = _create_windows_kill_job()
    process: subprocess.Popen[bytes] | None = None
    pipe_threads: tuple[threading.Thread, ...] = ()
    cleanup_complete = False
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=_WINDOWS_CREATE_SUSPENDED if os.name == "nt" else 0,
        )
        try:
            _assign_process_to_windows_job(windows_job, process)
            _resume_windows_process(process)
        except BaseException:
            process.kill()
            process.wait()
            raise
        if process.stdout is None or process.stderr is None:
            raise SandboxExecutionError("docker output pipes were unavailable")

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_errors: list[BaseException] = []
        stderr_errors: list[BaseException] = []
        stdout_thread = threading.Thread(
            target=_drain_bounded_pipe_safely,
            args=(
                process.stdout,
                stdout_chunks,
                MAX_DOCKER_CLI_OUTPUT_BYTES,
                stdout_errors,
            ),
            daemon=True,
            name="sandbox-docker-stdout-drain",
        )
        stderr_thread = threading.Thread(
            target=_drain_bounded_pipe_safely,
            args=(
                process.stderr,
                stderr_chunks,
                MAX_DOCKER_CLI_OUTPUT_BYTES,
                stderr_errors,
            ),
            daemon=True,
            name="sandbox-docker-stderr-drain",
        )
        stdout_thread.start()
        pipe_threads = (stdout_thread,)
        stderr_thread.start()
        pipe_threads = (stdout_thread, stderr_thread)
        timed_out = False
        wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=wait_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = -1
        cleanup_errors = _cleanup_docker_process_capture(
            process,
            windows_job,
            pipe_threads,
        )
        cleanup_complete = True
        windows_job = None
        if cleanup_errors:
            raise SandboxExecutionError("docker subprocess cleanup failed") from cleanup_errors[0]
        if stdout_errors or stderr_errors:
            raise SandboxExecutionError("docker output pipe capture failed") from (
                stdout_errors + stderr_errors
            )[0]
        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        if timed_out:
            if timeout is None:
                raise RuntimeError("a Docker subprocess timed out without a timeout value")
            raise subprocess.TimeoutExpired(
                list(argv),
                timeout,
                output=stdout,
                stderr=stderr,
            )
        return subprocess.CompletedProcess(
            args=list(argv),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        if not cleanup_complete:
            if process is None:
                try:
                    _close_windows_handle(windows_job)
                except BaseException as cleanup_exc:
                    active_error = sys.exc_info()[1]
                    if active_error is None:
                        raise SandboxExecutionError(
                            "docker subprocess cleanup failed"
                        ) from cleanup_exc
                    active_error.add_note(
                        f"Docker Job handle cleanup also failed ({type(cleanup_exc).__name__})."
                    )
            else:
                cleanup_errors = _cleanup_docker_process_capture(
                    process,
                    windows_job,
                    pipe_threads,
                )
                if cleanup_errors:
                    active_error = sys.exc_info()[1]
                    if active_error is None:
                        raise SandboxExecutionError(
                            "docker subprocess cleanup failed"
                        ) from cleanup_errors[0]
                    active_error.add_note(
                        "Docker subprocess cleanup also failed "
                        f"({type(cleanup_errors[0]).__name__})."
                    )


def _cleanup_docker_process_capture(
    process: subprocess.Popen[bytes],
    job_handle: int | None,
    pipe_threads: Sequence[threading.Thread],
) -> list[BaseException]:
    errors: list[BaseException] = []
    try:
        _terminate_owned_process_tree(process, job_handle)
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
    if not _join_pipe_threads_until(
        pipe_threads,
        deadline=time.monotonic() + 1.0,
    ):
        errors.append(RuntimeError("docker output pipes could not be closed"))
    for index, stream in enumerate((process.stdout, process.stderr)):
        pipe_thread = pipe_threads[index] if index < len(pipe_threads) else None
        if (pipe_thread is None or not pipe_thread.is_alive()) and stream is not None:
            try:
                stream.close()
            except OSError as exc:
                errors.append(exc)
    return errors


def _drain_bounded_pipe_safely(
    stream: object,
    chunks: list[bytes],
    limit: int,
    errors: list[BaseException],
) -> None:
    try:
        _drain_bounded_pipe(stream, chunks, limit)
    except BaseException as exc:
        errors.append(exc)
    finally:
        try:
            getattr(stream, "close")()
        except BaseException as exc:
            errors.append(exc)


def _join_pipe_threads_until(
    threads: Sequence[threading.Thread],
    *,
    deadline: float | None,
) -> bool:
    for thread in threads:
        if deadline is None:
            thread.join()
        else:
            thread.join(max(0.0, deadline - time.monotonic()))
    return not any(thread.is_alive() for thread in threads)


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
    set_information = kernel32.SetInformationJobObject
    if not set_information(
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
        raise SandboxExecutionError(
            f"could not resume the sandbox process (NTSTATUS 0x{status & 0xFFFFFFFF:08x})"
        )


def _terminate_owned_process_tree(
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
) -> None:
    read = getattr(stream, "read")
    captured = 0
    while True:
        chunk = read(65_536)
        if not chunk:
            return
        if not isinstance(chunk, bytes):
            raise RuntimeError("docker output pipe was not opened in binary mode")
        if captured < limit:
            bounded_chunk = chunk[: limit - captured]
            chunks.append(bounded_chunk)
            captured += len(bounded_chunk)


def _coerce_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
