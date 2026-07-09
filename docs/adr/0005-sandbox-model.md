# ADR 0005: Sandbox Model

## Status

Accepted for foundation.

## Context

Code agents can hallucinate about files, functions, tests, builds, and diffs. Text-only verification is not enough.

## Decision

Sandbox defaults:

- Network denied.
- Filesystem scoped to configured workspace.
- Commands are allowlisted.
- stdout, stderr, exit codes, and artifacts are captured.
- Claims about repo/test/build success require `SandboxRun` or equivalent deterministic evidence.

Runtime model:

- `SandboxRunner` keeps command parsing, destructive/network preflight regex checks, artifact capture, and host-side read-only git/static inspection.
- Command execution goes through `SandboxExecutionBackend`.
- Local development defaults to `HostSubprocessBackend` for compatibility.
- `DockerContainerBackend` is selected with `HALLU_DEFENSE_SANDBOX_BACKEND=docker`.
- Production and staging fail closed unless `HALLU_DEFENSE_SANDBOX_BACKEND=docker`.
- Docker execution uses argv lists only and pins isolation flags:
  `--rm`, `--network=none`, `--read-only`, `--tmpfs /tmp`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`,
  `--memory`, `--cpus`, `--user 10001`, one writable bind mount at
  `/workspace`, and `--workdir /workspace`.
- The sandbox image is `infra/docker/sandbox.Dockerfile`: pinned Python 3.12
  slim, pinned Node LTS/npm, pinned pytest, UID 10001 non-root, no remote
  `ADD`.

## Consequences

- Sandbox checks may be slower than text validation but are required for correctness.
- Docker startup cost may require tuning `HALLU_DEFENSE_MAX_COMMAND_SECONDS` and
  `HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS` for live deployments.
- The API container needs Docker daemon access to use the Docker backend; the
  production profile will document the socket-mount tradeoff separately.
- Docker live smoke remains opt-in locally and runs in the live workflow.
