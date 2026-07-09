from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SANDBOX_EXEC_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "sandbox_exec.py"
SANDBOX_SERVICE_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "sandbox.py"
CONFIG_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
API_DEPENDENCIES_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
DOCKERFILE_PATH = ROOT / "infra" / "docker" / "sandbox.Dockerfile"
MAKEFILE_PATH = ROOT / "Makefile"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"
SANDBOX_ADR_PATH = ROOT / "docs" / "adr" / "0005-sandbox-model.md"
CONTAINER_SCANNING_DOC_PATH = ROOT / "docs" / "security" / "container-scanning.md"

REQUIRED_ENV_KEYS = (
    "HALLU_DEFENSE_SANDBOX_BACKEND",
    "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PATH",
    "HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB",
    "HALLU_DEFENSE_SANDBOX_DOCKER_CPUS",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT",
    "HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS",
)
REQUIRED_DOCKER_ARG_SNIPPETS = (
    '"--rm"',
    '"--network=none"',
    '"--read-only"',
    '"--tmpfs"',
    '"/tmp"',
    '"--cap-drop"',
    '"ALL"',
    '"--security-opt"',
    '"no-new-privileges"',
    '"--pids-limit"',
    '"--memory"',
    '"--cpus"',
    '"--user"',
    "DOCKER_USER",
    '"--mount"',
    "target={DOCKER_WORKDIR}",
    '"--workdir"',
    "DOCKER_WORKDIR",
)
REQUIRED_MAKE_TARGETS = (
    "sandbox-image:",
    "sandbox-isolation-config:",
    "sandbox-live-smoke:",
)


class SandboxIsolationConfigError(ValueError):
    pass


def validate_sandbox_isolation_config(
    *,
    sandbox_exec_text: str,
    sandbox_service_text: str,
    config_text: str,
    api_dependencies_text: str,
    dockerfile_text: str,
    makefile_text: str,
    env_example_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    sandbox_adr_text: str,
    container_scanning_doc_text: str,
) -> None:
    errors: list[str] = []
    _validate_settings(config_text, env_example_text, errors)
    _validate_backend_code(
        sandbox_exec_text=sandbox_exec_text,
        sandbox_service_text=sandbox_service_text,
        api_dependencies_text=api_dependencies_text,
        errors=errors,
    )
    _validate_dockerfile(dockerfile_text, errors)
    _validate_wiring(
        makefile_text=makefile_text,
        security_workflow_text=security_workflow_text,
        live_workflow_text=live_workflow_text,
        errors=errors,
    )
    _validate_docs(
        sandbox_adr_text=sandbox_adr_text,
        container_scanning_doc_text=container_scanning_doc_text,
        errors=errors,
    )
    if errors:
        raise SandboxIsolationConfigError("\n".join(errors))


def _validate_settings(config_text: str, env_example_text: str, errors: list[str]) -> None:
    for key in REQUIRED_ENV_KEYS:
        if key not in config_text:
            errors.append(f"config.py must define/read {key}")
        if key not in env_example_text:
            errors.append(f".env.example must document {key}")
    if '"host"' not in config_text or '"docker"' not in config_text:
        errors.append("config.py must restrict HALLU_DEFENSE_SANDBOX_BACKEND to host|docker")
    if "Production and staging must set HALLU_DEFENSE_SANDBOX_BACKEND=docker." not in config_text:
        errors.append("config.py must fail closed for host sandbox backend in production/staging")
    for required_default in (
        '"512"',
        '"1.0"',
        '"256"',
    ):
        if required_default not in config_text:
            errors.append(f"config.py must keep Docker sandbox default {required_default}")


def _validate_backend_code(
    *,
    sandbox_exec_text: str,
    sandbox_service_text: str,
    api_dependencies_text: str,
    errors: list[str],
) -> None:
    for symbol in (
        "class SandboxExecutionBackend",
        "class ExecutionResult",
        "class HostSubprocessBackend",
        "class DockerContainerBackend",
        "build_sandbox_execution_backend",
    ):
        if symbol not in sandbox_exec_text:
            errors.append(f"sandbox_exec.py must define {symbol}")
    for snippet in REQUIRED_DOCKER_ARG_SNIPPETS:
        if snippet not in sandbox_exec_text:
            errors.append(f"Docker sandbox argv must include pinned flag/snippet {snippet}")
    if "shell=True" in sandbox_exec_text:
        errors.append("Docker sandbox execution must not use shell=True")
    if "docker kill" not in sandbox_exec_text or "[self._docker_path, \"kill\", container_id]" not in sandbox_exec_text:
        errors.append("Docker sandbox timeout path must kill the container by argv list")
    if "_CONTAINER_ENV_ALLOWLIST" not in sandbox_exec_text:
        errors.append("Docker sandbox must use a minimal container env allowlist")
    if "build_sandbox_execution_backend(settings)" not in sandbox_service_text:
        errors.append("SandboxRunner must select the configured execution backend")
    if "self._execution_backend.execute(" not in sandbox_service_text:
        errors.append("SandboxRunner must delegate command execution to the backend")
    if "DESTRUCTIVE_PATTERNS" not in sandbox_service_text or "NETWORK_PATTERNS" not in sandbox_service_text:
        errors.append("SandboxRunner must retain destructive/network preflight regex policy")
    if "subprocess.run(" not in sandbox_exec_text:
        errors.append("HostSubprocessBackend must contain the extracted subprocess.run implementation")
    if "sandbox_execution_backend = build_sandbox_execution_backend(settings)" not in api_dependencies_text:
        errors.append("API dependencies must create the configured sandbox execution backend")


def _validate_dockerfile(dockerfile_text: str, errors: list[str]) -> None:
    from_lines = [line.strip() for line in dockerfile_text.splitlines() if line.strip().startswith("FROM ")]
    if len(from_lines) < 2:
        errors.append("sandbox.Dockerfile must use pinned Python and Node stages")
    for line in from_lines:
        if ":latest" in line:
            errors.append("sandbox.Dockerfile must not use latest tags")
    if not any(line.startswith("FROM python:3.12.") and "slim" in line for line in from_lines):
        errors.append("sandbox.Dockerfile must use a pinned Python 3.12 slim base")
    if not any(line.startswith("FROM node:22.") or line.startswith("FROM node:24.") for line in from_lines):
        errors.append("sandbox.Dockerfile must use a pinned Node LTS base")
    if re.search(r"(?im)^ADD\s+https?://", dockerfile_text):
        errors.append("sandbox.Dockerfile must not ADD remote URLs")
    if "pytest==" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must install a pinned pytest")
    if "USER 10001" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must switch to non-root UID 10001")
    if "useradd --uid 10001" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must create the UID 10001 non-root user")
    if "WORKDIR /workspace" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must set /workspace as workdir")


def _validate_wiring(
    *,
    makefile_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    errors: list[str],
) -> None:
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    for target in REQUIRED_MAKE_TARGETS:
        target_name = target.rstrip(":")
        if target not in makefile_text:
            errors.append(f"Makefile must expose {target_name}")
        if target_name not in phony_line:
            errors.append(f".PHONY must include {target_name}")
    if "docker build -f infra/docker/sandbox.Dockerfile -t hallu-defense-sandbox:ci ." not in makefile_text:
        errors.append("Makefile sandbox-image must build hallu-defense-sandbox:ci")
    if "scripts/ci/check_sandbox_isolation_config.py" not in makefile_text:
        errors.append("Makefile must wire sandbox-isolation-config")
    if "scripts/dev/live_docker_sandbox_smoke.py" not in makefile_text:
        errors.append("Makefile must wire sandbox-live-smoke")
    security_section = makefile_text.partition("security-check:")[2]
    if "scripts/ci/check_sandbox_isolation_config.py" not in security_section:
        errors.append("security-check must include check_sandbox_isolation_config.py")
    if "python scripts/ci/check_sandbox_isolation_config.py" not in security_workflow_text:
        errors.append("security workflow must run check_sandbox_isolation_config.py")
    if "docker build -f infra/docker/sandbox.Dockerfile -t hallu-defense-sandbox:ci ." not in security_workflow_text:
        errors.append("security workflow must build hallu-defense-sandbox:ci")
    if "image-ref: hallu-defense-sandbox:ci" not in security_workflow_text:
        errors.append("security workflow must scan hallu-defense-sandbox:ci")
    if "sandbox-live:" not in live_workflow_text:
        errors.append("live workflow must include sandbox-live job")
    if "needs: [postgres-live, keycloak-live]" not in live_workflow_text:
        errors.append("sandbox-live job must run after Batch 2 live jobs")
    if "HALLU_DEFENSE_LIVE_DOCKER_SANDBOX_SMOKE_ENABLED: \"true\"" not in live_workflow_text:
        errors.append("sandbox-live job must enable the Docker sandbox smoke explicitly")


def _validate_docs(
    *,
    sandbox_adr_text: str,
    container_scanning_doc_text: str,
    errors: list[str],
) -> None:
    for marker in (
        "DockerContainerBackend",
        "--network=none",
        "--read-only",
        "Production and staging",
    ):
        if marker not in sandbox_adr_text:
            errors.append(f"sandbox ADR must document {marker}")
    for marker in (
        "hallu-defense-sandbox:ci",
        "infra/docker/sandbox.Dockerfile",
    ):
        if marker not in container_scanning_doc_text:
            errors.append(f"container scanning docs must mention {marker}")


def load_current_config() -> Mapping[str, str]:
    return {
        "sandbox_exec_text": SANDBOX_EXEC_PATH.read_text(encoding="utf-8"),
        "sandbox_service_text": SANDBOX_SERVICE_PATH.read_text(encoding="utf-8"),
        "config_text": CONFIG_PATH.read_text(encoding="utf-8"),
        "api_dependencies_text": API_DEPENDENCIES_PATH.read_text(encoding="utf-8"),
        "dockerfile_text": DOCKERFILE_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "env_example_text": ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "sandbox_adr_text": SANDBOX_ADR_PATH.read_text(encoding="utf-8"),
        "container_scanning_doc_text": CONTAINER_SCANNING_DOC_PATH.read_text(encoding="utf-8"),
    }


def main() -> None:
    validate_sandbox_isolation_config(**load_current_config())
    print("Validated sandbox Docker isolation config.")


if __name__ == "__main__":
    main()
