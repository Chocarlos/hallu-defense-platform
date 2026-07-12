from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SANDBOX_EXEC_PATH = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "sandbox_exec.py"
)
SANDBOX_SERVICE_PATH = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "sandbox.py"
)
CONFIG_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
API_DEPENDENCIES_PATH = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
)
DOCKERFILE_PATH = ROOT / "infra" / "docker" / "sandbox.Dockerfile"
KUBERNETES_BACKEND_PATH = (
    ROOT
    / "apps"
    / "api"
    / "src"
    / "hallu_defense"
    / "services"
    / "sandbox_kubernetes.py"
)
SANDBOX_RUNNER_PATH = ROOT / "infra" / "docker" / "sandbox_runner.py"
SANDBOX_BATCH_RUNNER_PATH = ROOT / "infra" / "docker" / "sandbox_batch_runner.py"
SANDBOX_GIT_INSPECTOR_SOURCE_PATH = (
    ROOT / "infra" / "docker" / "sandbox_git_inspector.py"
)
SANDBOX_WORKSPACE_PATH = ROOT / "infra" / "docker" / "sandbox_workspace.py"
MAKEFILE_PATH = ROOT / "Makefile"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"
SANDBOX_ADR_PATH = ROOT / "docs" / "adr" / "0005-sandbox-model.md"
KUBERNETES_SANDBOX_DOC_PATH = (
    ROOT / "docs" / "deployment" / "kubernetes-sandbox-jobs.md"
)
CONTAINER_SCANNING_DOC_PATH = ROOT / "docs" / "security" / "container-scanning.md"
PLAYWRIGHT_CONFIG_PATH = ROOT / "apps" / "console" / "playwright.config.ts"
PLAYWRIGHT_WEBSERVER_PATH = (
    ROOT / "apps" / "console" / "scripts" / "run-e2e-api-webserver.ts"
)
PLAYWRIGHT_TEARDOWN_PATH = ROOT / "apps" / "console" / "e2e" / "global-teardown.ts"
PLAYWRIGHT_LIFECYCLE_PATH = ROOT / "apps" / "console" / "lib" / "e2e-api-lifecycle.ts"
PLAYWRIGHT_SANDBOX_HELPER_PATH = ROOT / "apps" / "console" / "lib" / "e2e-sandbox.ts"

REQUIRED_ENV_KEYS = (
    "HALLU_DEFENSE_SANDBOX_BACKEND",
    "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PATH",
    "HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB",
    "HALLU_DEFENSE_SANDBOX_DOCKER_CPUS",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT",
    "HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_JOB_TTL_SECONDS",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_API_REQUEST_TIMEOUT_SECONDS",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_SETUP_GRACE_SECONDS",
    "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS",
)
REQUIRED_DOCKER_ARG_SNIPPETS = (
    '"--rm"',
    '"--network=none"',
    '"--read-only"',
    '"--tmpfs"',
    '"/tmp:rw,nosuid,nodev,size=64m,mode=1777"',
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
SANDBOX_MATRIX_ROW = {
    "name": "sandbox",
    "dockerfile": "infra/docker/sandbox.Dockerfile",
}
SANDBOX_MATRIX_IMAGE_REF = "hallu-defense-${{ matrix.name }}:ci"
TRIVY_ACTION = "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"
TRIVY_VERSION = "v0.72.0"


class SandboxIsolationConfigError(ValueError):
    pass


def validate_sandbox_isolation_config(
    *,
    sandbox_exec_text: str,
    sandbox_service_text: str,
    sandbox_kubernetes_text: str,
    sandbox_runner_text: str,
    sandbox_batch_runner_text: str,
    sandbox_git_inspector_text: str,
    sandbox_workspace_text: str,
    config_text: str,
    api_dependencies_text: str,
    dockerfile_text: str,
    makefile_text: str,
    env_example_text: str,
    security_workflow_text: str,
    ci_workflow_text: str,
    live_workflow_text: str,
    playwright_config_text: str,
    playwright_webserver_text: str,
    playwright_teardown_text: str,
    playwright_lifecycle_text: str,
    playwright_sandbox_helper_text: str,
    sandbox_adr_text: str,
    kubernetes_sandbox_doc_text: str,
    container_scanning_doc_text: str,
) -> None:
    errors: list[str] = []
    _validate_settings(config_text, env_example_text, errors)
    _validate_backend_code(
        sandbox_exec_text=sandbox_exec_text,
        sandbox_service_text=sandbox_service_text,
        sandbox_kubernetes_text=sandbox_kubernetes_text,
        sandbox_runner_text=sandbox_runner_text,
        sandbox_batch_runner_text=sandbox_batch_runner_text,
        sandbox_git_inspector_text=sandbox_git_inspector_text,
        sandbox_workspace_text=sandbox_workspace_text,
        api_dependencies_text=api_dependencies_text,
        errors=errors,
    )
    _validate_dockerfile(dockerfile_text, errors)
    _validate_wiring(
        makefile_text=makefile_text,
        security_workflow_text=security_workflow_text,
        ci_workflow_text=ci_workflow_text,
        live_workflow_text=live_workflow_text,
        playwright_config_text=playwright_config_text,
        playwright_webserver_text=playwright_webserver_text,
        playwright_teardown_text=playwright_teardown_text,
        playwright_lifecycle_text=playwright_lifecycle_text,
        playwright_sandbox_helper_text=playwright_sandbox_helper_text,
        errors=errors,
    )
    _validate_docs(
        sandbox_adr_text=sandbox_adr_text,
        kubernetes_sandbox_doc_text=kubernetes_sandbox_doc_text,
        container_scanning_doc_text=container_scanning_doc_text,
        errors=errors,
    )
    if errors:
        raise SandboxIsolationConfigError("\n".join(errors))


def _validate_settings(
    config_text: str, env_example_text: str, errors: list[str]
) -> None:
    for key in REQUIRED_ENV_KEYS:
        if key not in config_text:
            errors.append(f"config.py must define/read {key}")
        if key not in env_example_text:
            errors.append(f".env.example must document {key}")
    if any(backend not in config_text for backend in ('"docker"', '"kubernetes"')):
        errors.append(
            "config.py must restrict HALLU_DEFENSE_SANDBOX_BACKEND to docker|kubernetes"
        )
    if 'backend not in {"docker", "kubernetes"}' not in config_text:
        errors.append("config.py must reject the unisolated host sandbox backend")
    if '"HALLU_DEFENSE_SANDBOX_BACKEND", "docker"' not in config_text:
        errors.append("config.py must default local sandbox execution to Docker")
    if (
        "Production and staging require" not in config_text
        or "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation."
        not in config_text
    ):
        errors.append(
            "config.py must allow only the tenant-bound Kubernetes sandbox in production/staging"
        )
    for required_default in (
        '"512"',
        '"1.0"',
        '"256"',
    ):
        if required_default not in config_text:
            errors.append(
                f"config.py must keep Docker sandbox default {required_default}"
            )
    for marker in (
        "sandbox_kubernetes_cleanup_grace_seconds: float = 20.0",
        "15 <= settings.sandbox_kubernetes_cleanup_grace_seconds <= 30",
    ):
        if marker not in config_text:
            errors.append(
                "config.py must keep a Kubernetes-specific 15-30 second cleanup grace"
            )


def _validate_backend_code(
    *,
    sandbox_exec_text: str,
    sandbox_service_text: str,
    sandbox_kubernetes_text: str,
    sandbox_runner_text: str,
    sandbox_batch_runner_text: str,
    sandbox_git_inspector_text: str,
    sandbox_workspace_text: str,
    api_dependencies_text: str,
    errors: list[str],
) -> None:
    for symbol in (
        "class SandboxExecutionBackend",
        "class ExecutionResult",
        "class SandboxExecutionBatchResult",
        "class DockerContainerBackend",
        "build_sandbox_execution_backend",
    ):
        if symbol not in sandbox_exec_text:
            errors.append(f"sandbox_exec.py must define {symbol}")
    if (
        "HostSubprocessBackend" in sandbox_exec_text
        or "SANDBOX_BACKEND_HOST" in sandbox_exec_text
    ):
        errors.append(
            "sandbox_exec.py must not expose an unisolated host subprocess backend"
        )
    for snippet in REQUIRED_DOCKER_ARG_SNIPPETS:
        if snippet not in sandbox_exec_text:
            errors.append(
                f"Docker sandbox argv must include pinned flag/snippet {snippet}"
            )
    if "shell=True" in sandbox_exec_text:
        errors.append("Docker sandbox execution must not use shell=True")
    if (
        "docker kill" not in sandbox_exec_text
        or '[self._docker_path, "kill", container_id]' not in sandbox_exec_text
    ):
        errors.append(
            "Docker sandbox timeout path must kill the container by argv list"
        )
    if "_CONTAINER_ENV_ALLOWLIST" not in sandbox_exec_text:
        errors.append("Docker sandbox must use a minimal container env allowlist")
    for marker in (
        "MAX_SANDBOX_OUTPUT_CHARS",
        "MAX_SANDBOX_WORKSPACE_PATHS",
        "MAX_SANDBOX_PATH_BYTES",
        "MAX_SANDBOX_TOTAL_PATH_BYTES",
        "MAX_DOCKER_CLI_OUTPUT_BYTES",
        "_drain_bounded_pipe",
        "_drain_bounded_pipe_safely",
        "_cleanup_docker_process_capture",
        "_join_pipe_threads_until",
        "_WINDOWS_CREATE_SUSPENDED",
        "_create_windows_kill_job",
        "_assign_process_to_windows_job",
        "_resume_windows_process",
        "_terminate_owned_process_tree",
    ):
        if marker not in sandbox_exec_text:
            errors.append(f"Docker sandbox bounded execution is missing {marker}")
    for marker in (
        "SANDBOX_GIT_INSPECTOR_PATH",
        "target={DOCKER_SOURCE_DIR},readonly",
        "type=tmpfs,target={DOCKER_WORKDIR}",
        "tmpfs-size={MAX_SANDBOX_WORKSPACE_BYTES},tmpfs-mode=1777",
        "def execute_batch(",
        "SANDBOX_STREAM_RESULTS_ENV",
    ):
        if marker not in sandbox_exec_text:
            errors.append(
                f"Docker Git inspection must use a read-only isolated mount; missing {marker}"
            )
    if (
        "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation."
        not in sandbox_exec_text
    ):
        errors.append(
            "sandbox backend factory must reject host and Docker in production/staging"
        )
    if "build_sandbox_execution_backend(settings)" not in sandbox_service_text:
        errors.append("SandboxRunner must select the configured execution backend")
    if "self._execution_backend.execute(" not in sandbox_service_text:
        errors.append("SandboxRunner must delegate command execution to the backend")
    for marker in (
        "_run_isolated_git_inspector",
        "SANDBOX_GIT_INSPECTION_SCHEMA",
    ):
        if marker not in sandbox_service_text:
            errors.append(
                f"SandboxRunner must use the isolated Git inspector; missing {marker}"
            )
    if (
        "DESTRUCTIVE_PATTERNS" not in sandbox_service_text
        or "NETWORK_PATTERNS" not in sandbox_service_text
    ):
        errors.append(
            "SandboxRunner must retain destructive/network preflight regex policy"
        )
    for marker in (
        "_ephemeral_working_copy",
        "_workspace_fingerprint",
        "source workspace changed during the isolated sandbox run",
        "source workspace changed during sandbox command policy inspection",
        "allowlisted network policy requires an exact destination allowlist",
        'INSPECTION_EVIDENCE_SOURCE = "sandbox://inspection"',
    ):
        if marker not in sandbox_service_text:
            errors.append(f"SandboxRunner ephemeral isolation is missing {marker}")
    if "_write_inspection_report" in sandbox_service_text:
        errors.append(
            "SandboxRunner must keep inspection evidence out of the source tree"
        )
    for marker in (
        'SOURCE_MOUNT_PATH = "/hallu-source"',
        '"readOnly": True',
        '"name": "workspace"',
        '"emptyDir"',
        "def execute_batch(",
        "SANDBOX_BATCH_RUNNER_PATH",
        '"propagationPolicy": "Foreground"',
        '"preconditions": {"uid": job_uid}',
        "_wait_for_job_deletion",
        "_job_owned_pods_remain",
        "_reconcile_ambiguous_job_creation",
        "except SandboxExecutionError as exc",
        "self._cleanup_grace_seconds",
        "settings.sandbox_kubernetes_cleanup_grace_seconds",
    ):
        if marker not in sandbox_kubernetes_text:
            errors.append(
                f"Kubernetes ephemeral workspace isolation is missing {marker}"
            )
    if (
        "cleanup_grace_seconds=settings.sandbox_docker_timeout_grace_seconds"
        in sandbox_kubernetes_text
    ):
        errors.append(
            "Kubernetes foreground cleanup must not use the Docker timeout grace"
        )
    for marker in (
        "validate_workspace_tree",
        "workspace links are forbidden",
        "workspace special files are forbidden",
        "copy_workspace_tree",
        "MAX_WORKSPACE_PATHS",
        "MAX_TOTAL_PATH_BYTES",
        "_copy_regular_file_no_follow",
        "_directory_entries_no_follow",
    ):
        if marker not in sandbox_runner_text:
            errors.append(f"sandbox runner bounded copy is missing {marker}")
    for marker in (
        '"schema_version": "sandbox_execution_batch.v3"',
        '"pre_snapshot_fingerprint": pre_snapshot_fingerprint',
        '"post_snapshot_fingerprint": post_snapshot_fingerprint',
        "workspace_fingerprint(workspace)",
        "artifact_snapshot",
        "regular_file_sha256",
        "process.wait(timeout=timeout)",
        "_drain_bounded_pipe",
        "_drain_bounded_pipe_safely",
        "_ensure_child_subreaper",
        "_terminate_descendant_processes",
        "_directory_entries_no_follow",
    ):
        if marker not in sandbox_batch_runner_text:
            errors.append(f"sandbox batch runner is missing {marker}")
    for marker in (
        "pre_snapshot_fingerprint: str",
        "post_snapshot_fingerprint: str",
        "batch.pre_snapshot_fingerprint != source_fingerprint",
        "batch.post_snapshot_fingerprint != expected_source_fingerprint",
        "sandbox execution snapshot does not match",
    ):
        if marker not in sandbox_exec_text + sandbox_service_text:
            errors.append(f"sandbox snapshot evidence binding is missing {marker}")
    for marker in (
        "_repository_config_guard",
        '"--no-includes"',
        '"filter."',
        '"includeif."',
        '".textconv"',
        '"core.filemode=false"',
        '"core.ignoreCase=false"',
        '"--ignore-submodules=all"',
        '"GIT_NO_REPLACE_OBJECTS": "1"',
        "_repository_index_guard",
        'b"FSMN"',
        "_repository_attributes_guard",
        "_repository_attributes_batch_guard",
        "_prepare_private_index",
        "_repository_pre_git_guard",
        "_repository_static_config_guard",
        "_head_tree_guard",
        "_repository_structure_guard",
        "_git_index_guard",
        '"--index-info"',
        "unmerged stages",
        '"GIT_INDEX_FILE"',
        '"ident"',
        '"crlf"',
        "core.excludesfile",
        "core.attributesfile",
        "http-alternates",
        "info/exclude patterns are forbidden",
        '"--no-color"',
        '"--src-prefix=a/"',
        '"--dst-prefix=b/"',
        '"--text"',
        '"--full-index"',
        "git_control_fingerprint_before",
        "workspace_fingerprint_before",
        "_drain_bounded_pipe",
        "_drain_bounded_pipe_safely",
        "_cleanup_git_process_capture",
        "_write_git_stdin_safely",
        "_WINDOWS_CREATE_SUSPENDED",
        "_resume_windows_process",
    ):
        if marker not in sandbox_git_inspector_text:
            errors.append(f"sandbox Git configuration guard is missing {marker}")
    for marker in (
        "_update_digest_from_unchanged_regular_file",
        "regular_file_sha256",
        "MAX_WORKSPACE_PATHS",
        "MAX_PATH_BYTES",
        "MAX_TOTAL_PATH_BYTES",
        "_open_directory_no_follow",
        "_same_descriptor_snapshot",
        "stat.S_IMODE",
    ):
        if marker not in sandbox_workspace_text:
            errors.append(f"sandbox bounded streaming fingerprint is missing {marker}")
    if (
        "sandbox_execution_backend = build_sandbox_execution_backend(settings)"
        not in api_dependencies_text
    ):
        errors.append(
            "API dependencies must create the configured sandbox execution backend"
        )


def _validate_dockerfile(dockerfile_text: str, errors: list[str]) -> None:
    from_lines = [
        line.strip()
        for line in dockerfile_text.splitlines()
        if line.strip().startswith("FROM ")
    ]
    if len(from_lines) < 2:
        errors.append("sandbox.Dockerfile must use pinned Python and Node stages")
    for line in from_lines:
        if ":latest" in line:
            errors.append("sandbox.Dockerfile must not use latest tags")
    python_base = (
        "python:3.12.13-alpine3.24@sha256:"
        "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
    )
    node_base = (
        "node:24.18.0-alpine3.24@sha256:"
        "a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"
    )
    if sum(python_base in line for line in from_lines) != 2:
        errors.append(
            "sandbox.Dockerfile must use the exact pinned Python 3.12.13 Alpine base twice"
        )
    if not any(node_base in line for line in from_lines):
        errors.append(
            "sandbox.Dockerfile must use the exact pinned Node 24 Alpine base"
        )
    if re.search(r"(?im)^ADD\s+https?://", dockerfile_text):
        errors.append("sandbox.Dockerfile must not ADD remote URLs")
    for marker in (
        "COPY requirements/python/sandbox-linux-py312.lock",
        "--require-hashes",
        "--no-index --no-deps --require-hashes",
        "python -m pip check",
    ):
        if marker not in dockerfile_text:
            errors.append(
                "sandbox.Dockerfile must install its exact hashed Python dependency lock; "
                f"missing {marker}"
            )
    for marker in (
        "apk add --no-cache git=2.54.0-r0",
        "COPY infra/docker/sandbox_batch_runner.py /opt/hallu-defense/sandbox_batch_runner.py",
        "COPY infra/docker/sandbox_git_inspector.py /opt/hallu-defense/sandbox_git_inspector.py",
        "/opt/hallu-defense/sandbox_git_inspector.py",
    ):
        if marker not in dockerfile_text:
            errors.append(
                "sandbox.Dockerfile must bake the pinned isolated Git inspector; "
                f"missing {marker}"
            )
    if "USER 10001" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must switch to non-root UID 10001")
    if "adduser -D -u 10001" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must create the UID 10001 non-root user")
    if "WORKDIR /workspace" not in dockerfile_text:
        errors.append("sandbox.Dockerfile must set /workspace as workdir")


def _validate_wiring(
    *,
    makefile_text: str,
    security_workflow_text: str,
    ci_workflow_text: str,
    live_workflow_text: str,
    playwright_config_text: str,
    playwright_webserver_text: str,
    playwright_teardown_text: str,
    playwright_lifecycle_text: str,
    playwright_sandbox_helper_text: str,
    errors: list[str],
) -> None:
    phony_line = next(
        (line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), ""
    )
    for target in REQUIRED_MAKE_TARGETS:
        target_name = target.rstrip(":")
        if target not in makefile_text:
            errors.append(f"Makefile must expose {target_name}")
        if target_name not in phony_line:
            errors.append(f".PHONY must include {target_name}")
    if (
        "docker build -f infra/docker/sandbox.Dockerfile -t hallu-defense-sandbox:ci ."
        not in makefile_text
    ):
        errors.append("Makefile sandbox-image must build hallu-defense-sandbox:ci")
    if "scripts/ci/check_sandbox_isolation_config.py" not in makefile_text:
        errors.append("Makefile must wire sandbox-isolation-config")
    if "scripts/dev/live_docker_sandbox_smoke.py" not in makefile_text:
        errors.append("Makefile must wire sandbox-live-smoke")
    security_section = makefile_text.partition("security-check:")[2]
    if "scripts/ci/check_sandbox_isolation_config.py" not in security_section:
        errors.append("security-check must include check_sandbox_isolation_config.py")
    _validate_security_workflow(security_workflow_text, errors)
    if "sandbox-live:" not in live_workflow_text:
        errors.append("live workflow must include sandbox-live job")
    if "needs: [postgres-live, keycloak-live]" not in live_workflow_text:
        errors.append("sandbox-live job must run after Batch 2 live jobs")
    if (
        'HALLU_DEFENSE_LIVE_DOCKER_SANDBOX_SMOKE_ENABLED: "true"'
        not in live_workflow_text
    ):
        errors.append(
            "sandbox-live job must enable the Docker sandbox smoke explicitly"
        )
    for marker in (
        "node --import tsx apps/console/scripts/run-e2e-api-webserver.ts",
        'HALLU_DEFENSE_SANDBOX_BACKEND: "docker"',
        'HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE: sandboxImageTag',
        "resolveSandboxImageTag(repoRoot, sandboxRunId)",
        "resolvePythonExecutable(",
        "PYTHONPATH: apiSourceRoot",
        "globalTeardown:",
    ):
        if marker not in playwright_config_text:
            errors.append(
                "Playwright sandbox/python E2E wiring must build and select this "
                f"worktree's own scratch resources; missing {marker}"
            )
    if "globalSetup:" in playwright_config_text:
        errors.append(
            "Playwright config must not use globalSetup for scratch cleanup because "
            "webServer starts first"
        )
    if "hallu-defense-sandbox:ci" in playwright_config_text:
        errors.append(
            "Playwright config must not hardcode the shared hallu-defense-sandbox:ci "
            "tag; it must build a per-worktree/per-run scratch tag instead"
        )
    for marker in (
        "pythonSourcePreflightArgs(",
        '"infra/docker/sandbox.Dockerfile"',
        "SANDBOX_BUILD_TIMEOUT_MS",
        "cleanupScratch(sandboxImageTag, stateDir, repoRoot)",
        "runE2eApiLifecycle({",
    ):
        if marker not in playwright_webserver_text:
            errors.append(
                "Playwright API wrapper must preflight imports and clean scratch "
                f"resources on every exit path; missing {marker}"
            )
    for marker in ("dependencies.preflight();", "finally {", "dependencies.finalCleanup();"):
        if marker not in playwright_lifecycle_text:
            errors.append(
                "Playwright API lifecycle must keep preflight before scratch actions "
                f"and guarantee final cleanup; missing {marker}"
            )
    for marker in ("DOCKER_CLEANUP_TIMEOUT_MS = 5_000", "timeout: DOCKER_CLEANUP_TIMEOUT_MS"):
        if marker not in playwright_sandbox_helper_text:
            errors.append(f"Playwright Docker cleanup must be time-bounded; missing {marker}")
    for marker in ("removeSandboxImageIfPresent", "removeE2eStateDir"):
        if marker not in playwright_teardown_text:
            errors.append(
                "Playwright final teardown must remove only validated scratch resources; "
                f"missing {marker}"
            )
    for marker in (
        "E2E_PYTHON_BIN: ${{ steps.setup-python.outputs.python-path }}",
        "E2E_RUN_ID: ${{ github.run_id }}-${{ github.run_attempt }}",
        "npm --workspace @hallu-defense/console run test:e2e-static",
    ):
        if marker not in ci_workflow_text:
            errors.append(f"CI Console e2e wiring is missing {marker}")
    build_timeout = _typescript_integer_constant(
        playwright_webserver_text, "SANDBOX_BUILD_TIMEOUT_MS"
    )
    webserver_timeout = _typescript_integer_constant(
        playwright_config_text, "API_WEB_SERVER_TIMEOUT_MS"
    )
    if (
        build_timeout is None
        or webserver_timeout is None
        or build_timeout + 30_000 >= webserver_timeout
    ):
        errors.append(
            "Playwright sandbox build timeout must leave at least 30 seconds for "
            "wrapper final cleanup before the outer webServer timeout"
        )


def _typescript_integer_constant(text: str, name: str) -> int | None:
    match = re.search(rf"const {re.escape(name)} = ([0-9_]+);", text)
    return None if match is None else int(match.group(1).replace("_", ""))


def _validate_security_workflow(workflow_text: str, errors: list[str]) -> None:
    try:
        workflow = yaml.safe_load(workflow_text)
    except yaml.YAMLError as exc:
        errors.append(f"security workflow must be valid YAML: {exc}")
        return
    if not isinstance(workflow, Mapping):
        errors.append("security workflow must be a YAML mapping")
        return
    jobs = workflow.get("jobs")
    if not isinstance(jobs, Mapping):
        errors.append("security workflow must define jobs")
        return

    security_job = jobs.get("security-check")
    security_steps = (
        security_job.get("steps") if isinstance(security_job, Mapping) else None
    )
    checker_command = "python scripts/ci/check_sandbox_isolation_config.py"
    checker_steps = (
        [
            step
            for step in security_steps
            if isinstance(step, Mapping)
            and isinstance(step.get("run"), str)
            and " ".join(str(step["run"]).split()) == checker_command
        ]
        if isinstance(security_steps, list)
        else []
    )
    if len(checker_steps) != 1:
        errors.append("security workflow must run check_sandbox_isolation_config.py")
    elif "if" in checker_steps[0] or "continue-on-error" in checker_steps[0]:
        errors.append("security workflow sandbox checker must run unconditionally")

    image_job = jobs.get("first-party-images")
    if not isinstance(image_job, Mapping):
        errors.append("security workflow must define the first-party image matrix")
        return
    if "continue-on-error" in image_job:
        errors.append("sandbox image matrix job must not weaken failures")
    if "if" in image_job:
        errors.append("sandbox image matrix job must run unconditionally")
    strategy = image_job.get("strategy")
    if not isinstance(strategy, Mapping):
        errors.append("sandbox image matrix must define a strategy")
        return
    if strategy.get("fail-fast") is not False:
        errors.append("sandbox image matrix must set fail-fast: false")
    if strategy.get("max-parallel") != 1:
        errors.append(
            "sandbox image matrix must serialize Docker work with max-parallel: 1"
        )
    matrix = strategy.get("matrix")
    if isinstance(matrix, Mapping) and set(matrix) != {"include"}:
        errors.append("sandbox image matrix must not exclude or override approved rows")
    include = matrix.get("include") if isinstance(matrix, Mapping) else None
    if not isinstance(include, list):
        errors.append("sandbox image matrix must define an include list")
        return
    sandbox_rows = [
        dict(row)
        for row in include
        if isinstance(row, Mapping)
        and (
            row.get("name") == "sandbox"
            or row.get("dockerfile") == SANDBOX_MATRIX_ROW["dockerfile"]
        )
    ]
    if sandbox_rows != [SANDBOX_MATRIX_ROW]:
        errors.append(
            "sandbox image matrix must bind exactly one sandbox row to "
            "infra/docker/sandbox.Dockerfile"
        )

    steps = image_job.get("steps")
    if not isinstance(steps, list):
        errors.append("sandbox image matrix must define build and scan steps")
        return
    if any(isinstance(step, Mapping) and "continue-on-error" in step for step in steps):
        errors.append("sandbox image matrix steps must not weaken failures")

    build_steps = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and isinstance(step.get("run"), str)
        and re.search(r"\bdocker\s+build\b", str(step["run"]))
    ]
    build_commands = [" ".join(str(step["run"]).split()) for step in build_steps]
    expected_build = (
        'docker build -f "${{ matrix.dockerfile }}" '
        f'-t "{SANDBOX_MATRIX_IMAGE_REF}" .'
    )
    if build_commands != [expected_build]:
        errors.append(
            "sandbox image matrix must build its exact Dockerfile with the "
            "name-derived hallu-defense sandbox tag"
        )
    elif "if" in build_steps[0]:
        errors.append("sandbox image matrix build must run unconditionally")

    scans = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
    ]
    if len(scans) != 1:
        errors.append("sandbox image matrix must contain exactly one Trivy scan")
        return
    scan = scans[0]
    if scan.get("uses") != TRIVY_ACTION:
        errors.append(f"sandbox image matrix must pin Trivy action {TRIVY_ACTION}")
    if "if" in scan:
        errors.append("sandbox image matrix Trivy scan must be unconditional")
    inputs = scan.get("with")
    if not isinstance(inputs, Mapping):
        errors.append("sandbox image matrix Trivy scan must define fail-closed inputs")
        return
    expected_inputs = {
        "version": TRIVY_VERSION,
        "image-ref": SANDBOX_MATRIX_IMAGE_REF,
        "exit-code": "1",
        "vuln-type": "os,library",
        "severity": "CRITICAL,HIGH",
    }
    for key, expected in expected_inputs.items():
        if str(inputs.get(key, "")) != expected:
            errors.append(f"sandbox image matrix Trivy scan must set {key}: {expected}")
    if "ignore-unfixed" in inputs:
        errors.append(
            "sandbox image matrix Trivy scan must not ignore unfixed findings"
        )


def _validate_docs(
    *,
    sandbox_adr_text: str,
    kubernetes_sandbox_doc_text: str,
    container_scanning_doc_text: str,
    errors: list[str],
) -> None:
    for marker in (
        "DockerContainerBackend",
        "--network=none",
        "--read-only",
        "Production and staging",
        "assume-unchanged",
        "skip-worktree",
        "canonical",
        "zero-byte",
    ):
        if marker not in sandbox_adr_text:
            errors.append(f"sandbox ADR must document {marker}")
    for marker in (
        "preconditions.uid",
        "Foreground",
        "404",
        "Pods",
        "tenant",
    ):
        if marker not in kubernetes_sandbox_doc_text:
            errors.append(f"Kubernetes sandbox docs must document {marker}")
    for marker in (
        "hallu-defense-sandbox:ci",
        "infra/docker/sandbox.Dockerfile",
        "`sandbox`",
        "all eight first-party images",
    ):
        if marker not in container_scanning_doc_text:
            errors.append(f"container scanning docs must mention {marker}")


def load_current_config() -> Mapping[str, str]:
    return {
        "sandbox_exec_text": SANDBOX_EXEC_PATH.read_text(encoding="utf-8"),
        "sandbox_service_text": SANDBOX_SERVICE_PATH.read_text(encoding="utf-8"),
        "sandbox_kubernetes_text": KUBERNETES_BACKEND_PATH.read_text(encoding="utf-8"),
        "sandbox_runner_text": SANDBOX_RUNNER_PATH.read_text(encoding="utf-8"),
        "sandbox_batch_runner_text": SANDBOX_BATCH_RUNNER_PATH.read_text(
            encoding="utf-8"
        ),
        "sandbox_git_inspector_text": SANDBOX_GIT_INSPECTOR_SOURCE_PATH.read_text(
            encoding="utf-8"
        ),
        "sandbox_workspace_text": SANDBOX_WORKSPACE_PATH.read_text(encoding="utf-8"),
        "config_text": CONFIG_PATH.read_text(encoding="utf-8"),
        "api_dependencies_text": API_DEPENDENCIES_PATH.read_text(encoding="utf-8"),
        "dockerfile_text": DOCKERFILE_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "env_example_text": ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "playwright_config_text": PLAYWRIGHT_CONFIG_PATH.read_text(encoding="utf-8"),
        "playwright_webserver_text": PLAYWRIGHT_WEBSERVER_PATH.read_text(encoding="utf-8"),
        "playwright_teardown_text": PLAYWRIGHT_TEARDOWN_PATH.read_text(encoding="utf-8"),
        "playwright_lifecycle_text": PLAYWRIGHT_LIFECYCLE_PATH.read_text(encoding="utf-8"),
        "playwright_sandbox_helper_text": PLAYWRIGHT_SANDBOX_HELPER_PATH.read_text(
            encoding="utf-8"
        ),
        "sandbox_adr_text": SANDBOX_ADR_PATH.read_text(encoding="utf-8"),
        "kubernetes_sandbox_doc_text": KUBERNETES_SANDBOX_DOC_PATH.read_text(
            encoding="utf-8"
        ),
        "container_scanning_doc_text": CONTAINER_SCANNING_DOC_PATH.read_text(
            encoding="utf-8"
        ),
    }


def main() -> None:
    validate_sandbox_isolation_config(**load_current_config())
    print("Validated sandbox Docker isolation config.")


if __name__ == "__main__":
    main()
