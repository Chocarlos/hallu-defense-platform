from __future__ import annotations

import pytest

from scripts.ci.check_sandbox_isolation_config import (
    SandboxIsolationConfigError,
    load_current_config,
    validate_sandbox_isolation_config,
)


def test_sandbox_isolation_config_validates_current_artifacts() -> None:
    validate_sandbox_isolation_config(**load_current_config())


def test_sandbox_isolation_config_rejects_missing_network_none_flag() -> None:
    config = dict(load_current_config())
    config["sandbox_exec_text"] = config["sandbox_exec_text"].replace('"--network=none"', '"--network=bridge"')

    with pytest.raises(SandboxIsolationConfigError, match="--network=none"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_host_subprocess_backend() -> None:
    config = dict(load_current_config())
    config["sandbox_exec_text"] += "\nclass HostSubprocessBackend:\n    pass\n"

    with pytest.raises(SandboxIsolationConfigError, match="host subprocess"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_prod_fail_closed_guard() -> None:
    config = dict(load_current_config())
    config["config_text"] = config["config_text"].replace(
        "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation.",
        "HALLU_DEFENSE_SANDBOX_BACKEND=docker.",
    )

    with pytest.raises(
        SandboxIsolationConfigError,
        match="tenant-bound Kubernetes",
    ):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_root_dockerfile_user() -> None:
    config = dict(load_current_config())
    config["dockerfile_text"] = config["dockerfile_text"].replace("USER 10001", "USER root")

    with pytest.raises(SandboxIsolationConfigError, match="UID 10001"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_factory_production_docker_bypass() -> None:
    config = dict(load_current_config())
    config["sandbox_exec_text"] = config["sandbox_exec_text"].replace(
        "HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes for tenant-bound isolation.",
        "HALLU_DEFENSE_SANDBOX_BACKEND=docker.",
    )

    with pytest.raises(SandboxIsolationConfigError, match="factory.*Docker"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_bounded_ephemeral_docker_workspace() -> None:
    config = dict(load_current_config())
    config["sandbox_exec_text"] = config["sandbox_exec_text"].replace(
        "tmpfs-size={MAX_SANDBOX_WORKSPACE_BYTES},tmpfs-mode=1777",
        "tmpfs-mode=1777",
    )

    with pytest.raises(SandboxIsolationConfigError, match="tmpfs-size"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_post_snapshot_binding() -> None:
    config = dict(load_current_config())
    config["sandbox_service_text"] = config["sandbox_service_text"].replace(
        "batch.post_snapshot_fingerprint != expected_source_fingerprint",
        "False",
    )

    with pytest.raises(SandboxIsolationConfigError, match="post_snapshot"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_git_config_guard() -> None:
    config = dict(load_current_config())
    config["sandbox_git_inspector_text"] = config[
        "sandbox_git_inspector_text"
    ].replace("_repository_config_guard", "removed_repository_guard")

    with pytest.raises(SandboxIsolationConfigError, match="configuration guard"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_streaming_workspace_hash() -> None:
    config = dict(load_current_config())
    config["sandbox_workspace_text"] = config["sandbox_workspace_text"].replace(
        "_update_digest_from_unchanged_regular_file",
        "removed_digest_update",
    )

    with pytest.raises(SandboxIsolationConfigError, match="streaming fingerprint"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_baked_git_inspector() -> None:
    config = dict(load_current_config())
    config["dockerfile_text"] = config["dockerfile_text"].replace(
        "COPY infra/docker/sandbox_git_inspector.py /opt/hallu-defense/sandbox_git_inspector.py",
        "",
    )

    with pytest.raises(SandboxIsolationConfigError, match="sandbox_git_inspector"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_writable_docker_source_mount() -> None:
    config = dict(load_current_config())
    config["sandbox_exec_text"] = config["sandbox_exec_text"].replace(
        "target={DOCKER_SOURCE_DIR},readonly",
        "target={DOCKER_SOURCE_DIR}",
    )

    with pytest.raises(SandboxIsolationConfigError, match="DOCKER_SOURCE_DIR"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_ephemeral_kubernetes_workspace() -> None:
    config = dict(load_current_config())
    config["sandbox_kubernetes_text"] = config["sandbox_kubernetes_text"].replace(
        'SOURCE_MOUNT_PATH = "/hallu-source"',
        'SOURCE_MOUNT_PATH = "/workspace"',
    )

    with pytest.raises(SandboxIsolationConfigError, match="/hallu-source"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_allowlisted_fail_closed_gate() -> None:
    config = dict(load_current_config())
    config["sandbox_service_text"] = config["sandbox_service_text"].replace(
        "allowlisted network policy requires an exact destination allowlist",
        "allowlisted network policy enabled",
    )

    with pytest.raises(SandboxIsolationConfigError, match="destination allowlist"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_makefile_wiring() -> None:
    config = dict(load_current_config())
    config["makefile_text"] = config["makefile_text"].replace(
        "$(PY) scripts/ci/check_sandbox_isolation_config.py",
        "$(PY) scripts/ci/disabled_sandbox_isolation_config.py",
    )

    with pytest.raises(SandboxIsolationConfigError, match="sandbox-isolation-config"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_stale_playwright_sandbox_image() -> None:
    config = dict(load_current_config())
    config["playwright_webserver_text"] = config["playwright_webserver_text"].replace(
        '"infra/docker/sandbox.Dockerfile"', '"infra/docker/not-sandbox.Dockerfile"'
    )

    with pytest.raises(SandboxIsolationConfigError, match="Playwright API wrapper"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_reintroduced_shared_sandbox_tag() -> None:
    config = dict(load_current_config())
    config["playwright_config_text"] = (
        config["playwright_config_text"] + '\n// hallu-defense-sandbox:ci\n'
    )

    with pytest.raises(SandboxIsolationConfigError, match="shared hallu-defense-sandbox:ci"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_python_source_pythonpath() -> None:
    config = dict(load_current_config())
    config["playwright_config_text"] = config["playwright_config_text"].replace(
        "PYTHONPATH: apiSourceRoot", "PYTHONPATH: undefined"
    )

    with pytest.raises(SandboxIsolationConfigError, match="PYTHONPATH: apiSourceRoot"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_global_setup_cleanup_order() -> None:
    config = dict(load_current_config())
    config["playwright_config_text"] += '\nglobalSetup: "./e2e/global-setup",\n'

    with pytest.raises(SandboxIsolationConfigError, match="must not use globalSetup"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_preflight_wrapper() -> None:
    config = dict(load_current_config())
    config["playwright_webserver_text"] = config["playwright_webserver_text"].replace(
        "pythonSourcePreflightArgs(", "disabledPreflightArgs("
    )

    with pytest.raises(SandboxIsolationConfigError, match="preflight imports"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_final_teardown() -> None:
    config = dict(load_current_config())
    config["playwright_teardown_text"] = config["playwright_teardown_text"].replace(
        "removeSandboxImageIfPresent", "leaveSandboxImageBehind"
    )

    with pytest.raises(SandboxIsolationConfigError, match="final teardown"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_lifecycle_finally() -> None:
    config = dict(load_current_config())
    config["playwright_lifecycle_text"] = config["playwright_lifecycle_text"].replace(
        "dependencies.finalCleanup();", "return;"
    )

    with pytest.raises(SandboxIsolationConfigError, match="guarantee final cleanup"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_unbounded_cleanup() -> None:
    config = dict(load_current_config())
    config["playwright_sandbox_helper_text"] = config[
        "playwright_sandbox_helper_text"
    ].replace("timeout: DOCKER_CLEANUP_TIMEOUT_MS", "timeout: undefined")

    with pytest.raises(SandboxIsolationConfigError, match="time-bounded"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_requires_outer_timeout_cleanup_margin() -> None:
    config = dict(load_current_config())
    config["playwright_config_text"] = config["playwright_config_text"].replace(
        "API_WEB_SERVER_TIMEOUT_MS = 300_000", "API_WEB_SERVER_TIMEOUT_MS = 260_000"
    )

    with pytest.raises(SandboxIsolationConfigError, match="at least 30 seconds"):
        validate_sandbox_isolation_config(**config)
