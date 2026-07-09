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


def test_sandbox_isolation_config_rejects_missing_prod_fail_closed_guard() -> None:
    config = dict(load_current_config())
    config["config_text"] = config["config_text"].replace(
        "Production and staging must set HALLU_DEFENSE_SANDBOX_BACKEND=docker.",
        "Production and staging allow host sandbox.",
    )

    with pytest.raises(SandboxIsolationConfigError, match="fail closed"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_root_dockerfile_user() -> None:
    config = dict(load_current_config())
    config["dockerfile_text"] = config["dockerfile_text"].replace("USER 10001", "USER root")

    with pytest.raises(SandboxIsolationConfigError, match="UID 10001"):
        validate_sandbox_isolation_config(**config)


def test_sandbox_isolation_config_rejects_missing_makefile_wiring() -> None:
    config = dict(load_current_config())
    config["makefile_text"] = config["makefile_text"].replace(
        "$(PY) scripts/ci/check_sandbox_isolation_config.py",
        "$(PY) scripts/ci/disabled_sandbox_isolation_config.py",
    )

    with pytest.raises(SandboxIsolationConfigError, match="sandbox-isolation-config"):
        validate_sandbox_isolation_config(**config)
