from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from foundation infra test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_foundation_infra = importlib.import_module("scripts.ci.check_foundation_infra")
API_PYPROJECT_PATH = check_foundation_infra.API_PYPROJECT_PATH
CI_WORKFLOW_PATH = check_foundation_infra.CI_WORKFLOW_PATH
FoundationInfraError = check_foundation_infra.FoundationInfraError
MAKEFILE_PATH = check_foundation_infra.MAKEFILE_PATH
PACKAGE_JSON_PATH = check_foundation_infra.PACKAGE_JSON_PATH
REQUIRED_PATHS = check_foundation_infra.REQUIRED_PATHS
collect_existing_paths = check_foundation_infra.collect_existing_paths
collect_workflow_files = check_foundation_infra.collect_workflow_files
validate_foundation_infra = check_foundation_infra.validate_foundation_infra


def _current_inputs() -> dict[str, object]:
    return {
        "existing_paths": collect_existing_paths(),
        "package_json_text": PACKAGE_JSON_PATH.read_text(encoding="utf-8"),
        "api_pyproject_text": API_PYPROJECT_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "workflow_files": collect_workflow_files(),
    }


def test_foundation_infra_validator_accepts_current_repository() -> None:
    validate_foundation_infra(**_current_inputs())


def test_foundation_infra_rejects_missing_required_path() -> None:
    inputs = _current_inputs()
    paths = set(REQUIRED_PATHS)
    paths.remove("packages/contracts")
    inputs["existing_paths"] = paths

    with pytest.raises(FoundationInfraError, match="packages/contracts"):
        validate_foundation_infra(**inputs)


def test_foundation_infra_rejects_missing_workspace() -> None:
    inputs = _current_inputs()
    inputs["package_json_text"] = str(inputs["package_json_text"]).replace(
        '    "apps/console"',
        '    "apps/missing-console"',
    )

    with pytest.raises(FoundationInfraError, match="apps/console"):
        validate_foundation_infra(**inputs)


def test_foundation_infra_rejects_missing_make_target() -> None:
    inputs = _current_inputs()
    inputs["makefile_text"] = str(inputs["makefile_text"]).replace(
        "foundation-infra-check:\n\t$(PY) scripts/ci/check_foundation_infra.py\n",
        "",
    )

    with pytest.raises(FoundationInfraError, match="foundation-infra-check"):
        validate_foundation_infra(**inputs)


def test_foundation_infra_rejects_unwired_make_target_body() -> None:
    inputs = _current_inputs()
    inputs["makefile_text"] = str(inputs["makefile_text"]).replace(
        "$(PY) scripts/ci/check_foundation_infra.py",
        "$(PY) scripts/ci/missing_foundation_infra.py",
    )

    with pytest.raises(FoundationInfraError, match="check_foundation_infra.py"):
        validate_foundation_infra(**inputs)


def test_foundation_infra_rejects_missing_ci_step() -> None:
    inputs = _current_inputs()
    inputs["ci_workflow_text"] = str(inputs["ci_workflow_text"]).replace(
        "python scripts/ci/check_foundation_infra.py",
        "python scripts/ci/missing_foundation_infra.py",
    )

    with pytest.raises(FoundationInfraError, match="check_foundation_infra.py"):
        validate_foundation_infra(**inputs)


def test_foundation_infra_rejects_missing_workflow_file() -> None:
    inputs = _current_inputs()
    workflow_files = set(inputs["workflow_files"])
    workflow_files.remove("security.yml")
    inputs["workflow_files"] = workflow_files

    with pytest.raises(FoundationInfraError, match="security.yml"):
        validate_foundation_infra(**inputs)
