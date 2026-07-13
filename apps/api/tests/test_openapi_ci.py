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
    raise AssertionError("Repository root not found from OpenAPI CI test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_openapi = importlib.import_module("scripts.ci.check_openapi")
export_openapi = importlib.import_module("scripts.ci.export_openapi")
check_openapi_document = check_openapi.check_openapi_document
build_openapi_schema = export_openapi.build_openapi_schema
render_openapi = export_openapi.render_openapi


def test_openapi_check_accepts_generated_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "openapi.yaml"
    artifact.write_text(render_openapi(build_openapi_schema()), encoding="utf-8")

    check_openapi_document(artifact)


def test_openapi_check_detects_drift(tmp_path: Path) -> None:
    artifact = tmp_path / "openapi.yaml"
    artifact.write_text("openapi: stale\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        check_openapi_document(artifact)

    message = str(exc.value)
    assert "OpenAPI artifact is out of date" in message
    assert "---" in message
    assert "generated OpenAPI" in message


def test_openapi_check_matches_committed_artifact() -> None:
    check_openapi_document(_repo_root() / "docs" / "api" / "openapi.yaml")


def test_makefile_exposes_openapi_check_target() -> None:
    makefile = (_repo_root() / "Makefile").read_text(encoding="utf-8")

    assert "openapi-check:" in makefile
    assert "openapi-check" in makefile.partition(".PHONY:")[2].partition("\n")[0]
    assert "scripts/ci/check_openapi.py" in makefile


def test_ci_workflow_runs_openapi_drift_check() -> None:
    workflow = (_repo_root() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python scripts/ci/check_openapi.py" in workflow
    assert "PYTHONPATH: ${{ github.workspace }}/apps/api/src" in workflow


def test_api_readme_documents_openapi_check() -> None:
    readme = (_repo_root() / "docs" / "api" / "README.md").read_text(encoding="utf-8")

    assert "make openapi-check" in readme
