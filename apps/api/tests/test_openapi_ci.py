from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.check_openapi import check_openapi_document
from scripts.ci.export_openapi import build_openapi_schema, render_openapi


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
