from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_verifier_calibration_wiring_is_present() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    evals = (ROOT / ".github" / "workflows" / "evals.yml").read_text(encoding="utf-8")

    assert "verifier-calibration-generate" in makefile
    assert "verifier-calibration-check" in makefile
    assert "scripts/dev/generate_verifier_calibration.py" in makefile
    assert "scripts/ci/check_verifier_calibration.py" in makefile
    assert "scripts/ci/check_verifier_calibration.py" in ci
    assert "scripts/ci/check_verifier_calibration.py" in evals


def test_verifier_calibration_artifact_is_committed_under_evals_reports() -> None:
    artifact = ROOT / "evals" / "reports" / "verifier-calibration.json"

    assert artifact.exists()
    assert artifact.read_text(encoding="utf-8").startswith("{\n")


def test_verifier_calibration_wiring_test_detects_missing_makefile_target(
    tmp_path: Path,
) -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    broken = makefile.replace("verifier-calibration-check", "")

    with pytest.raises(AssertionError):
        assert "verifier-calibration-check" in broken
