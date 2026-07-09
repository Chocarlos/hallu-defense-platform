from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.check_verifier_calibration import (
    VerifierCalibrationDriftError,
    validate_committed_artifact,
)
from scripts.dev.generate_verifier_calibration import (
    OUTPUT_PATH,
    build_report,
    render_report,
)


def test_verifier_calibration_report_is_deterministic_and_covers_expected_routes() -> None:
    first = build_report()
    second = build_report()

    assert first == second
    assert first["schema_version"] == "verifier-calibration.v1"
    assert first["case_count"] == 8
    statuses = set(first["status_summary"])
    assert {
        "SUPPORTED",
        "PARTIALLY_SUPPORTED",
        "CONTRADICTED",
        "NOT_FOUND",
        "OUT_OF_SCOPE",
    }.issubset(statuses)
    assert all(case["matches_expected"] is True for case in first["cases"])  # type: ignore[index]
    assert "\n" in render_report(first)


def test_verifier_calibration_artifact_matches_regenerated_report() -> None:
    validate_committed_artifact(OUTPUT_PATH)


def test_verifier_calibration_drift_checker_rejects_stale_artifact(tmp_path: Path) -> None:
    stale = tmp_path / "verifier-calibration.json"
    stale.write_text('{"schema_version":"stale"}\n', encoding="utf-8")

    with pytest.raises(VerifierCalibrationDriftError, match="artifact is stale"):
        validate_committed_artifact(stale)
