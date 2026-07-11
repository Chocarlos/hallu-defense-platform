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
    raise AssertionError("Repository root not found from traceability matrix test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_traceability_matrix = importlib.import_module("scripts.ci.check_traceability_matrix")
TRACEABILITY_PATH = check_traceability_matrix.TRACEABILITY_PATH
PLAN_MASTER_PATH = check_traceability_matrix.PLAN_MASTER_PATH
TraceabilityMatrixError = check_traceability_matrix.TraceabilityMatrixError
extract_declared_requirement_ids = check_traceability_matrix.extract_declared_requirement_ids
parse_traceability_matrix = check_traceability_matrix.parse_traceability_matrix
validate_supporting_files = check_traceability_matrix.validate_supporting_files
validate_traceability_matrix = check_traceability_matrix.validate_traceability_matrix


VALID_TABLE = """# Traceability Matrix

Statuses: `not_started`, `designed`, `implemented`, `tested`, `documented`, `accepted`.

No item may be marked `accepted` without implementation, tests, documentation, and evidence.

| ID | Description | Files / modules affected | Related contracts | Related endpoints | Tests required | Evidence of validation | Status | Risks / notes |
|---|---|---|---|---|---|---|---|---|
| FND-001 | Root instructions | `AGENTS.md` | n/a | n/a | docs presence check | file created | documented | Keep updated |
| CI-999 | Traceability gate | `scripts/ci/check_traceability_matrix.py` | n/a | n/a | focused tests | `check_traceability_matrix.py` validated rows | accepted | Static gate only |
"""


def test_traceability_matrix_parses_rows() -> None:
    rows = parse_traceability_matrix(VALID_TABLE)

    assert [row.requirement_id for row in rows] == ["FND-001", "CI-999"]
    assert rows[1].status == "accepted"


def test_traceability_matrix_validates_committed_document() -> None:
    rows = validate_traceability_matrix(
        TRACEABILITY_PATH.read_text(encoding="utf-8"),
        plan_text=PLAN_MASTER_PATH.read_text(encoding="utf-8"),
    )

    assert len(rows) >= 180
    assert any(row.requirement_id == "FND-003" for row in rows)


def test_declared_requirement_ids_expand_master_plan_shorthand() -> None:
    declared = extract_declared_requirement_ids(
        "New EVAL-003/004/005, API-022/023, CTR-026 and CI-025/026."
    )

    assert declared == {
        "API-022",
        "API-023",
        "CI-025",
        "CI-026",
        "CTR-026",
        "EVAL-003",
        "EVAL-004",
        "EVAL-005",
    }


def test_traceability_matrix_rejects_master_plan_ids_missing_from_matrix() -> None:
    with pytest.raises(
        TraceabilityMatrixError,
        match="master plan declares requirement IDs missing.*API-022",
    ):
        validate_traceability_matrix(
            VALID_TABLE,
            plan_text="M6 declares API-022 and CI-999.",
        )


def test_traceability_matrix_rejects_duplicate_ids() -> None:
    duplicated = VALID_TABLE.replace("CI-999", "FND-001")

    with pytest.raises(TraceabilityMatrixError, match="duplicate requirement ID"):
        validate_traceability_matrix(duplicated)


def test_traceability_matrix_rejects_unknown_status() -> None:
    malformed = VALID_TABLE.replace(" | accepted | ", " | done | ")

    with pytest.raises(TraceabilityMatrixError, match="status must be one of"):
        validate_traceability_matrix(malformed)


def test_traceability_matrix_rejects_accepted_without_command_evidence() -> None:
    weak_evidence = VALID_TABLE.replace(
        "`check_traceability_matrix.py` validated rows",
        "manual review",
    )

    with pytest.raises(TraceabilityMatrixError, match="accepted rows need deterministic evidence"):
        validate_traceability_matrix(weak_evidence)


def test_traceability_supporting_files_must_wire_gate() -> None:
    with pytest.raises(TraceabilityMatrixError, match="Makefile"):
        validate_supporting_files(
            makefile_text=".PHONY: test\ntest:\n\tpython -m pytest\n",
            ci_workflow_text="python scripts/ci/check_traceability_matrix.py",
        )
