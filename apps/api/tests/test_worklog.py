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
    raise AssertionError("Repository root not found from worklog test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_worklog = importlib.import_module("scripts.ci.check_worklog")
WORKLOG_PATH = check_worklog.WORKLOG_PATH
WorklogError = check_worklog.WorklogError
parse_worklog = check_worklog.parse_worklog
validate_supporting_files = check_worklog.validate_supporting_files
validate_worklog = check_worklog.validate_worklog


VALID_WORKLOG = """# Worklog

## 2026-07-08 - Earlier entry

Legacy body format.

## 2026-07-08 - Latest structured entry

Slice selected:

- Add a small gate.

Implementation:

- Added `scripts/ci/check_worklog.py`.

Validation:

- `.venv\\Scripts\\python scripts\\ci\\check_worklog.py`: validated 2 entries.

Remaining risks:

- Static format check only.
"""


def test_worklog_parser_reads_dated_entries() -> None:
    entries = parse_worklog(VALID_WORKLOG)

    assert [entry.title for entry in entries] == ["Earlier entry", "Latest structured entry"]
    assert entries[1].date == "2026-07-08"


def test_worklog_validator_accepts_committed_document() -> None:
    entries = validate_worklog(WORKLOG_PATH.read_text(encoding="utf-8"))

    assert len(entries) >= 80
    assert entries[-1].title == "Batch 4 - Live observability and metrics scrape auth"


def test_worklog_validator_rejects_malformed_heading() -> None:
    malformed = VALID_WORKLOG.replace("## 2026-07-08 - Latest structured entry", "## Latest structured entry")

    with pytest.raises(WorklogError, match="malformed worklog heading"):
        validate_worklog(malformed)


def test_worklog_validator_rejects_latest_entry_missing_sections() -> None:
    malformed = VALID_WORKLOG.replace("Validation:", "Evidence:")

    with pytest.raises(WorklogError, match="Validation"):
        validate_worklog(malformed)


def test_worklog_validator_rejects_latest_entry_without_evidence() -> None:
    malformed = VALID_WORKLOG.replace(
        "`.venv\\Scripts\\python scripts\\ci\\check_worklog.py`: validated 2 entries.",
        "Manual review only.",
    )

    with pytest.raises(WorklogError, match="command or result evidence"):
        validate_worklog(malformed)


def test_worklog_supporting_files_must_wire_gate() -> None:
    with pytest.raises(WorklogError, match="Makefile"):
        validate_supporting_files(
            makefile_text=".PHONY: test\ntest:\n\tpython -m pytest\n",
            ci_workflow_text="python scripts/ci/check_worklog.py",
        )
