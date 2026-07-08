from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
WORKLOG_PATH = ROOT / "docs" / "WORKLOG.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"

HEADING_RE = re.compile(r"^## (?P<date>\d{4}-\d{2}-\d{2}) - (?P<title>.+)$")
REQUIRED_LATEST_SECTIONS = (
    "Slice selected:",
    "Implementation:",
    "Validation:",
    "Remaining risks:",
)
VALIDATION_EVIDENCE_MARKERS = (
    ".venv",
    "python ",
    "pytest",
    "ruff",
    "mypy",
    "npm ",
    "node ",
    "git ",
    "passed",
    "validated",
    "all checks passed",
    "no obvious secrets found",
)


class WorklogError(ValueError):
    pass


@dataclass(frozen=True)
class WorklogEntry:
    line_number: int
    heading: str
    date: str
    title: str
    body: str


def parse_worklog(text: str) -> list[WorklogEntry]:
    lines = text.splitlines()
    entries: list[WorklogEntry] = []
    heading_indexes = [index for index, line in enumerate(lines) if line.startswith("## ")]
    if not heading_indexes:
        raise WorklogError("worklog must contain at least one dated entry")

    for position, start_index in enumerate(heading_indexes):
        heading = lines[start_index]
        match = HEADING_RE.fullmatch(heading)
        if match is None:
            raise WorklogError(f"line {start_index + 1}: malformed worklog heading")

        end_index = heading_indexes[position + 1] if position + 1 < len(heading_indexes) else len(lines)
        body = "\n".join(lines[start_index + 1 : end_index]).strip()
        if not body:
            raise WorklogError(f"line {start_index + 1}: worklog entry must not be empty")

        entries.append(
            WorklogEntry(
                line_number=start_index + 1,
                heading=heading,
                date=match.group("date"),
                title=match.group("title").strip(),
                body=body,
            )
        )

    return entries


def validate_worklog(text: str) -> list[WorklogEntry]:
    errors: list[str] = []
    entries = parse_worklog(text)
    _validate_latest_entry(entries[-1], errors)
    if errors:
        raise WorklogError("\n".join(errors))
    return entries


def validate_supporting_files(*, makefile_text: str, ci_workflow_text: str) -> None:
    errors: list[str] = []
    required_script = "scripts/ci/check_worklog.py"
    if "worklog-check:" not in makefile_text or required_script not in makefile_text:
        errors.append("Makefile must expose worklog-check")
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    if "worklog-check" not in phony_line:
        errors.append(".PHONY must include worklog-check")
    if required_script not in ci_workflow_text:
        errors.append("CI workflow must run check_worklog.py")

    if errors:
        raise WorklogError("\n".join(errors))


def _validate_latest_entry(entry: WorklogEntry, errors: list[str]) -> None:
    if not entry.title:
        errors.append(f"line {entry.line_number}: latest worklog title must not be empty")
    for section in REQUIRED_LATEST_SECTIONS:
        if section not in entry.body:
            errors.append(f"line {entry.line_number}: latest worklog entry missing `{section}`")

    validation_text = entry.body.partition("Validation:")[2].partition("Remaining risks:")[0].lower()
    if not validation_text.strip():
        errors.append(f"line {entry.line_number}: latest worklog validation section must not be empty")
    elif not any(marker in validation_text for marker in VALIDATION_EVIDENCE_MARKERS):
        errors.append(
            f"line {entry.line_number}: latest worklog validation section must include command or result evidence"
        )


def main() -> None:
    entries = validate_worklog(WORKLOG_PATH.read_text(encoding="utf-8"))
    validate_supporting_files(
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(f"Validated worklog with {len(entries)} entries.")


if __name__ == "__main__":
    main()
