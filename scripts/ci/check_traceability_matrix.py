from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
TRACEABILITY_PATH = ROOT / "docs" / "TRACEABILITY_MATRIX.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"

EXPECTED_COLUMNS = [
    "ID",
    "Description",
    "Files / modules affected",
    "Related contracts",
    "Related endpoints",
    "Tests required",
    "Evidence of validation",
    "Status",
    "Risks / notes",
]
ALLOWED_STATUSES = {"not_started", "designed", "implemented", "tested", "documented", "accepted"}
ID_PATTERN = re.compile(r"^[A-Z]+-\d{3}$")
WEAK_EVIDENCE_VALUES = {
    "",
    "n/a",
    "this file",
    "file created",
    "existing workflow",
    "current tests partial",
    "manual review",
}
DETERMINISTIC_EVIDENCE_MARKERS = (
    "`",
    " passed",
    "validated",
    "validates",
    "validation",
    "tests prove",
    "test proves",
    "schema/example",
    "endpoint test",
    "focused tests",
    "ci ",
)


class TraceabilityMatrixError(ValueError):
    pass


@dataclass(frozen=True)
class TraceabilityRow:
    line_number: int
    requirement_id: str
    description: str
    files: str
    contracts: str
    endpoints: str
    tests_required: str
    evidence: str
    status: str
    risks: str


def parse_traceability_matrix(text: str) -> list[TraceabilityRow]:
    lines = text.splitlines()
    table_lines = [
        (index + 1, line)
        for index, line in enumerate(lines)
        if line.startswith("|")
    ]
    if len(table_lines) < 3:
        raise TraceabilityMatrixError("traceability matrix must contain a markdown table")

    header = _split_markdown_row(table_lines[0][1], table_lines[0][0])
    if header != EXPECTED_COLUMNS:
        raise TraceabilityMatrixError(
            "traceability table header changed; expected "
            f"{EXPECTED_COLUMNS}, got {header}"
        )

    separator = _split_markdown_row(table_lines[1][1], table_lines[1][0])
    if len(separator) != len(EXPECTED_COLUMNS) or not all(set(cell) <= {"-"} for cell in separator):
        raise TraceabilityMatrixError("traceability table separator is malformed")

    rows: list[TraceabilityRow] = []
    for line_number, line in table_lines[2:]:
        cells = _split_markdown_row(line, line_number)
        if len(cells) != len(EXPECTED_COLUMNS):
            raise TraceabilityMatrixError(
                f"line {line_number}: expected {len(EXPECTED_COLUMNS)} columns, got {len(cells)}"
            )
        rows.append(
            TraceabilityRow(
                line_number=line_number,
                requirement_id=cells[0],
                description=cells[1],
                files=cells[2],
                contracts=cells[3],
                endpoints=cells[4],
                tests_required=cells[5],
                evidence=cells[6],
                status=cells[7],
                risks=cells[8],
            )
        )
    return rows


def validate_traceability_matrix(text: str) -> list[TraceabilityRow]:
    errors: list[str] = []
    _validate_preamble(text, errors)
    rows = parse_traceability_matrix(text)
    _validate_rows(rows, errors)
    if errors:
        raise TraceabilityMatrixError("\n".join(errors))
    return rows


def validate_supporting_files(*, makefile_text: str, ci_workflow_text: str) -> None:
    errors: list[str] = []
    required_script = "scripts/ci/check_traceability_matrix.py"
    if "traceability-check:" not in makefile_text or required_script not in makefile_text:
        errors.append("Makefile must expose traceability-check")
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    if "traceability-check" not in phony_line:
        errors.append(".PHONY must include traceability-check")
    if required_script not in ci_workflow_text:
        errors.append("CI workflow must run check_traceability_matrix.py")

    if errors:
        raise TraceabilityMatrixError("\n".join(errors))


def _validate_preamble(text: str, errors: list[str]) -> None:
    for status in sorted(ALLOWED_STATUSES):
        if f"`{status}`" not in text:
            errors.append(f"status vocabulary is missing `{status}`")
    if "No item may be marked `accepted`" not in text:
        errors.append("accepted status rule is missing")


def _validate_rows(rows: list[TraceabilityRow], errors: list[str]) -> None:
    if not rows:
        errors.append("traceability matrix must contain at least one requirement row")
        return

    seen: set[str] = set()
    for row in rows:
        row_prefix = f"line {row.line_number} ({row.requirement_id})"
        if not ID_PATTERN.fullmatch(row.requirement_id):
            errors.append(f"{row_prefix}: ID must match PREFIX-000")
        if row.requirement_id in seen:
            errors.append(f"{row_prefix}: duplicate requirement ID")
        seen.add(row.requirement_id)

        for field_name, value in (
            ("Description", row.description),
            ("Files / modules affected", row.files),
            ("Related contracts", row.contracts),
            ("Related endpoints", row.endpoints),
            ("Tests required", row.tests_required),
            ("Evidence of validation", row.evidence),
            ("Status", row.status),
            ("Risks / notes", row.risks),
        ):
            if not value.strip():
                errors.append(f"{row_prefix}: {field_name} must not be empty")

        if row.status not in ALLOWED_STATUSES:
            errors.append(f"{row_prefix}: status must be one of {sorted(ALLOWED_STATUSES)}")

        if row.status == "accepted":
            _validate_accepted_row(row, row_prefix, errors)


def _validate_accepted_row(row: TraceabilityRow, row_prefix: str, errors: list[str]) -> None:
    evidence = _normalize(row.evidence)
    if evidence in WEAK_EVIDENCE_VALUES:
        errors.append(f"{row_prefix}: accepted rows need deterministic evidence")
    if _normalize(row.tests_required) in {"", "n/a", "manual review"}:
        errors.append(f"{row_prefix}: accepted rows require explicit tests")
    if _normalize(row.files) in {"", "n/a"}:
        errors.append(f"{row_prefix}: accepted rows require implementation files")
    if not _has_deterministic_evidence(row.evidence):
        errors.append(f"{row_prefix}: accepted rows require command/test/schema evidence")


def _has_deterministic_evidence(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in DETERMINISTIC_EVIDENCE_MARKERS)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _split_markdown_row(line: str, line_number: int) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise TraceabilityMatrixError(f"line {line_number}: markdown table row must start and end with |")
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def main() -> None:
    rows = validate_traceability_matrix(TRACEABILITY_PATH.read_text(encoding="utf-8"))
    validate_supporting_files(
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(f"Validated traceability matrix with {len(rows)} requirement row(s).")


if __name__ == "__main__":
    main()
