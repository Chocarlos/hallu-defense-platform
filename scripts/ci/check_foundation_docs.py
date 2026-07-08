from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_PATH = ROOT / "AGENTS.md"
PLAN_PATH = ROOT / "docs" / "PLAN_MASTER.md"
ADR_DIR = ROOT / "docs" / "ADR"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_AGENT_SECTIONS = (
    "## Required Working Loop",
    "## Non-Negotiable Rules",
    "## Current Architecture",
    "## Standard Commands",
)
REQUIRED_AGENT_MARKERS = (
    "docs/PLAN_MASTER.md",
    "docs/TRACEABILITY_MATRIX.md",
    "docs/WORKLOG.md",
    "Do not claim tests",
    "Do not mix tenants",
)
REQUIRED_PLAN_SECTIONS = (
    "## Product Goal",
    "## Product Surfaces",
    "## Mandatory Stack",
    "## Public Contracts",
    "## Verification Pipeline",
    "## Milestones",
)
REQUIRED_PLAN_MARKERS = (
    "LLM responses",
    "Atomic claims",
    "Agent actions",
    "Code Agents",
    "Claim",
    "Evidence",
    "ClaimVerdict",
    "VerificationRun",
    "ToolCallEnvelope",
    "SandboxRun",
)
REQUIRED_ADR_TOPICS = {
    "architecture": "Architecture",
    "data-plane-control-plane": "Data Plane",
    "verification-pipeline": "Verification Pipeline",
    "security-model": "Security Model",
    "sandbox-model": "Sandbox Model",
    "policy-engine": "Policy Engine",
}
ADR_REQUIRED_SECTION_ALIASES = (
    ("## Status", "## Estado"),
    ("## Context", "## Contexto"),
    ("## Decision", "## Decision"),
    ("## Consequences", "## Consecuencias"),
)


class FoundationDocsError(ValueError):
    pass


def validate_foundation_docs(
    *,
    agents_text: str,
    plan_text: str,
    adr_files: dict[str, str],
) -> None:
    errors: list[str] = []
    _validate_required_text("AGENTS.md", agents_text, REQUIRED_AGENT_SECTIONS, errors)
    _validate_required_text("AGENTS.md", agents_text, REQUIRED_AGENT_MARKERS, errors)
    _validate_required_text("docs/PLAN_MASTER.md", plan_text, REQUIRED_PLAN_SECTIONS, errors)
    _validate_required_text("docs/PLAN_MASTER.md", plan_text, REQUIRED_PLAN_MARKERS, errors)
    _validate_adrs(adr_files, errors)

    if errors:
        raise FoundationDocsError("\n".join(errors))


def validate_supporting_files(*, makefile_text: str, ci_workflow_text: str) -> None:
    errors: list[str] = []
    required_script = "scripts/ci/check_foundation_docs.py"
    if "foundation-docs-check:" not in makefile_text or required_script not in makefile_text:
        errors.append("Makefile must expose foundation-docs-check")
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    if "foundation-docs-check" not in phony_line:
        errors.append(".PHONY must include foundation-docs-check")
    if required_script not in ci_workflow_text:
        errors.append("CI workflow must run check_foundation_docs.py")

    if errors:
        raise FoundationDocsError("\n".join(errors))


def load_adr_files(path: Path = ADR_DIR) -> dict[str, str]:
    if not path.exists():
        return {}
    return {
        adr_path.name: adr_path.read_text(encoding="utf-8")
        for adr_path in sorted(path.glob("*.md"))
    }


def _validate_required_text(
    label: str,
    text: str,
    required_markers: tuple[str, ...],
    errors: list[str],
) -> None:
    if not text.strip():
        errors.append(f"{label} must not be empty")
        return
    for marker in required_markers:
        if marker not in text:
            errors.append(f"{label} missing required marker: {marker}")


def _validate_adrs(adr_files: dict[str, str], errors: list[str]) -> None:
    if len(adr_files) < len(REQUIRED_ADR_TOPICS):
        errors.append(
            f"docs/ADR must contain at least {len(REQUIRED_ADR_TOPICS)} ADR files"
        )
    for slug, title_marker in REQUIRED_ADR_TOPICS.items():
        matching = {
            name: text
            for name, text in adr_files.items()
            if slug in name
        }
        if not matching:
            errors.append(f"docs/ADR missing required ADR topic: {slug}")
            continue
        for name, text in matching.items():
            _validate_adr_file(name, text, title_marker, errors)


def _validate_adr_file(name: str, text: str, title_marker: str, errors: list[str]) -> None:
    if not text.startswith("# ADR "):
        errors.append(f"docs/ADR/{name} must start with an ADR heading")
    if title_marker not in text:
        errors.append(f"docs/ADR/{name} missing title marker: {title_marker}")
    for aliases in ADR_REQUIRED_SECTION_ALIASES:
        if not any(alias in text for alias in aliases):
            errors.append(f"docs/ADR/{name} missing section: {aliases[0]}")


def main() -> None:
    validate_foundation_docs(
        agents_text=AGENTS_PATH.read_text(encoding="utf-8"),
        plan_text=PLAN_PATH.read_text(encoding="utf-8"),
        adr_files=load_adr_files(),
    )
    validate_supporting_files(
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(f"Validated foundation docs with {len(load_adr_files())} ADR file(s).")


if __name__ == "__main__":
    main()
