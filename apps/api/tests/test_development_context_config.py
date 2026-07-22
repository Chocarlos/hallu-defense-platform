from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROJECT_BRIEF = ROOT / "docs" / "development" / "project-brief.md"
PRIOR_REPORT = ROOT / "docs" / "development" / "prior-session-report.md"
ENTERPRISE_BATCH = ROOT / "docs" / "development" / "enterprise-batch.md"
ENTERPRISE_BATCH_2 = ROOT / "docs" / "development" / "enterprise-batch-2.md"


def test_development_context_documents_use_neutral_names() -> None:
    for path in (
        PROJECT_BRIEF,
        PRIOR_REPORT,
        ENTERPRISE_BATCH,
        ENTERPRISE_BATCH_2,
    ):
        assert path.is_file()
        assert "claude" not in path.name.casefold()
        assert "fable" not in path.name.casefold()


def test_project_brief_preserves_security_and_evidence_rules() -> None:
    brief = PROJECT_BRIEF.read_text(encoding="utf-8")

    for marker in (
        "AGENTS.md",
        "docs/PLAN_MASTER.md",
        "docs/TRACEABILITY_MATRIX.md",
        "docs/WORKLOG.md",
        "deterministic evidence",
        "Do not weaken security defaults",
    ):
        assert marker in brief


def test_enterprise_batches_preserve_scoped_delivery_contract() -> None:
    batch = ENTERPRISE_BATCH.read_text(encoding="utf-8")
    batch_2 = ENTERPRISE_BATCH_2.read_text(encoding="utf-8")

    assert "RAG live persistence and tenant isolation" in batch
    assert "Contract/codegen drift reduction" in batch
    assert "full-slice discipline" in batch_2
    assert "TRACEABILITY_MATRIX.md" in batch_2
    assert "WORKLOG.md" in batch_2
