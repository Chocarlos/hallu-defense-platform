from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".claude" / "workflows" / "fable-delegate.js"
RUNBOOK = ROOT / "docs" / "development" / "fable-delegation.md"
BATCH_BACKLOG = ROOT / "docs" / "development" / "fable-enterprise-batch.md"


def test_fable_workflow_requires_goal_and_acceptance_for_write_mode() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "const mode = args?.mode === 'write' ? 'write' : 'read'" in workflow
    assert "if (mode === 'write' && !goal)" in workflow
    assert "Pass args.goal before delegating write-mode implementation." in workflow
    assert "if (mode === 'write' && !acceptance)" in workflow
    assert "Pass args.acceptance before delegating write-mode implementation." in workflow


def test_fable_workflow_injects_required_project_context() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    required_context = [
        "AGENTS.md",
        "docs/PLAN_MASTER.md",
        "docs/TRACEABILITY_MATRIX.md",
        "docs/WORKLOG.md",
        "docs/development/fable-project-brief.md",
        "docs/development/fable-prior-session-report.md",
    ]

    for path in required_context:
        assert path in workflow

    assert "projectBriefRead" in workflow
    assert "priorSessionReportRead" in workflow
    assert "acceptanceMet" in workflow


def test_fable_workflow_uses_fable_model_and_worktree_isolation() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "model: 'fable'" in workflow
    assert "isolation: 'worktree'" in workflow
    assert "effort: 'max'" in workflow


def test_fable_runbook_documents_persistent_branch_and_batch_policy() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")
    normalized_runbook = " ".join(runbook.split())
    batch = BATCH_BACKLOG.read_text(encoding="utf-8")

    assert "fable5/delegation" in runbook
    assert ".claude/worktrees/fable5-delegation" in runbook
    assert "Agent type 'general-purpose' not found" in normalized_runbook
    assert "docs/development/fable-enterprise-batch.md" in runbook
    assert "wf_6e5f935f-e44" in batch
    assert "RAG live persistence and tenant isolation" in batch
    assert "Contract/codegen drift reduction" in batch
