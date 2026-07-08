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
    raise AssertionError("Repository root not found from foundation docs test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_foundation_docs = importlib.import_module("scripts.ci.check_foundation_docs")
AGENTS_PATH = check_foundation_docs.AGENTS_PATH
PLAN_PATH = check_foundation_docs.PLAN_PATH
FoundationDocsError = check_foundation_docs.FoundationDocsError
load_adr_files = check_foundation_docs.load_adr_files
validate_foundation_docs = check_foundation_docs.validate_foundation_docs
validate_supporting_files = check_foundation_docs.validate_supporting_files


def _minimal_adr(title: str) -> str:
    return f"""# ADR 0001: {title}

## Status

Accepted.

## Context

Context.

## Decision

Decision.

## Consequences

Consequences.
"""


VALID_AGENTS = """# AGENTS.md

## Required Working Loop

Read docs/PLAN_MASTER.md, docs/TRACEABILITY_MATRIX.md, and docs/WORKLOG.md.

## Non-Negotiable Rules

Do not claim tests. Do not mix tenants.

## Current Architecture

Architecture.

## Standard Commands

Commands.
"""

VALID_PLAN = """# Plan Master

## Product Goal

LLM responses. Atomic claims. Agent actions. Code Agents.

## Product Surfaces

Surfaces.

## Mandatory Stack

Stack.

## Public Contracts

Claim Evidence ClaimVerdict VerificationRun ToolCallEnvelope SandboxRun

## Verification Pipeline

Pipeline.

## Milestones

Milestones.
"""

VALID_ADRS = {
    "0001-architecture.md": _minimal_adr("Architecture"),
    "0002-data-plane-control-plane.md": _minimal_adr("Data Plane"),
    "0003-verification-pipeline.md": _minimal_adr("Verification Pipeline"),
    "0004-security-model.md": _minimal_adr("Security Model"),
    "0005-sandbox-model.md": _minimal_adr("Sandbox Model"),
    "0006-policy-engine.md": _minimal_adr("Policy Engine"),
}


def test_foundation_docs_validator_accepts_current_repository_docs() -> None:
    validate_foundation_docs(
        agents_text=AGENTS_PATH.read_text(encoding="utf-8"),
        plan_text=PLAN_PATH.read_text(encoding="utf-8"),
        adr_files=load_adr_files(),
    )


def test_foundation_docs_validator_rejects_missing_agent_loop_marker() -> None:
    agents = VALID_AGENTS.replace("docs/WORKLOG.md", "docs/MISSING.md")

    with pytest.raises(FoundationDocsError, match="docs/WORKLOG.md"):
        validate_foundation_docs(agents_text=agents, plan_text=VALID_PLAN, adr_files=VALID_ADRS)


def test_foundation_docs_validator_rejects_missing_public_contract_marker() -> None:
    plan = VALID_PLAN.replace("SandboxRun", "")

    with pytest.raises(FoundationDocsError, match="SandboxRun"):
        validate_foundation_docs(agents_text=VALID_AGENTS, plan_text=plan, adr_files=VALID_ADRS)


def test_foundation_docs_validator_rejects_missing_required_adr_topic() -> None:
    adrs = dict(VALID_ADRS)
    adrs.pop("0005-sandbox-model.md")

    with pytest.raises(FoundationDocsError, match="sandbox-model"):
        validate_foundation_docs(agents_text=VALID_AGENTS, plan_text=VALID_PLAN, adr_files=adrs)


def test_foundation_docs_validator_rejects_malformed_adr() -> None:
    adrs = dict(VALID_ADRS)
    adrs["0004-security-model.md"] = "# Security Model\n\n## Status\n\nAccepted.\n"

    with pytest.raises(FoundationDocsError, match="ADR heading"):
        validate_foundation_docs(agents_text=VALID_AGENTS, plan_text=VALID_PLAN, adr_files=adrs)


def test_foundation_docs_supporting_files_must_wire_gate() -> None:
    with pytest.raises(FoundationDocsError, match="Makefile"):
        validate_supporting_files(
            makefile_text=".PHONY: test\ntest:\n\tpython -m pytest\n",
            ci_workflow_text="python scripts/ci/check_foundation_docs.py",
        )
