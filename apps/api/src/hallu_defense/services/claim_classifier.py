from __future__ import annotations

import re

from hallu_defense.domain.models import Claim, ClaimType, RiskLevel

FILE_RE = re.compile(r"\b[\w./-]+\.(?:py|ts|tsx|js|jsx|go|rs|java|kt|md|json|yaml|yml)\b", re.I)
TEST_RE = re.compile(r"\b(test|tests|pytest|passed|failed|exit code|build|lint|typecheck)\b", re.I)
TOOL_RE = re.compile(r"\b(tool|called|api|stdout|stderr|command output|observed|ejecute|corri)\b", re.I)
POLICY_RE = re.compile(r"\b(policy|politica|must|shall|required|requires|approval|permitido|obligatorio)\b", re.I)
ACTION_RE = re.compile(r"\b(delete|write|send|deploy|charge|transfer|remove|execute|borrar|enviar)\b", re.I)
OPINION_RE = re.compile(r"\b(i think|creo que|opinion|probably|tal vez|should|deberia)\b", re.I)
NUMBER_RE = re.compile(r"\d")
CALC_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:[+*/=-])\s*\d+(?:\.\d+)?\b")


class ClaimClassifier:
    def classify(self, claims: list[Claim], task_type: str = "chat") -> list[Claim]:
        return [self._classify_one(claim, task_type) for claim in claims]

    def _classify_one(self, claim: Claim, task_type: str) -> Claim:
        text = claim.text
        claim_type = ClaimType.WORLD_FACT
        risk = RiskLevel.MEDIUM
        requires_evidence = True

        if TEST_RE.search(text):
            claim_type = ClaimType.TEST_RESULT
            risk = RiskLevel.HIGH
        elif FILE_RE.search(text):
            claim_type = ClaimType.REPO_STATE
            risk = RiskLevel.HIGH
        elif TOOL_RE.search(text):
            claim_type = ClaimType.TOOL_OBSERVATION
            risk = RiskLevel.HIGH
        elif POLICY_RE.search(text):
            claim_type = ClaimType.POLICY_CLAIM
            risk = RiskLevel.HIGH
        elif ACTION_RE.search(text):
            claim_type = ClaimType.PROPOSED_ACTION
            risk = RiskLevel.HIGH
        elif NUMBER_RE.search(text) and CALC_RE.search(text):
            claim_type = ClaimType.COMPUTED_VALUE
            risk = RiskLevel.MEDIUM
        elif OPINION_RE.search(text):
            claim_type = ClaimType.OPINION
            risk = RiskLevel.LOW
            requires_evidence = False
        elif task_type in {"rag", "summary", "document_qa"}:
            claim_type = ClaimType.DOC_GROUNDED

        return claim.model_copy(
            update={
                "type": claim_type,
                "risk_level": risk,
                "requires_evidence": requires_evidence,
                "canonical_form": claim.canonical_form or text.lower(),
            }
        )
