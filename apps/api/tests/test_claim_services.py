from __future__ import annotations

from hallu_defense.domain.models import (
    Authority,
    Claim,
    ClaimExtractionRequest,
    ClaimType,
    Evidence,
    EvidenceKind,
    FinalDecision,
    RiskLevel,
    VerdictAction,
    VerdictStatus,
    ClaimVerdict,
)
from hallu_defense.services.claim_classifier import ClaimClassifier
from hallu_defense.services.claim_extractor import ClaimExtractor
from hallu_defense.services.repair import ResponseRepairer


def _claim(claim_id: str, text: str) -> Claim:
    return Claim(claim_id=claim_id, text=text, canonical_form=text.lower())


def _verdict(
    claim_id: str,
    *,
    status: VerdictStatus,
    action: VerdictAction,
    evidence_ids: list[str] | None = None,
    reason: str = "tested reason",
) -> ClaimVerdict:
    return ClaimVerdict(
        claim_id=claim_id,
        status=status,
        confidence=0.9,
        evidence_ids=evidence_ids or [],
        action=action,
        reason=reason,
    )


def test_claim_extractor_splits_long_atomic_parts_and_preserves_spans() -> None:
    message = (
        "Hola. "
        "The control plane records tenant-specific audit events for every verification run "
        "and the console shows reviewers pending approval requests for high-risk actions "
        "and the SDK rejects malformed approval decisions before proxying them."
    )

    claims = ClaimExtractor().extract(
        ClaimExtractionRequest(message_text=message, message_id="msg_unit_extract")
    )

    assert [claim.claim_id for claim in claims] == ["clm_0001", "clm_0002", "clm_0003"]
    assert [claim.text for claim in claims] == [
        "The control plane records tenant-specific audit events for every verification run",
        "the console shows reviewers pending approval requests for high-risk actions",
        "the SDK rejects malformed approval decisions before proxying them",
    ]
    for claim in claims:
        assert claim.source_span is not None
        assert claim.source_span.message_id == "msg_unit_extract"
        assert message[claim.source_span.start_char : claim.source_span.end_char] == claim.text


def test_claim_classifier_prioritizes_high_risk_deterministic_claims() -> None:
    classified = ClaimClassifier().classify(
        [
            _claim("clm_tests", "The pytest tests passed for apps/api/service.py."),
            _claim("clm_repo", "The function load_user exists in apps/api/service.py."),
            _claim("clm_tool", "The command output observed stdout with status ok."),
            _claim("clm_policy", "Policy requires approval for destructive actions."),
            _claim("clm_action", "Delete the production corpus."),
            _claim("clm_opinion", "I think this architecture is reasonable."),
            _claim("clm_doc", "Employees receive 15 days of vacation."),
        ],
        task_type="document_qa",
    )

    by_id = {claim.claim_id: claim for claim in classified}
    assert by_id["clm_tests"].type == ClaimType.TEST_RESULT
    assert by_id["clm_tests"].risk_level == RiskLevel.HIGH
    assert by_id["clm_repo"].type == ClaimType.REPO_STATE
    assert by_id["clm_tool"].type == ClaimType.TOOL_OBSERVATION
    assert by_id["clm_policy"].type == ClaimType.POLICY_CLAIM
    assert by_id["clm_action"].type == ClaimType.PROPOSED_ACTION
    assert by_id["clm_opinion"].type == ClaimType.OPINION
    assert by_id["clm_opinion"].risk_level == RiskLevel.LOW
    assert by_id["clm_opinion"].requires_evidence is False
    assert by_id["clm_doc"].type == ClaimType.DOC_GROUNDED
    assert by_id["clm_doc"].requires_evidence is True


def test_response_repairer_blocks_before_repairing_or_allowing() -> None:
    claims = [
        _claim("clm_supported", "The supported statement is safe."),
        _claim("clm_rewrite", "The unsupported statement needs rewrite."),
        _claim("clm_blocked", "The contradicted statement must be blocked."),
    ]
    verdicts = [
        _verdict("clm_supported", status=VerdictStatus.SUPPORTED, action=VerdictAction.ALLOW),
        _verdict("clm_rewrite", status=VerdictStatus.NOT_FOUND, action=VerdictAction.REWRITE),
        _verdict(
            "clm_blocked",
            status=VerdictStatus.CONTRADICTED,
            action=VerdictAction.BLOCK,
            reason="Contradicted by deterministic evidence.",
        ),
    ]

    response = ResponseRepairer().repair("original", claims, verdicts, evidence=[])

    assert response.final_decision == FinalDecision.BLOCKED
    assert response.blocked_claim_ids == ["clm_blocked"]
    assert response.repaired_claim_ids == ["clm_rewrite"]
    assert "Respuesta bloqueada" in response.final_text
    assert "The contradicted statement must be blocked." in response.final_text


def test_response_repairer_requires_human_review_without_rewriting() -> None:
    response = ResponseRepairer().repair(
        "original",
        [_claim("clm_review", "A high-risk action needs review.")],
        [
            _verdict(
                "clm_review",
                status=VerdictStatus.AMBIGUOUS,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
            )
        ],
        evidence=[],
    )

    assert response.final_decision == FinalDecision.REQUIRE_HUMAN_REVIEW
    assert response.blocked_claim_ids == []
    assert response.repaired_claim_ids == []
    assert "revision humana" in response.final_text


def test_response_repairer_abstains_when_no_claims_remain_supported() -> None:
    response = ResponseRepairer().repair(
        "unsupported original",
        [_claim("clm_missing", "No evidence supports this statement.")],
        [
            _verdict(
                "clm_missing",
                status=VerdictStatus.NOT_FOUND,
                action=VerdictAction.ABSTAIN,
                reason="No matching evidence.",
            )
        ],
        evidence=[
            Evidence(
                evidence_id="ev_unrelated",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="unrelated",
                content="Unrelated evidence.",
                authority=Authority.INTERNAL,
            )
        ],
    )

    assert response.final_decision == FinalDecision.ABSTAINED
    assert response.repaired_claim_ids == ["clm_missing"]
    assert "No encontre evidencia suficiente" in response.final_text
    assert "No matching evidence." in response.final_text
