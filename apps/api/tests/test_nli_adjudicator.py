from __future__ import annotations

from collections.abc import Sequence

from hallu_defense.domain.models import (
    Claim,
    ClaimType,
    Evidence,
    EvidenceKind,
    RiskLevel,
    VerdictAction,
    VerdictStatus,
)
from hallu_defense.services.nli import ProviderNliAdjudicator
from hallu_defense.services.providers import ProviderMessage, ProviderRequest, ProviderResponse
from hallu_defense.services.verifier import ClaimVerifier


class StaticProvider:
    provider_name = "mock"

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.requests: list[ProviderRequest] = []

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse:
        self.requests.append(provider_request)
        return ProviderResponse(
            text=self.response_text,
            provider=self.provider_name,
            model=provider_request.model or "mock-nli",
        )


class RaisingAdjudicator:
    def adjudicate(self, claim: Claim, evidence: list[Evidence]) -> None:
        raise AssertionError("NLI must not run for deterministic repo/test claims")


def _claim(
    text: str = "Acme supports regulated onboarding",
    *,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    claim_type: ClaimType = ClaimType.DOC_GROUNDED,
) -> Claim:
    return Claim(
        claim_id="clm_1",
        text=text,
        canonical_form=text.lower(),
        type=claim_type,
        risk_level=risk_level,
    )


def _evidence(content: str = "The customer program includes audited intake for compliance teams.") -> Evidence:
    return Evidence(
        evidence_id="ev_1",
        kind=EvidenceKind.DOCUMENT_CHUNK,
        source_ref="policy.md#1",
        content=content,
    )


def _verifier_with_provider(response_text: str) -> ClaimVerifier:
    provider = StaticProvider(response_text)
    return ClaimVerifier(nli_adjudicator=ProviderNliAdjudicator(provider))


def _last_user_message(messages: Sequence[ProviderMessage]) -> str:
    return [message.content for message in messages if message.role == "user"][-1]


def test_provider_nli_can_support_low_risk_claim_with_known_evidence_id() -> None:
    verifier = _verifier_with_provider(
        '{"status":"supported","confidence":0.84,"evidence_ids":["ev_1"],"reason":"semantic match"}'
    )

    verdict = verifier.verify([_claim()], [_evidence()])[0]

    assert verdict.status == VerdictStatus.SUPPORTED
    assert verdict.action == VerdictAction.ALLOW_WITH_CITATION
    assert verdict.confidence == 0.84
    assert verdict.evidence_ids == ["ev_1"]
    assert verdict.validator_trace["nli"] == {
        "provider": "mock",
        "model": "mock-nli",
        "status": "supported",
        "confidence": 0.84,
        "evidence_ids": ["ev_1"],
    }


def test_provider_nli_contradiction_blocks_high_risk_claim() -> None:
    verifier = _verifier_with_provider(
        '{"status":"contradicted","confidence":0.91,"evidence_ids":["ev_1"],"reason":"opposite meaning"}'
    )

    verdict = verifier.verify(
        [_claim(risk_level=RiskLevel.HIGH)],
        [_evidence()],
    )[0]

    assert verdict.status == VerdictStatus.CONTRADICTED
    assert verdict.action == VerdictAction.BLOCK
    assert verdict.evidence_ids == ["ev_1"]


def test_provider_nli_support_for_high_risk_claim_requires_human_review() -> None:
    verifier = _verifier_with_provider(
        '{"status":"supported","confidence":0.93,"evidence_ids":["ev_1"],"reason":"semantic match"}'
    )

    verdict = verifier.verify(
        [_claim(risk_level=RiskLevel.CRITICAL)],
        [_evidence()],
    )[0]

    assert verdict.status == VerdictStatus.AMBIGUOUS
    assert verdict.action == VerdictAction.REQUIRE_HUMAN_REVIEW
    assert verdict.evidence_ids == ["ev_1"]


def test_provider_nli_malformed_output_falls_back_to_deterministic_not_found() -> None:
    verifier = _verifier_with_provider("not-json")

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme")],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.NOT_FOUND
    assert verdict.action == VerdictAction.ABSTAIN
    assert verdict.evidence_ids == []


def test_provider_nli_rejects_unknown_evidence_ids() -> None:
    verifier = _verifier_with_provider(
        '{"status":"supported","confidence":0.91,"evidence_ids":["ev_missing"],"reason":"semantic match"}'
    )

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme")],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.NOT_FOUND
    assert verdict.evidence_ids == []


def test_provider_nli_redacts_sensitive_text_before_prompting_provider() -> None:
    provider = StaticProvider(
        '{"status":"insufficient_evidence","confidence":0.7,"evidence_ids":[],"reason":"not enough"}'
    )
    verifier = ClaimVerifier(nli_adjudicator=ProviderNliAdjudicator(provider))

    verdict = verifier.verify(
        [_claim("The token=abc123 grants access to Acme onboarding")],
        [_evidence("The api_key=abc123 appears in a copied note.")],
    )[0]

    assert verdict.status == VerdictStatus.NOT_FOUND
    assert provider.requests
    user_prompt = _last_user_message(provider.requests[0].messages)
    assert "abc123" not in user_prompt
    assert "[redacted]" in user_prompt


def test_nli_is_not_used_for_repo_claims() -> None:
    verifier = ClaimVerifier(nli_adjudicator=RaisingAdjudicator())

    verdict = verifier.verify(
        [
            _claim(
                "The repository contains service.py",
                claim_type=ClaimType.REPO_STATE,
            )
        ],
        [],
    )[0]

    assert verdict.status == VerdictStatus.NOT_FOUND
