from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import cast

import pytest

from hallu_defense.domain.models import (
    Authority,
    Claim,
    ClaimType,
    Evidence,
    EvidenceKind,
    Freshness,
    RiskLevel,
    StalenessClass,
    VerdictAction,
    VerdictStatus,
)
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.nli import NliAdjudicationOutcome, ProviderNliAdjudicator
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


class FailingProvider:
    provider_name = "mock"

    def complete(self, provider_request: ProviderRequest) -> ProviderResponse:
        del provider_request
        raise ConnectionError("provider outage contained super-secret-provider-payload")


class RaisingAdjudicator:
    def adjudicate(self, claim: Claim, evidence: list[Evidence]) -> None:
        raise AssertionError("NLI must not run for deterministic repo/test claims")


class UnavailableAdjudicator:
    def adjudicate(self, claim: Claim, evidence: list[Evidence]) -> None:
        del claim, evidence
        raise ConnectionError("provider unavailable")


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
        structured_content={},
        authority=Authority.UNKNOWN,
        freshness=Freshness(
            retrieved_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            staleness_class=StalenessClass.UNKNOWN,
        ),
    )


def _verifier_with_provider(
    response_text: str,
    *,
    observer: PrometheusMetrics | None = None,
) -> ClaimVerifier:
    provider = StaticProvider(response_text)
    return ClaimVerifier(
        nli_adjudicator=ProviderNliAdjudicator(provider, observer=observer)
    )


def _metrics() -> PrometheusMetrics:
    return PrometheusMetrics(
        service_name="nli-test",
        service_version="test",
        environment="test",
    )


def _nli_metric_samples(metrics: PrometheusMetrics) -> list[str]:
    return [
        line
        for line in metrics.render().splitlines()
        if line.startswith("hallu_nli_adjudications_total{")
    ]


def _last_user_message(messages: Sequence[ProviderMessage]) -> str:
    return [message.content for message in messages if message.role == "user"][-1]


def test_provider_nli_can_support_low_risk_claim_with_known_evidence_id() -> None:
    metrics = _metrics()
    verifier = _verifier_with_provider(
        '{"status":"supported","confidence":0.84,"evidence_ids":["ev_1"],"reason":"semantic match"}',
        observer=metrics,
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
    assert _nli_metric_samples(metrics) == [
        'hallu_nli_adjudications_total{outcome="supported"} 1'
    ]


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


def test_provider_nli_malformed_output_fails_closed_with_explicit_trace(
    caplog: pytest.LogCaptureFixture,
) -> None:
    metrics = _metrics()
    verifier = _verifier_with_provider(
        "not-json super-secret-nli-payload",
        observer=metrics,
    )

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme")],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.AMBIGUOUS
    assert verdict.action == VerdictAction.REWRITE
    assert verdict.evidence_ids == []
    assert verdict.validator_trace["nli"] == {
        "status": "unavailable",
        "error_type": "ProviderResponseError",
    }
    assert _nli_metric_samples(metrics) == [
        'hallu_nli_adjudications_total{outcome="invalid"} 1'
    ]
    assert "super-secret-nli-payload" not in caplog.text
    assert "super-secret-nli-payload" not in metrics.render()


def test_provider_nli_rejects_unknown_evidence_ids() -> None:
    verifier = _verifier_with_provider(
        '{"status":"supported","confidence":0.91,"evidence_ids":["ev_missing"],"reason":"semantic match"}'
    )

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme")],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.AMBIGUOUS
    assert verdict.action == VerdictAction.REWRITE
    assert verdict.evidence_ids == []
    assert verdict.validator_trace["nli"] == {
        "status": "unavailable",
        "error_type": "ProviderResponseError",
    }


def test_provider_nli_outage_requires_review_for_critical_claim() -> None:
    verifier = ClaimVerifier(nli_adjudicator=UnavailableAdjudicator())

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme", risk_level=RiskLevel.CRITICAL)],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.AMBIGUOUS
    assert verdict.action == VerdictAction.REQUIRE_HUMAN_REVIEW
    assert verdict.validator_trace["nli"] == {
        "status": "unavailable",
        "error_type": "ConnectionError",
    }


def test_provider_nli_outage_records_one_unavailable_attempt_without_payload_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    metrics = _metrics()
    verifier = ClaimVerifier(
        nli_adjudicator=ProviderNliAdjudicator(
            FailingProvider(),
            observer=metrics,
        )
    )

    verdict = verifier.verify(
        [_claim("Saturn rings are maintained by Acme")],
        [_evidence("The handbook explains payroll approvals.")],
    )[0]

    assert verdict.status == VerdictStatus.AMBIGUOUS
    assert _nli_metric_samples(metrics) == [
        'hallu_nli_adjudications_total{outcome="unavailable"} 1'
    ]
    assert "super-secret-provider-payload" not in caplog.text
    assert "super-secret-provider-payload" not in metrics.render()


@pytest.mark.parametrize(
    "outcome",
    [
        "supported",
        "contradicted",
        "insufficient_evidence",
        "unavailable",
        "invalid",
    ],
)
def test_nli_metric_render_has_one_bounded_outcome_label(
    outcome: NliAdjudicationOutcome,
) -> None:
    metrics = _metrics()

    metrics.record_nli_adjudication(outcome=outcome)

    assert _nli_metric_samples(metrics) == [
        f'hallu_nli_adjudications_total{{outcome="{outcome}"}} 1'
    ]


def test_nli_metric_rejects_unbounded_outcome() -> None:
    metrics = _metrics()

    with pytest.raises(ValueError, match="Unsupported NLI adjudication outcome"):
        metrics.record_nli_adjudication(
            outcome=cast(NliAdjudicationOutcome, "tenant-specific-outcome")
        )

    assert _nli_metric_samples(metrics) == []


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
    Authority,
