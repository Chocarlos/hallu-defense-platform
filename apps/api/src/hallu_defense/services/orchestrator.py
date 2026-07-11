from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone

from opentelemetry.util.types import AttributeValue

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    Authority,
    Claim,
    ClaimExtractionRequest,
    ClaimType,
    ClaimVerdict,
    Evidence,
    EvidenceKind,
    Freshness,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RiskLevel,
    StalenessClass,
    VerdictAction,
    VerdictStatus,
    VerificationRun,
    VerificationRunRequest,
)
from hallu_defense.services.claim_classifier import ClaimClassifier
from hallu_defense.services.claim_extractor import ClaimExtractor
from hallu_defense.services.content_security import ContentSecurityScanner, ContentThreat
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.policy import PolicyEngine
from hallu_defense.services.repair import ResponseRepairer
from hallu_defense.services.retrieval import HybridRetriever
from hallu_defense.services.telemetry import NoopSpanHandle, SpanHandle, TelemetryService
from hallu_defense.services.trace import current_trace_id
from hallu_defense.services.verifier import ClaimVerifier


class VerificationOrchestrator:
    def __init__(
        self,
        settings: Settings,
        extractor: ClaimExtractor,
        classifier: ClaimClassifier,
        retriever: HybridRetriever,
        verifier: ClaimVerifier,
        repairer: ResponseRepairer,
        metrics: PrometheusMetrics | None = None,
        telemetry: TelemetryService | None = None,
        policy_engine: PolicyEngine | None = None,
        content_scanner: ContentSecurityScanner | None = None,
    ) -> None:
        self._settings = settings
        self._extractor = extractor
        self._classifier = classifier
        self._retriever = retriever
        self._verifier = verifier
        self._repairer = repairer
        self._metrics = metrics
        self._telemetry = telemetry
        self._policy_engine = policy_engine
        self._content_scanner = content_scanner or ContentSecurityScanner()

    def run(self, request: VerificationRunRequest) -> VerificationRun:
        started_at = time.perf_counter()
        trace_id = current_trace_id()
        extraction_request = ClaimExtractionRequest(
            message_text=request.message_text,
            tool_outputs=request.tool_outputs,
            execution_artifacts=request.execution_artifacts,
            task_type=request.task_type,
            message_id=request.message_id,
        )
        base_attrs: dict[str, AttributeValue] = {
            "app.trace_id": trace_id,
            "app.component": "verification",
            "verification.task_type": request.task_type,
            "verification.document_count": len(request.documents),
            "verification.tool_output_count": len(request.tool_outputs),
        }
        with self._span("verification.extract_claims", base_attrs) as span:
            claims = self._extractor.extract(extraction_request)
            span.set_attribute("verification.claim_count", len(claims))
            span.set_attribute("app.outcome", "success")
        with self._span(
            "verification.classify_claims",
            {**base_attrs, "verification.claim_count": len(claims)},
        ) as span:
            classified = self._classifier.classify(claims, request.task_type)
            span.set_attribute("verification.classified_claim_count", len(classified))
            span.set_attribute("app.outcome", "success")

        with self._span("verification.scan_content_security", base_attrs) as span:
            input_threats = self._content_scanner.scan_user_message(
                request.message_text,
                source_ref=request.message_id,
            )
            span.set_attribute("verification.security_threat_count", len(input_threats))
            span.set_attribute("app.outcome", "blocked" if input_threats else "success")
            if input_threats:
                policy_response = self._evaluate_threat_policy(
                    input_threats,
                    trace_id=trace_id,
                    tenant_id=request.tenant_id or "local-dev",
                    action="verify_response",
                    resource=f"message:{request.message_id}",
                )
                if not policy_response.allowed:
                    return self._blocked_by_security_policy(
                        request=request,
                        trace_id=trace_id,
                        started_at=started_at,
                        claims=classified,
                        evidence=[],
                        threats=input_threats,
                        policy_response=policy_response,
                    )

        with self._span(
            "verification.retrieve_evidence",
            {**base_attrs, "verification.claim_count": len(classified)},
        ) as span:
            retrieved, _claim_map = self._retriever.retrieve(
                classified,
                request.documents,
                tenant_id=request.tenant_id or "local-dev",
            )
            span.set_attribute("verification.retrieved_evidence_count", len(retrieved))
            span.set_attribute("app.outcome", "success")
        evidence = [*request.tool_outputs, *retrieved]

        evidence_threats = self._content_scanner.threats_from_evidence(evidence)
        if evidence_threats:
            policy_response = self._evaluate_threat_policy(
                evidence_threats,
                trace_id=trace_id,
                tenant_id=request.tenant_id or "local-dev",
                action="retrieve_evidence",
                resource="evidence:selected",
            )
            if not policy_response.allowed:
                return self._blocked_by_security_policy(
                    request=request,
                    trace_id=trace_id,
                    started_at=started_at,
                    claims=classified,
                    evidence=evidence,
                    threats=evidence_threats,
                    policy_response=policy_response,
                )

        with self._span(
            "verification.verify_claims",
            {
                **base_attrs,
                "verification.claim_count": len(classified),
                "verification.evidence_count": len(evidence),
            },
        ) as span:
            verdicts = self._verifier.verify(classified, evidence)
            span.set_attribute("verification.verdict_count", len(verdicts))
            span.set_attribute("app.outcome", "success")
        with self._span(
            "verification.repair_response",
            {
                **base_attrs,
                "verification.claim_count": len(classified),
                "verification.evidence_count": len(evidence),
                "verification.verdict_count": len(verdicts),
            },
        ) as span:
            repair = self._repairer.repair(request.message_text, classified, verdicts, evidence)
            span.set_attribute("verification.final_decision", repair.final_decision.value)
            span.set_attribute("app.outcome", "success")

        run = VerificationRun(
            trace_id=trace_id,
            tenant_id=request.tenant_id or "local-dev",
            input={
                "message_text": request.message_text,
                "task_type": request.task_type,
                "document_count": len(request.documents),
                "tool_output_count": len(request.tool_outputs),
            },
            claims=classified,
            evidence=evidence,
            verdicts=verdicts,
            final_decision=repair.final_decision,
            final_text=repair.final_text,
            policy_version=self._settings.policy_version,
        )
        self._record_metrics(run, started_at)
        return run

    def replay(self, source: VerificationRun) -> VerificationRun:
        started_at = time.perf_counter()
        trace_id = current_trace_id()
        source_task_type = source.input.get("task_type")
        task_type = source_task_type if isinstance(source_task_type, str) else "chat"
        source_message_text = source.input.get("message_text")
        replay_text = source_message_text if isinstance(source_message_text, str) else source.final_text
        replay_input = {
            "replay_of": source.trace_id,
            "source_created_at": source.created_at.isoformat(),
            "task_type": task_type,
            "claim_count": len(source.claims),
            "evidence_count": len(source.evidence),
        }
        replay_request = VerificationRunRequest(
            tenant_id=source.tenant_id,
            message_text=replay_text,
            task_type=task_type,
        )
        base_attrs: dict[str, AttributeValue] = {
            "app.trace_id": trace_id,
            "app.component": "verification",
            "verification.replay": True,
            "verification.claim_count": len(source.claims),
            "verification.evidence_count": len(source.evidence),
        }
        with self._span("verification.replay_scan_content_security", base_attrs) as span:
            input_threats = self._content_scanner.scan_user_message(
                replay_text,
                source_ref=f"replay:{source.trace_id}",
            )
            span.set_attribute("verification.security_threat_count", len(input_threats))
            span.set_attribute("app.outcome", "blocked" if input_threats else "success")
            if input_threats:
                policy_response = self._evaluate_threat_policy(
                    input_threats,
                    trace_id=trace_id,
                    tenant_id=source.tenant_id,
                    action="verify_response",
                    resource=f"message:replay:{source.trace_id}",
                )
                if not policy_response.allowed:
                    return self._blocked_by_security_policy(
                        request=replay_request,
                        trace_id=trace_id,
                        started_at=started_at,
                        claims=source.claims,
                        evidence=source.evidence,
                        threats=input_threats,
                        policy_response=policy_response,
                        input_metadata=replay_input,
                    )

        evidence_threats = self._content_scanner.threats_from_evidence(source.evidence)
        if evidence_threats:
            policy_response = self._evaluate_threat_policy(
                evidence_threats,
                trace_id=trace_id,
                tenant_id=source.tenant_id,
                action="retrieve_evidence",
                resource=f"evidence:replay:{source.trace_id}",
            )
            if not policy_response.allowed:
                return self._blocked_by_security_policy(
                    request=replay_request,
                    trace_id=trace_id,
                    started_at=started_at,
                    claims=source.claims,
                    evidence=source.evidence,
                    threats=evidence_threats,
                    policy_response=policy_response,
                    input_metadata=replay_input,
                )

        with self._span("verification.replay_verify_claims", base_attrs) as span:
            verdicts = self._verifier.verify(source.claims, source.evidence)
            span.set_attribute("verification.verdict_count", len(verdicts))
            span.set_attribute("app.outcome", "success")

        with self._span(
            "verification.replay_repair_response",
            {**base_attrs, "verification.verdict_count": len(verdicts)},
        ) as span:
            repair = self._repairer.repair(replay_text, source.claims, verdicts, source.evidence)
            span.set_attribute("verification.final_decision", repair.final_decision.value)
            span.set_attribute("app.outcome", "success")

        source_task_type = source.input.get("task_type")
        run = VerificationRun(
            trace_id=trace_id,
            tenant_id=source.tenant_id,
            input=replay_input,
            claims=source.claims,
            evidence=source.evidence,
            verdicts=verdicts,
            final_decision=repair.final_decision,
            final_text=repair.final_text,
            policy_version=self._settings.policy_version,
        )
        self._record_metrics(run, started_at)
        return run

    def _evaluate_threat_policy(
        self,
        threats: list[ContentThreat],
        *,
        trace_id: str,
        tenant_id: str,
        action: str,
        resource: str,
    ) -> PolicyEvaluationResponse:
        if self._policy_engine is None:
            return PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["content_security_threat_detected"],
                explanation="Content security scanner detected untrusted or poisoned input.",
            )
        return self._policy_engine.evaluate(
            PolicyEvaluationRequest(
                action=action,
                resource=resource,
                risk_level=RiskLevel.HIGH,
                attributes=self._content_scanner.threat_attributes(threats),
            ),
            trace_id=trace_id,
            tenant_id=tenant_id,
        )

    def _blocked_by_security_policy(
        self,
        *,
        request: VerificationRunRequest,
        trace_id: str,
        started_at: float,
        claims: list[Claim],
        evidence: list[Evidence],
        threats: list[ContentThreat],
        policy_response: PolicyEvaluationResponse,
        input_metadata: Mapping[str, object] | None = None,
    ) -> VerificationRun:
        security_evidence = self._security_policy_evidence(threats, policy_response)
        blocked_claims = claims or [self._security_claim()]
        evidence_ids = self._threat_evidence_ids(evidence) or [security_evidence.evidence_id]
        action = (
            policy_response.action
            if policy_response.action in {VerdictAction.BLOCK, VerdictAction.REQUIRE_HUMAN_REVIEW}
            else VerdictAction.BLOCK
        )
        verdicts = [
            ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.UNVERIFIABLE,
                confidence=1.0,
                evidence_ids=evidence_ids,
                action=action,
                reason=policy_response.explanation,
                validator_trace={
                    "policy_version": policy_response.policy_version,
                    "matched_rules": policy_response.matched_rules,
                    "content_threats": [threat.to_metadata() for threat in threats],
                },
            )
            for claim in blocked_claims
        ]
        repair = self._repairer.repair(request.message_text, blocked_claims, verdicts, evidence)
        input_payload: dict[str, object] = {
            "message_text": request.message_text,
            "task_type": request.task_type,
            "document_count": len(request.documents),
            "tool_output_count": len(request.tool_outputs),
            "security_threat_count": len(threats),
        }
        if input_metadata is not None:
            input_payload.update(input_metadata)
        run = VerificationRun(
            trace_id=trace_id,
            tenant_id=request.tenant_id or "local-dev",
            input=input_payload,
            claims=blocked_claims,
            evidence=[*evidence, security_evidence],
            verdicts=verdicts,
            final_decision=repair.final_decision,
            final_text=repair.final_text,
            policy_version=self._settings.policy_version,
        )
        self._record_metrics(run, started_at)
        return run

    def _security_claim(self) -> Claim:
        return Claim(
            claim_id="clm_content_security_policy",
            text="Content security policy detected untrusted or poisoned input.",
            type=ClaimType.POLICY_CLAIM,
            risk_level=RiskLevel.CRITICAL,
            requires_evidence=True,
        )

    def _security_policy_evidence(
        self,
        threats: list[ContentThreat],
        policy_response: PolicyEvaluationResponse,
    ) -> Evidence:
        return Evidence(
            evidence_id="ev_content_security_policy",
            kind=EvidenceKind.POLICY_RULE,
            source_ref="security/content-scanner",
            content="Content security scanner detected untrusted instructions or poisoned evidence.",
            structured_content={
                "policy_version": policy_response.policy_version,
                "matched_rules": policy_response.matched_rules,
                "threats": [threat.to_metadata() for threat in threats],
            },
            authority=Authority.INTERNAL,
            freshness=Freshness(
                retrieved_at=datetime.now(timezone.utc),
                staleness_class=StalenessClass.FRESH,
            ),
        )

    def _threat_evidence_ids(self, evidence: list[Evidence]) -> list[str]:
        evidence_ids: list[str] = []
        for item in evidence:
            security = item.structured_content.get("security")
            if isinstance(security, dict) and security.get("threats"):
                evidence_ids.append(item.evidence_id)
        return evidence_ids

    def _record_metrics(self, run: VerificationRun, started_at: float) -> None:
        if self._metrics is not None:
            self._metrics.record_verification_run(
                final_decision=run.final_decision.value,
                duration_seconds=time.perf_counter() - started_at,
            )
            for verdict in run.verdicts:
                self._metrics.record_claim_verdict(
                    status=verdict.status.value,
                    action=verdict.action.value,
                )

    @contextmanager
    def _span(
        self,
        name: str,
        attributes: Mapping[str, AttributeValue],
    ) -> Iterator[SpanHandle]:
        if self._telemetry is None:
            yield NoopSpanHandle()
            return
        with self._telemetry.span(name, attributes=attributes) as span:
            yield span
