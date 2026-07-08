from __future__ import annotations

from hallu_defense.domain.models import (
    Claim,
    ClaimVerdict,
    Evidence,
    FinalDecision,
    ResponseRepairResponse,
    VerdictAction,
    VerdictStatus,
)


class ResponseRepairer:
    def repair(
        self,
        original_text: str,
        claims: list[Claim],
        verdicts: list[ClaimVerdict],
        evidence: list[Evidence],
    ) -> ResponseRepairResponse:
        claim_by_id = {claim.claim_id: claim for claim in claims}
        evidence_by_id = {item.evidence_id: item for item in evidence}

        blocked = [verdict for verdict in verdicts if verdict.action == VerdictAction.BLOCK]
        human_review = [
            verdict for verdict in verdicts if verdict.action == VerdictAction.REQUIRE_HUMAN_REVIEW
        ]
        rewrite = [verdict for verdict in verdicts if verdict.action == VerdictAction.REWRITE]
        abstain = [verdict for verdict in verdicts if verdict.action == VerdictAction.ABSTAIN]
        supported = [
            verdict
            for verdict in verdicts
            if verdict.status in {VerdictStatus.SUPPORTED, VerdictStatus.OUT_OF_SCOPE}
        ]

        if blocked:
            return ResponseRepairResponse(
                final_text=self._blocked_text(blocked, claim_by_id),
                final_decision=FinalDecision.BLOCKED,
                blocked_claim_ids=[verdict.claim_id for verdict in blocked],
                repaired_claim_ids=[verdict.claim_id for verdict in rewrite],
            )

        if human_review:
            return ResponseRepairResponse(
                final_text="Esta respuesta requiere revision humana antes de continuar.",
                final_decision=FinalDecision.REQUIRE_HUMAN_REVIEW,
                blocked_claim_ids=[],
                repaired_claim_ids=[],
            )

        if rewrite or abstain:
            final_text = self._verified_summary(supported, claim_by_id, evidence_by_id)
            missing = rewrite + abstain
            final_text += "\n\nNo pude verificar estos puntos y fueron removidos o marcados como inciertos:\n"
            final_text += "\n".join(
                f"- {claim_by_id[verdict.claim_id].text}: {verdict.reason}" for verdict in missing
            )
            return ResponseRepairResponse(
                final_text=final_text.strip(),
                final_decision=FinalDecision.REPAIRED if supported else FinalDecision.ABSTAINED,
                repaired_claim_ids=[verdict.claim_id for verdict in missing],
            )

        return ResponseRepairResponse(
            final_text=original_text,
            final_decision=FinalDecision.ALLOW,
            repaired_claim_ids=[],
        )

    def _blocked_text(self, verdicts: list[ClaimVerdict], claims: dict[str, Claim]) -> str:
        lines = ["Respuesta bloqueada por claims no soportados o contradichos:"]
        for verdict in verdicts:
            claim = claims[verdict.claim_id]
            lines.append(f"- {claim.text}: {verdict.reason}")
        return "\n".join(lines)

    def _verified_summary(
        self,
        supported: list[ClaimVerdict],
        claims: dict[str, Claim],
        evidence: dict[str, Evidence],
    ) -> str:
        if not supported:
            return "No encontre evidencia suficiente para responder con seguridad."

        lines = ["Version verificada:"]
        for verdict in supported:
            claim = claims[verdict.claim_id]
            citation = ""
            if verdict.evidence_ids:
                refs = [
                    evidence[evidence_id].source_ref
                    for evidence_id in verdict.evidence_ids
                    if evidence_id in evidence
                ]
                citation = f" [{', '.join(refs)}]" if refs else ""
            lines.append(f"- {claim.text}{citation}")
        return "\n".join(lines)

