from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from hallu_defense.config import Settings
from hallu_defense.domain.models import Claim, ClaimType, Evidence, EvidenceKind
from hallu_defense.services.providers import (
    ModelProvider,
    ProviderMessage,
    ProviderRequest,
    ProviderResponseError,
)

NliStatus = Literal["supported", "contradicted", "insufficient_evidence"]
NliAdjudicationOutcome = Literal[
    "supported",
    "contradicted",
    "insufficient_evidence",
    "unavailable",
    "invalid",
]
ALLOWED_NLI_STATUSES: set[str] = {"supported", "contradicted", "insufficient_evidence"}
NLI_ADJUDICATION_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "supported",
        "contradicted",
        "insufficient_evidence",
        "unavailable",
        "invalid",
    }
)
NLI_SUPPORTED_CLAIM_TYPES = {ClaimType.WORLD_FACT, ClaimType.DOC_GROUNDED}
NLI_SUPPORTED_EVIDENCE_KINDS = {EvidenceKind.DOCUMENT_CHUNK, EvidenceKind.WEB_SOURCE}
SECRET_TEXT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|authorization)\b\s*[:=]\s*['\"]?([^\s,;'\"]+)"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


@dataclass(frozen=True)
class NliAdjudication:
    status: NliStatus
    confidence: float
    evidence_ids: list[str]
    reason: str
    provider: str
    model: str


class NliAdjudicator(Protocol):
    def adjudicate(self, claim: Claim, evidence: list[Evidence]) -> NliAdjudication | None: ...


class NliAdjudicationObserver(Protocol):
    def record_nli_adjudication(self, *, outcome: NliAdjudicationOutcome) -> None: ...


class ProviderNliAdjudicator:
    def __init__(
        self,
        provider: ModelProvider,
        *,
        max_evidence_items: int = 3,
        max_evidence_chars: int = 900,
        observer: NliAdjudicationObserver | None = None,
    ) -> None:
        if max_evidence_items < 1:
            raise ValueError("max_evidence_items must be at least 1")
        if max_evidence_chars < 100:
            raise ValueError("max_evidence_chars must be at least 100")
        self._provider = provider
        self._max_evidence_items = max_evidence_items
        self._max_evidence_chars = max_evidence_chars
        self._observer = observer

    def adjudicate(self, claim: Claim, evidence: list[Evidence]) -> NliAdjudication | None:
        if claim.type not in NLI_SUPPORTED_CLAIM_TYPES:
            return None

        candidates = [
            item
            for item in evidence
            if item.kind in NLI_SUPPORTED_EVIDENCE_KINDS and item.content.strip()
        ][: self._max_evidence_items]
        if not candidates:
            return None

        try:
            provider_response = self._provider.complete(
                ProviderRequest(
                    messages=[
                        ProviderMessage(
                            role="system",
                            content=(
                                "You are a strict NLI verifier. Return only JSON with keys "
                                "status, confidence, evidence_ids, and reason. Allowed status values "
                                "are supported, contradicted, and insufficient_evidence. Use only the "
                                "provided evidence IDs."
                            ),
                        ),
                        ProviderMessage(
                            role="user",
                            content=self._prompt(claim, candidates),
                        ),
                    ],
                    temperature=0.0,
                    max_tokens=300,
                )
            )
            adjudication = self._parse_response(provider_response, candidates)
        except ProviderResponseError:
            self._record_outcome("invalid")
            raise
        except Exception:
            self._record_outcome("unavailable")
            raise
        self._record_outcome(adjudication.status)
        return adjudication

    def _record_outcome(self, outcome: NliAdjudicationOutcome) -> None:
        if self._observer is not None:
            self._observer.record_nli_adjudication(outcome=outcome)

    def _prompt(self, claim: Claim, evidence: list[Evidence]) -> str:
        evidence_blocks = []
        for item in evidence:
            content = _redact_sensitive_text(item.content)
            evidence_blocks.append(
                "\n".join(
                    [
                        f"Evidence ID: {item.evidence_id}",
                        f"Source: {item.source_ref}",
                        f"Content: {content[: self._max_evidence_chars]}",
                    ]
                )
            )
        return "\n\n".join(
            [
                f"Claim ID: {claim.claim_id}",
                f"Claim: {_redact_sensitive_text(claim.text)}",
                "Evidence:",
                "\n\n".join(evidence_blocks),
            ]
        )

    def _parse_response(
        self,
        response: object,
        evidence: list[Evidence],
    ) -> NliAdjudication:
        if not hasattr(response, "text") or not hasattr(response, "provider") or not hasattr(response, "model"):
            raise ProviderResponseError("NLI provider response metadata is incomplete.")
        raw_text = getattr(response, "text")
        if not isinstance(raw_text, str):
            raise ProviderResponseError("NLI provider response text must be a string.")
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ProviderResponseError("NLI provider response is not valid JSON.") from exc
        if not isinstance(payload, Mapping):
            raise ProviderResponseError("NLI provider response must be a JSON object.")

        raw_status = payload.get("status")
        if not isinstance(raw_status, str) or raw_status not in ALLOWED_NLI_STATUSES:
            raise ProviderResponseError("NLI provider response status is invalid.")
        status = _nli_status(raw_status)

        raw_confidence = payload.get("confidence")
        if not isinstance(raw_confidence, int | float):
            raise ProviderResponseError("NLI provider confidence must be numeric.")
        confidence = float(raw_confidence)
        if confidence < 0 or confidence > 1:
            raise ProviderResponseError("NLI provider confidence must be between zero and one.")

        raw_ids = payload.get("evidence_ids")
        if not isinstance(raw_ids, list) or not all(isinstance(item, str) for item in raw_ids):
            raise ProviderResponseError("NLI provider evidence_ids must be a string list.")
        evidence_ids = list(dict.fromkeys(raw_ids))
        known_ids = {item.evidence_id for item in evidence}
        if any(item not in known_ids for item in evidence_ids):
            raise ProviderResponseError("NLI provider cited an unknown evidence ID.")
        if status in {"supported", "contradicted"} and not evidence_ids:
            raise ProviderResponseError("NLI provider omitted evidence IDs for a decisive status.")

        raw_reason = payload.get("reason")
        if not isinstance(raw_reason, str) or not raw_reason.strip():
            raise ProviderResponseError("NLI provider reason must be non-empty.")

        provider_name = getattr(response, "provider")
        model = getattr(response, "model")
        if not isinstance(provider_name, str) or not isinstance(model, str):
            raise ProviderResponseError("NLI provider identity metadata is invalid.")
        return NliAdjudication(
            status=status,
            confidence=confidence,
            evidence_ids=evidence_ids,
            reason=raw_reason[:500],
            provider=provider_name,
            model=model,
        )


def create_nli_adjudicator(
    settings: Settings,
    provider: ModelProvider,
    *,
    observer: NliAdjudicationObserver | None = None,
) -> NliAdjudicator | None:
    if not settings.provider_nli_enabled:
        return None
    return ProviderNliAdjudicator(provider, observer=observer)


def _nli_status(value: str) -> NliStatus:
    if value == "supported":
        return "supported"
    if value == "contradicted":
        return "contradicted"
    if value == "insufficient_evidence":
        return "insufficient_evidence"
    raise ProviderResponseError(f"Unsupported NLI status {value!r}")


def _redact_sensitive_text(value: str) -> str:
    redacted = SECRET_TEXT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", value)
    return BEARER_RE.sub("Bearer [redacted]", redacted)
