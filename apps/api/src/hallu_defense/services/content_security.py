from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from hallu_defense.domain.models import Evidence

ThreatType = Literal["prompt_injection", "indirect_prompt_injection", "data_poisoning"]
ThreatSourceKind = Literal["user_message", "document", "tool_output", "evidence"]


@dataclass(frozen=True)
class ContentThreat:
    threat_type: ThreatType
    source_kind: ThreatSourceKind
    source_ref: str
    rule_id: str

    def to_metadata(self) -> dict[str, str]:
        return {
            "threat_type": self.threat_type,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "rule_id": self.rule_id,
        }


class ContentSecurityScanner:
    """Deterministic scanner for untrusted instructions and poisoned evidence markers."""

    _DIRECT_PROMPT_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("ignore_previous_instructions", re.compile(r"\bignore (?:all )?(?:previous|prior|above) instructions\b", re.I)),
        ("disregard_system_instructions", re.compile(r"\bdisregard (?:the )?(?:system|developer) instructions\b", re.I)),
        ("reveal_system_prompt", re.compile(r"\b(?:reveal|print|show|dump) (?:the )?(?:system|developer) prompt\b", re.I)),
        ("jailbreak_roleplay", re.compile(r"\b(?:jailbreak|developer mode|do anything now|dan mode)\b", re.I)),
        ("bypass_policy", re.compile(r"\b(?:bypass|disable|override) (?:the )?(?:safety|policy|guardrail|instructions)\b", re.I)),
    )
    _INDIRECT_PROMPT_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("untrusted_instruction_override", re.compile(r"\b(?:assistant|model|agent) (?:must|should|shall) ignore\b", re.I)),
        ("document_says_ignore_instructions", re.compile(r"\bignore (?:all )?(?:previous|prior|system|developer) instructions\b", re.I)),
        ("exfiltrate_secret_instruction", re.compile(r"\b(?:exfiltrate|leak|send|reveal) (?:secrets?|tokens?|credentials?|system prompt)\b", re.I)),
        ("tool_result_instruction", re.compile(r"\btool result instruction\s*:\s*", re.I)),
    )
    _DATA_POISONING_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("declared_data_poisoning", re.compile(r"\bdata poisoning\s*:", re.I)),
        ("poisoned_evidence_marker", re.compile(r"\bpoisoned[_ -]?evidence\s*[:=]\s*(?:true|1|yes)\b", re.I)),
        ("retrieval_override", re.compile(r"\bretrieval override\s*:\s*", re.I)),
        ("tamper_verification", re.compile(r"\b(?:tamper|override) (?:verification|evidence ranking|retrieval)\b", re.I)),
    )

    def scan_user_message(self, text: str, *, source_ref: str = "message") -> list[ContentThreat]:
        return self._scan(
            text,
            source_kind="user_message",
            source_ref=source_ref,
            rules=(("prompt_injection", self._DIRECT_PROMPT_INJECTION_RULES),),
        )

    def scan_document(self, text: str, *, source_ref: str) -> list[ContentThreat]:
        return self._scan(
            text,
            source_kind="document",
            source_ref=source_ref,
            rules=(
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ),
        )

    def scan_tool_output(self, evidence: Evidence) -> list[ContentThreat]:
        return self._scan(
            evidence.content,
            source_kind="tool_output",
            source_ref=evidence.source_ref or evidence.evidence_id,
            rules=(
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ),
        )

    def scan_tool_payload(
        self,
        payload: Mapping[str, object],
        *,
        source_ref: str,
        pre_tool: bool,
    ) -> list[ContentThreat]:
        """Scan an untrusted tool payload without persisting or logging it."""
        try:
            text = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            text = ""
        rule_list: list[
            tuple[ThreatType, tuple[tuple[str, re.Pattern[str]], ...]]
        ] = []
        if pre_tool:
            rule_list.append(("prompt_injection", self._DIRECT_PROMPT_INJECTION_RULES))
        rule_list.extend(
            [
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ]
        )
        rules = tuple(rule_list)
        return self._scan(
            text,
            source_kind="user_message" if pre_tool else "tool_output",
            source_ref=source_ref,
            rules=rules,
        )

    def mark_evidence(self, evidence: Evidence) -> Evidence:
        threats = self.scan_document(evidence.content, source_ref=evidence.source_ref)
        if not threats:
            return evidence
        raw_security = evidence.structured_content.get("security")
        security: dict[str, object] = dict(raw_security) if isinstance(raw_security, dict) else {}
        security["threats"] = [threat.to_metadata() for threat in threats]
        return evidence.model_copy(
            update={"structured_content": {**evidence.structured_content, "security": security}}
        )

    def threat_attributes(self, threats: list[ContentThreat]) -> dict[str, object]:
        threat_types = {threat.threat_type for threat in threats}
        return {
            "prompt_injection_detected": "prompt_injection" in threat_types,
            "indirect_prompt_injection_detected": "indirect_prompt_injection" in threat_types,
            "data_poisoning_detected": "data_poisoning" in threat_types,
        }

    def threats_from_evidence(self, evidence: list[Evidence]) -> list[ContentThreat]:
        threats: list[ContentThreat] = []
        for item in evidence:
            threats.extend(self.scan_tool_output(item) if item.kind.value == "tool_output" else [])
            security = item.structured_content.get("security")
            if not isinstance(security, dict):
                continue
            raw_threats = security.get("threats")
            if not isinstance(raw_threats, list):
                continue
            for raw in raw_threats:
                if not isinstance(raw, dict):
                    continue
                threat = self._threat_from_metadata(raw, fallback_source_ref=item.source_ref)
                if threat is not None:
                    threats.append(threat)
        return threats

    def _scan(
        self,
        text: str,
        *,
        source_kind: ThreatSourceKind,
        source_ref: str,
        rules: tuple[tuple[ThreatType, tuple[tuple[str, re.Pattern[str]], ...]], ...],
    ) -> list[ContentThreat]:
        findings: list[ContentThreat] = []
        for threat_type, threat_rules in rules:
            for rule_id, pattern in threat_rules:
                if pattern.search(text):
                    findings.append(
                        ContentThreat(
                            threat_type=threat_type,
                            source_kind=source_kind,
                            source_ref=source_ref,
                            rule_id=rule_id,
                        )
                    )
        return findings

    def _threat_from_metadata(
        self,
        raw: dict[object, object],
        *,
        fallback_source_ref: str,
    ) -> ContentThreat | None:
        threat_type = raw.get("threat_type")
        source_kind = raw.get("source_kind")
        rule_id = raw.get("rule_id")
        source_ref = raw.get("source_ref") or fallback_source_ref
        if not isinstance(threat_type, str) or threat_type not in {
            "prompt_injection",
            "indirect_prompt_injection",
            "data_poisoning",
        }:
            return None
        if not isinstance(source_kind, str) or source_kind not in {
            "user_message",
            "document",
            "tool_output",
            "evidence",
        }:
            return None
        if not isinstance(rule_id, str) or not isinstance(source_ref, str):
            return None
        return ContentThreat(
            threat_type=cast(ThreatType, threat_type),
            source_kind=cast(ThreatSourceKind, source_kind),
            source_ref=source_ref,
            rule_id=rule_id,
        )
