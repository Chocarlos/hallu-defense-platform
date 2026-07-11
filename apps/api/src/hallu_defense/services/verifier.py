from __future__ import annotations

import json
import logging
import re
from typing import cast

from hallu_defense.domain.models import (
    Claim,
    ClaimType,
    ClaimVerdict,
    Evidence,
    EvidenceKind,
    RiskLevel,
    VerdictAction,
    VerdictStatus,
)
from hallu_defense.services.nli import NliAdjudicator
from hallu_defense.services.text import tokenize

LOGGER = logging.getLogger(__name__)
NUMBER_RE = re.compile(r"\b\d+(?:[.,]\d+)?\b")
PASS_RE = re.compile(r"\b(pass|passed|green|exito|exit code 0)\b", re.I)
FAIL_RE = re.compile(r"\b(fail|failed|error|traceback|exit code [1-9])\b", re.I)
FILE_RE = re.compile(r"\b[\w./-]+\.(?:py|ts|tsx|js|jsx|go|rs|java|kt|md|json|yaml|yml)\b", re.I)
DIFF_RE = re.compile(
    r"\b(diff|change|changed|modify|modified|update|updates|updated|implement|implements|implemented|"
    r"cambio|modifico|modifica|actualizo|implementa|implemento)\b",
    re.I,
)
IMPLEMENTATION_RE = re.compile(
    r"\b(implement|implements|implemented|fix|fixes|fixed|resolve|resolves|resolved|"
    r"implementa|implemento|corrige|corregido|arregla|arreglo)\b",
    re.I,
)
VALIDATION_PROOF_RE = re.compile(
    r"\b(fix|fixes|fixed|resolve|resolves|resolved|validate|validates|validated|verify|verifies|verified|"
    r"work|works|working|pass|passes|passed|test|tests|tested|build|builds|built|compile|compiles|compiled|"
    r"corrige|corregido|arregla|arreglo|validado|verificado|funciona|prueba|pruebas|compila)\b",
    re.I,
)
TEST_PROOF_RE = re.compile(r"\b(test|tests|tested|pass|passes|passed|pytest|vitest|jest|unittest|prueba|pruebas)\b", re.I)
BUILD_PROOF_RE = re.compile(r"\b(build|builds|built|compile|compiles|compiled|tsc|compila)\b", re.I)
VALIDATION_COMMAND_RE = re.compile(
    r"\b(test|pytest|vitest|jest|unittest|build|compile|tsc|typecheck|mypy|ruff|lint|check)\b",
    re.I,
)
IMPLEMENTATION_STOPWORDS = {
    "actualiza",
    "actualizo",
    "add",
    "adds",
    "added",
    "arregla",
    "arreglo",
    "change",
    "changed",
    "class",
    "clase",
    "code",
    "codigo",
    "corrige",
    "corregido",
    "diff",
    "file",
    "fix",
    "fixed",
    "fixes",
    "funcion",
    "function",
    "implement",
    "implemented",
    "implementa",
    "implemento",
    "implements",
    "method",
    "metodo",
    "modifica",
    "modified",
    "modify",
    "repo",
    "repository",
    "resolve",
    "resolved",
    "resolves",
    "validated",
    "validates",
    "validate",
    "verified",
    "verifies",
    "verify",
    "work",
    "working",
    "works",
    "update",
    "updated",
    "updates",
}
COMMAND_TARGET_STOPWORDS = IMPLEMENTATION_STOPWORDS | {
    "build",
    "builds",
    "built",
    "check",
    "compile",
    "compiled",
    "compiles",
    "exit_code",
    "lint",
    "pass",
    "passed",
    "passes",
    "prueba",
    "pruebas",
    "test",
    "tested",
    "tests",
    "typecheck",
}
SYMBOL_KIND_RE = re.compile(
    r"\b(function|funcion|función|class|clase|method|metodo|método)\s+`?([A-Za-z_][\w.]*)`?",
    re.I,
)
BACKTICK_RE = re.compile(r"`([A-Za-z_][\w.]*)`")


class ClaimVerifier:
    def __init__(self, nli_adjudicator: NliAdjudicator | None = None) -> None:
        self._nli_adjudicator = nli_adjudicator

    def verify(self, claims: list[Claim], evidence: list[Evidence]) -> list[ClaimVerdict]:
        return [self._verify_one(claim, evidence) for claim in claims]

    def _verify_one(self, claim: Claim, evidence: list[Evidence]) -> ClaimVerdict:
        if not claim.requires_evidence:
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.OUT_OF_SCOPE,
                confidence=0.95,
                action=VerdictAction.ALLOW,
                reason="Claim type does not require external evidence.",
            )

        if claim.type == ClaimType.TEST_RESULT:
            return self._verify_test_result(claim, evidence)

        if claim.type in {ClaimType.REPO_STATE, ClaimType.TOOL_OBSERVATION}:
            required_kinds = {
                ClaimType.REPO_STATE: {EvidenceKind.REPO_FILE, EvidenceKind.COMMAND_OUTPUT},
                ClaimType.TOOL_OBSERVATION: {EvidenceKind.TOOL_OUTPUT, EvidenceKind.COMMAND_OUTPUT},
            }[claim.type]
            route_evidence = [item for item in evidence if item.kind in required_kinds]
            if not route_evidence:
                return self._not_found(claim, "Operational claims require deterministic tool/repo evidence.")
            if claim.type == ClaimType.REPO_STATE:
                return self._verify_repo_state(claim, route_evidence)
            return self._textual_verdict(claim, route_evidence)

        if claim.type == ClaimType.COMPUTED_VALUE:
            return self._verify_computed(claim)

        if not evidence:
            return self._not_found(claim, "No evidence was provided.")

        return self._textual_verdict(claim, evidence)

    def _textual_verdict(self, claim: Claim, evidence: list[Evidence]) -> ClaimVerdict:
        if not evidence:
            return self._not_found(claim, "No evidence was provided.")

        claim_tokens = tokenize(claim.text)
        scored: list[tuple[float, Evidence]] = []
        for item in evidence:
            evidence_tokens = tokenize(item.content)
            overlap = claim_tokens.intersection(evidence_tokens)
            coverage = len(overlap) / max(len(claim_tokens), 1)
            scored.append((coverage, item))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        best_score, best = scored[0]
        claim_numbers = NUMBER_RE.findall(claim.text)
        source_contradiction = self._detect_source_contradiction(claim, scored, claim_numbers)
        if source_contradiction is not None:
            return source_contradiction

        evidence_numbers = NUMBER_RE.findall(best.content)

        if claim_numbers and evidence_numbers and set(claim_numbers).isdisjoint(evidence_numbers):
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.CONTRADICTED,
                confidence=0.82,
                evidence_ids=[best.evidence_id],
                action=VerdictAction.BLOCK if claim.risk_level == RiskLevel.HIGH else VerdictAction.REWRITE,
                reason="Numeric values in claim do not match the strongest evidence.",
                validator_trace={"overlap": best_score, "claim_numbers": claim_numbers},
            )

        if best_score >= 0.55:
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.SUPPORTED,
                confidence=min(0.98, 0.55 + best_score / 2),
                evidence_ids=[best.evidence_id],
                action=VerdictAction.ALLOW_WITH_CITATION,
                reason="Claim has strong lexical support in selected evidence.",
                validator_trace={"overlap": best_score},
            )

        nli_verdict = self._nli_verdict(claim, evidence, best_score)
        if nli_verdict is not None:
            return nli_verdict

        if best_score >= 0.25:
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.PARTIALLY_SUPPORTED,
                confidence=0.55,
                evidence_ids=[best.evidence_id],
                action=VerdictAction.REWRITE,
                reason="Evidence overlaps with the claim but does not fully support it.",
                validator_trace={"overlap": best_score},
            )

        return self._not_found(claim, "No evidence has enough overlap with the claim.")

    def _nli_verdict(
        self,
        claim: Claim,
        evidence: list[Evidence],
        best_score: float,
    ) -> ClaimVerdict | None:
        if self._nli_adjudicator is None:
            return None
        if claim.type not in {ClaimType.WORLD_FACT, ClaimType.DOC_GROUNDED}:
            return None
        try:
            adjudication = self._nli_adjudicator.adjudicate(claim, evidence)
        except Exception as exc:
            error_type = type(exc).__name__
            LOGGER.error(
                "Provider NLI adjudication failed closed",
                extra={"claim_id": claim.claim_id, "error_type": error_type},
            )
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.AMBIGUOUS,
                confidence=min(0.49, max(0.1, best_score)),
                action=(
                    VerdictAction.REQUIRE_HUMAN_REVIEW
                    if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                    else VerdictAction.REWRITE
                ),
                reason="Provider NLI was unavailable or invalid; conservative fallback applied.",
                validator_trace={
                    "overlap": best_score,
                    "nli": {"status": "unavailable", "error_type": error_type},
                },
            )
        if adjudication is None:
            return None

        trace = {
            "overlap": best_score,
            "nli": {
                "provider": adjudication.provider,
                "model": adjudication.model,
                "status": adjudication.status,
                "confidence": adjudication.confidence,
                "evidence_ids": adjudication.evidence_ids,
            },
        }
        if adjudication.status == "contradicted":
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.CONTRADICTED,
                confidence=min(0.92, adjudication.confidence),
                evidence_ids=adjudication.evidence_ids,
                action=VerdictAction.BLOCK
                if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                else VerdictAction.REWRITE,
                reason=f"Provider NLI found contradiction: {adjudication.reason}",
                validator_trace=trace,
            )

        if adjudication.status == "supported":
            if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.AMBIGUOUS,
                    confidence=min(0.65, adjudication.confidence),
                    evidence_ids=adjudication.evidence_ids,
                    action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                    reason="Provider NLI support for high-risk claims requires human review.",
                    validator_trace=trace,
                )
            if adjudication.confidence >= 0.7:
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=min(0.85, adjudication.confidence),
                    evidence_ids=adjudication.evidence_ids,
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason=f"Provider NLI found support in cited evidence: {adjudication.reason}",
                    validator_trace=trace,
                )

        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.NOT_FOUND,
            confidence=max(0.7, adjudication.confidence),
            evidence_ids=adjudication.evidence_ids,
            action=VerdictAction.BLOCK
            if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else VerdictAction.ABSTAIN,
            reason=f"Provider NLI did not find sufficient support: {adjudication.reason}",
            validator_trace=trace,
        )

    def _verify_repo_state(self, claim: Claim, evidence: list[Evidence]) -> ClaimVerdict:
        inspection = self._inspection_from_evidence(evidence)
        files = self._claim_files(claim.text)
        symbols = self._claim_symbols(claim.text)
        implementation_claim = IMPLEMENTATION_RE.search(claim.text) is not None
        diff_claim = DIFF_RE.search(claim.text) is not None or implementation_claim

        if inspection is None:
            if files or symbols or diff_claim:
                return self._not_found(
                    claim,
                    "Repository file/function/diff claims require sandbox inspection evidence.",
                )
            return self._textual_verdict(claim, evidence)

        evidence_id = cast(str, inspection["evidence_id"])
        report = cast(dict[str, object], inspection["report"])
        static = self._dict_field(report, "static")
        git = self._dict_field(report, "git")
        inspected_files = set(self._string_list(static.get("files")))
        diff_files = set(self._string_list(git.get("diff_files")))
        static_symbols = self._combined_symbol_index(static)
        raw_changed_symbols = self._dict_list(git.get("changed_symbols"))
        changed_symbols = self._symbol_index(raw_changed_symbols)
        changed_lines = self._dict_list(git.get("changed_lines"))
        command_outputs = [item for item in evidence if item.kind == EvidenceKind.COMMAND_OUTPUT]
        truncated = static.get("truncated") is True

        if implementation_claim:
            return self._verify_implementation_claim(
                claim,
                evidence_id,
                files,
                symbols,
                diff_files,
                raw_changed_symbols,
                changed_lines,
                command_outputs,
            )

        if diff_claim and symbols:
            missing_changed_symbols = [
                symbol
                for symbol in symbols
                if not self._symbol_found(symbol, changed_symbols, files)
            ]
            if not missing_changed_symbols:
                matched = sorted(symbol for symbol in symbols if self._symbol_found(symbol, changed_symbols, files))
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.98,
                    evidence_ids=[evidence_id],
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason="Sandbox git inspection shows the claimed code symbol was changed.",
                    validator_trace={
                        "matched_changed_symbols": matched,
                        "changed_symbols_sample": sorted(changed_symbols["names"])[:25],
                    },
                )
            return self._repo_contradiction(
                claim,
                evidence_id,
                "Sandbox git inspection does not show the claimed code symbol was changed.",
                {
                    "missing_changed_symbols": missing_changed_symbols,
                    "changed_symbols_sample": sorted(changed_symbols["names"])[:25],
                    "requested_files": files,
                },
            )

        if diff_claim and files:
            missing = sorted(file for file in files if file not in diff_files)
            if not missing:
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.98,
                    evidence_ids=[evidence_id],
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason="Sandbox git inspection shows the claimed file in the diff.",
                    validator_trace={"diff_files": sorted(diff_files), "matched_files": files},
                )
            return self._repo_contradiction(
                claim,
                evidence_id,
                "Sandbox git inspection does not include the claimed file in the diff.",
                {"diff_files": sorted(diff_files), "missing_files": missing},
            )

        if symbols:
            missing_symbols = [
                symbol
                for symbol in symbols
                if not self._symbol_found(symbol, static_symbols, files)
            ]
            if not missing_symbols:
                matched = sorted(symbol for symbol in symbols if self._symbol_found(symbol, static_symbols, files))
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.98,
                    evidence_ids=[evidence_id],
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason="Sandbox static inspection found the claimed code symbol.",
                    validator_trace={"matched_symbols": matched},
                )
            if truncated:
                return self._not_found(
                    claim,
                    "Sandbox AST inspection was truncated and cannot prove the claimed symbol.",
                )
            return self._repo_contradiction(
                claim,
                evidence_id,
                "Sandbox static inspection did not find the claimed code symbol.",
                {
                    "missing_symbols": missing_symbols,
                    "available_symbols_sample": sorted(static_symbols["names"])[:25],
                    "requested_files": files,
                },
            )

        if files:
            missing_files = sorted(file for file in files if file not in inspected_files)
            if not missing_files:
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.98,
                    evidence_ids=[evidence_id],
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason="Sandbox static inspection found the claimed repository file.",
                    validator_trace={"matched_files": files},
                )
            if truncated:
                return self._not_found(
                    claim,
                    "Sandbox static inspection was truncated and cannot prove the claimed file.",
                )
            return self._repo_contradiction(
                claim,
                evidence_id,
                "Sandbox static inspection did not find the claimed repository file.",
                {
                    "missing_files": missing_files,
                    "available_files_sample": sorted(inspected_files)[:25],
                },
            )

        return self._not_found(
            claim,
            "Repository claim is not specific enough for deterministic sandbox verification.",
        )

    def _verify_implementation_claim(
        self,
        claim: Claim,
        evidence_id: str,
        files: list[str],
        symbols: list[str],
        diff_files: set[str],
        changed_symbols: list[dict[str, object]],
        changed_lines: list[dict[str, object]],
        command_outputs: list[Evidence],
    ) -> ClaimVerdict:
        if not files and not symbols:
            return self._repo_not_found(
                claim,
                evidence_id,
                "Implementation claims require a specific changed file or code symbol.",
                {"reason": "missing_file_or_symbol"},
            )

        missing_files = sorted(file for file in files if file not in diff_files)
        if missing_files:
            return self._repo_contradiction(
                claim,
                evidence_id,
                "Sandbox git inspection does not include the claimed implementation file in the diff.",
                {"diff_files": sorted(diff_files), "missing_files": missing_files},
            )

        matched_symbol_records: list[dict[str, object]] = []
        if symbols:
            missing_symbols = []
            for symbol in symbols:
                matches = self._matching_symbol_records(symbol, changed_symbols, files)
                if matches:
                    matched_symbol_records.extend(matches)
                else:
                    missing_symbols.append(symbol)
            if missing_symbols:
                return self._repo_contradiction(
                    claim,
                    evidence_id,
                    "Sandbox git inspection does not show the claimed code symbol was changed.",
                    {
                        "missing_changed_symbols": missing_symbols,
                        "changed_symbols_sample": self._symbol_record_sample(changed_symbols),
                        "requested_files": files,
                    },
                )

        implementation_terms = self._implementation_terms(claim.text, files, symbols)
        command_evidence_ids, command_trace, command_failure = self._required_command_evidence(
            claim,
            evidence_id,
            command_outputs,
            implementation_terms,
            files,
            symbols,
            matched_symbol_records,
        )
        if command_failure is not None:
            return command_failure

        if not implementation_terms:
            if matched_symbol_records:
                return ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.94,
                    evidence_ids=[evidence_id, *command_evidence_ids],
                    action=VerdictAction.ALLOW_WITH_CITATION,
                    reason="Sandbox git inspection shows the claimed code symbol was changed.",
                    validator_trace={
                        "matched_changed_symbols": sorted(
                            {
                                str(record.get("qualified_name"))
                                for record in matched_symbol_records
                                if isinstance(record.get("qualified_name"), str)
                            }
                        ),
                        "implementation_terms": [],
                        **command_trace,
                    },
                )
            return self._repo_not_found(
                claim,
                evidence_id,
                "Implementation claims over files need behavior-specific changed-line evidence.",
                {"diff_files": sorted(diff_files), "requested_files": files},
            )

        changed_line_tokens = self._changed_line_tokens(changed_lines, files, matched_symbol_records)
        missing_terms = sorted(term for term in implementation_terms if term not in changed_line_tokens)
        if missing_terms:
            return self._repo_not_found(
                claim,
                evidence_id,
                "Sandbox changed-line evidence does not prove the asserted implementation terms.",
                {
                    "missing_implementation_terms": missing_terms,
                    "implementation_terms": implementation_terms,
                    "changed_line_tokens_sample": sorted(changed_line_tokens)[:25],
                    "requested_files": files,
                    "matched_changed_symbols": self._symbol_record_sample(matched_symbol_records),
                },
            )

        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.SUPPORTED,
            confidence=0.96,
            evidence_ids=[evidence_id, *command_evidence_ids],
            action=VerdictAction.ALLOW_WITH_CITATION,
            reason="Sandbox changed-line evidence includes the asserted implementation terms.",
            validator_trace={
                "matched_implementation_terms": implementation_terms,
                "matched_changed_symbols": self._symbol_record_sample(matched_symbol_records),
                "requested_files": files,
                **command_trace,
            },
        )

    def _inspection_from_evidence(self, evidence: list[Evidence]) -> dict[str, object] | None:
        for item in evidence:
            report = self._inspection_payload(item.structured_content)
            if report is None:
                try:
                    parsed = json.loads(item.content)
                except json.JSONDecodeError:
                    parsed = None
                report = self._inspection_payload(parsed)
            if report is not None:
                return {"evidence_id": item.evidence_id, "report": report}
        return None

    def _inspection_payload(self, candidate: object) -> dict[str, object] | None:
        if not isinstance(candidate, dict):
            return None
        if candidate.get("schema_version") == "sandbox_inspection.v1":
            return cast(dict[str, object], candidate)
        nested = candidate.get("sandbox_inspection")
        if isinstance(nested, dict) and nested.get("schema_version") == "sandbox_inspection.v1":
            return cast(dict[str, object], nested)
        return None

    def _claim_files(self, text: str) -> list[str]:
        return sorted({match.rstrip(".,;:") for match in FILE_RE.findall(text)})

    def _claim_symbols(self, text: str) -> list[str]:
        symbols = [match.group(2) for match in SYMBOL_KIND_RE.finditer(text)]
        symbols.extend(BACKTICK_RE.findall(text))
        return sorted({symbol for symbol in symbols if not FILE_RE.fullmatch(symbol)})

    def _combined_symbol_index(self, static_report: dict[str, object]) -> dict[str, set[str]]:
        names: set[str] = set()
        path_names: set[str] = set()
        for key in ("python_symbols", "javascript_symbols"):
            index = self._symbol_index(static_report.get(key))
            names.update(index["names"])
            path_names.update(index["path_names"])
        return {"names": names, "path_names": path_names}

    def _symbol_index(self, raw_symbols: object) -> dict[str, set[str]]:
        names: set[str] = set()
        path_names: set[str] = set()
        if not isinstance(raw_symbols, list):
            return {"names": names, "path_names": path_names}
        for raw_symbol in raw_symbols:
            if not isinstance(raw_symbol, dict):
                continue
            raw_path = raw_symbol.get("path")
            path = raw_path if isinstance(raw_path, str) else ""
            for key in ("name", "qualified_name"):
                value = raw_symbol.get(key)
                if isinstance(value, str) and value:
                    names.add(value)
                    if path:
                        path_names.add(f"{path}:{value}")
        return {"names": names, "path_names": path_names}

    def _matching_symbol_records(
        self,
        symbol: str,
        raw_symbols: list[dict[str, object]],
        requested_files: list[str],
    ) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for raw_symbol in raw_symbols:
            raw_path = raw_symbol.get("path")
            path = raw_path if isinstance(raw_path, str) else ""
            if requested_files and path not in requested_files:
                continue
            names = [
                value
                for key in ("name", "qualified_name")
                for value in [raw_symbol.get(key)]
                if isinstance(value, str)
            ]
            if symbol in names:
                matches.append(raw_symbol)
        return matches

    def _symbol_record_sample(self, raw_symbols: list[dict[str, object]]) -> list[str]:
        names = [
            value
            for raw_symbol in raw_symbols
            for value in [raw_symbol.get("qualified_name")]
            if isinstance(value, str)
        ]
        return sorted(set(names))[:25]

    def _symbol_found(
        self,
        symbol: str,
        python_symbols: dict[str, set[str]],
        requested_files: list[str],
    ) -> bool:
        if not requested_files:
            return symbol in python_symbols["names"]
        return any(f"{path}:{symbol}" in python_symbols["path_names"] for path in requested_files)

    def _dict_field(self, payload: dict[str, object], key: str) -> dict[str, object]:
        value = payload.get(key)
        return value if isinstance(value, dict) else {}

    def _string_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _dict_list(self, value: object) -> list[dict[str, object]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def _implementation_terms(self, text: str, files: list[str], symbols: list[str]) -> list[str]:
        terms = self._expanded_tokens(text)
        for value in [*files, *symbols]:
            terms.difference_update(self._expanded_tokens(value))
        terms.difference_update(IMPLEMENTATION_STOPWORDS)
        return sorted(terms)

    def _command_target_terms(
        self,
        implementation_terms: list[str],
        files: list[str],
        symbols: list[str],
        matched_symbol_records: list[dict[str, object]],
    ) -> list[str]:
        terms = set(implementation_terms)
        for target_value in [*files, *symbols]:
            terms.update(self._expanded_tokens(target_value))
        for record in matched_symbol_records:
            for key in ("name", "qualified_name", "path"):
                record_value = record.get(key)
                if isinstance(record_value, str):
                    terms.update(self._expanded_tokens(record_value))
        terms.difference_update(COMMAND_TARGET_STOPWORDS)
        return sorted(term for term in terms if len(term) > 2)

    def _expanded_tokens(self, value: str) -> set[str]:
        tokens = {token.rstrip(".,;:") for token in tokenize(value)}
        tokens.discard("")
        expanded = set(tokens)
        for token in tokens:
            expanded.update(
                part
                for part in re.split(r"[./:-]+", token)
                if len(part) > 2
            )
        return expanded

    def _changed_line_tokens(
        self,
        changed_lines: list[dict[str, object]],
        requested_files: list[str],
        matched_symbol_records: list[dict[str, object]],
    ) -> set[str]:
        scoped_ranges = [
            changed_range
            for symbol in matched_symbol_records
            for ranges in [symbol.get("changed_ranges")]
            if isinstance(ranges, list)
            for changed_range in ranges
            if isinstance(changed_range, dict)
        ]
        tokens: set[str] = set()
        for changed_line in changed_lines:
            if changed_line.get("kind") != "added":
                continue
            path = changed_line.get("path")
            lineno = changed_line.get("lineno")
            text = changed_line.get("text")
            if not isinstance(path, str) or not isinstance(lineno, int) or not isinstance(text, str):
                continue
            if requested_files and path not in requested_files:
                continue
            if scoped_ranges and not self._line_in_ranges(path, lineno, changed_line, scoped_ranges):
                continue
            tokens.update(self._expanded_tokens(text))
        return tokens

    def _line_in_ranges(
        self,
        path: str,
        lineno: int,
        changed_line: dict[str, object],
        changed_ranges: list[dict[str, object]],
    ) -> bool:
        line_source = changed_line.get("source")
        for changed_range in changed_ranges:
            range_path = changed_range.get("path")
            new_start = changed_range.get("new_start")
            new_lines = changed_range.get("new_lines")
            range_source = changed_range.get("source")
            if not isinstance(range_path, str) or not isinstance(new_start, int) or not isinstance(new_lines, int):
                continue
            if range_path != path:
                continue
            if isinstance(line_source, str) and isinstance(range_source, str) and line_source != range_source:
                continue
            new_end = new_start + max(new_lines - 1, 0)
            if new_start <= lineno <= new_end:
                return True
        return False

    def _required_command_evidence(
        self,
        claim: Claim,
        inspection_evidence_id: str,
        command_outputs: list[Evidence],
        implementation_terms: list[str],
        files: list[str],
        symbols: list[str],
        matched_symbol_records: list[dict[str, object]],
    ) -> tuple[list[str], dict[str, object], ClaimVerdict | None]:
        requirement = self._command_requirement(claim.text)
        if requirement is None:
            return [], {"command_requirement": None}, None

        relevant = [item for item in command_outputs if self._command_matches_requirement(item, requirement)]
        target_terms = self._command_target_terms(implementation_terms, files, symbols, matched_symbol_records)
        targeted = [item for item in relevant if self._command_targets_claim(item, target_terms)]
        command_candidates = targeted if target_terms else relevant
        trace: dict[str, object] = {
            "command_requirement": requirement,
            "command_target_terms": target_terms,
            "available_command_ids": [item.evidence_id for item in command_outputs],
            "relevant_command_ids": [item.evidence_id for item in relevant],
            "targeted_command_ids": [item.evidence_id for item in targeted],
        }
        if not relevant:
            return (
                [],
                trace,
                self._repo_not_found(
                    claim,
                    inspection_evidence_id,
                    "Fix/validation claims require relevant successful sandbox command evidence.",
                    trace,
                ),
            )

        if target_terms and not targeted:
            return (
                [],
                trace,
                self._repo_not_found(
                    claim,
                    inspection_evidence_id,
                    "Relevant sandbox command evidence does not target the claimed file, symbol, or behavior.",
                    trace,
                ),
            )

        failed = [item for item in command_candidates if self._command_exit_code(item) not in {0, None}]
        failed.extend(
            item
            for item in command_candidates
            if item not in failed and FAIL_RE.search(self._command_text(item)) is not None
        )
        if failed:
            failed_ids = [item.evidence_id for item in failed]
            failure_trace = {
                **trace,
                "failed_command_ids": failed_ids,
                "exit_codes": {
                    item.evidence_id: self._command_exit_code(item)
                    for item in command_candidates
                },
            }
            return (
                [],
                failure_trace,
                ClaimVerdict(
                    claim_id=claim.claim_id,
                    status=VerdictStatus.CONTRADICTED,
                    confidence=0.98,
                    evidence_ids=[inspection_evidence_id, *failed_ids],
                    action=VerdictAction.BLOCK
                    if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                    else VerdictAction.REWRITE,
                    reason="Relevant sandbox command evidence failed, so the fix/validation claim is contradicted.",
                    validator_trace=failure_trace,
                ),
            )

        successful = [item for item in command_candidates if self._command_exit_code(item) == 0]
        if not successful:
            pending_trace = {
                **trace,
                "exit_codes": {
                    item.evidence_id: self._command_exit_code(item)
                    for item in command_candidates
                },
            }
            return (
                [],
                pending_trace,
                self._repo_not_found(
                    claim,
                    inspection_evidence_id,
                    "Relevant sandbox command evidence is present but does not prove success.",
                    pending_trace,
                ),
            )

        success_ids = [item.evidence_id for item in successful]
        success_trace = {
            **trace,
            "matched_command_ids": success_ids,
            "exit_codes": {item.evidence_id: self._command_exit_code(item) for item in command_candidates},
        }
        return success_ids, success_trace, None

    def _command_requirement(self, text: str) -> str | None:
        if TEST_PROOF_RE.search(text):
            return "test"
        if BUILD_PROOF_RE.search(text):
            return "build"
        if VALIDATION_PROOF_RE.search(text):
            return "validation"
        return None

    def _command_matches_requirement(self, evidence: Evidence, requirement: str) -> bool:
        command_kind = self._command_kind(evidence)
        if command_kind is not None:
            if requirement == "test":
                return command_kind == "test"
            if requirement == "build":
                return command_kind == "build"
            return command_kind in {"test", "build", "typecheck", "lint", "check"}

        command_text = self._command_text(evidence)
        if requirement == "test":
            return TEST_PROOF_RE.search(command_text) is not None
        if requirement == "build":
            return BUILD_PROOF_RE.search(command_text) is not None
        return VALIDATION_COMMAND_RE.search(command_text) is not None

    def _command_targets_claim(self, evidence: Evidence, target_terms: list[str]) -> bool:
        if not target_terms:
            return True
        command_target_tokens = self._command_target_tokens(evidence)
        if command_target_tokens is not None:
            return any(term in command_target_tokens for term in target_terms)
        command_tokens = self._expanded_tokens(self._command_text(evidence))
        return any(term in command_tokens for term in target_terms)

    def _command_kind(self, evidence: Evidence) -> str | None:
        value = evidence.structured_content.get("command_kind")
        return value if isinstance(value, str) else None

    def _command_target_tokens(self, evidence: Evidence) -> set[str] | None:
        value = evidence.structured_content.get("command_target_tokens")
        if not isinstance(value, list):
            return None
        return {item for item in value if isinstance(item, str)}

    def _command_text(self, evidence: Evidence) -> str:
        command = evidence.structured_content.get("command")
        return "\n".join(
            [
                evidence.source_ref,
                command if isinstance(command, str) else "",
                evidence.content,
            ]
        )

    def _command_exit_code(self, evidence: Evidence) -> int | None:
        exit_code = evidence.structured_content.get("exit_code")
        return exit_code if isinstance(exit_code, int) else None

    def _repo_not_found(
        self,
        claim: Claim,
        evidence_id: str,
        reason: str,
        validator_trace: dict[str, object],
    ) -> ClaimVerdict:
        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.NOT_FOUND,
            confidence=0.82,
            evidence_ids=[evidence_id],
            action=VerdictAction.BLOCK
            if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else VerdictAction.ABSTAIN,
            reason=reason,
            validator_trace=validator_trace,
        )

    def _repo_contradiction(
        self,
        claim: Claim,
        evidence_id: str,
        reason: str,
        validator_trace: dict[str, object],
    ) -> ClaimVerdict:
        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.CONTRADICTED,
            confidence=0.96,
            evidence_ids=[evidence_id],
            action=VerdictAction.BLOCK
            if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else VerdictAction.REWRITE,
            reason=reason,
            validator_trace=validator_trace,
        )

    def _detect_source_contradiction(
        self,
        claim: Claim,
        scored: list[tuple[float, Evidence]],
        claim_numbers: list[str],
    ) -> ClaimVerdict | None:
        if not claim_numbers:
            return None

        claim_number_set = set(claim_numbers)
        relevant = [
            (score, item, set(NUMBER_RE.findall(item.content)))
            for score, item in scored
            if score >= 0.25 and NUMBER_RE.findall(item.content)
        ]
        supporting = [
            (score, item)
            for score, item, evidence_numbers in relevant
            if claim_number_set.issubset(evidence_numbers)
        ]
        contradicting = [
            (score, item)
            for score, item, evidence_numbers in relevant
            if claim_number_set.isdisjoint(evidence_numbers)
        ]
        if not supporting or not contradicting:
            return None

        evidence_ids = [supporting[0][1].evidence_id, contradicting[0][1].evidence_id]
        overlap_by_evidence = {
            item.evidence_id: round(score, 4)
            for score, item in [supporting[0], contradicting[0]]
        }
        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.CONTRADICTED,
            confidence=0.9,
            evidence_ids=evidence_ids,
            action=VerdictAction.BLOCK
            if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else VerdictAction.REWRITE,
            reason="Relevant evidence sources provide contradictory numeric values for the claim.",
            validator_trace={
                "claim_numbers": sorted(claim_number_set),
                "supporting_evidence_ids": [item.evidence_id for _score, item in supporting],
                "contradicting_evidence_ids": [item.evidence_id for _score, item in contradicting],
                "overlap_by_evidence": overlap_by_evidence,
            },
        )

    def _verify_test_result(self, claim: Claim, evidence: list[Evidence]) -> ClaimVerdict:
        command_outputs = [item for item in evidence if item.kind == EvidenceKind.COMMAND_OUTPUT]
        if not command_outputs:
            return self._not_found(claim, "Test/build claims require command output evidence.")

        combined = "\n".join(item.content for item in command_outputs)
        exit_codes = [
            int(code)
            for item in command_outputs
            for code in [item.structured_content.get("exit_code")]
            if isinstance(code, int)
        ]

        claims_success = PASS_RE.search(claim.text) is not None
        observed_failure = any(code != 0 for code in exit_codes) or FAIL_RE.search(combined) is not None
        if claims_success and observed_failure:
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.CONTRADICTED,
                confidence=0.98,
                evidence_ids=[item.evidence_id for item in command_outputs],
                action=VerdictAction.BLOCK,
                reason="The claim reports passing checks, but command evidence shows failure.",
                validator_trace={"exit_codes": exit_codes},
            )

        if exit_codes and all(code == 0 for code in exit_codes):
            return ClaimVerdict(
                claim_id=claim.claim_id,
                status=VerdictStatus.SUPPORTED,
                confidence=0.98,
                evidence_ids=[item.evidence_id for item in command_outputs],
                action=VerdictAction.ALLOW_WITH_CITATION,
                reason="Command evidence completed successfully.",
                validator_trace={"exit_codes": exit_codes},
            )

        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.AMBIGUOUS,
            confidence=0.45,
            evidence_ids=[item.evidence_id for item in command_outputs],
            action=VerdictAction.ASK_CLARIFICATION,
            reason="Command evidence is present but does not prove the claim.",
            validator_trace={"exit_codes": exit_codes},
        )

    def _verify_computed(self, claim: Claim) -> ClaimVerdict:
        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.UNVERIFIABLE,
            confidence=0.4,
            action=VerdictAction.REWRITE,
            reason="Deterministic calculation engine is reserved for a later adapter.",
        )

    def _not_found(self, claim: Claim, reason: str) -> ClaimVerdict:
        action = VerdictAction.BLOCK if claim.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} else VerdictAction.ABSTAIN
        return ClaimVerdict(
            claim_id=claim.claim_id,
            status=VerdictStatus.NOT_FOUND,
            confidence=0.9,
            action=action,
            reason=reason,
        )
