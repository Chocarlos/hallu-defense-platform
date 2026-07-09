from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
API_SRC = ROOT / "apps" / "api" / "src"
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

from hallu_defense.domain.models import (  # noqa: E402
    Claim,
    ClaimType,
    Evidence,
    EvidenceKind,
    RiskLevel,
    VerdictAction,
    VerdictStatus,
)
from hallu_defense.services.verifier import ClaimVerifier  # noqa: E402

OUTPUT_PATH = ROOT / "evals" / "reports" / "verifier-calibration.json"
SCHEMA_VERSION = "verifier-calibration.v1"
CONFIDENCE_THRESHOLDS = (0.4, 0.55, 0.7, 0.82, 0.9, 0.95, 0.98)


@dataclass(frozen=True)
class CalibrationCase:
    case_id: str
    category: str
    claim: Claim
    evidence: tuple[Evidence, ...]
    expected_status: VerdictStatus
    expected_action: VerdictAction


def build_report() -> dict[str, object]:
    verifier = ClaimVerifier()
    cases = calibration_cases()
    case_results: list[dict[str, object]] = []
    by_status: defaultdict[str, list[float]] = defaultdict(list)
    failures: list[str] = []

    for case in cases:
        verdict = verifier.verify([case.claim], list(case.evidence))[0]
        matches_expected = (
            verdict.status == case.expected_status and verdict.action == case.expected_action
        )
        if not matches_expected:
            failures.append(
                f"{case.case_id}: expected {case.expected_status.value}/{case.expected_action.value}, "
                f"got {verdict.status.value}/{verdict.action.value}"
            )
        by_status[verdict.status.value].append(verdict.confidence)
        case_results.append(
            _round_floats(
                {
                    "id": case.case_id,
                    "category": case.category,
                    "claim_type": case.claim.type.value,
                    "risk_level": case.claim.risk_level.value,
                    "evidence_count": len(case.evidence),
                    "expected_status": case.expected_status.value,
                    "expected_action": case.expected_action.value,
                    "actual_status": verdict.status.value,
                    "actual_action": verdict.action.value,
                    "confidence": verdict.confidence,
                    "evidence_ids": verdict.evidence_ids,
                    "matches_expected": matches_expected,
                    "validator_trace": verdict.validator_trace,
                }
            )
        )

    if failures:
        raise RuntimeError("Verifier calibration fixtures no longer match expectations:\n- " + "\n- ".join(failures))

    return {
        "schema_version": SCHEMA_VERSION,
        "suite": "deterministic_claim_verifier",
        "verifier": "hallu_defense.services.verifier.ClaimVerifier",
        "case_count": len(cases),
        "status_summary": _status_summary(by_status),
        "confidence_curve": _confidence_curve(case_results),
        "cases": case_results,
    }


def calibration_cases() -> list[CalibrationCase]:
    return [
        CalibrationCase(
            case_id="doc_supported_exact_overlap",
            category="document_grounding",
            claim=Claim(
                claim_id="clm_supported",
                text="Remote work requests must be approved by a manager.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_supported",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="hr-policy",
                    content="Remote work requests must be approved by a manager.",
                ),
            ),
            expected_status=VerdictStatus.SUPPORTED,
            expected_action=VerdictAction.ALLOW_WITH_CITATION,
        ),
        CalibrationCase(
            case_id="doc_partial_overlap",
            category="document_grounding",
            claim=Claim(
                claim_id="clm_partial",
                text="Remote work approvals require manager, finance, legal, and security review.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_partial",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="hr-policy",
                    content="Remote work requests require manager approval.",
                ),
            ),
            expected_status=VerdictStatus.PARTIALLY_SUPPORTED,
            expected_action=VerdictAction.REWRITE,
        ),
        CalibrationCase(
            case_id="doc_numeric_contradiction",
            category="numeric_contradiction",
            claim=Claim(
                claim_id="clm_numeric",
                text="The service has 99 replicas.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_numeric",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="runbook",
                    content="The service has 3 replicas.",
                ),
            ),
            expected_status=VerdictStatus.CONTRADICTED,
            expected_action=VerdictAction.REWRITE,
        ),
        CalibrationCase(
            case_id="doc_not_found_low_overlap",
            category="insufficient_evidence",
            claim=Claim(
                claim_id="clm_not_found",
                text="Quantum payroll policy requires blue badges.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_unrelated",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="hr-policy",
                    content="Remote work requests require manager approval.",
                ),
            ),
            expected_status=VerdictStatus.NOT_FOUND,
            expected_action=VerdictAction.ABSTAIN,
        ),
        CalibrationCase(
            case_id="high_risk_no_evidence_blocks",
            category="insufficient_evidence",
            claim=Claim(
                claim_id="clm_high_risk",
                text="Production egress allowlist is disabled.",
                type=ClaimType.WORLD_FACT,
                risk_level=RiskLevel.HIGH,
            ),
            evidence=(),
            expected_status=VerdictStatus.NOT_FOUND,
            expected_action=VerdictAction.BLOCK,
        ),
        CalibrationCase(
            case_id="creative_out_of_scope",
            category="scope",
            claim=Claim(
                claim_id="clm_creative",
                text="The draft uses a confident executive tone.",
                type=ClaimType.CREATIVE_STATEMENT,
                risk_level=RiskLevel.LOW,
                requires_evidence=False,
            ),
            evidence=(),
            expected_status=VerdictStatus.OUT_OF_SCOPE,
            expected_action=VerdictAction.ALLOW,
        ),
        CalibrationCase(
            case_id="test_result_exit_zero_supported",
            category="code_agent_evidence",
            claim=Claim(
                claim_id="clm_tests_passed",
                text="The targeted pytest suite passed.",
                type=ClaimType.TEST_RESULT,
                risk_level=RiskLevel.HIGH,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_pytest_ok",
                    kind=EvidenceKind.COMMAND_OUTPUT,
                    source_ref="pytest",
                    content="2 passed",
                    structured_content={"exit_code": 0},
                ),
            ),
            expected_status=VerdictStatus.SUPPORTED,
            expected_action=VerdictAction.ALLOW_WITH_CITATION,
        ),
        CalibrationCase(
            case_id="test_result_exit_nonzero_contradicted",
            category="code_agent_evidence",
            claim=Claim(
                claim_id="clm_tests_green",
                text="The pytest suite passed.",
                type=ClaimType.TEST_RESULT,
                risk_level=RiskLevel.HIGH,
            ),
            evidence=(
                Evidence(
                    evidence_id="ev_pytest_failed",
                    kind=EvidenceKind.COMMAND_OUTPUT,
                    source_ref="pytest",
                    content="1 failed",
                    structured_content={"exit_code": 1},
                ),
            ),
            expected_status=VerdictStatus.CONTRADICTED,
            expected_action=VerdictAction.BLOCK,
        ),
    ]


def render_report(report: Mapping[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def write_report(path: Path = OUTPUT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(build_report()), encoding="utf-8")


def _status_summary(by_status: Mapping[str, list[float]]) -> dict[str, dict[str, float | int]]:
    summary: dict[str, dict[str, float | int]] = {}
    for status, confidences in sorted(by_status.items()):
        summary[status] = _round_floats(
            {
                "count": len(confidences),
                "min_confidence": min(confidences),
                "max_confidence": max(confidences),
                "avg_confidence": sum(confidences) / len(confidences),
            }
        )
    return summary


def _confidence_curve(case_results: list[dict[str, object]]) -> list[dict[str, float | int]]:
    curve: list[dict[str, float | int]] = []
    for threshold in CONFIDENCE_THRESHOLDS:
        selected = [
            result for result in case_results if float(result["confidence"]) >= threshold
        ]
        matches = sum(1 for result in selected if result["matches_expected"] is True)
        curve.append(
            _round_floats(
                {
                    "threshold": threshold,
                    "included_cases": len(selected),
                    "expected_precision": _ratio(matches, len(selected)),
                    "suite_recall": _ratio(len(selected), len(case_results)),
                }
            )
        )
    return curve


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator


def _round_floats(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, dict):
        return {str(key): _round_floats(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_round_floats(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic verifier calibration report.")
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Path to write the calibration JSON artifact.",
    )
    args = parser.parse_args()
    write_report(args.output)
    print(f"Wrote verifier calibration report to {args.output}")


if __name__ == "__main__":
    main()
