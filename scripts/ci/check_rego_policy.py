from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPA_ROOT = ROOT / "infra" / "opa"
POLICY_FILE = OPA_ROOT / "policies" / "access_risk_approval.rego"
TEST_FILE = OPA_ROOT / "tests" / "access_risk_approval_test.rego"
PACKAGE_RE = re.compile(r"(?m)^package\s+hallucination_defense\.policy\s*$")

EXPECTED_POLICY_IDENTIFIERS = (
    "decision",
    "cross_tenant_access_denied",
    "high_risk_requires_approval",
    "secret_leakage_blocks_output",
    "prompt_injection_blocks_untrusted_instruction",
    "indirect_prompt_injection_blocks_document_instruction",
    "data_poisoning_blocks_evidence_use",
    "pii_leakage_requires_redaction",
    "sensitive_action_requires_human_review",
    "tool_output_contradiction_requires_repair",
    "rewrite_rules",
    "sandbox_network_policy_deny_by_default",
    "repo_test_build_claim_requires_deterministic_evidence",
    "repo_claim_requires_deterministic_evidence",
)

EXPECTED_TEST_IDENTIFIERS = (
    "test_cross_tenant_access_denied",
    "test_high_risk_requires_approval",
    "test_secret_leakage_blocks_output",
    "test_prompt_injection_blocks_untrusted_instruction",
    "test_indirect_prompt_injection_blocks_document_instruction",
    "test_data_poisoning_blocks_evidence_use",
    "test_pii_leakage_requires_redaction",
    "test_sensitive_action_requires_human_review",
    "test_tool_output_contradiction_low_risk_requires_repair",
    "test_tool_output_contradiction_high_risk_blocks",
    "test_sandbox_network_policy_deny_by_default",
    "test_repo_test_build_claim_requires_deterministic_evidence",
)


def read_required(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"Required Rego file is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_package(path: Path, text: str) -> None:
    if not PACKAGE_RE.search(text):
        raise SystemExit(
            f"{path.relative_to(ROOT)} must declare package hallucination_defense.policy"
        )


def require_identifiers(path: Path, text: str, identifiers: tuple[str, ...]) -> None:
    missing = [
        identifier
        for identifier in identifiers
        if not re.search(rf"\b{re.escape(identifier)}\b", text)
    ]
    if missing:
        raise SystemExit(
            f"{path.relative_to(ROOT)} is missing required identifiers: "
            + ", ".join(missing)
        )


def main() -> None:
    policy_text = read_required(POLICY_FILE)
    test_text = read_required(TEST_FILE)

    require_package(POLICY_FILE, policy_text)
    require_package(TEST_FILE, test_text)
    require_identifiers(POLICY_FILE, policy_text, EXPECTED_POLICY_IDENTIFIERS)
    require_identifiers(TEST_FILE, test_text, EXPECTED_TEST_IDENTIFIERS)

    rego_files = sorted(OPA_ROOT.rglob("*.rego"))
    if len(rego_files) < 2:
        raise SystemExit("Expected at least one policy Rego file and one Rego test file.")

    print(
        "Static Rego policy checks passed for "
        f"{len(rego_files)} files. This helper does not execute OPA/Rego."
    )


if __name__ == "__main__":
    main()
