package hallucination_defense.policy

import rego.v1

base_verified := {
	"context_version": "verified-policy-context.v1",
	"identity": {"tenant_id": "tenant-a", "subject_id": "agent-a"},
	"request": {"action": "read", "resource": "document:a", "risk_level": "low"},
	"resource": {"tenant_id": "tenant-a"},
	"definition": {"known": true, "version": "public-policy-actions.v1"},
	"approval": {
		"required_for_action": true,
		"granted": false,
		"binding_valid": false,
		"approval_id": "",
	},
	"signals": {
		"prompt_injection_detected": false,
		"indirect_prompt_injection_detected": false,
		"data_poisoning_detected": false,
		"contains_secret": false,
		"contains_pii": false,
		"contradiction_detected": false,
		"source_authority": "",
		"claim_surface": "",
	},
	"sandbox": {"network_policy": "deny"},
	"evidence": {"deterministic_verified": false},
}

input_for(action, risk) := {"verified": object.union(base_verified, {
	"request": object.union(base_verified.request, {"action": action, "risk_level": risk}),
})}

test_missing_verified_context_fails_closed if {
	result := decision with input as {"attributes": {"approval_status": "approved"}}
	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "invalid_verified_policy_context"
}

test_cross_tenant_access_denied if {
	payload := input_for("read", "low")
	updated := object.union(payload.verified, {"resource": {"tenant_id": "tenant-b"}})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "cross_tenant_access_denied"
}

test_unknown_action_fails_closed if {
	result := decision with input as input_for("purge_all", "low")
	result.allowed == false
	result.matched_rules[_] == "unknown_policy_action_blocked"
}

test_unknown_definition_fails_closed if {
	payload := input_for("read", "low")
	updated := object.union(payload.verified, {"definition": {"known": false, "version": ""}})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "unknown_tool_definition_blocked"
}

test_high_risk_requires_approval if {
	result := decision with input as input_for("deploy", "critical")
	result.allowed == false
	result.action == "require_human_review"
	result.matched_rules == ["high_risk_requires_human_review"]
}

test_grant_without_binding_cannot_autoapprove if {
	payload := input_for("deploy", "critical")
	updated := object.union(payload.verified, {
		"approval": {
			"required_for_action": true,
			"granted": true,
			"binding_valid": false,
			"approval_id": "apr-spoof",
		},
	})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "require_human_review"
}

test_bound_approval_allows_registered_high_risk_action if {
	payload := input_for("deploy", "critical")
	updated := object.union(payload.verified, {
		"approval": {
			"required_for_action": true,
			"granted": true,
			"binding_valid": true,
			"approval_id": "apr-valid",
		},
	})
	result := decision with input as {"verified": updated}
	result.allowed == true
	result.action == "allow"
}

test_secret_leakage_blocks_output if {
	payload := input_for("validate_tool_output", "medium")
	signals := object.union(base_verified.signals, {"contains_secret": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "secret_leakage_blocks_output"
}

test_pii_leakage_requires_redaction if {
	payload := input_for("validate_tool_output", "medium")
	signals := object.union(base_verified.signals, {"contains_pii": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "rewrite"
}

test_prompt_injection_blocks_untrusted_instruction if {
	payload := input_for("verify_response", "medium")
	signals := object.union(base_verified.signals, {"prompt_injection_detected": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "prompt_injection_blocks_untrusted_instruction"
}

test_indirect_prompt_injection_blocks_document_instruction if {
	payload := input_for("verify_response", "medium")
	signals := object.union(base_verified.signals, {"indirect_prompt_injection_detected": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "indirect_prompt_injection_blocks_document_instruction"
}

test_data_poisoning_blocks_evidence_use if {
	payload := input_for("retrieve_evidence", "medium")
	signals := object.union(base_verified.signals, {"data_poisoning_detected": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "data_poisoning_blocks_evidence_use"
}

test_tool_output_contradiction_low_risk_requires_repair if {
	payload := input_for("validate_tool_output", "medium")
	signals := object.union(base_verified.signals, {"contradiction_detected": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "rewrite"
}

test_sandbox_allowlisted_network_requires_bound_approval if {
	payload := input_for("run_repo_checks", "low")
	updated := object.union(payload.verified, {"sandbox": {"network_policy": "allowlisted"}})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "require_human_review"
}

test_repo_test_build_claim_requires_deterministic_evidence if {
	payload := input_for("verify_repo_claim", "low")
	spoofed := object.union(payload, {"attributes": {"has_sandbox_run": true}})
	result := decision with input as spoofed
	result.allowed == false
	result.matched_rules[_] == "repo_claim_requires_deterministic_evidence"
}

test_repo_claim_with_verified_evidence_is_allowed if {
	payload := input_for("verify_repo_claim", "low")
	updated := object.union(payload.verified, {"evidence": {"deterministic_verified": true}})
	result := decision with input as {"verified": updated}
	result.allowed == true
}

test_unknown_source_blocks_consistently if {
	payload := input_for("read", "low")
	signals := object.union(base_verified.signals, {"source_authority": "unknown"})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.matched_rules[_] == "unknown_source_blocks_policy_claim"
}

test_sensitive_action_requires_human_review if {
	result := decision with input as input_for("send_email", "low")
	result.allowed == false
	result.action == "require_human_review"
	result.matched_rules[_] == "sensitive_action_requires_human_review"
}

test_tool_output_contradiction_high_risk_blocks if {
	payload := input_for("validate_tool_output", "high")
	signals := object.union(base_verified.signals, {"contradiction_detected": true})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "tool_output_contradiction_requires_repair"
}

test_sandbox_network_policy_deny_by_default if {
	result := decision with input as input_for("run_repo_checks", "low")
	result.allowed == true
	result.network_policy == "deny"
	result.matched_rules == ["sandbox_network_policy_deny_by_default"]
	result.explanation == "Sandbox network policy defaults to deny."
}

test_default_allow_rule_is_explicit if {
	result := decision with input as input_for("read", "low")
	result.allowed == true
	result.matched_rules == ["default_allow_registered_action"]
	result.explanation == "No blocking enterprise policy matched the registered action."
}

test_block_precedence_suppresses_rewrite_and_review_diagnostics if {
	payload := input_for("deploy", "high")
	signals := object.union(base_verified.signals, {
		"contains_secret": true,
		"contains_pii": true,
	})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.allowed == false
	result.action == "block"
	result.matched_rules == ["secret_leakage_blocks_output"]
	result.explanation == "Tool or model output contains secret-like material and must be blocked."
}

test_contradiction_block_explanation_precedes_pii_rewrite if {
	payload := input_for("validate_tool_output", "high")
	signals := object.union(base_verified.signals, {
		"contains_pii": true,
		"contradiction_detected": true,
	})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["tool_output_contradiction_requires_repair"]
	result.explanation == "Tool output contradicts available evidence and requires repair or block."
}

test_unknown_source_block_precedes_contradiction_rewrite if {
	payload := input_for("validate_tool_output", "medium")
	signals := object.union(base_verified.signals, {
		"contradiction_detected": true,
		"source_authority": "unknown",
	})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["unknown_source_blocks_policy_claim"]
	result.explanation == "Unknown-authority sources cannot authorize policy claims."
}

test_malformed_signal_type_fails_closed if {
	payload := input_for("read", "low")
	signals := object.union(base_verified.signals, {"contains_pii": 1})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_malformed_approval_type_fails_closed if {
	payload := input_for("deploy", "high")
	updated := object.union(payload.verified, {
		"approval": {
			"required_for_action": true,
			"granted": 1,
			"binding_valid": 1,
			"approval_id": "apr-malformed",
		},
	})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_verified_approval_requires_nonempty_identifier if {
	payload := input_for("deploy", "high")
	updated := object.union(payload.verified, {
		"approval": {
			"required_for_action": true,
			"granted": true,
			"binding_valid": true,
			"approval_id": "",
		},
	})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_unknown_source_authority_value_fails_closed if {
	payload := input_for("read", "low")
	signals := object.union(base_verified.signals, {"source_authority": "UNKNOWN"})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_unknown_claim_surface_value_fails_closed if {
	payload := input_for("read", "low")
	signals := object.union(base_verified.signals, {"claim_surface": "REPO"})
	updated := object.union(payload.verified, {"signals": signals})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_oversized_subject_fails_closed if {
	payload := input_for("read", "low")
	identity := object.union(base_verified.identity, {
		"subject_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	updated := object.union(payload.verified, {"identity": identity})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}

test_missing_network_policy_fails_closed if {
	payload := input_for("read", "low")
	updated := object.remove(payload.verified, {"sandbox"})
	result := decision with input as {"verified": updated}
	result.action == "block"
	result.matched_rules == ["invalid_verified_policy_context"]
}
