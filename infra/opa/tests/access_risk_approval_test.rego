package hallucination_defense.policy

import rego.v1

test_cross_tenant_access_denied if {
	result := decision with input as {"attributes": {
		"request_tenant_id": "tenant-a",
		"resource_tenant_id": "tenant-b",
	}}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "cross_tenant_access_denied"
}

test_high_risk_requires_approval if {
	result := decision with input as {
		"action": "deploy",
		"risk_level": "high",
	}

	result.allowed == false
	result.action == "require_human_review"
	result.matched_rules[_] == "high_risk_requires_approval"
}

test_high_risk_with_approval_is_allowed if {
	result := decision with input as {
		"action": "deploy",
		"risk_level": "critical",
		"attributes": {"approval_status": "approved"},
	}

	result.allowed == true
	result.action == "allow"
}

test_secret_leakage_blocks_output if {
	result := decision with input as {
		"action": "validate_tool_output",
		"output": {"secret_findings": ["credential-like-value"]},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "secret_leakage_blocks_output"
}

test_pii_leakage_requires_redaction if {
	result := decision with input as {
		"action": "validate_tool_output",
		"risk_level": "medium",
		"attributes": {"contains_pii": true},
	}

	result.allowed == false
	result.action == "rewrite"
	result.matched_rules[_] == "pii_leakage_requires_redaction"
}

test_secret_leakage_takes_precedence_over_pii_redaction if {
	result := decision with input as {
		"action": "validate_tool_output",
		"risk_level": "medium",
		"attributes": {
			"contains_pii": true,
			"contains_secret": true,
		},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "secret_leakage_blocks_output"
}

test_prompt_injection_blocks_untrusted_instruction if {
	result := decision with input as {
		"action": "verify_response",
		"risk_level": "medium",
		"attributes": {"prompt_injection_detected": true},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "prompt_injection_blocks_untrusted_instruction"
}

test_indirect_prompt_injection_blocks_document_instruction if {
	result := decision with input as {
		"action": "verify_response",
		"risk_level": "medium",
		"attributes": {"indirect_prompt_injection_detected": true},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "indirect_prompt_injection_blocks_document_instruction"
}

test_data_poisoning_blocks_evidence_use if {
	result := decision with input as {
		"action": "retrieve_evidence",
		"risk_level": "medium",
		"attributes": {"data_poisoning_detected": true},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "data_poisoning_blocks_evidence_use"
}

test_sensitive_action_requires_human_review if {
	result := decision with input as {
		"action": "send_email",
		"risk_level": "low",
	}

	result.allowed == false
	result.action == "require_human_review"
	result.matched_rules[_] == "sensitive_action_requires_human_review"
}

test_tool_output_contradiction_low_risk_requires_repair if {
	result := decision with input as {
		"action": "validate_tool_output",
		"risk_level": "medium",
		"attributes": {"contradiction_detected": true},
	}

	result.allowed == false
	result.action == "rewrite"
	result.matched_rules[_] == "tool_output_contradiction_requires_repair"
}

test_tool_output_contradiction_high_risk_blocks if {
	result := decision with input as {
		"action": "validate_tool_output",
		"risk_level": "high",
		"attributes": {"contradicted": true},
	}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "tool_output_contradiction_requires_repair"
}

test_sandbox_network_policy_deny_by_default if {
	result := decision with input as {"action": "run_repo_checks"}

	result.allowed == true
	result.network_policy == "deny"
	result.matched_rules[_] == "sandbox_network_policy_deny_by_default"
}

test_sandbox_allowlisted_network_requires_approval if {
	result := decision with input as {
		"action": "run_repo_checks",
		"network_policy": "allowlisted",
	}

	result.allowed == false
	result.action == "require_human_review"
	result.matched_rules[_] == "sandbox_network_allowlist_requires_approval"
}

test_repo_test_build_claim_requires_deterministic_evidence if {
	result := decision with input as {"action": "verify_test_claim"}

	result.allowed == false
	result.action == "block"
	result.matched_rules[_] == "repo_claim_requires_deterministic_evidence"
}

test_repo_claim_with_deterministic_command_evidence_is_allowed if {
	result := decision with input as {
		"action": "verify_repo_claim",
		"evidence": [{
			"kind": "command_output",
			"structured_content": {"metadata_schema": "sandbox_command.v1"},
		}],
	}

	result.allowed == true
	result.action == "allow"
}
