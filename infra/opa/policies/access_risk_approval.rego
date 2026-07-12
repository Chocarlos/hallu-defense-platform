package hallucination_defense.policy

import rego.v1

policy_version := "opa-access-risk-approval-v2"

default allow := false

verified := object.get(input, "verified", {})
identity := object.get(verified, "identity", {})
request := object.get(verified, "request", {})
resource := object.get(verified, "resource", {})
definition := object.get(verified, "definition", {})
approval := object.get(verified, "approval", {})
signals := object.get(verified, "signals", {})
sandbox := object.get(verified, "sandbox", {})
evidence := object.get(verified, "evidence", {})

request_action := object.get(request, "action", "")
risk_level := object.get(request, "risk_level", "")
network_policy := object.get(sandbox, "network_policy", false)
source_authority := object.get(signals, "source_authority", false)
claim_surface := object.get(signals, "claim_surface", false)

known_actions := {
	"charge",
	"delete",
	"deploy",
	"publish_output",
	"read",
	"retrieve_evidence",
	"run_repo_checks",
	"sandbox.run",
	"sandbox_run",
	"send_email",
	"tool_output",
	"transfer",
	"validate_output",
	"validate_tool_call",
	"validate_tool_output",
	"verify_build_claim",
	"verify_repo_claim",
	"verify_response",
	"verify_test_claim",
	"write_file",
}

sensitive_actions := {"delete", "deploy", "send_email", "transfer", "charge", "write_file"}
sandbox_actions := {"run_repo_checks", "sandbox.run", "sandbox_run"}
repo_claim_actions := {"verify_repo_claim", "verify_test_claim", "verify_build_claim"}
tool_output_actions := {"publish_output", "tool_output", "validate_output", "validate_tool_output"}
known_source_authorities := {"", "authoritative", "external", "internal", "unknown", "untrusted"}
known_claim_surfaces := {"", "repo", "test", "build", "unknown"}

decision := {
	"allowed": allow,
	"action": decision_action,
	"policy_version": policy_version,
	"matched_rules": [primary_rule],
	"network_policy": network_policy,
	"explanation": explanation,
}

allow if {
	count(blocking_rules) == 0
	count(approval_rules) == 0
	count(rewrite_rules) == 0
}

decision_action := "block" if {
	count(blocking_rules) > 0
} else := "rewrite" if {
	count(blocking_rules) == 0
	count(rewrite_rules) > 0
} else := "require_human_review" if {
	count(blocking_rules) == 0
	count(rewrite_rules) == 0
	count(approval_rules) > 0
} else := "allow"

blocking_rules contains "invalid_verified_policy_context" if {
	not valid_context_shape
}

blocking_rules contains "unknown_policy_action_blocked" if {
	valid_context_shape
	not known_policy_action
}

blocking_rules contains "unknown_tool_definition_blocked" if {
	valid_context_shape
	not trusted_definition
}

blocking_rules contains "cross_tenant_access_denied" if {
	valid_context_shape
	object.get(identity, "tenant_id", "") != object.get(resource, "tenant_id", "")
}

blocking_rules contains "prompt_injection_blocks_untrusted_instruction" if {
	object.get(signals, "prompt_injection_detected", false) == true
}

blocking_rules contains "indirect_prompt_injection_blocks_document_instruction" if {
	object.get(signals, "indirect_prompt_injection_detected", false) == true
}

blocking_rules contains "data_poisoning_blocks_evidence_use" if {
	object.get(signals, "data_poisoning_detected", false) == true
}

blocking_rules contains "secret_leakage_blocks_output" if {
	object.get(signals, "contains_secret", false) == true
}

blocking_rules contains "repo_claim_requires_deterministic_evidence" if {
	repo_test_build_claim_requires_deterministic_evidence
}

blocking_rules contains "tool_output_contradiction_requires_repair" if {
	tool_output_action
	object.get(signals, "contradiction_detected", false) == true
	high_or_critical_risk
}

blocking_rules contains "unknown_source_blocks_policy_claim" if {
	object.get(signals, "source_authority", "") == "unknown"
}

blocking_rules contains "sandbox_network_policy_invalid" if {
	sandbox_action
	network_policy != "deny"
	network_policy != "allowlisted"
}

rewrite_rules contains "pii_leakage_requires_redaction" if {
	object.get(signals, "contains_pii", false) == true
}

rewrite_rules contains "tool_output_contradiction_requires_repair" if {
	tool_output_action
	object.get(signals, "contradiction_detected", false) == true
	not high_or_critical_risk
}

high_risk_requires_approval if {
	object.get(approval, "required_for_action", true) == true
	high_or_critical_risk
	not approval_verified
}

approval_rules contains "high_risk_requires_human_review" if {
	high_risk_requires_approval
}

approval_rules contains "sensitive_action_requires_human_review" if {
	sensitive_actions[request_action]
	not approval_verified
}

approval_rules contains "sandbox_network_denied_by_default" if {
	sandbox_action
	network_policy == "allowlisted"
	not approval_verified
}

info_rules contains "sandbox_network_policy_deny_by_default" if {
	sandbox_action
	network_policy == "deny"
}

# Select one deterministic rule using the same precedence as PolicyEngine.
# Other matches cannot downgrade a block and do not produce backend-specific
# diagnostic arrays.
primary_rule := "invalid_verified_policy_context" if {
	blocking_rules["invalid_verified_policy_context"]
} else := "unknown_policy_action_blocked" if {
	blocking_rules["unknown_policy_action_blocked"]
} else := "unknown_tool_definition_blocked" if {
	blocking_rules["unknown_tool_definition_blocked"]
} else := "cross_tenant_access_denied" if {
	blocking_rules["cross_tenant_access_denied"]
} else := "prompt_injection_blocks_untrusted_instruction" if {
	blocking_rules["prompt_injection_blocks_untrusted_instruction"]
} else := "indirect_prompt_injection_blocks_document_instruction" if {
	blocking_rules["indirect_prompt_injection_blocks_document_instruction"]
} else := "data_poisoning_blocks_evidence_use" if {
	blocking_rules["data_poisoning_blocks_evidence_use"]
} else := "secret_leakage_blocks_output" if {
	blocking_rules["secret_leakage_blocks_output"]
} else := "sandbox_network_policy_invalid" if {
	blocking_rules["sandbox_network_policy_invalid"]
} else := "repo_claim_requires_deterministic_evidence" if {
	blocking_rules["repo_claim_requires_deterministic_evidence"]
} else := "tool_output_contradiction_requires_repair" if {
	blocking_rules["tool_output_contradiction_requires_repair"]
} else := "unknown_source_blocks_policy_claim" if {
	blocking_rules["unknown_source_blocks_policy_claim"]
} else := "tool_output_contradiction_requires_repair" if {
	rewrite_rules["tool_output_contradiction_requires_repair"]
} else := "pii_leakage_requires_redaction" if {
	rewrite_rules["pii_leakage_requires_redaction"]
} else := "sandbox_network_denied_by_default" if {
	approval_rules["sandbox_network_denied_by_default"]
} else := "high_risk_requires_human_review" if {
	approval_rules["high_risk_requires_human_review"]
} else := "sensitive_action_requires_human_review" if {
	approval_rules["sensitive_action_requires_human_review"]
} else := "sandbox_network_policy_deny_by_default" if {
	info_rules["sandbox_network_policy_deny_by_default"]
} else := "default_allow_registered_action" if {
	true
}

matched_rules contains rule if {
	blocking_rules[rule]
}

matched_rules contains rule if {
	rewrite_rules[rule]
}

matched_rules contains rule if {
	approval_rules[rule]
}

matched_rules contains rule if {
	info_rules[rule]
}

valid_context_shape if {
	object.get(verified, "context_version", "") == "verified-policy-context.v1"
	bounded_nonempty_string(object.get(identity, "tenant_id", false), 256)
	bounded_nonempty_string(object.get(identity, "subject_id", false), 256)
	bounded_nonempty_string(request_action, 128)
	bounded_string(object.get(request, "resource", false), 512)
	risk_level in {"low", "medium", "high", "critical"}
	bounded_nonempty_string(object.get(resource, "tenant_id", false), 256)
	is_boolean(object.get(definition, "known", ""))
	bounded_string(object.get(definition, "version", false), 128)
	is_boolean(object.get(approval, "granted", ""))
	is_boolean(object.get(approval, "binding_valid", ""))
	is_boolean(object.get(approval, "required_for_action", ""))
	bounded_string(object.get(approval, "approval_id", false), 256)
	approval_identifier_valid
	is_boolean(object.get(signals, "prompt_injection_detected", ""))
	is_boolean(object.get(signals, "indirect_prompt_injection_detected", ""))
	is_boolean(object.get(signals, "data_poisoning_detected", ""))
	is_boolean(object.get(signals, "contains_secret", ""))
	is_boolean(object.get(signals, "contains_pii", ""))
	is_boolean(object.get(signals, "contradiction_detected", ""))
	bounded_string(source_authority, 128)
	source_authority in known_source_authorities
	bounded_string(claim_surface, 32)
	claim_surface in known_claim_surfaces
	is_string(object.get(sandbox, "network_policy", false))
	network_policy in {"deny", "allowlisted", "untrusted"}
	is_boolean(object.get(evidence, "deterministic_verified", ""))
}

bounded_nonempty_string(value, max_length) if {
	is_string(value)
	value != ""
	count(value) <= max_length
	trim_space(value) == value
}

bounded_string(value, max_length) if {
	is_string(value)
	count(value) <= max_length
	trim_space(value) == value
}

approval_identifier_valid if {
	not approval_verified
}

approval_identifier_valid if {
	approval_verified
	object.get(approval, "approval_id", "") != ""
}

known_policy_action if {
	known_actions[request_action]
}

trusted_definition if {
	object.get(definition, "known", false) == true
	object.get(definition, "version", "") != ""
}

approval_verified if {
	object.get(approval, "granted", false) == true
	object.get(approval, "binding_valid", false) == true
}

high_or_critical_risk if {
	risk_level in {"high", "critical"}
}

sandbox_action if {
	sandbox_actions[request_action]
}

tool_output_action if {
	tool_output_actions[request_action]
}

repo_test_build_claim if {
	repo_claim_actions[request_action]
}

repo_test_build_claim if {
	object.get(signals, "claim_surface", "") in {"repo", "test", "build"}
}

repo_test_build_claim_requires_deterministic_evidence if {
	repo_test_build_claim
	object.get(evidence, "deterministic_verified", false) != true
}

explanation := "Verified policy context is missing or malformed." if {
	primary_rule == "invalid_verified_policy_context"
} else := "Unknown policy actions are blocked until registered server-side." if {
	primary_rule == "unknown_policy_action_blocked"
} else := "Tool definition is unknown or unversioned." if {
	primary_rule == "unknown_tool_definition_blocked"
} else := "Request tenant does not match the target resource tenant." if {
	primary_rule == "cross_tenant_access_denied"
} else := "Prompt injection attempts cannot override system or policy instructions." if {
	primary_rule == "prompt_injection_blocks_untrusted_instruction"
} else := "Retrieved or tool-provided content contains untrusted instructions." if {
	primary_rule == "indirect_prompt_injection_blocks_document_instruction"
} else := "Poisoned or tampered evidence cannot be used for verification." if {
	primary_rule == "data_poisoning_blocks_evidence_use"
} else := "Tool or model output contains secret-like material and must be blocked." if {
	primary_rule == "secret_leakage_blocks_output"
} else := "Sandbox network policy is invalid." if {
	primary_rule == "sandbox_network_policy_invalid"
} else := "Repository, test, and build claims require verified SandboxRun or command evidence." if {
	primary_rule == "repo_claim_requires_deterministic_evidence"
} else := "Tool output contradicts available evidence and requires repair or block." if {
	primary_rule == "tool_output_contradiction_requires_repair"
} else := "Unknown-authority sources cannot authorize policy claims." if {
	primary_rule == "unknown_source_blocks_policy_claim"
} else := "PII-like output requires redaction before release." if {
	primary_rule == "pii_leakage_requires_redaction"
} else := "Sandbox network access is denied by default and requires explicit review." if {
	primary_rule == "sandbox_network_denied_by_default"
} else := "High-risk actions require a bound human approval." if {
	primary_rule == "high_risk_requires_human_review"
} else := "Sensitive actions require human review before execution." if {
	primary_rule == "sensitive_action_requires_human_review"
} else := "Sandbox network policy defaults to deny." if {
	primary_rule == "sandbox_network_policy_deny_by_default"
} else := "No blocking enterprise policy matched the registered action."
