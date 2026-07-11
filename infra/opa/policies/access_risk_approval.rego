package hallucination_defense.policy

import rego.v1

policy_version := "opa-access-risk-approval-v1"

default allow := false

decision := {
	"allowed": allow,
	"action": decision_action,
	"policy_version": policy_version,
	"matched_rules": [rule | matched_rules[rule]],
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

network_policy := "allowlisted" if {
	input.network_policy == "allowlisted"
} else := "allowlisted" if {
	input.attributes.network_policy == "allowlisted"
} else := "deny"

blocking_rules contains "cross_tenant_access_denied" if {
	cross_tenant_access_denied
}

blocking_rules contains "secret_leakage_blocks_output" if {
	secret_leakage_blocks_output
}

blocking_rules contains "prompt_injection_blocks_untrusted_instruction" if {
	prompt_injection_blocks_untrusted_instruction
}

blocking_rules contains "indirect_prompt_injection_blocks_document_instruction" if {
	indirect_prompt_injection_blocks_document_instruction
}

blocking_rules contains "data_poisoning_blocks_evidence_use" if {
	data_poisoning_blocks_evidence_use
}

blocking_rules contains "repo_claim_requires_deterministic_evidence" if {
	repo_claim_requires_deterministic_evidence
}

blocking_rules contains "tool_output_contradiction_requires_repair" if {
	tool_output_contradiction_requires_repair
	high_or_critical_risk
}

rewrite_rules contains "pii_leakage_requires_redaction" if {
	pii_leakage_requires_redaction
}

rewrite_rules contains "tool_output_contradiction_requires_repair" if {
	tool_output_contradiction_requires_repair
	not high_or_critical_risk
}

approval_rules contains "high_risk_requires_approval" if {
	high_risk_requires_approval
}

approval_rules contains "sensitive_action_requires_human_review" if {
	sensitive_action_requires_human_review
}

approval_rules contains "sandbox_network_allowlist_requires_approval" if {
	sandbox_network_allowlist_requires_approval
}

info_rules contains "sandbox_network_policy_deny_by_default" if {
	sandbox_network_policy_deny_by_default
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

explanation := "Request tenant does not match the target resource tenant." if {
	cross_tenant_access_denied
} else := "Prompt injection attempts cannot override system or policy instructions." if {
	prompt_injection_blocks_untrusted_instruction
} else := "Retrieved or tool-provided content contains untrusted instructions." if {
	indirect_prompt_injection_blocks_document_instruction
} else := "Poisoned or tampered evidence cannot be used for verification." if {
	data_poisoning_blocks_evidence_use
} else := "Tool or model output contains secret-like material and must be blocked." if {
	secret_leakage_blocks_output
} else := "Repository, test, and build claims require SandboxRun or deterministic command evidence." if {
	repo_claim_requires_deterministic_evidence
} else := "PII-like output requires redaction before release." if {
	pii_leakage_requires_redaction
} else := "Tool output contradicts available evidence and requires repair or block." if {
	tool_output_contradiction_requires_repair
} else := "High-risk actions require explicit approval before execution." if {
	high_risk_requires_approval
} else := "Sensitive actions require human review before execution." if {
	sensitive_action_requires_human_review
} else := "Sandbox network access is denied by default and allowlisted access requires approval." if {
	sandbox_network_allowlist_requires_approval
} else := "Sandbox network policy defaults to deny." if {
	sandbox_network_policy_deny_by_default
} else := "No blocking enterprise policy matched."

cross_tenant_access_denied if {
	subject_tenant := input.subject.tenant_id
	resource_tenant := input.resource.tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied if {
	subject_tenant := input.tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied if {
	subject_tenant := input.attributes.request_tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied if {
	subject_tenant := input.attributes.tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

high_risk_requires_approval if {
	high_risk_action
	not approval_granted
}

high_risk_action if {
	input.risk_level == "high"
}

high_risk_action if {
	input.risk_level == "critical"
}

high_risk_action if {
	input.action.risk_level == "high"
}

high_risk_action if {
	input.action.risk_level == "critical"
}

high_risk_action if {
	input.action.risk == "high"
}

high_risk_action if {
	input.action.risk == "critical"
}

high_risk_action if {
	input.attributes.risk_level == "high"
}

high_risk_action if {
	input.attributes.risk_level == "critical"
}

high_or_critical_risk if {
	input.risk_level == "high"
}

high_or_critical_risk if {
	input.risk_level == "critical"
}

high_or_critical_risk if {
	input.action.risk_level == "high"
}

high_or_critical_risk if {
	input.action.risk_level == "critical"
}

high_or_critical_risk if {
	input.action.risk == "high"
}

high_or_critical_risk if {
	input.action.risk == "critical"
}

high_or_critical_risk if {
	input.attributes.risk_level == "high"
}

high_or_critical_risk if {
	input.attributes.risk_level == "critical"
}

approval_granted if {
	input.approval.status == "approved"
}

approval_granted if {
	input.action.approval.status == "approved"
}

approval_granted if {
	input.attributes.approval_status == "approved"
}

approval_granted if {
	input.attributes.approved == true
}

secret_leakage_blocks_output if {
	input.attributes.contains_secret == true
}

secret_leakage_blocks_output if {
	input.attributes.secret_detected == true
}

secret_leakage_blocks_output if {
	input.attributes.secret_leakage == true
}

secret_leakage_blocks_output if {
	input.output.contains_secret == true
}

secret_leakage_blocks_output if {
	findings := input.output.secret_findings
	count(findings) > 0
}

prompt_injection_blocks_untrusted_instruction if {
	truthy(input.attributes.prompt_injection_detected)
}

prompt_injection_blocks_untrusted_instruction if {
	truthy(input.attributes.prompt_injection)
}

prompt_injection_blocks_untrusted_instruction if {
	truthy(input.input.prompt_injection_detected)
}

prompt_injection_blocks_untrusted_instruction if {
	truthy(input.output.prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction if {
	truthy(input.attributes.indirect_prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction if {
	truthy(input.attributes.indirect_prompt_injection)
}

indirect_prompt_injection_blocks_document_instruction if {
	truthy(input.input.indirect_prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction if {
	truthy(input.output.indirect_prompt_injection_detected)
}

data_poisoning_blocks_evidence_use if {
	truthy(input.attributes.data_poisoning_detected)
}

data_poisoning_blocks_evidence_use if {
	truthy(input.attributes.poisoned_evidence)
}

data_poisoning_blocks_evidence_use if {
	truthy(input.input.data_poisoning_detected)
}

data_poisoning_blocks_evidence_use if {
	truthy(input.output.data_poisoning_detected)
}

pii_leakage_requires_redaction if {
	truthy(input.attributes.contains_pii)
}

pii_leakage_requires_redaction if {
	truthy(input.attributes.pii_detected)
}

pii_leakage_requires_redaction if {
	truthy(input.output.contains_pii)
}

pii_leakage_requires_redaction if {
	truthy(input.output.pii_detected)
}

pii_leakage_requires_redaction if {
	findings := input.output.pii_findings
	count(findings) > 0
}

sensitive_action_requires_human_review if {
	sensitive_action
	not approval_granted
}

sensitive_action if {
	input.action == "delete"
}

sensitive_action if {
	input.action == "deploy"
}

sensitive_action if {
	input.action == "send_email"
}

sensitive_action if {
	input.action == "transfer"
}

sensitive_action if {
	input.action == "charge"
}

sensitive_action if {
	input.action == "write_file"
}

sensitive_action if {
	input.action.name == "delete"
}

sensitive_action if {
	input.action.name == "deploy"
}

sensitive_action if {
	input.action.name == "send_email"
}

sensitive_action if {
	input.action.name == "transfer"
}

sensitive_action if {
	input.action.name == "charge"
}

sensitive_action if {
	input.action.name == "write_file"
}

sensitive_action if {
	input.attributes.action == "delete"
}

sensitive_action if {
	input.attributes.action == "deploy"
}

sensitive_action if {
	input.attributes.action == "send_email"
}

sensitive_action if {
	input.attributes.action == "transfer"
}

sensitive_action if {
	input.attributes.action == "charge"
}

sensitive_action if {
	input.attributes.action == "write_file"
}

tool_output_contradiction_requires_repair if {
	tool_output_action
	contradiction_detected
}

tool_output_action if {
	input.action == "tool_output"
}

tool_output_action if {
	input.action == "validate_output"
}

tool_output_action if {
	input.action == "validate_tool_output"
}

tool_output_action if {
	input.action.name == "tool_output"
}

tool_output_action if {
	input.action.name == "validate_output"
}

tool_output_action if {
	input.action.name == "validate_tool_output"
}

contradiction_detected if {
	truthy(input.attributes.contradicted)
}

contradiction_detected if {
	truthy(input.attributes.contradiction_detected)
}

contradiction_detected if {
	truthy(input.output.contradicted)
}

contradiction_detected if {
	truthy(input.output.contradiction_detected)
}

contradiction_detected if {
	input.output.verdict == "CONTRADICTED"
}

truthy(value) if {
	value == true
}

truthy(value) if {
	value == "true"
}

truthy(value) if {
	value == "1"
}

truthy(value) if {
	value == "yes"
}

sandbox_network_policy_deny_by_default if {
	sandbox_action
	not input.network_policy
	not input.attributes.network_policy
}

sandbox_network_policy_deny_by_default if {
	sandbox_action
	input.network_policy == "deny"
}

sandbox_network_policy_deny_by_default if {
	sandbox_action
	input.attributes.network_policy == "deny"
}

sandbox_network_allowlist_requires_approval if {
	sandbox_action
	network_policy == "allowlisted"
	not approval_granted
}

sandbox_action if {
	input.action == "run_repo_checks"
}

sandbox_action if {
	input.action == "sandbox.run"
}

sandbox_action if {
	input.action == "sandbox_run"
}

sandbox_action if {
	input.resource == "sandbox"
}

repo_claim_requires_deterministic_evidence if {
	repo_test_build_claim_requires_deterministic_evidence
}

repo_test_build_claim_requires_deterministic_evidence if {
	repo_test_build_claim
	not deterministic_evidence_present
}

repo_test_build_claim if {
	input.action == "verify_repo_claim"
}

repo_test_build_claim if {
	input.action == "verify_test_claim"
}

repo_test_build_claim if {
	input.action == "verify_build_claim"
}

repo_test_build_claim if {
	input.attributes.claim_surface == "repo"
}

repo_test_build_claim if {
	input.attributes.claim_surface == "test"
}

repo_test_build_claim if {
	input.attributes.claim_surface == "build"
}

repo_test_build_claim if {
	input.claim.type == "repo_state"
}

repo_test_build_claim if {
	input.claim.type == "test_result"
}

deterministic_evidence_present if {
	input.attributes.has_sandbox_run == true
}

deterministic_evidence_present if {
	input.attributes.has_deterministic_evidence == true
}

deterministic_evidence_present if {
	input.attributes.deterministic_evidence == true
}

deterministic_evidence_present if {
	evidence := input.evidence[_]
	deterministic_evidence(evidence)
}

deterministic_evidence(evidence) if {
	evidence.deterministic == true
}

deterministic_evidence(evidence) if {
	evidence.kind == "command_output"
	evidence.structured_content.metadata_schema == "sandbox_command.v1"
}

deterministic_evidence(evidence) if {
	evidence.kind == "command_output"
	evidence.structured_content.metadata_schema == "sandbox_inspection.v1"
}

deterministic_evidence(evidence) if {
	evidence.kind == "sandbox_run"
}
