package hallucination_defense.policy

policy_version = "opa-access-risk-approval-v1"

default allow = false

decision = {
	"allowed": allow,
	"action": decision_action,
	"policy_version": policy_version,
	"matched_rules": [rule | matched_rules[rule]],
	"network_policy": network_policy,
	"explanation": explanation,
}

allow {
	count(blocking_rules) == 0
	count(approval_rules) == 0
	count(rewrite_rules) == 0
}

decision_action = "block" {
	count(blocking_rules) > 0
} else = "rewrite" {
	count(blocking_rules) == 0
	count(rewrite_rules) > 0
} else = "require_human_review" {
	count(blocking_rules) == 0
	count(rewrite_rules) == 0
	count(approval_rules) > 0
} else = "allow" {
	true
}

network_policy = "allowlisted" {
	input.network_policy == "allowlisted"
} else = "allowlisted" {
	input.attributes.network_policy == "allowlisted"
} else = "deny" {
	true
}

blocking_rules["cross_tenant_access_denied"] {
	cross_tenant_access_denied
}

blocking_rules["secret_leakage_blocks_output"] {
	secret_leakage_blocks_output
}

blocking_rules["prompt_injection_blocks_untrusted_instruction"] {
	prompt_injection_blocks_untrusted_instruction
}

blocking_rules["indirect_prompt_injection_blocks_document_instruction"] {
	indirect_prompt_injection_blocks_document_instruction
}

blocking_rules["data_poisoning_blocks_evidence_use"] {
	data_poisoning_blocks_evidence_use
}

blocking_rules["repo_claim_requires_deterministic_evidence"] {
	repo_claim_requires_deterministic_evidence
}

blocking_rules["tool_output_contradiction_requires_repair"] {
	tool_output_contradiction_requires_repair
	high_or_critical_risk
}

rewrite_rules["pii_leakage_requires_redaction"] {
	pii_leakage_requires_redaction
}

rewrite_rules["tool_output_contradiction_requires_repair"] {
	tool_output_contradiction_requires_repair
	not high_or_critical_risk
}

approval_rules["high_risk_requires_approval"] {
	high_risk_requires_approval
}

approval_rules["sensitive_action_requires_human_review"] {
	sensitive_action_requires_human_review
}

approval_rules["sandbox_network_allowlist_requires_approval"] {
	sandbox_network_allowlist_requires_approval
}

info_rules["sandbox_network_policy_deny_by_default"] {
	sandbox_network_policy_deny_by_default
}

matched_rules[rule] {
	blocking_rules[rule]
}

matched_rules[rule] {
	rewrite_rules[rule]
}

matched_rules[rule] {
	approval_rules[rule]
}

matched_rules[rule] {
	info_rules[rule]
}

explanation = "Request tenant does not match the target resource tenant." {
	cross_tenant_access_denied
} else = "Prompt injection attempts cannot override system or policy instructions." {
	prompt_injection_blocks_untrusted_instruction
} else = "Retrieved or tool-provided content contains untrusted instructions." {
	indirect_prompt_injection_blocks_document_instruction
} else = "Poisoned or tampered evidence cannot be used for verification." {
	data_poisoning_blocks_evidence_use
} else = "Tool or model output contains secret-like material and must be blocked." {
	secret_leakage_blocks_output
} else = "Repository, test, and build claims require SandboxRun or deterministic command evidence." {
	repo_claim_requires_deterministic_evidence
} else = "PII-like output requires redaction before release." {
	pii_leakage_requires_redaction
} else = "Tool output contradicts available evidence and requires repair or block." {
	tool_output_contradiction_requires_repair
} else = "High-risk actions require explicit approval before execution." {
	high_risk_requires_approval
} else = "Sensitive actions require human review before execution." {
	sensitive_action_requires_human_review
} else = "Sandbox network access is denied by default and allowlisted access requires approval." {
	sandbox_network_allowlist_requires_approval
} else = "Sandbox network policy defaults to deny." {
	sandbox_network_policy_deny_by_default
} else = "No blocking enterprise policy matched." {
	true
}

cross_tenant_access_denied {
	subject_tenant := input.subject.tenant_id
	resource_tenant := input.resource.tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied {
	subject_tenant := input.tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied {
	subject_tenant := input.attributes.request_tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

cross_tenant_access_denied {
	subject_tenant := input.attributes.tenant_id
	resource_tenant := input.attributes.resource_tenant_id
	subject_tenant != resource_tenant
}

high_risk_requires_approval {
	high_risk_action
	not approval_granted
}

high_risk_action {
	input.risk_level == "high"
}

high_risk_action {
	input.risk_level == "critical"
}

high_risk_action {
	input.action.risk_level == "high"
}

high_risk_action {
	input.action.risk_level == "critical"
}

high_risk_action {
	input.action.risk == "high"
}

high_risk_action {
	input.action.risk == "critical"
}

high_risk_action {
	input.attributes.risk_level == "high"
}

high_risk_action {
	input.attributes.risk_level == "critical"
}

high_or_critical_risk {
	input.risk_level == "high"
}

high_or_critical_risk {
	input.risk_level == "critical"
}

high_or_critical_risk {
	input.action.risk_level == "high"
}

high_or_critical_risk {
	input.action.risk_level == "critical"
}

high_or_critical_risk {
	input.action.risk == "high"
}

high_or_critical_risk {
	input.action.risk == "critical"
}

high_or_critical_risk {
	input.attributes.risk_level == "high"
}

high_or_critical_risk {
	input.attributes.risk_level == "critical"
}

approval_granted {
	input.approval.status == "approved"
}

approval_granted {
	input.action.approval.status == "approved"
}

approval_granted {
	input.attributes.approval_status == "approved"
}

approval_granted {
	input.attributes.approved == true
}

secret_leakage_blocks_output {
	input.attributes.contains_secret == true
}

secret_leakage_blocks_output {
	input.attributes.secret_detected == true
}

secret_leakage_blocks_output {
	input.attributes.secret_leakage == true
}

secret_leakage_blocks_output {
	input.output.contains_secret == true
}

secret_leakage_blocks_output {
	findings := input.output.secret_findings
	count(findings) > 0
}

prompt_injection_blocks_untrusted_instruction {
	truthy(input.attributes.prompt_injection_detected)
}

prompt_injection_blocks_untrusted_instruction {
	truthy(input.attributes.prompt_injection)
}

prompt_injection_blocks_untrusted_instruction {
	truthy(input.input.prompt_injection_detected)
}

prompt_injection_blocks_untrusted_instruction {
	truthy(input.output.prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction {
	truthy(input.attributes.indirect_prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction {
	truthy(input.attributes.indirect_prompt_injection)
}

indirect_prompt_injection_blocks_document_instruction {
	truthy(input.input.indirect_prompt_injection_detected)
}

indirect_prompt_injection_blocks_document_instruction {
	truthy(input.output.indirect_prompt_injection_detected)
}

data_poisoning_blocks_evidence_use {
	truthy(input.attributes.data_poisoning_detected)
}

data_poisoning_blocks_evidence_use {
	truthy(input.attributes.poisoned_evidence)
}

data_poisoning_blocks_evidence_use {
	truthy(input.input.data_poisoning_detected)
}

data_poisoning_blocks_evidence_use {
	truthy(input.output.data_poisoning_detected)
}

pii_leakage_requires_redaction {
	truthy(input.attributes.contains_pii)
}

pii_leakage_requires_redaction {
	truthy(input.attributes.pii_detected)
}

pii_leakage_requires_redaction {
	truthy(input.output.contains_pii)
}

pii_leakage_requires_redaction {
	truthy(input.output.pii_detected)
}

pii_leakage_requires_redaction {
	findings := input.output.pii_findings
	count(findings) > 0
}

sensitive_action_requires_human_review {
	sensitive_action
	not approval_granted
}

sensitive_action {
	input.action == "delete"
}

sensitive_action {
	input.action == "deploy"
}

sensitive_action {
	input.action == "send_email"
}

sensitive_action {
	input.action == "transfer"
}

sensitive_action {
	input.action == "charge"
}

sensitive_action {
	input.action == "write_file"
}

sensitive_action {
	input.action.name == "delete"
}

sensitive_action {
	input.action.name == "deploy"
}

sensitive_action {
	input.action.name == "send_email"
}

sensitive_action {
	input.action.name == "transfer"
}

sensitive_action {
	input.action.name == "charge"
}

sensitive_action {
	input.action.name == "write_file"
}

sensitive_action {
	input.attributes.action == "delete"
}

sensitive_action {
	input.attributes.action == "deploy"
}

sensitive_action {
	input.attributes.action == "send_email"
}

sensitive_action {
	input.attributes.action == "transfer"
}

sensitive_action {
	input.attributes.action == "charge"
}

sensitive_action {
	input.attributes.action == "write_file"
}

tool_output_contradiction_requires_repair {
	tool_output_action
	contradiction_detected
}

tool_output_action {
	input.action == "tool_output"
}

tool_output_action {
	input.action == "validate_output"
}

tool_output_action {
	input.action == "validate_tool_output"
}

tool_output_action {
	input.action.name == "tool_output"
}

tool_output_action {
	input.action.name == "validate_output"
}

tool_output_action {
	input.action.name == "validate_tool_output"
}

contradiction_detected {
	truthy(input.attributes.contradicted)
}

contradiction_detected {
	truthy(input.attributes.contradiction_detected)
}

contradiction_detected {
	truthy(input.output.contradicted)
}

contradiction_detected {
	truthy(input.output.contradiction_detected)
}

contradiction_detected {
	input.output.verdict == "CONTRADICTED"
}

truthy(value) {
	value == true
}

truthy(value) {
	value == "true"
}

truthy(value) {
	value == "1"
}

truthy(value) {
	value == "yes"
}

sandbox_network_policy_deny_by_default {
	sandbox_action
	not input.network_policy
	not input.attributes.network_policy
}

sandbox_network_policy_deny_by_default {
	sandbox_action
	input.network_policy == "deny"
}

sandbox_network_policy_deny_by_default {
	sandbox_action
	input.attributes.network_policy == "deny"
}

sandbox_network_allowlist_requires_approval {
	sandbox_action
	network_policy == "allowlisted"
	not approval_granted
}

sandbox_action {
	input.action == "run_repo_checks"
}

sandbox_action {
	input.action == "sandbox.run"
}

sandbox_action {
	input.action == "sandbox_run"
}

sandbox_action {
	input.resource == "sandbox"
}

repo_claim_requires_deterministic_evidence {
	repo_test_build_claim_requires_deterministic_evidence
}

repo_test_build_claim_requires_deterministic_evidence {
	repo_test_build_claim
	not deterministic_evidence_present
}

repo_test_build_claim {
	input.action == "verify_repo_claim"
}

repo_test_build_claim {
	input.action == "verify_test_claim"
}

repo_test_build_claim {
	input.action == "verify_build_claim"
}

repo_test_build_claim {
	input.attributes.claim_surface == "repo"
}

repo_test_build_claim {
	input.attributes.claim_surface == "test"
}

repo_test_build_claim {
	input.attributes.claim_surface == "build"
}

repo_test_build_claim {
	input.claim.type == "repo_state"
}

repo_test_build_claim {
	input.claim.type == "test_result"
}

deterministic_evidence_present {
	input.attributes.has_sandbox_run == true
}

deterministic_evidence_present {
	input.attributes.has_deterministic_evidence == true
}

deterministic_evidence_present {
	input.attributes.deterministic_evidence == true
}

deterministic_evidence_present {
	evidence := input.evidence[_]
	deterministic_evidence(evidence)
}

deterministic_evidence(evidence) {
	evidence.deterministic == true
}

deterministic_evidence(evidence) {
	evidence.kind == "command_output"
	evidence.structured_content.metadata_schema == "sandbox_command.v1"
}

deterministic_evidence(evidence) {
	evidence.kind == "command_output"
	evidence.structured_content.metadata_schema == "sandbox_inspection.v1"
}

deterministic_evidence(evidence) {
	evidence.kind == "sandbox_run"
}
