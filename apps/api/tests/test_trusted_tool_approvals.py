from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    ApprovalDecision,
    ApprovalDecisionRequest,
    ApprovalListRequest,
    ApprovalStatus,
    RiskLevel,
    ToolCallEnvelope,
)
from hallu_defense.services.approvals import (
    APPROVAL_BINDING_STORAGE_KEY,
    TOOL_CALL_COMMITMENT_STORAGE_KEY,
    ApprovalAuthorizationIssuer,
    ApprovalExecutionGrantConsumedError,
    ApprovalExecutionGrantError,
    ApprovalNotFoundError,
    ApprovalPayloadSanitizationError,
    ApprovalQueue,
    ApprovalQueueStorageError,
    create_approval_queue,
)
from hallu_defense.services.content_security import (
    REDACTED_ADDRESS,
    REDACTED_CARD,
    REDACTED_DOB,
    REDACTED_KEY,
    REDACTED_PASSPORT,
    REDACTED_PHONE,
    REDACTED_SECRET,
    REDACTED_SSN,
    RedactionLimits,
    SensitiveDataRedactor,
    ContentSecurityScanner,
)
from hallu_defense.services.policy import PolicyEngine
from hallu_defense.services.tool_definitions import (
    InvalidToolDefinitionError,
    ToolDefinitionMismatchError,
    TrustedToolDefinition,
    TrustedToolRegistry,
    UnknownToolDefinitionError,
    canonical_json_dumps,
    get_trusted_tool_binding,
)
from hallu_defense.services.tool_safety import ToolSafetyService

INPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {"target": {"type": "string", "minLength": 1}},
    "required": ["target"],
    "additionalProperties": False,
}
OUTPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["deleted"]}},
    "required": ["status"],
    "additionalProperties": False,
}


def _registry(*, version: str = "1.0.0") -> TrustedToolRegistry:
    return TrustedToolRegistry(
        (
            TrustedToolDefinition(
                name="records.purge",
                version=version,
                policy_action="delete",
                input_schema=INPUT_SCHEMA,
                output_schema=OUTPUT_SCHEMA,
                risk_level=RiskLevel.CRITICAL,
                approval_required=True,
                side_effects=("records_delete",),
            ),
        )
    )


def _sensitive_registry() -> TrustedToolRegistry:
    sensitive_input: dict[str, object] = {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "private_key": {"type": "string"},
            "ssn": {"type": "integer"},
            "phone": {"type": "integer"},
            "card": {"type": "string"},
            "passport": {"type": "string"},
            "dob": {"type": "string"},
            "address": {"type": "string"},
        },
        "required": ["target"],
        "additionalProperties": False,
    }
    return TrustedToolRegistry(
        (
            TrustedToolDefinition(
                name="records.purge",
                version="sensitive-test-v1",
                policy_action="delete",
                input_schema=sensitive_input,
                output_schema=OUTPUT_SCHEMA,
                risk_level=RiskLevel.CRITICAL,
                approval_required=True,
                side_effects=("records_delete",),
            ),
        )
    )


def _call(
    *,
    target: str = "record-7",
    schema: dict[str, object] | None = None,
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    approval_required: bool = True,
    caller_context: dict[str, object] | None = None,
    approval_id: str | None = None,
    execution_token: str | None = None,
) -> ToolCallEnvelope:
    return ToolCallEnvelope(
        tool_name="records.purge",
        input={"target": target},
        tool_schema=schema if schema is not None else INPUT_SCHEMA,
        risk_level=risk_level,
        approval_required=approval_required,
        caller_context=caller_context
        if caller_context is not None
        else {"tenant_id": "tenant-a", "subject": "subject-a"},
        approval_id=approval_id,
        approval_execution_token=execution_token,
    )


def _approve(queue: ApprovalQueue) -> tuple[str, str]:
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_binding",
        tool_call=_call(),
        reason="Destructive record purge.",
        requested_by="subject-a",
    )
    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer-a",
        ),
    )
    assert result.execution_grant is not None
    return approval.approval_id, result.execution_grant.execution_token


def test_registry_derives_distinct_phase_schemas_and_private_metadata() -> None:
    registry = _registry()
    input_envelope = registry.bind(_call(), phase="input")
    output_envelope = registry.bind(
        ToolCallEnvelope(
            tool_name=" RECORDS.PURGE ",
            input={"status": "deleted"},
            tool_schema=OUTPUT_SCHEMA,
            risk_level=RiskLevel.CRITICAL,
            approval_required=True,
            caller_context={
                "expected_definition_version": "1.0.0",
                "policy_action": "delete",
                "side_effects": ["records_delete"],
            },
        ),
        phase="output",
    )

    assert input_envelope.tool_schema == INPUT_SCHEMA
    assert output_envelope.tool_schema == OUTPUT_SCHEMA
    assert input_envelope.tool_schema != output_envelope.tool_schema
    assert output_envelope.tool_name == "records.purge"
    # A high-risk post-tool envelope retains canonical metadata; consumers use
    # phase, not a caller-supplied false value, to avoid a second approval.
    assert output_envelope.approval_required is True
    binding = get_trusted_tool_binding(output_envelope)
    assert binding.policy_action == "delete"
    assert binding.side_effects == ("records_delete",)
    assert "_trusted_definition" not in output_envelope.model_dump(mode="json")


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"tool_schema": {"type": "object"}}, "schema"),
        ({"risk_level": RiskLevel.LOW}, "risk_level"),
        ({"approval_required": False}, "approval_required"),
        (
            {"caller_context": {"expected_definition_version": "0.9.0"}},
            "definition_version",
        ),
        ({"caller_context": {"policy_action": "read"}}, "policy_action"),
        ({"caller_context": {"side_effects": []}}, "side_effects"),
        ({"caller_context": {"ＡＰＰＲＯＶＡＬ＿ＳＴＡＴＵＳ": "approved"}}, "approval_status"),
    ],
)
def test_registry_rejects_public_metadata_spoofing(
    changes: dict[str, object],
    field: str,
) -> None:
    envelope = _call().model_copy(update=changes)

    with pytest.raises(ToolDefinitionMismatchError, match=field):
        _registry().bind(envelope)


def test_registry_fails_closed_for_unknown_and_deceptive_unicode_names() -> None:
    registry = _registry()
    for tool_name in ("custom.operation", "purge_all", "records.\u0440urge", "records.\u200dpurge"):
        with pytest.raises(UnknownToolDefinitionError):
            registry.resolve(tool_name)


def test_registry_definition_is_deeply_immutable_and_content_addressed() -> None:
    registry = _registry()
    definition = registry.resolve("records.purge")
    original_digest = definition.digest
    schema_copy = definition.input_schema
    schema_copy["properties"] = {}

    assert definition.input_schema == INPUT_SCHEMA
    assert definition.digest == original_digest
    assert _registry().resolve("records.purge").digest == original_digest
    assert _registry(version="2.0.0").resolve("records.purge").digest != original_digest
    with pytest.raises(AttributeError, match="immutable"):
        setattr(registry, "_definitions", {})


@pytest.mark.parametrize(
    ("tool_name", "required_input"),
    [
        ("delete_repository", "repo"),
        ("deploy_release", "release"),
        ("deploy_service", "service"),
        ("fetch_config", "key"),
        ("fetch_record", "id"),
        ("lookup", "query"),
        ("lookup_customer", "customer_id"),
        ("customer_lookup", "customer_id"),
        ("lookup_policy", "query"),
        ("summarize", "text"),
        ("summarize_build", "build_id"),
    ],
)
def test_default_registry_schemas_are_closed_and_meaningful(
    tool_name: str,
    required_input: str,
) -> None:
    definition = TrustedToolRegistry.default().resolve(tool_name)

    assert definition.input_schema["additionalProperties"] is False
    assert required_input in definition.input_schema["required"]
    assert definition.output_schema["additionalProperties"] is False
    assert definition.output_schema != definition.input_schema


def test_registry_rejects_unsafe_schema_and_non_json_values() -> None:
    with pytest.raises(InvalidToolDefinitionError, match="schema"):
        TrustedToolDefinition(
            name="records.purge",
            version="1.0.0",
            policy_action="delete",
            input_schema={"$ref": "https://attacker.invalid/schema.json"},
            risk_level=RiskLevel.CRITICAL,
            approval_required=True,
        )

    cyclic: dict[str, object] = {}
    cyclic["cycle"] = cyclic
    with pytest.raises(ToolDefinitionMismatchError):
        # The public envelope cannot install a private binding even if it was
        # constructed in-process; malformed metadata fails before comparison.
        _registry().bind(_call(schema=cyclic))


def test_public_model_cannot_deserialize_private_trusted_binding() -> None:
    payload = _call().model_dump(mode="json", by_alias=True)
    payload["_trusted_definition"] = {"definition_version": "attacker"}

    with pytest.raises(ValidationError):
        ToolCallEnvelope.model_validate(payload)


@pytest.mark.parametrize(
    "missing_field",
    ["input", "schema", "risk_level", "approval_required", "caller_context"],
)
def test_public_tool_call_metadata_is_explicitly_required(missing_field: str) -> None:
    payload = _call().model_dump(mode="json", by_alias=True)
    del payload[missing_field]

    with pytest.raises(ValidationError):
        ToolCallEnvelope.model_validate(payload)


def test_approval_binding_rejects_args_schema_tenant_subject_and_replay(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        commitment_key=b"k" * 32,
    )
    approval_id, token = _approve(queue)

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        queue.consume_execution_grant(
            "tenant-a",
            _call(target="record-8", approval_id=approval_id, execution_token=token),
            subject_id="subject-a",
        )
    with pytest.raises(ApprovalExecutionGrantError, match="trusted tool definition"):
        queue.consume_execution_grant(
            "tenant-a",
            _call(
                schema={"type": "object"},
                approval_id=approval_id,
                execution_token=token,
            ),
            subject_id="subject-a",
        )
    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        queue.consume_execution_grant(
            "tenant-a",
            _call(approval_id=approval_id, execution_token=token),
            subject_id="subject-b",
        )
    with pytest.raises(ApprovalNotFoundError):
        queue.consume_execution_grant(
            "tenant-b",
            _call(
                caller_context={"tenant_id": "tenant-b", "subject": "subject-a"},
                approval_id=approval_id,
                execution_token=token,
            ),
            subject_id="subject-a",
        )

    consumed = queue.consume_execution_grant(
        "tenant-a",
        _call(approval_id=approval_id, execution_token=token),
        subject_id="subject-a",
    )
    assert consumed.approval_id == approval_id
    with pytest.raises(ApprovalExecutionGrantConsumedError):
        queue.consume_execution_grant(
            "tenant-a",
            _call(approval_id=approval_id, execution_token=token),
            subject_id="subject-a",
        )


def test_execution_capability_is_issuer_bound_and_single_use_in_tool_safety(
    tmp_path: Path,
) -> None:
    issuer = ApprovalAuthorizationIssuer()
    registry = _registry()
    queue = ApprovalQueue(
        tool_registry=registry,
        authorization_issuer=issuer,
        commitment_key=b"k" * 32,
    )
    approval_id, token = _approve(queue)
    envelope = _call(approval_id=approval_id, execution_token=token)
    authorization = queue.consume_execution_grant(
        "tenant-a",
        envelope,
        subject_id="subject-a",
    )
    service = ToolSafetyService(
        policy_engine=PolicyEngine(
            Settings(
                environment="test",
                policy_version="capability-test-v1",
                auth_required=False,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1_000,
            )
        ),
        content_scanner=ContentSecurityScanner(),
        tool_registry=registry,
        authorization_issuer=issuer,
    )
    rogue = ApprovalAuthorizationIssuer().issue(
        approval_id=authorization.approval_id,
        binding=authorization.binding,
    )

    forged = service.validate_input(
        envelope,
        tenant_id="tenant-a",
        approval_authorization=rogue,
    )
    allowed = service.validate_input(
        envelope,
        tenant_id="tenant-a",
        approval_authorization=authorization,
    )
    replayed = service.validate_input(
        envelope,
        tenant_id="tenant-a",
        approval_authorization=authorization,
    )

    assert forged.allowed is False
    assert forged.action.value == "block"
    assert allowed.allowed is True
    assert allowed.action.value == "allow"
    assert replayed.allowed is False
    assert replayed.action.value == "block"


def test_execution_capability_is_bound_to_runtime_environment(tmp_path: Path) -> None:
    issuer = ApprovalAuthorizationIssuer()
    registry = _registry()
    queue = ApprovalQueue(
        tool_registry=registry,
        authorization_issuer=issuer,
        commitment_key=b"k" * 32,
        commitment_environment="local",
    )
    approval_id, token = _approve(queue)
    envelope = _call(approval_id=approval_id, execution_token=token)
    authorization = queue.consume_execution_grant(
        "tenant-a",
        envelope,
        subject_id="subject-a",
    )
    production_service = ToolSafetyService(
        policy_engine=PolicyEngine(
            Settings(
                environment="test",
                policy_version="capability-environment-test-v1",
                auth_required=False,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1_000,
            )
        ),
        content_scanner=ContentSecurityScanner(),
        tool_registry=registry,
        authorization_issuer=issuer,
        environment="production",
    )

    response = production_service.validate_input(
        envelope,
        tenant_id="tenant-a",
        approval_authorization=authorization,
    )

    assert response.allowed is False
    assert response.action.value == "block"


def test_approval_binding_is_private_and_explicit_in_durable_storage(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(storage_path=queue_path, tool_registry=_registry())
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_private_binding",
        tool_call=_call(target="sensitive-target"),
        reason="Destructive action.",
        requested_by="subject-a",
    )

    public = approval.model_dump(mode="json")
    stored = json.loads(queue_path.read_text(encoding="utf-8"))
    binding = stored["payload"][APPROVAL_BINDING_STORAGE_KEY]
    assert APPROVAL_BINDING_STORAGE_KEY not in public
    assert binding["tenant_id"] == "tenant-a"
    assert binding["subject_id"] == "subject-a"
    assert binding["approval_id"] == approval.approval_id
    assert binding["origin_trace_id"] == "tr_private_binding"
    assert binding["tool_name"] == "records.purge"
    assert binding["policy_action"] == "delete"
    assert binding["arguments_hash"].startswith("sha256:")
    assert binding["definition_version"] == "1.0.0"


def test_separate_approval_records_have_distinct_commitments_and_cannot_substitute(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        commitment_key=b"k" * 32,
    )
    first = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_origin_first",
        tool_call=_call(),
        reason="First review of the same operation.",
        requested_by="subject-a",
    )
    second = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_origin_second",
        tool_call=_call(),
        reason="Second review of the same operation.",
        requested_by="subject-a",
    )

    snapshots = [
        item["payload"]
        for item in (
            json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()
        )
        if item["record_type"] == "approval_record"
    ]
    bindings = [item[APPROVAL_BINDING_STORAGE_KEY] for item in snapshots]
    commitments = [item[TOOL_CALL_COMMITMENT_STORAGE_KEY] for item in snapshots]
    assert [binding["approval_id"] for binding in bindings] == [
        first.approval_id,
        second.approval_id,
    ]
    assert [binding["origin_trace_id"] for binding in bindings] == [
        "tr_origin_first",
        "tr_origin_second",
    ]
    assert commitments[0] != commitments[1]

    first_result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=first.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer-a",
        ),
    )
    second_result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=second.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer-a",
        ),
    )
    assert first_result.execution_grant is not None
    assert second_result.execution_grant is not None

    with pytest.raises(ApprovalExecutionGrantError, match="invalid"):
        queue.consume_execution_grant(
            "tenant-a",
            _call(
                approval_id=first.approval_id,
                execution_token=second_result.execution_grant.execution_token,
            ),
            subject_id="subject-a",
        )
    with pytest.raises(ApprovalExecutionGrantError, match="invalid"):
        queue.consume_execution_grant(
            "tenant-a",
            _call(
                approval_id=second.approval_id,
                execution_token=first_result.execution_grant.execution_token,
            ),
            subject_id="subject-a",
        )

    assert queue.consume_execution_grant(
        "tenant-a",
        _call(
            approval_id=first.approval_id,
            execution_token=first_result.execution_grant.execution_token,
        ),
        subject_id="subject-a",
    ).approval_id == first.approval_id
    assert queue.consume_execution_grant(
        "tenant-a",
        _call(
            approval_id=second.approval_id,
            execution_token=second_result.execution_grant.execution_token,
        ),
        subject_id="subject-a",
    ).approval_id == second.approval_id


def test_approval_queue_factory_propagates_injected_registry(tmp_path: Path) -> None:
    registry = _registry()
    queue = create_approval_queue(
        Settings(
            environment="test",
            policy_version="test",
            auth_required=False,
            allowed_workspace=tmp_path,
            max_command_seconds=5,
            max_output_chars=1000,
            approval_queue_backend="memory",
        ),
        tool_registry=registry,
    )

    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_factory_registry",
        tool_call=_call(),
        reason="Destructive action.",
        requested_by="subject-a",
    )
    assert approval.tool_call.tool_name == "records.purge"


def test_approval_redacts_recursive_secrets_pii_reasons_and_numeric_values(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    registry = _sensitive_registry()
    schema = registry.resolve("records.purge").input_schema
    sensitive_values = {
        "private_key": "-----BEGIN " + "PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
        "ssn": 123456789,
        "phone": 14155552671,
        "card": "4111111111111111",
        "passport": "X12345678",
        "dob": "1990-01-02",
        "address": "123 Main Street",
    }
    queue = ApprovalQueue(storage_path=queue_path, tool_registry=registry)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_sensitive_approval",
        tool_call=ToolCallEnvelope(
            tool_name="records.purge",
            input={"target": "record-7", **sensitive_values},
            tool_schema=schema,
            risk_level=RiskLevel.CRITICAL,
            approval_required=True,
            caller_context={
                "tenant_id": "tenant-a",
                "subject": "subject-a",
                "nested": {"access_key": "AKIAIOSFODNN7EXAMPLE"},
            },
        ),
        reason="api_key=approval-reason-secret",
        requested_by="subject-a",
    )

    assert approval.tool_call.input["private_key"] == REDACTED_SECRET
    assert approval.tool_call.input["ssn"] == REDACTED_SSN
    assert approval.tool_call.input["phone"] == REDACTED_PHONE
    assert approval.tool_call.input["card"] == REDACTED_CARD
    assert approval.tool_call.input["passport"] == REDACTED_PASSPORT
    assert approval.tool_call.input["dob"] == REDACTED_DOB
    assert approval.tool_call.input["address"] == REDACTED_ADDRESS
    assert approval.tool_call.caller_context["nested"] == {"access_key": REDACTED_SECRET}
    assert "approval-reason-secret" not in approval.reason

    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.REJECT,
            decided_by="reviewer-a",
            reason="passport: X98765432; address: 456 Other Avenue",
        ),
    )
    assert result.approval.decision_reason is not None
    assert "X98765432" not in result.approval.decision_reason
    assert "456 Other Avenue" not in result.approval.decision_reason
    persisted = queue_path.read_text(encoding="utf-8")
    assert all(str(value) not in persisted for value in sensitive_values.values())
    assert "AKIAIOSFODNN7EXAMPLE" not in persisted
    assert "approval-reason-secret" not in persisted
    assert "X98765432" not in persisted
    assert "456 Other Avenue" not in persisted


def test_approval_never_persists_secret_material_in_mapping_keys(tmp_path: Path) -> None:
    secret_key = "sk-" + "A" * 24
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(storage_path=queue_path, tool_registry=_registry())
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_sensitive_key",
        tool_call=_call(
            caller_context={
                "tenant_id": "tenant-a",
                "subject": "subject-a",
                secret_key: "safe-value",
            }
        ),
        reason="Destructive action.",
        requested_by="subject-a",
    )

    assert approval.tool_call.caller_context[REDACTED_KEY] == "safe-value"
    assert secret_key not in approval.model_dump_json()
    assert secret_key not in queue_path.read_text(encoding="utf-8")


def test_incomplete_approval_redaction_rejects_before_persistence(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval.jsonl"
    limits = RedactionLimits(max_depth=4)
    queue = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        redactor=SensitiveDataRedactor(limits),
    )
    nested: dict[str, object] = {}
    cursor = nested
    for _ in range(8):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    envelope = _call(caller_context={"tenant_id": "tenant-a", "subject": "subject-a"})
    envelope.caller_context["nested"] = nested

    with pytest.raises(ApprovalPayloadSanitizationError, match="max_depth"):
        queue.request_approval(
            tenant_id="tenant-a",
            trace_id="tr_incomplete_redaction",
            tool_call=envelope,
            reason="Destructive action.",
            requested_by="subject-a",
        )

    assert not queue_path.exists()


def test_incomplete_decision_reason_redaction_leaves_approval_pending(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        redactor=SensitiveDataRedactor(RedactionLimits(max_string_chars=64)),
    )
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_decision_redaction",
        tool_call=_call(),
        reason="Destructive action.",
        requested_by="subject-a",
    )

    with pytest.raises(ApprovalPayloadSanitizationError, match="max_string_chars"):
        queue.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer-a",
                reason="x" * 65,
            ),
        )

    pending = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
    ).list_for_tenant("tenant-a", ApprovalListRequest(status=ApprovalStatus.PENDING))
    assert [item.approval_id for item in pending] == [approval.approval_id]


def test_tampered_review_snapshot_cannot_issue_grant(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval.jsonl"
    queue = ApprovalQueue(storage_path=queue_path, tool_registry=_registry())
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_tampered_snapshot",
        tool_call=_call(),
        reason="Destructive action.",
        requested_by="subject-a",
    )
    stored = json.loads(queue_path.read_text(encoding="utf-8"))
    stored["payload"]["tool_call"]["caller_context"]["subject"] = "attacker"
    queue_path.write_text(json.dumps(stored), encoding="utf-8")
    tampered = ApprovalQueue(storage_path=queue_path, tool_registry=_registry())

    with pytest.raises(ApprovalQueueStorageError, match="authorization binding"):
        tampered.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer-a",
            ),
        )


def test_tampered_origin_trace_cannot_consume_or_burn_execution_grant(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    original = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        commitment_key=b"k" * 32,
    )
    approval_id, token = _approve(original)
    original_text = queue_path.read_text(encoding="utf-8")
    records = [json.loads(line) for line in original_text.splitlines()]
    for record in records:
        if record["record_type"] == "approval_record":
            record["payload"][APPROVAL_BINDING_STORAGE_KEY]["origin_trace_id"] = (
                "tr_substituted"
            )
    queue_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    tampered_line_count = len(queue_path.read_text(encoding="utf-8").splitlines())
    tampered = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        commitment_key=b"k" * 32,
    )

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        tampered.consume_execution_grant(
            "tenant-a",
            _call(approval_id=approval_id, execution_token=token),
            subject_id="subject-a",
        )

    assert len(queue_path.read_text(encoding="utf-8").splitlines()) == tampered_line_count
    queue_path.write_text(original_text, encoding="utf-8")
    restored = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(),
        commitment_key=b"k" * 32,
    )
    assert restored.consume_execution_grant(
        "tenant-a",
        _call(approval_id=approval_id, execution_token=token),
        subject_id="subject-a",
    ).approval_id == approval_id


def test_definition_rotation_invalidates_pending_approval_without_deciding_it(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    original = ApprovalQueue(storage_path=queue_path, tool_registry=_registry(version="1.0.0"))
    approval = original.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_rotation",
        tool_call=_call(),
        reason="Destructive action.",
        requested_by="subject-a",
    )
    rotated = ApprovalQueue(storage_path=queue_path, tool_registry=_registry(version="2.0.0"))

    with pytest.raises(ApprovalQueueStorageError, match="stale tool definition"):
        rotated.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer-a",
            ),
        )

    pending = ApprovalQueue(
        storage_path=queue_path,
        tool_registry=_registry(version="1.0.0"),
    ).list_for_tenant("tenant-a", ApprovalListRequest(status=ApprovalStatus.PENDING))
    assert [item.approval_id for item in pending] == [approval.approval_id]


def test_definition_rotation_invalidates_issued_grant_without_consuming_it(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval.jsonl"
    original = ApprovalQueue(storage_path=queue_path, tool_registry=_registry(version="1.0.0"))
    approval_id, token = _approve(original)
    rotated = ApprovalQueue(storage_path=queue_path, tool_registry=_registry(version="2.0.0"))

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        rotated.consume_execution_grant(
            "tenant-a",
            _call(approval_id=approval_id, execution_token=token),
            subject_id="subject-a",
        )

    restored = ApprovalQueue(storage_path=queue_path, tool_registry=_registry(version="1.0.0"))
    assert (
        restored.consume_execution_grant(
            "tenant-a",
            _call(approval_id=approval_id, execution_token=token),
            subject_id="subject-a",
        ).approval_id
        == approval_id
    )


def test_canonical_json_rejects_cycles_and_non_finite_numbers() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cycles"):
        canonical_json_dumps(cyclic)
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json_dumps({"value": float("nan")})


def test_registry_rejects_cyclic_arguments_before_schema_evaluation() -> None:
    cyclic: dict[str, object] = {}
    cyclic["target"] = cyclic
    envelope = _call().model_copy(update={"input": cyclic})

    with pytest.raises(ToolDefinitionMismatchError, match="bounded canonical JSON"):
        _registry().bind(envelope)
