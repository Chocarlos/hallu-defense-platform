from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from hallu_defense.domain.models import RiskLevel, ToolCallEnvelope

MAX_CANONICAL_DEPTH = 32
MAX_CANONICAL_NODES = 16_384
MAX_CANONICAL_BYTES = 1_048_576
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
ACTION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
SIDE_EFFECT_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
EXTERNAL_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
RESERVED_AUTHORIZATION_CONTEXT_KEYS = frozenset(
    {
        "approval",
        "approval_granted",
        "approval_status",
        "approved",
        "claim_surface",
        "contains_pii",
        "contains_secret",
        "contradicted",
        "contradiction_detected",
        "data_poisoning_detected",
        "deterministic_evidence",
        "execution_token",
        "has_deterministic_evidence",
        "has_sandbox_run",
        "indirect_prompt_injection_detected",
        "network_policy",
        "prompt_injection_detected",
        "resource_tenant_id",
        "source_authority",
        "target_tenant_id",
    }
)


class ToolDefinitionError(ValueError):
    """Base failure for trusted tool-definition resolution."""


class UnknownToolDefinitionError(ToolDefinitionError):
    """Raised when no trusted server-side definition exists for a tool."""


class ToolDefinitionMismatchError(ToolDefinitionError):
    """Raised when public metadata disagrees with the trusted definition."""


class InvalidToolDefinitionError(ToolDefinitionError):
    """Raised when a server-provided tool definition is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class TrustedToolBinding:
    """Immutable metadata copied from a registry entry, never from JSON input."""

    tool_name: str
    definition_version: str
    definition_digest: str
    policy_action: str
    risk_level: RiskLevel
    approval_required: bool
    side_effects: tuple[str, ...]
    input_schema_json: str
    output_schema_json: str

    @property
    def input_schema(self) -> dict[str, object]:
        return _schema_from_json(self.input_schema_json)

    @property
    def output_schema(self) -> dict[str, object]:
        return _schema_from_json(self.output_schema_json)


@dataclass(frozen=True, slots=True, init=False)
class TrustedToolDefinition:
    """Deeply immutable, content-addressed server-side tool definition."""

    name: str
    version: str
    policy_action: str
    risk_level: RiskLevel
    approval_required: bool
    side_effects: tuple[str, ...]
    _input_schema_json: str
    _output_schema_json: str
    digest: str

    def __init__(
        self,
        *,
        name: str,
        version: str,
        policy_action: str,
        input_schema: Mapping[str, object],
        output_schema: Mapping[str, object] | None = None,
        risk_level: RiskLevel,
        approval_required: bool,
        side_effects: Iterable[str] = (),
    ) -> None:
        if not isinstance(version, str) or not isinstance(policy_action, str):
            raise InvalidToolDefinitionError(
                "Tool definition version and policy action must be text."
            )
        if not isinstance(risk_level, RiskLevel) or not isinstance(approval_required, bool):
            raise InvalidToolDefinitionError(
                "Tool definition risk and approval requirement are invalid."
            )
        if isinstance(side_effects, (str, bytes, bytearray)):
            raise InvalidToolDefinitionError("Tool definition side effects must be a collection.")
        canonical_name = canonicalize_tool_name(name)
        if canonical_name != name:
            raise InvalidToolDefinitionError(
                f"Trusted tool name must already be canonical: {canonical_name!r}."
            )
        if VERSION_RE.fullmatch(version) is None:
            raise InvalidToolDefinitionError("Tool definition version is invalid.")
        if ACTION_RE.fullmatch(policy_action) is None:
            raise InvalidToolDefinitionError("Tool definition policy action is invalid.")
        effects = tuple(sorted(set(side_effects)))
        if any(SIDE_EFFECT_RE.fullmatch(effect) is None for effect in effects):
            raise InvalidToolDefinitionError("Tool definition side effects are invalid.")
        input_json = _validated_schema_json(input_schema, label="input")
        output_json = _validated_schema_json(
            output_schema if output_schema is not None else input_schema,
            label="output",
        )
        digest_payload = {
            "approval_required": approval_required,
            "input_schema": json.loads(input_json),
            "name": canonical_name,
            "output_schema": json.loads(output_json),
            "policy_action": policy_action,
            "risk_level": risk_level.value,
            "side_effects": list(effects),
            "version": version,
        }
        digest = "sha256:" + hashlib.sha256(
            canonical_json_dumps(digest_payload).encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "name", canonical_name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "policy_action", policy_action)
        object.__setattr__(self, "risk_level", risk_level)
        object.__setattr__(self, "approval_required", approval_required)
        object.__setattr__(self, "side_effects", effects)
        object.__setattr__(self, "_input_schema_json", input_json)
        object.__setattr__(self, "_output_schema_json", output_json)
        object.__setattr__(self, "digest", digest)

    @property
    def input_schema(self) -> dict[str, object]:
        return _schema_from_json(self._input_schema_json)

    @property
    def output_schema(self) -> dict[str, object]:
        return _schema_from_json(self._output_schema_json)

    def binding(self) -> TrustedToolBinding:
        return TrustedToolBinding(
            tool_name=self.name,
            definition_version=self.version,
            definition_digest=self.digest,
            policy_action=self.policy_action,
            risk_level=self.risk_level,
            approval_required=self.approval_required,
            side_effects=self.side_effects,
            input_schema_json=self._input_schema_json,
            output_schema_json=self._output_schema_json,
        )


class TrustedToolRegistry:
    """Immutable lookup for definitions provisioned by the server operator."""

    __slots__ = ("_definitions",)

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("TrustedToolRegistry is immutable.")
        object.__setattr__(self, name, value)

    def __init__(self, definitions: Iterable[TrustedToolDefinition]) -> None:
        entries: dict[str, TrustedToolDefinition] = {}
        for definition in definitions:
            if not isinstance(definition, TrustedToolDefinition):
                raise InvalidToolDefinitionError(
                    "TrustedToolRegistry accepts only TrustedToolDefinition entries."
                )
            if definition.name in entries:
                raise InvalidToolDefinitionError(
                    f"Duplicate trusted tool definition: {definition.name}."
                )
            entries[definition.name] = definition
        self._definitions = MappingProxyType(entries)

    @classmethod
    def default(cls) -> TrustedToolRegistry:
        return cls(default_tool_definitions())

    def resolve(self, tool_name: str) -> TrustedToolDefinition:
        try:
            canonical_name = canonicalize_tool_name(tool_name)
        except ToolDefinitionError as exc:
            raise UnknownToolDefinitionError("Tool has no trusted server-side definition.") from exc
        definition = self._definitions.get(canonical_name)
        if definition is None:
            raise UnknownToolDefinitionError(
                f"Tool {canonical_name!r} has no trusted server-side definition."
            )
        return definition

    def bind(
        self,
        envelope: ToolCallEnvelope,
        *,
        phase: Literal["input", "output"] = "input",
    ) -> ToolCallEnvelope:
        definition = self.resolve(envelope.tool_name)
        expected_schema = (
            definition.input_schema if phase == "input" else definition.output_schema
        )
        mismatches: list[str] = []
        try:
            # Bound every caller-controlled structure before JSON Schema or
            # assertion traversal to prevent cyclic/deep payload DoS.
            canonical_json_dumps(envelope.input)
            canonical_json_dumps(envelope.caller_context)
            if canonical_json_dumps(envelope.tool_schema) != canonical_json_dumps(expected_schema):
                mismatches.append("schema")
        except ToolDefinitionError as exc:
            raise ToolDefinitionMismatchError(
                "Public tool envelope is not bounded canonical JSON."
            ) from exc
        if envelope.risk_level is not definition.risk_level:
            mismatches.append("risk_level")
        if envelope.approval_required is not definition.approval_required:
            mismatches.append("approval_required")
        self._check_context_assertions(envelope.caller_context, definition, mismatches)
        if mismatches:
            joined = ", ".join(sorted(set(mismatches)))
            raise ToolDefinitionMismatchError(
                f"Public tool metadata does not match the trusted definition: {joined}."
            )
        try:
            validation_errors = sorted(
                Draft202012Validator(expected_schema).iter_errors(envelope.input),
                key=lambda error: tuple(str(part) for part in error.absolute_path),
            )
        except Exception as exc:
            raise ToolDefinitionMismatchError(
                f"Trusted tool {phase} schema could not be evaluated safely."
            ) from exc
        if validation_errors:
            raise ToolDefinitionMismatchError(
                f"Tool {phase} payload does not satisfy the trusted definition schema."
            )
        canonical = envelope.model_copy(
            update={
                "tool_name": definition.name,
                "tool_schema": expected_schema,
                "risk_level": definition.risk_level,
                "approval_required": definition.approval_required,
            },
            deep=True,
        )
        canonical._trusted_definition = definition.binding()
        return canonical

    def verify_binding(self, envelope: ToolCallEnvelope) -> TrustedToolBinding:
        binding = get_trusted_tool_binding(envelope)
        definition = self.resolve(binding.tool_name)
        if binding != definition.binding():
            raise ToolDefinitionMismatchError(
                "Bound tool definition is stale or belongs to another registry."
            )
        if canonicalize_tool_name(envelope.tool_name) != binding.tool_name:
            raise ToolDefinitionMismatchError("Bound tool name does not match the envelope.")
        if envelope.risk_level is not binding.risk_level:
            raise ToolDefinitionMismatchError("Bound tool risk does not match the envelope.")
        if envelope.approval_required is not binding.approval_required:
            raise ToolDefinitionMismatchError(
                "Bound tool approval requirement does not match the envelope."
            )
        return binding

    def _check_context_assertions(
        self,
        context: Mapping[str, object],
        definition: TrustedToolDefinition,
        mismatches: list[str],
    ) -> None:
        for raw_key in context:
            normalized_key = re.sub(
                r"[^a-z0-9]+",
                "_",
                "".join(
                    character
                    for character in unicodedata.normalize("NFKC", str(raw_key)).casefold()
                    if unicodedata.category(character) != "Cf"
                ),
            ).strip("_")
            if normalized_key in RESERVED_AUTHORIZATION_CONTEXT_KEYS:
                mismatches.append(f"caller_context.{normalized_key}")
        expected: dict[str, object] = {
            "definition_version": definition.version,
            "expected_definition_version": definition.version,
            "definition_digest": definition.digest,
            "policy_action": definition.policy_action,
            "side_effects": list(definition.side_effects),
            "risk_level": definition.risk_level.value,
            "approval_required": definition.approval_required,
        }
        for key, expected_value in expected.items():
            if key not in context:
                continue
            actual = context[key]
            if key == "side_effects" and isinstance(actual, Sequence) and not isinstance(
                actual, (str, bytes, bytearray)
            ):
                if not all(isinstance(item, str) for item in actual):
                    mismatches.append(f"caller_context.{key}")
                    continue
                actual = sorted(set(actual))
                expected_value = sorted(definition.side_effects)
            if actual != expected_value:
                mismatches.append(f"caller_context.{key}")


def get_trusted_tool_binding(envelope: ToolCallEnvelope) -> TrustedToolBinding:
    binding = envelope._trusted_definition
    if not isinstance(binding, TrustedToolBinding):
        raise ToolDefinitionMismatchError(
            "Tool envelope has not been resolved by the trusted definition registry."
        )
    return binding


def canonicalize_tool_name(value: str) -> str:
    if not isinstance(value, str):
        raise ToolDefinitionError("Tool name must be text.")
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if any(unicodedata.category(character) == "Cf" for character in normalized):
        raise ToolDefinitionError("Tool name contains an invisible formatting character.")
    if TOOL_NAME_RE.fullmatch(normalized) is None:
        raise ToolDefinitionError("Tool name is not a safe canonical identifier.")
    return normalized


def canonical_json_dumps(value: object) -> str:
    _validate_json_value(value, depth=0, seen=set(), counter=[0, 0])
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ToolDefinitionError("Value cannot be represented as canonical JSON.") from exc
    if len(serialized.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise ToolDefinitionError("Canonical JSON exceeds the trusted metadata size limit.")
    return serialized


def default_tool_definitions() -> tuple[TrustedToolDefinition, ...]:
    strict_path = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"path": {"type": "string", "minLength": 1}},
        "required": ["path"],
        "additionalProperties": False,
    }
    file_output = {
        "type": "object",
        "properties": {"content": {"type": "string"}},
        "required": ["content"],
        "additionalProperties": False,
    }
    delete_repository_input = {
        "type": "object",
        "properties": {"repo": {"type": "string", "minLength": 1}},
        "required": ["repo"],
        "additionalProperties": False,
    }
    deploy_release_input = {
        "type": "object",
        "properties": {"release": {"type": "string", "minLength": 1}},
        "required": ["release"],
        "additionalProperties": False,
    }
    deploy_service_input = {
        "type": "object",
        "properties": {"service": {"type": "string", "minLength": 1}},
        "required": ["service"],
        "additionalProperties": False,
    }
    mutation_output = {
        "type": "object",
        "properties": {"status": {"type": "string", "minLength": 1}},
        "required": ["status"],
        "additionalProperties": False,
    }
    read_document_input = {
        "type": "object",
        "properties": {"document_id": {"type": "string", "minLength": 1}},
        "required": ["document_id"],
        "additionalProperties": False,
    }
    document_output = {
        "type": "object",
        "properties": {"content": {"type": "string"}},
        "required": ["content"],
        "additionalProperties": False,
    }
    keyed_lookup_input = {
        "type": "object",
        "properties": {"query": {"type": "string", "minLength": 1}},
        "required": ["query"],
        "additionalProperties": False,
    }
    lookup_output = {
        "type": "object",
        "properties": {"results": {"type": "array"}},
        "required": ["results"],
        "additionalProperties": False,
    }
    customer_input = {
        "type": "object",
        "properties": {"customer_id": {"type": "string", "minLength": 1}},
        "required": ["customer_id"],
        "additionalProperties": False,
    }
    customer_output = {
        "type": "object",
        "properties": {
            "customer_id": {"type": "string"},
            "email": {"type": "string"},
            "notes": {"type": "string"},
        },
        "required": ["customer_id"],
        "additionalProperties": False,
    }
    fetch_config_input = {
        "type": "object",
        "properties": {"key": {"type": "string", "minLength": 1}},
        "required": ["key"],
        "additionalProperties": False,
    }
    fetch_config_output = {
        "type": "object",
        "properties": {"value": {}},
        "required": ["value"],
        "additionalProperties": False,
    }
    fetch_record_input = {
        "type": "object",
        "properties": {"id": {"type": "string", "minLength": 1}},
        "required": ["id"],
        "additionalProperties": False,
    }
    fetch_record_output = {
        "type": "object",
        "properties": {"record": {"type": "object"}},
        "required": ["record"],
        "additionalProperties": False,
    }
    summarize_input = {
        "type": "object",
        "properties": {"text": {"type": "string", "minLength": 1}},
        "required": ["text"],
        "additionalProperties": False,
    }
    summarize_output = {
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"],
        "additionalProperties": False,
    }
    summarize_build_input = {
        "type": "object",
        "properties": {"build_id": {"type": "string", "minLength": 1}},
        "required": ["build_id"],
        "additionalProperties": False,
    }
    specs: tuple[
        tuple[
            str,
            str,
            Mapping[str, object],
            Mapping[str, object],
            RiskLevel,
            bool,
            tuple[str, ...],
        ],
        ...,
    ] = (
        ("read_file", "read", strict_path, file_output, RiskLevel.LOW, False, ()),
        (
            "delete_file",
            "delete",
            strict_path,
            mutation_output,
            RiskLevel.HIGH,
            True,
            ("filesystem_delete",),
        ),
        (
            "delete_repository",
            "delete",
            delete_repository_input,
            mutation_output,
            RiskLevel.HIGH,
            True,
            ("filesystem_delete",),
        ),
        (
            "deploy_release",
            "deploy",
            deploy_release_input,
            mutation_output,
            RiskLevel.HIGH,
            True,
            ("deployment_write",),
        ),
        (
            "deploy_service",
            "deploy",
            deploy_service_input,
            mutation_output,
            RiskLevel.HIGH,
            True,
            ("deployment_write",),
        ),
        (
            "read_document",
            "read",
            read_document_input,
            document_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        (
            "fetch_config",
            "read",
            fetch_config_input,
            fetch_config_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        (
            "fetch_record",
            "read",
            fetch_record_input,
            fetch_record_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        ("lookup", "read", keyed_lookup_input, lookup_output, RiskLevel.LOW, False, ()),
        (
            "lookup_customer",
            "read",
            customer_input,
            customer_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        (
            "customer_lookup",
            "read",
            customer_input,
            customer_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        (
            "lookup_policy",
            "read",
            keyed_lookup_input,
            lookup_output,
            RiskLevel.LOW,
            False,
            (),
        ),
        ("summarize", "read", summarize_input, summarize_output, RiskLevel.LOW, False, ()),
        (
            "summarize_build",
            "read",
            summarize_build_input,
            summarize_output,
            RiskLevel.LOW,
            False,
            (),
        ),
    )
    return tuple(
        TrustedToolDefinition(
            name=name,
            version="1.0.0",
            policy_action=action,
            input_schema=input_schema,
            output_schema=output_schema,
            risk_level=risk,
            approval_required=approval,
            side_effects=side_effects,
        )
        for name, action, input_schema, output_schema, risk, approval, side_effects in specs
    )


def _validated_schema_json(schema: Mapping[str, object], *, label: str) -> str:
    if not isinstance(schema, Mapping):
        raise InvalidToolDefinitionError(f"Trusted {label} schema must be an object.")
    try:
        serialized = canonical_json_dumps(dict(schema))
        normalized = json.loads(serialized)
        _reject_external_refs(normalized)
        Draft202012Validator.check_schema(normalized)
    except (ToolDefinitionError, SchemaError) as exc:
        raise InvalidToolDefinitionError(f"Trusted {label} schema is invalid.") from exc
    return serialized


def _reject_external_refs(value: object) -> None:
    if isinstance(value, Mapping):
        reference = value.get("$ref")
        if isinstance(reference, str) and EXTERNAL_REF_RE.match(reference):
            raise InvalidToolDefinitionError("External schema references are forbidden.")
        for nested in value.values():
            _reject_external_refs(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_external_refs(nested)


def _validate_json_value(
    value: object,
    *,
    depth: int,
    seen: set[int],
    counter: list[int],
) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise ToolDefinitionError("Canonical JSON exceeds the maximum nesting depth.")
    counter[0] += 1
    if counter[0] > MAX_CANONICAL_NODES:
        raise ToolDefinitionError("Canonical JSON exceeds the maximum node count.")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _account_canonical_text(value, counter)
        return
    if isinstance(value, int):
        if value.bit_length() > MAX_CANONICAL_BYTES * 4:
            raise ToolDefinitionError("Canonical JSON number exceeds the size limit.")
        counter[1] += max(1, int(value.bit_length() * 0.302) + 1)
        if counter[1] > MAX_CANONICAL_BYTES:
            raise ToolDefinitionError("Canonical JSON exceeds the metadata size limit.")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ToolDefinitionError("Canonical JSON cannot contain non-finite numbers.")
        return
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise ToolDefinitionError("Canonical JSON cannot contain cycles.")
        seen.add(identity)
        try:
            try:
                items = value.items()
                for key, nested in items:
                    if not isinstance(key, str):
                        raise ToolDefinitionError("Canonical JSON object keys must be strings.")
                    _account_canonical_text(key, counter)
                    _validate_json_value(
                        nested,
                        depth=depth + 1,
                        seen=seen,
                        counter=counter,
                    )
            except ToolDefinitionError:
                raise
            except Exception as exc:
                raise ToolDefinitionError(
                    "Canonical JSON mapping could not be traversed safely."
                ) from exc
        finally:
            seen.remove(identity)
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in seen:
            raise ToolDefinitionError("Canonical JSON cannot contain cycles.")
        seen.add(identity)
        try:
            for nested in value:
                _validate_json_value(
                    nested,
                    depth=depth + 1,
                    seen=seen,
                    counter=counter,
                )
        finally:
            seen.remove(identity)
        return
    raise ToolDefinitionError("Canonical JSON contains an unsupported value type.")


def _account_canonical_text(value: str, counter: list[int]) -> None:
    if len(value) > MAX_CANONICAL_BYTES:
        raise ToolDefinitionError("Canonical JSON string exceeds the size limit.")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ToolDefinitionError("Canonical JSON text contains an invalid Unicode surrogate.")
    # Four bytes per code point is a safe UTF-8 upper bound and avoids first
    # allocating an attacker-sized encoded copy merely to enforce the cap.
    counter[1] += len(value) * 4
    if counter[1] > MAX_CANONICAL_BYTES:
        raise ToolDefinitionError("Canonical JSON exceeds the metadata size limit.")


def _schema_from_json(value: str) -> dict[str, object]:
    loaded = json.loads(value)
    if not isinstance(loaded, dict):  # pragma: no cover - constructor guarantees this
        raise InvalidToolDefinitionError("Stored trusted schema is not an object.")
    return loaded
