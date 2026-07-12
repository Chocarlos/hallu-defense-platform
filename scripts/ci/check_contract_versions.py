from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import cast, get_args

import yaml
from pydantic import BaseModel

from hallu_defense.domain import models

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "packages" / "contracts" / "contract-versions.json"
SCHEMA_DIR = ROOT / "packages" / "contracts" / "schemas"
TYPESCRIPT_PATH = ROOT / "packages" / "contracts" / "src" / "index.ts"
OPENAPI_PATH = ROOT / "docs" / "api" / "openapi.yaml"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
CORE_V1_CONTRACTS = frozenset(
    {"Claim", "Evidence", "ClaimVerdict", "VerificationRun", "ToolCallEnvelope", "SandboxRun"}
)

_INTERFACE_RE = re.compile(
    r"^export interface (?P<name>[A-Za-z0-9_]+)(?: extends [^{]+)?\s*\{"
    r"(?P<body>.*?)^\}",
    re.MULTILINE | re.DOTALL,
)
_FIELD_RE = re.compile(
    r"^\s*readonly\s+(?P<name>[A-Za-z0-9_]+)(?P<optional>\?)?:\s*"
    r"(?P<type>[^;]+);\s*$",
    re.MULTILINE,
)


class ContractVersionError(RuntimeError):
    pass


def validate_contract_versions(
    *,
    manifest_path: Path = MANIFEST_PATH,
    schema_dir: Path = SCHEMA_DIR,
    typescript_path: Path = TYPESCRIPT_PATH,
    openapi_path: Path = OPENAPI_PATH,
) -> None:
    manifest = _load_json(manifest_path)
    typescript_source = typescript_path.read_text(encoding="utf-8")
    interfaces = _typescript_interfaces(typescript_source)
    openapi = _load_yaml(openapi_path)
    errors: list[str] = []

    _validate_manifest_version(manifest, errors)
    _validate_core_version_declarations(manifest, errors)
    _validate_vocabularies(manifest, typescript_source, errors)
    _validate_models(
        manifest,
        interfaces,
        schema_dir,
        openapi,
        errors,
    )
    _validate_vocabulary_bindings(
        manifest,
        interfaces,
        typescript_source,
        schema_dir,
        openapi,
        errors,
    )
    _validate_v2_schema_versions(
        manifest,
        interfaces,
        typescript_source,
        schema_dir,
        openapi,
        errors,
    )
    _validate_endpoints(manifest, openapi, errors)
    _validate_wiring(errors)

    if errors:
        formatted = "\n".join(f"- {error}" for error in errors)
        raise ContractVersionError(f"Contract version gate failed:\n{formatted}")


def _validate_manifest_version(manifest: dict[str, object], errors: list[str]) -> None:
    if manifest.get("manifest_version") != "contract-versions.v1":
        errors.append("manifest_version must be contract-versions.v1")


def _validate_core_version_declarations(
    manifest: dict[str, object],
    errors: list[str],
) -> None:
    legacy_models = _object(manifest.get("legacy_models"), "legacy_models")
    for model_name in sorted(CORE_V1_CONTRACTS):
        spec = _object(legacy_models.get(model_name), f"legacy_models.{model_name}")
        if spec.get("contract_version") != "1.0":
            errors.append(f"Core v1 model {model_name} must declare contract_version 1.0")

    v2_models = _object(manifest.get("v2_models"), "v2_models")
    for model_name, raw_spec in v2_models.items():
        spec = _object(raw_spec, f"v2_models.{model_name}")
        if spec.get("contract_version") != "2.0":
            errors.append(f"V2 model {model_name} must declare contract_version 2.0")


def _validate_vocabularies(
    manifest: dict[str, object],
    typescript_source: str,
    errors: list[str],
) -> None:
    vocabularies = _object(manifest.get("vocabularies"), "vocabularies")
    for version in ("v1", "v2"):
        vocabulary = _object(vocabularies.get(version), f"vocabularies.{version}")
        for kind, manifest_key, type_key in (
            ("status", "statuses", "status_type"),
            ("action", "actions", "action_type"),
        ):
            expected = _string_list(
                vocabulary.get(manifest_key),
                f"vocabularies.{version}.{manifest_key}",
            )
            type_name = _string(vocabulary.get(type_key), f"vocabularies.{version}.{type_key}")
            python_type = getattr(models, type_name, None)
            if not isinstance(python_type, type) or not issubclass(python_type, Enum):
                errors.append(f"Pydantic {type_name} enum is missing")
            elif [item.value for item in python_type] != expected:
                errors.append(f"Pydantic {type_name} {kind} vocabulary differs from manifest")
            if _typescript_union(typescript_source, type_name) != expected:
                errors.append(f"TypeScript {type_name} {kind} vocabulary differs from manifest")


def _validate_models(
    manifest: dict[str, object],
    interfaces: dict[str, tuple[dict[str, str], set[str]]],
    schema_dir: Path,
    openapi: dict[str, object],
    errors: list[str],
) -> None:
    for group_name in ("legacy_models", "v2_models"):
        group = _object(manifest.get(group_name), group_name)
        for model_name, raw_spec in group.items():
            spec = _object(raw_spec, f"{group_name}.{model_name}")
            expected_fields = set(
                _string_list(spec.get("fields"), f"{group_name}.{model_name}.fields")
            )
            python_model = _pydantic_model(model_name, errors)
            if python_model is not None:
                python_fields = _pydantic_public_fields(python_model)
                _compare_set(
                    f"Pydantic {model_name} fields",
                    set(python_fields),
                    expected_fields,
                    errors,
                )

            ts_interface = interfaces.get(model_name)
            if ts_interface is None:
                errors.append(f"TypeScript interface {model_name} is missing")
            else:
                _compare_set(
                    f"TypeScript {model_name} fields",
                    set(ts_interface[0]),
                    expected_fields,
                    errors,
                )

            schema_name = _string(
                spec.get("json_schema"),
                f"{group_name}.{model_name}.json_schema",
            )
            json_schema = _load_json(schema_dir / schema_name)
            _compare_set(
                f"JSON Schema {model_name} fields",
                set(_properties(json_schema, f"JSON Schema {model_name}")),
                expected_fields,
                errors,
            )

            openapi_schema = _openapi_component(openapi, model_name, errors)
            if openapi_schema is not None:
                _compare_set(
                    f"OpenAPI {model_name} fields",
                    set(_properties(openapi_schema, f"OpenAPI {model_name}")),
                    expected_fields,
                    errors,
                )

            contract_version = spec.get("contract_version")
            if contract_version is not None:
                expected_version = _string(
                    contract_version,
                    f"{group_name}.{model_name}.contract_version",
                )
                if (
                    python_model is not None
                    and python_model.model_json_schema(by_alias=True).get("x-contract-version")
                    != expected_version
                ):
                    errors.append(
                        f"Pydantic {model_name} x-contract-version must be {expected_version}"
                    )
                if json_schema.get("x-contract-version") != expected_version:
                    errors.append(
                        f"JSON Schema {model_name} x-contract-version must be {expected_version}"
                    )
                if (
                    openapi_schema is not None
                    and openapi_schema.get("x-contract-version") != expected_version
                ):
                    errors.append(
                        f"OpenAPI {model_name} x-contract-version must be {expected_version}"
                    )

            if "required" in spec:
                expected_required = set(
                    _string_list(
                        spec.get("required"),
                        f"{group_name}.{model_name}.required",
                    )
                )
                if python_model is not None:
                    python_fields = _pydantic_public_fields(python_model)
                    python_required = {
                        name for name, field in python_fields.items() if field.is_required()
                    }
                    _compare_set(
                        f"Pydantic {model_name} required fields",
                        python_required,
                        expected_required,
                        errors,
                    )
                if ts_interface is not None:
                    _compare_set(
                        f"TypeScript {model_name} required fields",
                        ts_interface[1],
                        expected_required,
                        errors,
                    )
                _compare_set(
                    f"JSON Schema {model_name} required fields",
                    set(_string_list(json_schema.get("required", []), f"{model_name}.required")),
                    expected_required,
                    errors,
                )
                if openapi_schema is not None:
                    _compare_set(
                        f"OpenAPI {model_name} required fields",
                        set(
                            _string_list(
                                openapi_schema.get("required", []),
                                f"OpenAPI {model_name}.required",
                            )
                        ),
                        expected_required,
                        errors,
                    )


def _validate_vocabulary_bindings(
    manifest: dict[str, object],
    interfaces: dict[str, tuple[dict[str, str], set[str]]],
    typescript_source: str,
    schema_dir: Path,
    openapi: dict[str, object],
    errors: list[str],
) -> None:
    vocabularies = _object(manifest.get("vocabularies"), "vocabularies")
    bindings = _list(manifest.get("vocabulary_bindings"), "vocabulary_bindings")
    model_specs = {
        **_object(manifest.get("legacy_models"), "legacy_models"),
        **_object(manifest.get("v2_models"), "v2_models"),
    }
    for index, raw_binding in enumerate(bindings):
        binding = _object(raw_binding, f"vocabulary_bindings[{index}]")
        model_name = _string(binding.get("model"), f"vocabulary_bindings[{index}].model")
        field_name = _string(binding.get("field"), f"vocabulary_bindings[{index}].field")
        vocabulary_path = _string(
            binding.get("vocabulary"),
            f"vocabulary_bindings[{index}].vocabulary",
        )
        version, vocabulary_name = vocabulary_path.split(".", maxsplit=1)
        vocabulary = _object(vocabularies.get(version), f"vocabularies.{version}")
        expected = _string_list(
            vocabulary.get(vocabulary_name),
            f"vocabularies.{vocabulary_path}",
        )

        python_model = _pydantic_model(model_name, errors)
        if python_model is not None:
            field = python_model.model_fields.get(field_name)
            annotation = field.annotation if field is not None else None
            if not isinstance(annotation, type) or not issubclass(annotation, Enum):
                errors.append(f"Pydantic {model_name}.{field_name} is not an enum field")
            elif [item.value for item in annotation] != expected:
                errors.append(f"Pydantic {model_name}.{field_name} vocabulary differs")

        ts_interface = interfaces.get(model_name)
        ts_field_type = ts_interface[0].get(field_name) if ts_interface is not None else None
        if ts_field_type is None or _typescript_union(typescript_source, ts_field_type) != expected:
            errors.append(f"TypeScript {model_name}.{field_name} vocabulary differs")

        spec = _object(model_specs.get(model_name), f"model spec {model_name}")
        json_schema = _load_json(
            schema_dir / _string(spec.get("json_schema"), f"{model_name}.json_schema")
        )
        json_property = _object(
            _properties(json_schema, f"JSON Schema {model_name}").get(field_name),
            f"JSON Schema {model_name}.{field_name}",
        )
        if _string_list(json_property.get("enum"), f"{model_name}.{field_name}.enum") != expected:
            errors.append(f"JSON Schema {model_name}.{field_name} vocabulary differs")

        openapi_schema = _openapi_component(openapi, model_name, errors)
        if openapi_schema is not None:
            openapi_property = _object(
                _properties(openapi_schema, f"OpenAPI {model_name}").get(field_name),
                f"OpenAPI {model_name}.{field_name}",
            )
            resolved = _resolve_openapi_schema(openapi, openapi_property, errors)
            if resolved is not None and _string_list(
                resolved.get("enum"),
                f"OpenAPI {model_name}.{field_name}.enum",
            ) != expected:
                errors.append(f"OpenAPI {model_name}.{field_name} vocabulary differs")


def _validate_v2_schema_versions(
    manifest: dict[str, object],
    interfaces: dict[str, tuple[dict[str, str], set[str]]],
    typescript_source: str,
    schema_dir: Path,
    openapi: dict[str, object],
    errors: list[str],
) -> None:
    v2_vocabulary = _object(
        _object(manifest.get("vocabularies"), "vocabularies").get("v2"),
        "vocabularies.v2",
    )
    expected = _string(v2_vocabulary.get("schema_version"), "vocabularies.v2.schema_version")
    ts_version_type = _string(
        v2_vocabulary.get("schema_version_type"),
        "vocabularies.v2.schema_version_type",
    )
    if _typescript_union(typescript_source, ts_version_type) != [expected]:
        errors.append(f"TypeScript {ts_version_type} must be the literal {expected}")

    for model_name, raw_spec in _object(manifest.get("v2_models"), "v2_models").items():
        spec = _object(raw_spec, f"v2_models.{model_name}")
        python_model = _pydantic_model(model_name, errors)
        if python_model is not None:
            field = python_model.model_fields.get("schema_version")
            literal_values = list(get_args(field.annotation)) if field is not None else []
            if literal_values != [expected]:
                errors.append(f"Pydantic {model_name}.schema_version must be Literal[{expected!r}]")

        ts_interface = interfaces.get(model_name)
        if ts_interface is None or ts_interface[0].get("schema_version") != ts_version_type:
            errors.append(
                f"TypeScript {model_name}.schema_version must use {ts_version_type}"
            )

        json_schema = _load_json(
            schema_dir / _string(spec.get("json_schema"), f"{model_name}.json_schema")
        )
        json_version = _object(
            _properties(json_schema, f"JSON Schema {model_name}").get("schema_version"),
            f"JSON Schema {model_name}.schema_version",
        )
        if json_version.get("const") != expected:
            errors.append(f"JSON Schema {model_name}.schema_version must const {expected}")

        openapi_schema = _openapi_component(openapi, model_name, errors)
        if openapi_schema is not None:
            openapi_version = _object(
                _properties(openapi_schema, f"OpenAPI {model_name}").get("schema_version"),
                f"OpenAPI {model_name}.schema_version",
            )
            if openapi_version.get("const") != expected:
                errors.append(f"OpenAPI {model_name}.schema_version must const {expected}")


def _validate_endpoints(
    manifest: dict[str, object],
    openapi: dict[str, object],
    errors: list[str],
) -> None:
    paths = _object(openapi.get("paths"), "OpenAPI paths")
    for path, raw_spec in _object(manifest.get("endpoints"), "endpoints").items():
        spec = _object(raw_spec, f"endpoints.{path}")
        path_item = _object(paths.get(path), f"OpenAPI path {path}")
        operation = _object(path_item.get("post"), f"OpenAPI POST {path}")
        request_schema = _object(
            _object(
                _object(operation.get("requestBody"), f"OpenAPI POST {path} requestBody").get(
                    "content"
                ),
                f"OpenAPI POST {path} request content",
            ).get("application/json"),
            f"OpenAPI POST {path} request application/json",
        ).get("schema")
        response_schema = _object(
            _object(
                _object(
                    _object(operation.get("responses"), f"OpenAPI POST {path} responses").get(
                        "200"
                    ),
                    f"OpenAPI POST {path} response 200",
                ).get("content"),
                f"OpenAPI POST {path} response content",
            ).get("application/json"),
            f"OpenAPI POST {path} response application/json",
        ).get("schema")
        expected_request = _string(spec.get("request_model"), f"endpoints.{path}.request_model")
        expected_response = _string(
            spec.get("response_model"),
            f"endpoints.{path}.response_model",
        )
        if _openapi_ref_name(request_schema) != expected_request:
            errors.append(f"OpenAPI POST {path} request model must be {expected_request}")
        if _openapi_ref_name(response_schema) != expected_response:
            errors.append(f"OpenAPI POST {path} response model must be {expected_response}")


def _validate_wiring(errors: list[str]) -> None:
    makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
    workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    command = "scripts/ci/check_contract_versions.py"
    if "contract-versions-check:" not in makefile or command not in makefile:
        errors.append("Makefile must expose contract-versions-check and run the semantic gate")
    if command not in workflow:
        errors.append("CI backend job must run the semantic contract version gate")


def _typescript_interfaces(source: str) -> dict[str, tuple[dict[str, str], set[str]]]:
    interfaces: dict[str, tuple[dict[str, str], set[str]]] = {}
    for match in _INTERFACE_RE.finditer(source):
        fields: dict[str, str] = {}
        required: set[str] = set()
        for field_match in _FIELD_RE.finditer(match.group("body")):
            field_name = field_match.group("name")
            fields[field_name] = field_match.group("type").strip()
            if field_match.group("optional") is None:
                required.add(field_name)
        interfaces[match.group("name")] = (fields, required)
    return interfaces


def _typescript_union(source: str, type_name: str) -> list[str]:
    match = re.search(
        rf"^export type {re.escape(type_name)}\s*=\s*(?P<body>.*?);",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        return []
    return re.findall(r'"([^"\r\n]+)"', match.group("body"))


def _pydantic_model(name: str, errors: list[str]) -> type[BaseModel] | None:
    candidate = getattr(models, name, None)
    if not isinstance(candidate, type) or not issubclass(candidate, BaseModel):
        errors.append(f"Pydantic model {name} is missing")
        return None
    return candidate


def _pydantic_public_fields(model: type[BaseModel]) -> dict[str, object]:
    return {
        field.alias or name: field
        for name, field in model.model_fields.items()
    }


def _openapi_component(
    openapi: dict[str, object],
    name: str,
    errors: list[str],
) -> dict[str, object] | None:
    components = _object(openapi.get("components"), "OpenAPI components")
    schemas = _object(components.get("schemas"), "OpenAPI component schemas")
    schema = schemas.get(name)
    if not isinstance(schema, dict):
        errors.append(f"OpenAPI component {name} is missing")
        return None
    return cast(dict[str, object], schema)


def _resolve_openapi_schema(
    openapi: dict[str, object],
    schema: dict[str, object],
    errors: list[str],
) -> dict[str, object] | None:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    name = _openapi_ref_name(schema)
    if name is None:
        errors.append(f"Unsupported OpenAPI schema reference: {reference!r}")
        return None
    return _openapi_component(openapi, name, errors)


def _openapi_ref_name(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    reference = value.get("$ref")
    prefix = "#/components/schemas/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        return None
    return reference.removeprefix(prefix)


def _properties(payload: dict[str, object], label: str) -> dict[str, object]:
    return _object(payload.get("properties"), f"{label}.properties")


def _compare_set(
    label: str,
    actual: set[str],
    expected: set[str],
    errors: list[str],
) -> None:
    if actual != expected:
        errors.append(
            f"{label} differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _load_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ContractVersionError(f"Required JSON file is missing: {path}")
    return _object(json.loads(path.read_text(encoding="utf-8")), str(path))


def _load_yaml(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ContractVersionError(f"Required YAML file is missing: {path}")
    return _object(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractVersionError(f"{label} must be an object with string keys")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractVersionError(f"{label} must be an array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractVersionError(f"{label} must be a non-empty string")
    return value


def _string_list(value: object, label: str) -> list[str]:
    values = _list(value, label)
    if not all(isinstance(item, str) for item in values):
        raise ContractVersionError(f"{label} must contain only strings")
    return cast(list[str], values)


def main() -> None:
    validate_contract_versions()
    manifest = _load_json(MANIFEST_PATH)
    legacy_models = _object(manifest.get("legacy_models"), "legacy_models")
    legacy_count = len(legacy_models)
    versioned_core_count = sum(
        "contract_version" in _object(spec, f"legacy_models.{name}")
        for name, spec in legacy_models.items()
    )
    v2_count = len(_object(manifest.get("v2_models"), "v2_models"))
    print(
        "Validated semantic contract versions across Pydantic, TypeScript, "
        f"JSON Schema, and OpenAPI: {legacy_count} legacy models, "
        f"{versioned_core_count} versioned core v1 models, {v2_count} v2 models."
    )


if __name__ == "__main__":
    main()
