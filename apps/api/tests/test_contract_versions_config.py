from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from scripts.ci.check_contract_versions import (
    MANIFEST_PATH,
    OPENAPI_PATH,
    SCHEMA_DIR,
    TYPESCRIPT_PATH,
    ContractVersionError,
    validate_contract_versions,
)


def test_contract_version_gate_validates_all_four_surfaces() -> None:
    validate_contract_versions()


def test_contract_version_gate_rejects_manifest_vocabulary_drift(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["vocabularies"]["v2"]["statuses"][0] = "SUPPORTED"
    modified = tmp_path / "contract-versions.json"
    modified.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractVersionError, match="Pydantic VerdictStatusV2"):
        validate_contract_versions(manifest_path=modified)


def test_contract_version_gate_rejects_removed_core_version_metadata(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    del manifest["legacy_models"]["ToolCallEnvelope"]["contract_version"]
    modified = tmp_path / "contract-versions.json"
    modified.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractVersionError, match="Core v1 model ToolCallEnvelope"):
        validate_contract_versions(manifest_path=modified)


def test_contract_version_gate_rejects_typescript_field_drift(tmp_path: Path) -> None:
    source = TYPESCRIPT_PATH.read_text(encoding="utf-8")
    modified = tmp_path / "index.ts"
    modified.write_text(
        source.replace(
            "  readonly schema_version: ContractSchemaVersionV2;\n"
            "  readonly claim_id: string;",
            "  readonly claim_id: string;",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ContractVersionError, match="TypeScript ClaimVerdictV2 fields"):
        validate_contract_versions(typescript_path=modified)


def test_contract_version_gate_rejects_json_schema_field_drift(tmp_path: Path) -> None:
    copied_schemas = tmp_path / "schemas"
    shutil.copytree(SCHEMA_DIR, copied_schemas)
    schema_path = copied_schemas / "claim-verdict-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    del schema["properties"]["reason"]
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    with pytest.raises(ContractVersionError, match="JSON Schema ClaimVerdictV2 fields"):
        validate_contract_versions(schema_dir=copied_schemas)


def test_contract_version_gate_rejects_openapi_field_drift(tmp_path: Path) -> None:
    openapi = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    del openapi["components"]["schemas"]["VerificationRunV2"]["properties"]["policy_version"]
    modified = tmp_path / "openapi.yaml"
    modified.write_text(yaml.safe_dump(openapi, sort_keys=False), encoding="utf-8")

    with pytest.raises(ContractVersionError, match="OpenAPI VerificationRunV2 fields"):
        validate_contract_versions(openapi_path=modified)
