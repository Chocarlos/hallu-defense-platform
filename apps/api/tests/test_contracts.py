from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from hallu_defense.api import routes
from hallu_defense.config import Settings
from hallu_defense.main import app
from hallu_defense.services.sandbox import SandboxRunner

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = ROOT / "packages" / "contracts" / "schemas"
EXAMPLES_DIR = ROOT / "packages" / "contracts" / "examples"
REQUIRED_SCHEMA_NAMES = {
    "approval-decision-request",
    "approval-decision-response",
    "approval-execution-grant",
    "approval-list-request",
    "approval-list-response",
    "approval-record",
    "claim",
    "claim-classification-request",
    "claim-classification-response",
    "claim-extraction-request",
    "claim-extraction-response",
    "claim-verification-request",
    "claim-verification-response",
    "corpus-grant",
    "corpus-grant-disable-request",
    "corpus-grant-history-diff",
    "corpus-grant-history-diff-request",
    "corpus-grant-history-diff-response",
    "corpus-grant-history-request",
    "corpus-grant-history-response",
    "corpus-grant-upsert-request",
    "corpus-grant-list-request",
    "corpus-grant-response",
    "corpus-grant-list-response",
    "document-ingestion-request",
    "document-ingestion-response",
    "document-ingestion-status-request",
    "document-ingestion-status-response",
    "source-span",
    "freshness",
    "evidence",
    "evidence-retrieval-request",
    "evidence-retrieval-response",
    "verdict",
    "verification-replay-request",
    "verification-replay-response",
    "verification-run",
    "verification-run-request",
    "tool-call-envelope",
    "tool-validation-response",
    "response-repair-request",
    "response-repair-response",
    "policy-evaluation-request",
    "policy-evaluation-response",
    "repo-checks-run-request",
    "sandbox-run",
    "error-response",
    "eval-smoke-metrics",
    "eval-smoke-report",
    "eval-smoke-scenario-result",
    "eval-report",
    "eval-report-list-request",
    "eval-report-list-response",
    "eval-report-metrics",
    "eval-report-publish-request",
    "eval-report-publish-response",
    "audit-event",
    "audit-export-request",
    "audit-export-response",
    "document-input",
}

CLAIM_PAYLOAD = {
    "claim_id": "clm_contract",
    "text": "Full-time employees receive 15 days of paid vacation per year.",
    "canonical_form": "full-time employees receive 15 days of paid vacation per year",
    "type": "doc_grounded",
    "risk_level": "medium",
    "requires_evidence": True,
    "metadata": {},
}

EVIDENCE_PAYLOAD = {
    "evidence_id": "ev_contract",
    "kind": "document_chunk",
    "source_ref": "hr-manual-v7",
    "content": "Full-time employees receive 15 days of paid vacation per year.",
    "structured_content": {},
    "authority": "internal",
    "freshness": {
        "retrieved_at": "2026-07-07T00:00:00Z",
        "published_at": None,
        "staleness_class": "fresh",
    },
}

VERDICT_PAYLOAD = {
    "claim_id": "clm_contract",
    "status": "SUPPORTED",
    "confidence": 0.95,
    "evidence_ids": ["ev_contract"],
    "action": "allow_with_citation",
    "reason": "Evidence supports the claim.",
    "validator_trace": {},
}

REQUIRED_ENDPOINT_PAYLOADS = {
    "/claims/extract": {
        "message_text": "Full-time employees receive 15 days of paid vacation per year.",
    },
    "/claims/classify": {"claims": [CLAIM_PAYLOAD], "task_type": "document_qa"},
    "/evidence/retrieve": {
        "claims": [CLAIM_PAYLOAD],
        "documents": [
            {
                "source_ref": "hr-manual-v7",
                "content": "Full-time employees receive 15 days of paid vacation per year.",
                "authority": "internal",
            }
        ],
    },
    "/documents/ingest": {
        "documents": [
            {
                "source_ref": "hr-manual-v7",
                "content": "Full-time employees receive 15 days of paid vacation per year.",
                "authority": "internal",
                "metadata": {"department": "hr"},
            }
        ],
        "corpus_id": "hr",
    },
    "/rag/corpus-grants/upsert": {
        "corpus_id": "hr",
        "reader_roles": ["hr_reader"],
        "writer_roles": ["hr_writer"],
    },
    "/rag/corpus-grants/disable": {"corpus_id": "hr"},
    "/rag/corpus-grants/list": {},
    "/rag/corpus-grants/history": {},
    "/rag/corpus-grants/history/diff": {},
    "/claims/verify": {"claims": [CLAIM_PAYLOAD], "evidence": [EVIDENCE_PAYLOAD]},
    "/response/repair": {
        "original_text": "Full-time employees receive 15 days of paid vacation per year.",
        "claims": [CLAIM_PAYLOAD],
        "verdicts": [VERDICT_PAYLOAD],
        "evidence": [EVIDENCE_PAYLOAD],
    },
    "/tools/validate-input": {
        "tool_name": "read_document",
        "input": {"document_id": "hr-manual-v7"},
        "schema": {"type": "object", "required": ["document_id"]},
        "risk_level": "low",
        "approval_required": False,
        "caller_context": {},
    },
    "/tools/validate-output": {
        "tool_name": "read_document",
        "input": {"content": "safe output"},
        "schema": {"type": "object"},
        "risk_level": "low",
        "approval_required": False,
        "caller_context": {},
    },
    "/policy/evaluate": {
        "subject": "contract-test",
        "action": "read",
        "resource": "hr-manual-v7",
        "risk_level": "low",
        "attributes": {},
    },
    "/repo/checks/run": {
        "repo_ref": ".",
        "commands": ["python --version"],
        "network_policy": "deny",
    },
    "/audit/export": {"include_events": True},
    "/evals/reports/publish": {
        "suite": "scenarios",
        "run_id": "contract-report",
        "source": "contract-test",
        "metrics": {
            "scenario_count": 1,
            "pass_rate": 1.0,
            "p95_latency_ms": 4.2,
            "groundedness": 1.0,
            "faithfulness": 1.0,
        },
        "payload": {"contract": True},
    },
    "/evals/reports/list": {"suite": "scenarios", "limit": 5},
    "/verification/replay": {"trace_id": "tr_api_discipline_replay_missing"},
}


def test_json_schemas_are_loadable_and_versioned() -> None:
    schemas = sorted(SCHEMA_DIR.glob("*.schema.json"))
    schema_names = {schema.stem.removesuffix(".schema") for schema in schemas}
    assert REQUIRED_SCHEMA_NAMES.issubset(schema_names)
    for schema in schemas:
        payload = json.loads(schema.read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["$id"].startswith("https://hallu-defense.local/schemas/")
        assert payload["additionalProperties"] is False
        Draft202012Validator.check_schema(payload)


def test_json_schema_examples_are_enforced() -> None:
    schemas = {
        schema.stem.removesuffix(".schema"): json.loads(schema.read_text(encoding="utf-8"))
        for schema in SCHEMA_DIR.glob("*.schema.json")
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )

    for example in sorted((EXAMPLES_DIR / "valid").glob("*.json")):
        validator = Draft202012Validator(
            schemas[example.stem],
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = list(validator.iter_errors(json.loads(example.read_text(encoding="utf-8"))))
        assert not errors, f"{example} should be valid: {errors}"

    for example in sorted((EXAMPLES_DIR / "invalid").glob("*.json")):
        validator = Draft202012Validator(
            schemas[example.stem],
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = list(validator.iter_errors(json.loads(example.read_text(encoding="utf-8"))))
        assert errors, f"{example} should be invalid"


def test_openapi_contains_required_endpoints() -> None:
    required_paths = {
        "/claims/extract",
        "/claims/classify",
        "/documents/ingest",
        "/documents/ingest/status",
        "/rag/corpus-grants/upsert",
        "/rag/corpus-grants/disable",
        "/rag/corpus-grants/list",
        "/rag/corpus-grants/history",
        "/rag/corpus-grants/history/diff",
        "/evidence/retrieve",
        "/claims/verify",
        "/response/repair",
        "/tools/validate-input",
        "/tools/validate-output",
        "/policy/evaluate",
        "/repo/checks/run",
        "/audit/export",
        "/evals/reports/publish",
        "/evals/reports/list",
        "/approvals/list",
        "/approvals/decide",
        "/verification/replay",
    }
    openapi = TestClient(app).get("/openapi.json").json()
    assert required_paths.issubset(openapi["paths"].keys())
    for path in required_paths:
        responses = openapi["paths"][path]["post"]["responses"]
        for status_code in ["400", "401", "422", "500"]:
            assert status_code in responses
            schema_ref = responses[status_code]["content"]["application/json"]["schema"]["$ref"]
            assert schema_ref.endswith("/ErrorResponse")


def test_openapi_exposes_metrics_as_plain_text() -> None:
    openapi = TestClient(app).get("/openapi.json").json()
    responses = openapi["paths"]["/metrics"]["get"]["responses"]
    assert "200" in responses
    assert "text/plain" in responses["200"]["content"]


def test_verification_run_contract_has_trace_claims_and_verdicts() -> None:
    response = TestClient(app).post(
        "/verification/run",
        json={
            "tenant_id": "contract-test",
            "message_text": "Full-time employees receive 15 days of paid vacation per year.",
            "task_type": "document_qa",
            "documents": [
                {
                    "source_ref": "hr-manual-v7",
                    "content": "Full-time employees receive 15 days of paid vacation per year.",
                    "authority": "internal",
                }
            ],
        },
    )
    payload = response.json()
    assert response.status_code == 200
    assert payload["trace_id"].startswith("tr_")
    assert payload["claims"]
    assert payload["verdicts"]
    assert payload["policy_version"]


def test_verification_run_uses_tenant_header_when_body_omits_tenant() -> None:
    response = TestClient(app).post(
        "/verification/run",
        json={
            "message_text": "Full-time employees receive 15 days of paid vacation per year.",
            "documents": [
                {
                    "source_ref": "hr-manual-v7",
                    "content": "Full-time employees receive 15 days of paid vacation per year.",
                    "authority": "internal",
                }
            ],
        },
        headers={"x-tenant-id": "tenant-from-header", "x-trace-id": "tr_tenant_header"},
    )

    payload = response.json()
    assert response.status_code == 200
    assert response.headers["x-trace-id"] == "tr_tenant_header"
    assert payload["trace_id"] == "tr_tenant_header"
    assert payload["tenant_id"] == "tenant-from-header"


def test_required_endpoints_emit_trace_header_and_audit_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox_workspace = tmp_path / "sandbox-workspace"
    sandbox_repo = sandbox_workspace / "repo"
    sandbox_repo.mkdir(parents=True)
    monkeypatch.setattr(
        routes,
        "sandbox_runner",
        SandboxRunner(
            Settings(
                environment="test",
                policy_version="test",
                auth_required=False,
                allowed_workspace=sandbox_workspace,
                max_command_seconds=5,
                max_output_chars=1000,
            )
        ),
    )
    client = TestClient(app)
    tenant_id = "api-discipline-contract"
    expected_paths = set(REQUIRED_ENDPOINT_PAYLOADS)
    endpoint_payloads = {
        **REQUIRED_ENDPOINT_PAYLOADS,
        "/repo/checks/run": {
            "repo_ref": "repo",
            "commands": ["python --version"],
            "network_policy": "deny",
        },
    }

    for index, (path, payload) in enumerate(endpoint_payloads.items(), start=1):
        trace_id = f"tr_api_discipline_{index:02d}"
        response = client.post(
            path,
            json=payload,
            headers={"x-tenant-id": tenant_id, "x-trace-id": trace_id},
        )
        assert response.status_code < 500, response.text
        assert response.headers["x-trace-id"] == trace_id

    audit_response = client.post(
        "/audit/export",
        json={"tenant_id": tenant_id, "include_events": True},
        headers={"x-tenant-id": tenant_id, "x-trace-id": "tr_api_discipline_audit"},
    )
    assert audit_response.status_code == 200
    payload = audit_response.json()
    assert payload["trace_id"] == "tr_api_discipline_audit"
    audited_paths = {event["path"] for event in payload["events"]}
    assert expected_paths.issubset(audited_paths)
    assert all(event["tenant_id"] == tenant_id for event in payload["events"])


def test_http_errors_use_error_response_contract() -> None:
    response = TestClient(app).post(
        "/repo/checks/run",
        json={"repo_ref": "..", "commands": ["python --version"]},
        headers={"x-tenant-id": "error-contract", "x-trace-id": "tr_error_contract"},
    )

    assert response.status_code == 400
    assert response.headers["x-trace-id"] == "tr_error_contract"
    payload = response.json()
    assert payload["trace_id"] == "tr_error_contract"
    assert payload["error"] == "http_400"
    assert "workspace" in payload["message"]


def test_validation_errors_use_error_response_contract() -> None:
    response = TestClient(app).post(
        "/claims/extract",
        json={},
        headers={"x-tenant-id": "validation-contract", "x-trace-id": "tr_validation_contract"},
    )

    assert response.status_code == 422
    payload = response.json()
    assert payload["trace_id"] == "tr_validation_contract"
    assert payload["error"] == "validation_error"
    assert payload["details"]["errors"]
