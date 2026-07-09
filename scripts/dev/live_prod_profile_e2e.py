"""Env-gated scaffold for a production-profile end-to-end smoke.

The default path is intentionally skip-safe. When enabled, this script expects a
running production-profile API and a real bearer token from the deployed OIDC
provider, then exercises the production runtime surface end to end.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENABLED_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_ENABLED"
API_URL_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_API_URL"
BEARER_TOKEN_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_BEARER_TOKEN"
TENANT_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_TENANT"
REPO_REF_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_REPO_REF"
TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_TIMEOUT_SECONDS"

DEFAULT_API_URL = "https://api.example.invalid"
DEFAULT_TENANT = "tenant-a"
DEFAULT_REPO_REF = "."
DEFAULT_TIMEOUT_SECONDS = 10

class LiveProdProfileE2eError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveProdProfileE2eConfig:
    api_url: str
    bearer_token: str
    tenant_id: str
    repo_ref: str
    timeout_seconds: int


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the production profile e2e smoke",
            "planned_checks": [
                "auth",
                "verification",
                "approval",
                "grant",
                "sandbox",
                "corpus",
                "eval",
                "audit",
                "metrics",
            ],
        }
    config = _config_from_env(effective_env)
    return run_smoke(config)


def run_smoke(config: LiveProdProfileE2eConfig) -> dict[str, object]:
    checks: dict[str, object] = {}
    trace_id = ""

    unauth = _post(config, "/verification/run", {"message_text": "Prod profile auth check."}, auth=False)
    if unauth.status_code not in {401, 403}:
        raise LiveProdProfileE2eError(
            f"unauthenticated verification should fail closed, got HTTP {unauth.status_code}"
        )
    checks["auth"] = {"status": "passed", "unauthenticated_status": unauth.status_code}

    verification = _post(
        config,
        "/verification/run",
        {
            "tenant_id": config.tenant_id,
            "message_text": "The production profile smoke has evidence.",
            "documents": [
                {
                    "content": "The production profile smoke has evidence.",
                    "source_ref": "prod-profile-e2e",
                    "authority": "internal",
                    "metadata": {"corpus_id": "prod-profile-smoke"},
                }
            ],
        },
    )
    _require_status(verification, 200, "verification")
    verification_payload = verification.json()
    trace_id = _string_field(verification_payload, "trace_id")
    checks["verification"] = {"status": "passed", "trace_id": trace_id}

    tool_call = {
        "tool_name": "delete_records",
        "input": {"target": "prod-profile-smoke"},
        "risk_level": "high",
        "approval_required": True,
        "caller_context": {"subject": "prod-profile-smoke"},
    }
    approval_request = _post(config, "/tools/validate-input", tool_call)
    _require_status(approval_request, 200, "approval request")
    approval_payload = approval_request.json()
    approval_id = _string_field(approval_payload, "approval_id")
    checks["approval"] = {"status": "passed", "approval_id": approval_id}

    decision = _post(
        config,
        "/approvals/decide",
        {
            "approval_id": approval_id,
            "decision": "approve",
            "reason": "production profile e2e smoke",
        },
    )
    _require_status(decision, 200, "approval decision")
    decision_payload = decision.json()
    grant = decision_payload.get("execution_grant")
    if not isinstance(grant, Mapping):
        raise LiveProdProfileE2eError("approval decision did not return an execution grant")
    execution_token = _string_field(grant, "execution_token")
    grant_call = dict(tool_call)
    grant_call["approval_id"] = approval_id
    grant_call["approval_execution_token"] = execution_token
    grant_consume = _post(config, "/tools/validate-input", grant_call)
    _require_status(grant_consume, 200, "approval grant consume")
    second_consume = _post(config, "/tools/validate-input", grant_call)
    if second_consume.status_code not in {403, 404}:
        raise LiveProdProfileE2eError(
            f"second approval grant consume should fail, got HTTP {second_consume.status_code}"
        )
    checks["grant"] = {"status": "passed", "second_consume_status": second_consume.status_code}

    sandbox = _post(
        config,
        "/repo/checks/run",
        {"repo_ref": config.repo_ref, "commands": ["python --version"], "network_policy": "deny"},
    )
    _require_status(sandbox, 200, "sandbox")
    checks["sandbox"] = {"status": "passed"}

    corpus_id = "prod-profile-smoke"
    corpus = _post(
        config,
        "/rag/corpus-grants/upsert",
        {
            "corpus_id": corpus_id,
            "reader_roles": ["verifier"],
            "writer_roles": ["rag_writer"],
        },
    )
    _require_status(corpus, 200, "corpus grant upsert")
    corpus_list = _post(config, "/rag/corpus-grants/list", {"corpus_id": corpus_id})
    _require_status(corpus_list, 200, "corpus grant list")
    checks["corpus"] = {"status": "passed", "corpus_id": corpus_id}

    audit = _post(config, "/audit/export", {"trace_id": trace_id, "include_events": True})
    _require_status(audit, 200, "audit export")
    checks["audit"] = {"status": "passed"}

    metrics = _get(config, "/metrics")
    _require_status(metrics, 200, "metrics")
    checks["metrics"] = {"status": "passed"}

    eval_suite = "prod-profile-smoke"
    eval_publish = _post(
        config,
        "/evals/reports/publish",
        {
            "suite": eval_suite,
            "run_id": f"{trace_id}-eval",
            "source": "scripts/dev/live_prod_profile_e2e.py",
            "metrics": {
                "scenario_count": 1,
                "pass_rate": 1.0,
                "p95_latency_ms": 1.0,
                "groundedness": 1.0,
                "faithfulness": 1.0,
            },
            "payload": {"trace_id": trace_id},
        },
    )
    _require_status(eval_publish, 200, "eval report publish")
    eval_list = _post(config, "/evals/reports/list", {"suite": eval_suite, "limit": 5})
    _require_status(eval_list, 200, "eval report list")
    reports = eval_list.json().get("reports")
    if not isinstance(reports, list) or not reports:
        raise LiveProdProfileE2eError("eval report list did not return the published report")
    checks["eval"] = {"status": "passed", "suite": eval_suite}
    return {"status": "passed", "checks": checks}


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    body: bytes

    def json(self) -> Mapping[str, object]:
        parsed = json.loads(self.body.decode("utf-8"))
        if not isinstance(parsed, Mapping):
            raise LiveProdProfileE2eError("HTTP response body must be a JSON object")
        return parsed


def _post(
    config: LiveProdProfileE2eConfig,
    path: str,
    payload: Mapping[str, object],
    *,
    auth: bool = True,
) -> HttpResult:
    return _request(config, "POST", path, payload=payload, auth=auth)


def _get(config: LiveProdProfileE2eConfig, path: str, *, auth: bool = True) -> HttpResult:
    return _request(config, "GET", path, payload=None, auth=auth)


def _request(
    config: LiveProdProfileE2eConfig,
    method: str,
    path: str,
    *,
    payload: Mapping[str, object] | None,
    auth: bool,
) -> HttpResult:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Tenant-Id": config.tenant_id}
    if auth:
        headers["Authorization"] = f"Bearer {config.bearer_token}"
    http_request = request.Request(
        config.api_url.rstrip("/") + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with request.urlopen(http_request, timeout=config.timeout_seconds) as response:
            return HttpResult(status_code=response.status, body=response.read())
    except error.HTTPError as exc:
        return HttpResult(status_code=exc.code, body=exc.read())
    except (error.URLError, TimeoutError, OSError) as exc:
        raise LiveProdProfileE2eError(f"{method} {path} failed") from exc


def _config_from_env(env: Mapping[str, str]) -> LiveProdProfileE2eConfig:
    token = _optional(env, BEARER_TOKEN_ENV)
    if token is None:
        raise LiveProdProfileE2eError(f"{BEARER_TOKEN_ENV} is required when {ENABLED_ENV}=true")
    return LiveProdProfileE2eConfig(
        api_url=_optional(env, API_URL_ENV) or DEFAULT_API_URL,
        bearer_token=token,
        tenant_id=_optional(env, TENANT_ENV) or DEFAULT_TENANT,
        repo_ref=_optional(env, REPO_REF_ENV) or DEFAULT_REPO_REF,
        timeout_seconds=_int_env(env, TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS),
    )


def _require_status(result: HttpResult, expected: int, label: str) -> None:
    if result.status_code != expected:
        body = result.body.decode("utf-8", errors="replace")[:500]
        raise LiveProdProfileE2eError(f"{label} expected HTTP {expected}, got {result.status_code}: {body}")


def _string_field(mapping: Mapping[str, object], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or not value:
        raise LiveProdProfileE2eError(f"response missing string field {field!r}")
    return value


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LiveProdProfileE2eError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise LiveProdProfileE2eError(f"{name} must be positive")
    return parsed


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    _ = argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        print(_json_result({"status": "failed", "error": str(exc)}))
        return 1
    print(_json_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
