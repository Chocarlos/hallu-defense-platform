from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    VerdictAction,
)

OPA_DECISION_QUERY = "data.hallucination_defense.policy.decision"


class OpaPolicyEvaluationError(RuntimeError):
    pass


class OpaPolicyEvaluator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
    ) -> PolicyEvaluationResponse | None:
        if not self._settings.opa_enabled:
            return None

        opa_path = self._resolve_opa_path()
        if opa_path is None:
            return None

        raw_decision = self._evaluate_with_opa(opa_path, self._build_input(request, tenant_id))
        return self._to_response(raw_decision, trace_id)

    def _resolve_opa_path(self) -> str | None:
        if self._settings.opa_path:
            return self._settings.opa_path
        return shutil.which("opa")

    def _evaluate_with_opa(self, opa_path: str, input_payload: dict[str, object]) -> dict[str, object]:
        input_path = self._write_input(input_payload)
        try:
            try:
                completed = self._run_opa(opa_path, input_path)
            except subprocess.TimeoutExpired as exc:
                raise OpaPolicyEvaluationError("OPA evaluation timed out.") from exc
        finally:
            input_path.unlink(missing_ok=True)

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "opa exited without stderr"
            raise OpaPolicyEvaluationError(f"OPA evaluation failed: {stderr}")

        return self._extract_decision(completed.stdout)

    def _run_opa(self, opa_path: str, input_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                opa_path,
                "eval",
                "--format",
                "json",
                "--data",
                str(self._settings.opa_policy_dir),
                "--input",
                str(input_path),
                OPA_DECISION_QUERY,
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=self._settings.opa_timeout_seconds,
        )

    def _write_input(self, input_payload: dict[str, object]) -> Path:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
            suffix=".json",
        ) as handle:
            json.dump(input_payload, handle, sort_keys=True)
            return Path(handle.name)

    def _build_input(
        self,
        request: PolicyEvaluationRequest,
        tenant_id: str,
    ) -> dict[str, object]:
        resource_tenant = self._string_attr(request, "resource_tenant_id") or tenant_id
        payload: dict[str, object] = {
            "tenant_id": tenant_id,
            "subject": {
                "id": request.subject,
                "tenant_id": tenant_id,
            },
            "action": request.action.strip().lower(),
            "resource": {
                "id": request.resource,
                "tenant_id": resource_tenant,
            },
            "risk_level": request.risk_level.value,
            "attributes": request.attributes,
        }
        network_policy = self._string_attr(request, "network_policy")
        if network_policy is not None:
            payload["network_policy"] = network_policy
        return payload

    def _extract_decision(self, stdout: str) -> dict[str, object]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise OpaPolicyEvaluationError("OPA returned invalid JSON.") from exc

        if not isinstance(payload, dict):
            raise OpaPolicyEvaluationError("OPA response must be an object.")

        result = payload.get("result")
        if not isinstance(result, list) or not result:
            raise OpaPolicyEvaluationError("OPA response did not include a decision result.")

        first = result[0]
        if not isinstance(first, dict):
            raise OpaPolicyEvaluationError("OPA result entry must be an object.")

        expressions = first.get("expressions")
        if not isinstance(expressions, list) or not expressions:
            raise OpaPolicyEvaluationError("OPA result did not include expressions.")

        expression = expressions[0]
        if not isinstance(expression, dict):
            raise OpaPolicyEvaluationError("OPA expression entry must be an object.")

        value = expression.get("value")
        if not isinstance(value, dict):
            raise OpaPolicyEvaluationError("OPA decision value must be an object.")
        return value

    def _to_response(
        self,
        decision: dict[str, object],
        trace_id: str,
    ) -> PolicyEvaluationResponse:
        action = decision.get("action")
        if not isinstance(action, str):
            raise OpaPolicyEvaluationError("OPA decision action must be a string.")

        allowed = decision.get("allowed")
        if not isinstance(allowed, bool):
            raise OpaPolicyEvaluationError("OPA decision allowed flag must be a boolean.")

        matched_rules = decision.get("matched_rules")
        if not isinstance(matched_rules, list) or not all(
            isinstance(rule, str) for rule in matched_rules
        ):
            raise OpaPolicyEvaluationError("OPA decision matched_rules must be a string array.")

        policy_version = decision.get("policy_version")
        explanation = decision.get("explanation")
        try:
            verdict_action = VerdictAction(action)
        except ValueError as exc:
            raise OpaPolicyEvaluationError(f"OPA decision action is unsupported: {action}") from exc

        return PolicyEvaluationResponse(
            trace_id=trace_id,
            allowed=allowed,
            action=verdict_action,
            policy_version=policy_version if isinstance(policy_version, str) else self._settings.policy_version,
            matched_rules=matched_rules,
            explanation=explanation if isinstance(explanation, str) else "OPA policy decision applied.",
        )

    def _string_attr(self, request: PolicyEvaluationRequest, name: str) -> str | None:
        value = request.attributes.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None
