from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from typing import TYPE_CHECKING

from hallu_defense.config import Settings, validate_opa_settings
from hallu_defense.domain.models import (
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    VerdictAction,
)

if TYPE_CHECKING:
    from hallu_defense.services.policy import VerifiedPolicyContext

OPA_DECISION_QUERY = "data.hallucination_defense.policy.decision"
OPA_MAX_INPUT_BYTES = 256 * 1024
OPA_MAX_OUTPUT_BYTES = 64 * 1024
OPA_MAX_MATCHED_RULES = 64
OPA_MAX_RULE_LENGTH = 128
OPA_MAX_POLICY_VERSION_LENGTH = 128
OPA_MAX_EXPLANATION_LENGTH = 2048
OPA_RULE_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]*$")
OPA_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class OpaPolicyEvaluationError(RuntimeError):
    pass


class OpaPolicyEvaluator:
    def __init__(self, settings: Settings) -> None:
        validate_opa_settings(settings)
        self._settings = settings

    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
        *,
        verified_context: VerifiedPolicyContext | None = None,
    ) -> PolicyEvaluationResponse | None:
        if not self._settings.opa_enabled:
            return None

        opa_path = self._resolve_opa_path()
        if opa_path is None:
            raise OpaPolicyEvaluationError("OPA executable is unavailable.")

        if verified_context is None:
            # Direct internal callers receive the same restrictive conversion as
            # the public policy endpoint. Authorization and command-evidence
            # assertions in request.attributes are never forwarded to Rego.
            from hallu_defense.services.policy import VerifiedPolicyContext

            verified_context = VerifiedPolicyContext.from_public_request(
                request,
                tenant_id=tenant_id,
                subject_id=None,
            )
        if not verified_context.matches_request(
            request,
            tenant_id=tenant_id,
            subject_id=None,
        ):
            raise OpaPolicyEvaluationError("Verified policy context did not match the request.")
        raw_decision = self._evaluate_with_opa(
            opa_path,
            self._build_input(verified_context),
        )
        return self._to_response(raw_decision, trace_id)

    def _resolve_opa_path(self) -> str | None:
        if self._settings.opa_path:
            return self._settings.opa_path
        return shutil.which("opa")

    def _evaluate_with_opa(self, opa_path: str, input_payload: dict[str, object]) -> dict[str, object]:
        input_text = self._encode_input(input_payload)
        try:
            completed = self._run_opa(opa_path, input_text)
        except subprocess.TimeoutExpired:
            raise OpaPolicyEvaluationError("OPA evaluation timed out.") from None
        except (FileNotFoundError, PermissionError, OSError, subprocess.SubprocessError):
            raise OpaPolicyEvaluationError("OPA executable is unavailable.") from None

        if completed.returncode != 0:
            raise OpaPolicyEvaluationError("OPA evaluation failed.")

        if len(completed.stdout.encode("utf-8")) > OPA_MAX_OUTPUT_BYTES:
            raise OpaPolicyEvaluationError("OPA response exceeded the output limit.")

        return self._extract_decision(completed.stdout)

    def _run_opa(self, opa_path: str, input_text: str) -> subprocess.CompletedProcess[str]:
        args = [
            opa_path,
            "eval",
            "--format",
            "json",
            "--data",
            str(self._settings.opa_policy_dir),
            "--stdin-input",
            OPA_DECISION_QUERY,
        ]
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
            mode="w+b"
        ) as stderr_file:
            _set_private_permissions(stdout_file.fileno())
            _set_private_permissions(stderr_file.fileno())
            completed = subprocess.run(
                args,
                input=input_text.encode("utf-8"),
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                timeout=self._settings.opa_timeout_seconds,
                env=_minimal_subprocess_environment(),
            )
            if _file_size(stdout_file.fileno()) > OPA_MAX_OUTPUT_BYTES:
                raise OpaPolicyEvaluationError("OPA response exceeded the output limit.")
            if _file_size(stderr_file.fileno()) > OPA_MAX_OUTPUT_BYTES:
                raise OpaPolicyEvaluationError("OPA diagnostic output exceeded the output limit.")
            stdout_file.seek(0)
            raw_stdout = stdout_file.read(OPA_MAX_OUTPUT_BYTES + 1)
        try:
            stdout = raw_stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise OpaPolicyEvaluationError("OPA returned invalid UTF-8 output.") from None
        return subprocess.CompletedProcess(
            args=args,
            returncode=completed.returncode,
            stdout=stdout,
            stderr="",
        )

    def _encode_input(self, input_payload: dict[str, object]) -> str:
        try:
            input_text = json.dumps(
                input_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError):
            raise OpaPolicyEvaluationError("OPA input could not be encoded.") from None
        if len(input_text.encode("utf-8")) > OPA_MAX_INPUT_BYTES:
            raise OpaPolicyEvaluationError("OPA input exceeded the input limit.")
        return input_text

    def _build_input(
        self,
        verified_context: VerifiedPolicyContext,
    ) -> dict[str, object]:
        return verified_context.to_opa_input()

    def _extract_decision(self, stdout: str) -> dict[str, object]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            raise OpaPolicyEvaluationError("OPA returned invalid JSON.") from None

        if not isinstance(payload, dict):
            raise OpaPolicyEvaluationError("OPA response must be an object.")

        result = payload.get("result")
        if not isinstance(result, list) or len(result) != 1:
            raise OpaPolicyEvaluationError("OPA response did not include a decision result.")

        first = result[0]
        if not isinstance(first, dict):
            raise OpaPolicyEvaluationError("OPA result entry must be an object.")

        expressions = first.get("expressions")
        if not isinstance(expressions, list) or len(expressions) != 1:
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
        if (
            not isinstance(matched_rules, list)
            or len(matched_rules) > OPA_MAX_MATCHED_RULES
            or not all(
                isinstance(rule, str)
                and len(rule) <= OPA_MAX_RULE_LENGTH
                and OPA_RULE_RE.fullmatch(rule) is not None
                for rule in matched_rules
            )
        ):
            raise OpaPolicyEvaluationError("OPA decision matched_rules must be a string array.")

        policy_version = decision.get("policy_version")
        explanation = decision.get("explanation")
        if (
            not isinstance(policy_version, str)
            or len(policy_version) > OPA_MAX_POLICY_VERSION_LENGTH
            or OPA_POLICY_VERSION_RE.fullmatch(policy_version) is None
        ):
            raise OpaPolicyEvaluationError("OPA decision policy_version is invalid.")
        if (
            not isinstance(explanation, str)
            or not explanation
            or len(explanation) > OPA_MAX_EXPLANATION_LENGTH
            or any(ord(character) < 32 and character not in {"\t"} for character in explanation)
        ):
            raise OpaPolicyEvaluationError("OPA decision explanation is invalid.")
        try:
            verdict_action = VerdictAction(action)
        except ValueError:
            raise OpaPolicyEvaluationError("OPA decision action is unsupported.") from None
        if allowed != (verdict_action is VerdictAction.ALLOW):
            raise OpaPolicyEvaluationError("OPA decision allowed/action fields are inconsistent.")

        return PolicyEvaluationResponse(
            trace_id=trace_id,
            allowed=allowed,
            action=verdict_action,
            policy_version=policy_version,
            matched_rules=matched_rules,
            explanation=explanation,
        )

def _set_private_permissions(file_descriptor: int) -> None:
    if os.name == "nt":
        return
    fchmod = getattr(os, "fchmod", None)
    if not callable(fchmod):
        raise OpaPolicyEvaluationError("OPA output permissions could not be secured.")
    try:
        fchmod(file_descriptor, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        raise OpaPolicyEvaluationError(
            "OPA output permissions could not be secured."
        ) from None


def _file_size(file_descriptor: int) -> int:
    return os.fstat(file_descriptor).st_size


def _minimal_subprocess_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR"):
        value = os.getenv(name)
        if value:
            environment[name] = value
    return environment
