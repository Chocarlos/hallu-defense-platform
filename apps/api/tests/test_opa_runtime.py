from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO

import pytest

import hallu_defense.config as config_module
from hallu_defense.config import (
    OpaConfigurationError,
    Settings,
    validate_opa_settings,
)
from hallu_defense.domain.models import PolicyEvaluationRequest, RiskLevel, VerdictAction
from hallu_defense.services.opa import (
    OPA_MAX_INPUT_BYTES,
    OPA_MAX_OUTPUT_BYTES,
    OpaPolicyEvaluationError,
    OpaPolicyEvaluator,
)
from hallu_defense.services.policy import PolicyEngine, VerifiedPolicyContext


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "policy_version": "opa-runtime-test",
        "auth_required": False,
        "allowed_workspace": tmp_path,
        "max_command_seconds": 5,
        "max_output_chars": 1000,
        "opa_enabled": True,
        "opa_policy_dir": tmp_path,
        "opa_timeout_seconds": 1,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _decision_stdout(**overrides: object) -> str:
    decision: dict[str, object] = {
        "allowed": False,
        "action": "block",
        "policy_version": "opa-access-risk-approval-v1",
        "matched_rules": ["cross_tenant_access_denied"],
        "explanation": "Request tenant does not match the target resource tenant.",
    }
    decision.update(overrides)
    return json.dumps(
        {"result": [{"expressions": [{"value": decision}]}]},
        separators=(",", ":"),
    )


class StaticProcessEvaluator(OpaPolicyEvaluator):
    def __init__(
        self,
        settings: Settings,
        *,
        completed: subprocess.CompletedProcess[str] | None = None,
        error: BaseException | None = None,
    ) -> None:
        super().__init__(settings)
        self._completed = completed
        self._error = error
        self.input_text: str | None = None

    def _resolve_opa_path(self) -> str | None:
        return "opa"

    def _run_opa(self, opa_path: str, input_text: str) -> subprocess.CompletedProcess[str]:
        del opa_path
        self.input_text = input_text
        if self._error is not None:
            raise self._error
        assert self._completed is not None
        return self._completed


def _request(**overrides: object) -> PolicyEvaluationRequest:
    values: dict[str, object] = {
        "subject": "agent-a",
        "action": "read",
        "resource": "doc-a",
        "risk_level": RiskLevel.LOW,
        "attributes": {},
    }
    values.update(overrides)
    return PolicyEvaluationRequest(**values)  # type: ignore[arg-type]


def test_missing_opa_executable_fails_closed_without_exposing_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "private-opa-location"
    settings = _settings(tmp_path, opa_path=str(missing_path))
    evaluator = OpaPolicyEvaluator(settings)

    with pytest.raises(OpaPolicyEvaluationError) as exc_info:
        evaluator.evaluate(_request(), trace_id="tr_missing_opa", tenant_id="tenant-a")

    assert str(missing_path) not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    response = PolicyEngine(settings, opa_evaluator=evaluator).evaluate(
        _request(),
        trace_id="tr_missing_opa_engine",
        tenant_id="tenant-a",
    )
    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["opa_policy_evaluation_failed"]
    assert response.explanation == "OPA policy evaluation failed closed."


def test_opa_rejects_cross_subject_verified_context_before_execution(
    tmp_path: Path,
) -> None:
    evaluator = StaticProcessEvaluator(
        _settings(tmp_path),
        completed=subprocess.CompletedProcess(
            args=["opa"],
            returncode=0,
            stdout=_decision_stdout(),
            stderr="",
        ),
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-b",
        action="read",
        resource="doc-a",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.LOW,
        definition_known=True,
        definition_version="read.v1",
        approval_granted=True,
        approval_binding_valid=True,
        approval_id="apr-agent-b",
    )

    with pytest.raises(OpaPolicyEvaluationError, match="did not match"):
        evaluator.evaluate(
            _request(subject="agent-a"),
            trace_id="tr_cross_subject",
            tenant_id="tenant-a",
            verified_context=context,
        )

    assert evaluator.input_text is None


def test_nonzero_exit_and_malicious_stderr_are_redacted(tmp_path: Path) -> None:
    malicious = "stderr-redaction-marker-opa-diagnostic"
    evaluator = StaticProcessEvaluator(
        _settings(tmp_path),
        completed=subprocess.CompletedProcess(
            args=["opa"],
            returncode=2,
            stdout="",
            stderr=malicious,
        ),
    )

    with pytest.raises(OpaPolicyEvaluationError) as exc_info:
        evaluator.evaluate(_request(), trace_id="tr_opa_stderr", tenant_id="tenant-a")

    assert str(exc_info.value) == "OPA evaluation failed."
    assert malicious not in str(exc_info.value)
    response = PolicyEngine(_settings(tmp_path), opa_evaluator=evaluator).evaluate(
        _request(),
        trace_id="tr_opa_stderr_engine",
        tenant_id="tenant-a",
    )
    assert malicious not in response.explanation


@pytest.mark.parametrize(
    "stdout",
    [
        "malformed-output-redaction-marker",
        "x" * (OPA_MAX_OUTPUT_BYTES + 1),
    ],
    ids=("malformed", "oversized"),
)
def test_malformed_or_oversized_stdout_fails_closed_without_raw_output(
    tmp_path: Path,
    stdout: str,
) -> None:
    evaluator = StaticProcessEvaluator(
        _settings(tmp_path),
        completed=subprocess.CompletedProcess(
            args=["opa"],
            returncode=0,
            stdout=stdout,
            stderr="",
        ),
    )

    with pytest.raises(OpaPolicyEvaluationError) as exc_info:
        evaluator.evaluate(_request(), trace_id="tr_opa_output", tenant_id="tenant-a")

    assert stdout[:32] not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "decision_overrides",
    [
        {"allowed": True, "action": "block"},
        {"matched_rules": ["rule with spaces"]},
        {"policy_version": "../../private"},
        {"explanation": "unsafe\nmultiline"},
    ],
)
def test_opa_decision_schema_rejects_inconsistent_or_unbounded_fields(
    tmp_path: Path,
    decision_overrides: dict[str, object],
) -> None:
    evaluator = StaticProcessEvaluator(
        _settings(tmp_path),
        completed=subprocess.CompletedProcess(
            args=["opa"],
            returncode=0,
            stdout=_decision_stdout(**decision_overrides),
            stderr="",
        ),
    )

    with pytest.raises(OpaPolicyEvaluationError):
        evaluator.evaluate(_request(), trace_id="tr_opa_schema", tenant_id="tenant-a")


def test_opa_uses_stdin_private_bounded_outputs_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setenv("OPA_PARENT_MARKER", "must-not-reach-child")

    def fake_run(
        args: list[str],
        *,
        input: bytes,
        stdout: BinaryIO,
        stderr: BinaryIO,
        check: bool,
        timeout: int,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(
            {
                "args": args,
                "input": input,
                "check": check,
                "timeout": timeout,
                "env": dict(env),
            }
        )
        if os.name != "nt":
            assert stat.S_IMODE(os.fstat(stdout.fileno()).st_mode) == 0o600
            assert stat.S_IMODE(os.fstat(stderr.fileno()).st_mode) == 0o600
        stdout.write(_decision_stdout().encode("utf-8"))
        stderr.write(b"diagnostic-redaction-marker-that-must-not-be-returned")
        return subprocess.CompletedProcess(args=args, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    evaluator = OpaPolicyEvaluator(
        _settings(tmp_path, opa_path=str(Path(sys.executable).resolve()))
    )
    response = evaluator.evaluate(
        _request(attributes={"private_input": "sensitive-input-value"}),
        trace_id="tr_opa_stdin",
        tenant_id="tenant-a",
    )

    assert response is not None and response.allowed is False
    assert len(calls) == 1
    args = calls[0]["args"]
    assert isinstance(args, list)
    assert "--stdin-input" in args
    assert "--input" not in args
    input_payload = json.loads(calls[0]["input"])
    assert set(input_payload) == {"verified"}
    assert input_payload["verified"]["identity"] == {
        "subject_id": "agent-a",
        "tenant_id": "tenant-a",
    }
    assert "sensitive-input-value" not in calls[0]["input"].decode("utf-8")
    assert "OPA_PARENT_MARKER" not in calls[0]["env"]


def test_opa_timeout_and_input_limit_fail_without_causal_payload(tmp_path: Path) -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=["opa"],
        timeout=1,
        output="sensitive-input-value",
        stderr="sensitive-diagnostic-value",
    )
    timed_out = StaticProcessEvaluator(_settings(tmp_path), error=timeout)

    with pytest.raises(OpaPolicyEvaluationError) as timeout_error:
        timed_out.evaluate(_request(), trace_id="tr_opa_timeout", tenant_id="tenant-a")
    assert timeout_error.value.__cause__ is None
    assert "sensitive" not in str(timeout_error.value)

    oversized = StaticProcessEvaluator(
        _settings(tmp_path),
        completed=subprocess.CompletedProcess(
            args=["opa"],
            returncode=0,
            stdout=_decision_stdout(),
            stderr="",
        ),
    )
    with pytest.raises(OpaPolicyEvaluationError, match="input limit"):
        oversized._encode_input({"payload": "x" * (OPA_MAX_INPUT_BYTES + 1)})
    assert oversized.input_text is None


def test_production_opa_config_requires_enabled_absolute_executable_and_policy_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled = _settings(
        tmp_path,
        environment="production",
        opa_enabled=False,
        opa_path=None,
        opa_policy_dir=tmp_path / "missing",
    )
    with pytest.raises(OpaConfigurationError) as disabled_error:
        validate_opa_settings(disabled)
    assert "OPA_ENABLED=true" in str(disabled_error.value)
    assert "OPA_PATH" in str(disabled_error.value)

    valid = _settings(
        tmp_path,
        environment="production",
        opa_enabled=True,
        opa_path=str(Path(sys.executable).resolve()),
        opa_policy_dir=tmp_path,
    )
    # Portable unit-test fixtures cannot be made root-owned on every runner.
    # The dedicated POSIX test below and the real non-root image smoke cover
    # the production permission boundary.
    monkeypatch.setattr(config_module, "POSIX_OPA_PERMISSION_CHECKS", False)
    validate_opa_settings(valid)


def test_production_opa_config_rejects_mutable_posix_runtime_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opa_path = tmp_path / "opa"
    opa_path.write_bytes(b"not-an-actual-opa-binary")
    opa_path.chmod(0o777)
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.rego"
    policy_file.write_text("package test\n", encoding="utf-8")
    policy_dir.chmod(0o777)
    policy_file.chmod(0o666)
    monkeypatch.setattr(config_module, "POSIX_OPA_PERMISSION_CHECKS", True)

    with pytest.raises(OpaConfigurationError) as error:
        validate_opa_settings(
            _settings(
                tmp_path,
                environment="production",
                opa_enabled=True,
                opa_path=str(opa_path.resolve()),
                opa_policy_dir=policy_dir.resolve(),
            )
        )

    message = str(error.value)
    assert "write mode bits disabled" in message
    assert str(tmp_path) not in message


def test_local_disabled_opa_keeps_python_policy_fallback(tmp_path: Path) -> None:
    settings = _settings(tmp_path, opa_enabled=False, opa_path=None)
    evaluator = OpaPolicyEvaluator(settings)
    engine = PolicyEngine(settings, opa_evaluator=evaluator)

    response = engine.evaluate(
        _request(risk_level=RiskLevel.HIGH),
        trace_id="tr_local_python_fallback",
        tenant_id="tenant-a",
    )

    assert response.action is VerdictAction.REQUIRE_HUMAN_REVIEW
    assert response.matched_rules == ["high_risk_requires_human_review"]
