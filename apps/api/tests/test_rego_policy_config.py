from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci import check_rego_policy as gate


def test_committed_rego_modules_are_v1_compatible_and_ci_uses_opa_1() -> None:
    gate.main()

    workflow = (gate.ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    runner = (gate.ROOT / "scripts" / "ci" / "run_policy_tests.py").read_text(
        encoding="utf-8"
    )

    assert "version: 1.18.2" in workflow
    assert 'run([opa, "check", "--strict", OPA_TEST_TARGET])' in runner


def test_rego_gate_rejects_module_without_v1_import() -> None:
    module = gate.ROOT / "legacy.rego"

    with pytest.raises(SystemExit, match=r"must import rego\.v1"):
        gate.require_rego_v1(module, "package hallucination_defense.policy\n")


def test_rego_gate_accepts_exact_v1_import(tmp_path: Path) -> None:
    module = tmp_path / "policy.rego"

    gate.require_rego_v1(
        module,
        "package hallucination_defense.policy\n\nimport rego.v1\n",
    )
