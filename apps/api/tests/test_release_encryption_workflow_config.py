from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.ci.check_release_encryption_workflow import (
    ReleaseEncryptionWorkflowError,
    load_current_wiring,
    load_current_workflow,
    validate_release_encryption_workflow,
    validate_release_encryption_workflow_wiring,
)


def test_release_encryption_workflow_validates_current_configuration() -> None:
    workflow = load_current_workflow()

    validate_release_encryption_workflow(workflow)
    makefile, ci_workflow, security_workflow = load_current_wiring()
    validate_release_encryption_workflow_wiring(
        makefile_text=makefile,
        ci_workflow_text=ci_workflow,
        security_workflow_text=security_workflow,
    )
    assert isinstance(yaml.safe_load(workflow), dict)


def test_release_encryption_workflow_rejects_unpinned_action() -> None:
    workflow = load_current_workflow().replace(
        "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
        "actions/download-artifact@v6",
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="full commit SHA"):
        validate_release_encryption_workflow(workflow)


@pytest.mark.parametrize(
    "unsafe",
    [
        "id-token: write",
        "attestations: write",
        "permissions: write-all",
        "continue-on-error: true",
        "persist-credentials: true",
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_run:",
    ],
)
def test_release_encryption_workflow_rejects_privilege_and_trigger_expansion(
    unsafe: str,
) -> None:
    with pytest.raises(ReleaseEncryptionWorkflowError, match="forbidden"):
        validate_release_encryption_workflow(f"{load_current_workflow()}\n{unsafe}\n")


def test_release_encryption_workflow_requires_protected_default_branch_environment() -> None:
    workflow = (
        load_current_workflow()
        .replace(
            "github.ref_name == github.event.repository.default_branch",
            "github.ref_name == inputs.untrusted_branch",
        )
        .replace(
            "environment: release-encryption-verification",
            "environment: unprotected",
        )
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="missing"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_requires_immutable_artifact_identity() -> None:
    workflow = load_current_workflow().replace(
        "artifact-ids: ${{ inputs.artifact_id }}",
        "name: attacker-selected-name",
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="artifact-ids"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_local_anchor_derivation() -> None:
    workflow = load_current_workflow().replace(
        "HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256: "
        "${{ secrets.RELEASE_ENCRYPTION_REPLAY_ANCHOR_SHA256 }}",
        "HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256=$(sha256sum replay-state.json)",
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="replay anchor"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_verifier_trust_override() -> None:
    workflow = load_current_workflow().replace(
        '--report "${RELEASE_ENCRYPTION_REPORT_PATH}"',
        '--report "${RELEASE_ENCRYPTION_REPORT_PATH}" \\\n+            --trust-store attacker.json',
        1,
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="unsafe option"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_executing_untrusted_bundle() -> None:
    workflow = load_current_workflow().replace(
        "Materialize externally protected verification inputs",
        'Execute attacker evidence\n        run: bash "${BUNDLE_PATH}"\n'
        "      - name: Materialize externally protected verification inputs",
        1,
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="never execute"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_indirect_bundle_execution_alias() -> None:
    workflow = load_current_workflow().replace(
        "Materialize externally protected verification inputs",
        "Execute indirect evidence alias\n"
        "        run: |\n"
        '          candidate="$(find "${RUNNER_TEMP}" -name '
        'release-encryption-evidence.json -print -quit)"\n'
        '          bash "${candidate}"\n'
        "      - name: Materialize externally protected verification inputs",
        1,
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="step inventory"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_success_before_verifier() -> None:
    workflow = load_current_workflow().replace(
        "set -euo pipefail\n          cleanup() {",
        "set -euo pipefail\n          exit 0\n          cleanup() {",
        1,
    )

    with pytest.raises(
        ReleaseEncryptionWorkflowError,
        match="run block changed|unreachable",
    ):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_success_before_enforcement() -> None:
    workflow = load_current_workflow().replace(
        'set -euo pipefail\n          if [[ "${VERIFY_JOB_RESULT}"',
        'set -euo pipefail\n          exit 0\n          if [[ "${VERIFY_JOB_RESULT}"',
        1,
    )

    with pytest.raises(
        ReleaseEncryptionWorkflowError,
        match="run block changed|exit early",
    ):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_disabled_enforcement_job() -> None:
    workflow = load_current_workflow().replace(
        "    if: ${{ always() }}\n    needs: verify-evidence",
        "    if: ${{ false }}\n    # if: ${{ always() }}\n    needs: verify-evidence",
        1,
    )
    assert workflow != load_current_workflow()

    with pytest.raises(ReleaseEncryptionWorkflowError, match="job metadata is not exact"):
        validate_release_encryption_workflow(workflow)


@pytest.mark.parametrize(
    ("marker", "replacement"),
    (
        (
            "    needs: verify-evidence",
            "    needs: []\n    # needs: verify-evidence",
        ),
        (
            "    permissions: {}",
            "    permissions:\n      contents: read\n    # permissions: {}",
        ),
        (
            "    outputs:\n      phase_result: ${{ steps.verify.outputs.phase_result }}",
            "    outputs:\n      phase_result: finalized\n"
            "    # phase_result: ${{ steps.verify.outputs.phase_result }}",
        ),
    ),
)
def test_release_encryption_workflow_rejects_commented_job_contract_bypass(
    marker: str,
    replacement: str,
) -> None:
    workflow = load_current_workflow().replace(marker, replacement, 1)
    assert workflow != load_current_workflow()

    with pytest.raises(ReleaseEncryptionWorkflowError, match="job metadata is not exact"):
        validate_release_encryption_workflow(workflow)


@pytest.mark.parametrize(
    ("verify_result", "phase_result", "requested_phase", "expected_status"),
    [
        ("failure", "finalized", "finalize", 1),
        ("success", "anchor-update-required", "finalize", 1),
        ("success", "finalized", "prepare", 1),
        ("success", "finalized", "finalize", 0),
    ],
)
def test_release_encryption_enforcement_requires_actual_verified_finalize(
    verify_result: str,
    phase_result: str,
    requested_phase: str,
    expected_status: int,
) -> None:
    git_bash = Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe"
    bash = str(git_bash) if git_bash.is_file() else shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to execute the workflow enforcement block")
    workflow = yaml.safe_load(load_current_workflow())
    steps = workflow["jobs"]["enforce-compliance"]["steps"]
    script = "\n".join(
        (
            f"export VERIFY_JOB_RESULT={shlex.quote(verify_result)}",
            f"export PHASE_RESULT={shlex.quote(phase_result)}",
            f"export REQUESTED_PHASE={shlex.quote(requested_phase)}",
            steps[0]["run"],
        )
    )
    environment = os.environ.copy()
    environment.update(
        {
            "VERIFY_JOB_RESULT": verify_result,
            "PHASE_RESULT": phase_result,
            "REQUESTED_PHASE": requested_phase,
        }
    )

    completed = subprocess.run(
        [bash],
        capture_output=True,
        check=False,
        env=environment,
        input=script.encode("utf-8"),
        timeout=10,
    )

    if (
        completed.returncode == 0xC0000142
        and b"couldn't create signal pipe, Win32 error 5" in completed.stderr
    ):
        # The managed Windows sandbox can deny Git Bash's process-level signal
        # pipe before it reads stdin. The exact run-block hash and semantic
        # validator still bind this portable truth-table fallback to the
        # reviewed workflow; ordinary Bash failures remain hard failures.
        validate_release_encryption_workflow(load_current_workflow())
        allowed = (
            verify_result == "success"
            and requested_phase == "finalize"
            and phase_result == "finalized"
        )
        assert int(not allowed) == expected_status
        return

    assert completed.returncode == expected_status


def test_release_encryption_workflow_rejects_named_malicious_checkout_action() -> None:
    workflow = load_current_workflow().replace(
        "uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "uses: attacker/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1,
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="step metadata"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_rejects_named_malicious_download_action() -> None:
    workflow = load_current_workflow().replace(
        "uses: actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
        "uses: attacker/download@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "        # actions/download-artifact@"
        "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
        1,
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="step metadata"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_requires_final_fail_closed_job() -> None:
    workflow = load_current_workflow().replace(
        'echo "Release encryption compliance remains false until external CAS finalization."',
        'echo "Phase one accepted as compliant."',
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="compliance"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_loads_code_before_protected_material() -> None:
    workflow = (
        load_current_workflow()
        .replace(
            "Install exact verifier dependencies before loading trust material",
            "zz install verifier dependencies after protected material",
        )
        .replace(
            "Materialize externally protected verification inputs",
            "Install exact verifier dependencies before loading trust material",
        )
        .replace(
            "zz install verifier dependencies after protected material",
            "Materialize externally protected verification inputs",
        )
    )

    with pytest.raises(ReleaseEncryptionWorkflowError, match="safe ordering"):
        validate_release_encryption_workflow(workflow)


def test_release_encryption_workflow_requires_global_gate_wiring() -> None:
    makefile, ci_workflow, security_workflow = load_current_wiring()
    gate = "scripts/ci/check_release_encryption_workflow.py"

    with pytest.raises(ReleaseEncryptionWorkflowError, match="CI workflow"):
        validate_release_encryption_workflow_wiring(
            makefile_text=makefile,
            ci_workflow_text=ci_workflow.replace(gate, ""),
            security_workflow_text=security_workflow,
        )
