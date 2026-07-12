from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "verify-release-encryption.yml"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
GATE_PATH = "scripts/ci/check_release_encryption_workflow.py"

REMOTE_ACTION_RE = re.compile(
    r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
    re.MULTILINE,
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERIFIER_INVOCATION_RE = re.compile(
    r"python scripts/ci/verify_release_encryption_evidence\.py\s+"
    r"\\\s*\n\s*--bundle \"\$\{BUNDLE_PATH\}\"\s+"
    r"\\\s*\n\s*--report \"\$\{RELEASE_ENCRYPTION_REPORT_PATH\}\""
)
UNTRUSTED_EXECUTION_LINE_RE = re.compile(
    r"(?im)^(?=[^\n]*(?:\$\{?BUNDLE_PATH\}?|\$\{?bundle_path\}?|"
    r"untrusted-release-encryption-artifact))"
    r"(?=[^\n]*(?:\b(?:bash|sh|python|node|source|eval|exec)\b|"
    r"chmod\s+\+x|\$\(|`))[^\n]*$"
)
EXPECTED_STEP_IDENTITIES = {
    "verify-evidence": (
        "Validate protected control-plane invocation",
        "Check out protected verifier control code",
        "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
        "Install exact verifier dependencies before loading trust material",
        "Download the immutable evidence artifact",
        "Require the exact evidence bundle artifact shape",
        "Materialize externally protected verification inputs",
        "Verify evidence and enforce the selected CAS phase contract",
        "Upload authenticated report and replay-state transition",
    ),
    "enforce-compliance": ("Fail closed until the external CAS is finalized",),
}
EXPECTED_JOB_METADATA = {
    "verify-evidence": {
        "if": (
            "github.ref_protected && github.ref_type == 'branch' && "
            "github.ref_name == github.event.repository.default_branch"
        ),
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 20,
        "environment": "release-encryption-verification",
        "outputs": {
            "phase_result": "${{ steps.verify.outputs.phase_result }}",
        },
    },
    "enforce-compliance": {
        "if": "${{ always() }}",
        "needs": "verify-evidence",
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 5,
        "permissions": {},
    },
}
EXPECTED_RUN_SHA256 = {
    "Validate protected control-plane invocation": (
        "44f8d9be5f485426148efe13ce4b48209c5b4483fb09e615b6f4ffa3d126cc81"
    ),
    "Install exact verifier dependencies before loading trust material": (
        "6c5897d2ac6b33d934b95a62e3f36bc020c6b2bd5c6ae7b0b7b206b1519e64da"
    ),
    "Require the exact evidence bundle artifact shape": (
        "5396764c2b791f1f366fb4f883dc311266fe30c9592bc946adc43ae2449601cb"
    ),
    "Materialize externally protected verification inputs": (
        "69b673a623b994e7aee705438cf83aa3d0efd0987e8c1c7e8377ce46ab3f1279"
    ),
    "Verify evidence and enforce the selected CAS phase contract": (
        "6e449e8005d2c8c56d321fd7cc393c8b20887840bf95618aa7e8e7b7092e7436"
    ),
    "Fail closed until the external CAS is finalized": (
        "8aae0aa7465c196a10965105679f063196fc55b98c94719ed94315a34ea9cec7"
    ),
}
EXPECTED_STEP_METADATA_SHA256 = {
    "Validate protected control-plane invocation": "641423ef8e9c30a004546271fcdb632cee4e0a7d7ed1394438e9022d11009d94",
    "Check out protected verifier control code": "9c85c93c324a0a65b6717434af9cc6ac2d04130d9f6f3f4a0c00d1ab7d2a5bdd",
    "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405": "380f70ada59958b900d99f174d440c42277d7ce83468359a794ef3712b65a030",
    "Install exact verifier dependencies before loading trust material": "2abe8949b42bb5048c4c648b1bacb692ec40b03047fef6f0cdac5e252ce1835e",
    "Download the immutable evidence artifact": "5cd5636dde07576f282b99479cfd7845cbea93849bf84bb490a7e9d06b02d1ad",
    "Require the exact evidence bundle artifact shape": "695edbf9eae5ade44b97e309756ef75f6db84a8556b35c77b172918e7e58e463",
    "Materialize externally protected verification inputs": "18d050e9fa5d17a3eba16ccd8a8c073eddef731585800caf8dffd777e93ccdfe",
    "Verify evidence and enforce the selected CAS phase contract": "6be41bb630aac4b8fb908698a7af10f60ba1f2ee299a32b5b44c600cca29ca33",
    "Upload authenticated report and replay-state transition": "8ca160e944a838f3b6757e725e3c2932597a1213538e7b80dd83701f2b8cbe39",
    "Fail closed until the external CAS is finalized": "9e2cc0f153e6178f2251a2738a95bd93b49ea7fcf16938f96e3bdfb2f1d17ff2",
}


class ReleaseEncryptionWorkflowError(ValueError):
    pass


def validate_release_encryption_workflow(workflow_text: str) -> None:
    errors: list[str] = []
    _validate_exact_step_inventory(workflow_text, errors)
    required = {
        "workflow_dispatch:",
        "github.ref_protected && github.ref_type == 'branch'",
        "github.ref_name == github.event.repository.default_branch",
        "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
        'test "${GITHUB_REF_NAME}" = "${DEFAULT_BRANCH}"',
        "environment: release-encryption-verification",
        "contents: read",
        "actions: read",
        "permissions: {}",
        "ref: ${{ github.sha }}",
        "persist-credentials: false",
        "artifact-ids: ${{ inputs.artifact_id }}",
        "run-id: ${{ inputs.artifact_run_id }}",
        "github-token: ${{ github.token }}",
        "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "RELEASE_ENCRYPTION_DEPLOYMENT_SUBJECT_B64",
        "RELEASE_ENCRYPTION_TRUST_STORE_B64",
        "RELEASE_ENCRYPTION_KEYRING_B64",
        "RELEASE_ENCRYPTION_REPLAY_STATE_B64",
        "HALLU_DEFENSE_RELEASE_EXPECTED_TENANT_ID: ${{ secrets.RELEASE_ENCRYPTION_EXPECTED_TENANT_ID }}",
        "HALLU_DEFENSE_RELEASE_EXPECTED_ENVIRONMENT: ${{ secrets.RELEASE_ENCRYPTION_EXPECTED_ENVIRONMENT }}",
        "HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_STORE_ID: ${{ secrets.RELEASE_ENCRYPTION_EXPECTED_TRUST_STORE_ID }}",
        "HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_ROOT_ID: ${{ secrets.RELEASE_ENCRYPTION_EXPECTED_TRUST_ROOT_ID }}",
        "HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256: ${{ secrets.RELEASE_ENCRYPTION_REPLAY_ANCHOR_SHA256 }}",
        "report_authenticator_is_valid(",
        'failure_codes") == ["anchor.update_required"]',
        "replay_sha256 == expected_anchor",
        "needs: verify-evidence",
        "if: ${{ always() }}",
        "PHASE_RESULT: ${{ needs.verify-evidence.outputs.phase_result }}",
        "REQUESTED_PHASE: ${{ inputs.phase }}",
        'echo "Release encryption compliance remains false until external CAS finalization."',
        "if-no-files-found: error",
        "include-hidden-files: false",
        "if: ${{ success() && steps.verify.outputs.phase_result != '' }}",
    }
    for marker in sorted(required):
        if marker not in workflow_text:
            errors.append(f"verification workflow missing `{marker}`")

    actions = REMOTE_ACTION_RE.findall(workflow_text)
    if len(actions) != 4:
        errors.append(
            "verification workflow must use exactly four reviewed remote actions"
        )
    for action, ref in actions:
        if FULL_SHA_RE.fullmatch(ref) is None:
            errors.append(
                f"verification workflow action {action} must use a full commit SHA"
            )

    invocations = VERIFIER_INVOCATION_RE.findall(workflow_text)
    if len(invocations) != 1:
        errors.append(
            "verification workflow must invoke the verifier once with only --bundle and --report"
        )
    verifier_block = _between(
        workflow_text,
        "python scripts/ci/verify_release_encryption_evidence.py",
        "verifier_status=$?",
    )
    for forbidden_option in (
        "--schema",
        "--policy",
        "--trust-store",
        "--keyring",
        "--replay-state",
        "--tenant",
        "--environment",
        "--expected-anchor",
    ):
        if forbidden_option in verifier_block:
            errors.append(
                f"verifier invocation contains unsafe option `{forbidden_option}`"
            )

    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_run:",
        "  push:",
        "id-token:",
        "attestations:",
        "permissions: write-all",
        "continue-on-error:",
        "persist-credentials: true",
        "hashFiles(",
        "github.event.pull_request",
    ):
        if forbidden in workflow_text:
            errors.append(
                f"verification workflow contains forbidden setting `{forbidden}`"
            )

    if UNTRUSTED_EXECUTION_LINE_RE.search(workflow_text):
        errors.append(
            "verification workflow must never execute the untrusted evidence bundle"
        )
    if workflow_text.count('"${BUNDLE_PATH}"') != 1 or "$BUNDLE_PATH" in workflow_text:
        errors.append(
            "verification workflow may pass BUNDLE_PATH only to the exact verifier invocation"
        )

    if re.search(
        r"(?is)HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256\s*="
        r"[^\n]*(?:sha256sum|hashlib|replay-state\.json)",
        workflow_text,
    ):
        errors.append(
            "expected replay anchor must never be derived from local replay state"
        )
    if workflow_text.count("exit 1") < 1:
        errors.append(
            "prepare and failed verification must leave the workflow non-compliant"
        )
    upload_position = workflow_text.find("Upload authenticated report")
    enforcement_position = workflow_text.find(
        "Fail closed until the external CAS is finalized"
    )
    if (
        upload_position >= 0
        and enforcement_position >= 0
        and upload_position > enforcement_position
    ):
        errors.append(
            "phase-one evidence must be uploaded before the final fail-closed job"
        )
    ordered_steps = (
        "Install exact verifier dependencies before loading trust material",
        "Download the immutable evidence artifact",
        "Require the exact evidence bundle artifact shape",
        "Materialize externally protected verification inputs",
        "Verify evidence and enforce the selected CAS phase contract",
        "Upload authenticated report and replay-state transition",
    )
    positions = [workflow_text.find(step) for step in ordered_steps]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append(
            "untrusted artifact and protected trust material steps must preserve safe ordering"
        )

    if errors:
        raise ReleaseEncryptionWorkflowError("\n".join(errors))


def _validate_exact_step_inventory(workflow_text: str, errors: list[str]) -> None:
    try:
        workflow = yaml.safe_load(workflow_text)
        jobs = workflow["jobs"]
    except (KeyError, TypeError, yaml.YAMLError):
        errors.append("verification workflow jobs/steps must be valid YAML mappings")
        return
    if not isinstance(jobs, dict) or set(jobs) != set(EXPECTED_STEP_IDENTITIES):
        errors.append("verification workflow job inventory is not exact")
        return
    _validate_top_level_control_plane(workflow, errors)
    for job_name, expected_identities in EXPECTED_STEP_IDENTITIES.items():
        job = jobs.get(job_name)
        metadata = (
            {key: value for key, value in job.items() if key != "steps"}
            if isinstance(job, dict)
            else None
        )
        if metadata != EXPECTED_JOB_METADATA[job_name]:
            errors.append(f"verification workflow {job_name} job metadata is not exact")
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list) or not all(
            isinstance(step, dict) for step in steps
        ):
            errors.append(f"verification workflow {job_name} steps are invalid")
            continue
        identities = tuple(
            str(step.get("name") or step.get("uses") or "") for step in steps
        )
        if identities != expected_identities:
            errors.append(
                f"verification workflow {job_name} step inventory is not exact"
            )
            continue
        for step, identity in zip(steps, identities, strict=True):
            metadata = {key: value for key, value in step.items() if key != "run"}
            metadata_bytes = json.dumps(
                metadata,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if (
                hashlib.sha256(metadata_bytes).hexdigest()
                != EXPECTED_STEP_METADATA_SHA256[identity]
            ):
                errors.append(
                    f"verification workflow step metadata changed: {identity}"
                )
            expected_hash = EXPECTED_RUN_SHA256.get(identity)
            if expected_hash is None:
                continue
            run = step.get("run")
            if not isinstance(run, str) or not _run_block_matches(run, expected_hash):
                errors.append(f"verification workflow run block changed: {identity}")
        _validate_reachable_enforcement(steps, errors)


def _validate_top_level_control_plane(
    workflow: object,
    errors: list[str],
) -> None:
    if not isinstance(workflow, dict):
        errors.append("verification workflow top-level definition is invalid")
        return
    if set(workflow) != {"name", True, "permissions", "concurrency", "jobs"}:
        errors.append("verification workflow top-level control plane is not exact")
    if workflow.get("name") != "verify release encryption evidence":
        errors.append("verification workflow name is not exact")
    if workflow.get("permissions") != {"contents": "read", "actions": "read"}:
        errors.append("verification workflow top-level permissions are not exact")
    if workflow.get("concurrency") != {
        "group": "release-encryption-anchor",
        "cancel-in-progress": False,
    }:
        errors.append("verification workflow replay concurrency is not exact")
    dispatch = workflow.get(True)
    if not isinstance(dispatch, dict) or set(dispatch) != {"workflow_dispatch"}:
        errors.append("verification workflow dispatch trigger is not exact")
        return
    workflow_dispatch = dispatch.get("workflow_dispatch")
    inputs = (
        workflow_dispatch.get("inputs") if isinstance(workflow_dispatch, dict) else None
    )
    if not isinstance(inputs, dict) or set(inputs) != {
        "artifact_run_id",
        "artifact_id",
        "phase",
    }:
        errors.append("verification workflow dispatch inputs are not exact")
        return
    for input_name in ("artifact_run_id", "artifact_id"):
        definition = inputs.get(input_name)
        if (
            not isinstance(definition, dict)
            or set(definition) != {"description", "required", "type"}
            or not isinstance(definition.get("description"), str)
            or definition.get("required") is not True
            or definition.get("type") != "string"
        ):
            errors.append(f"verification workflow input {input_name} is not exact")
    phase = inputs.get("phase")
    if (
        not isinstance(phase, dict)
        or set(phase) != {"description", "required", "type", "options"}
        or not isinstance(phase.get("description"), str)
        or phase.get("required") is not True
        or phase.get("type") != "choice"
        or phase.get("options") != ["prepare", "finalize"]
    ):
        errors.append("verification workflow input phase is not exact")


def _run_block_matches(value: str, expected: str) -> bool:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() == expected


def _validate_reachable_enforcement(
    steps: list[dict[str, object]],
    errors: list[str],
) -> None:
    by_name = {
        str(step["name"]): step for step in steps if isinstance(step.get("name"), str)
    }
    verify_step = by_name.get(
        "Verify evidence and enforce the selected CAS phase contract"
    )
    if verify_step is not None:
        verify_run = verify_step.get("run")
        if not isinstance(verify_run, str):
            errors.append("verification workflow verifier execution is missing")
        else:
            lines = [line.strip() for line in verify_run.splitlines()]
            invocation_indexes = [
                index
                for index, line in enumerate(lines)
                if line == "python scripts/ci/verify_release_encryption_evidence.py \\"
            ]
            if len(invocation_indexes) != 1:
                errors.append("verification workflow verifier execution is not unique")
            elif any(
                re.fullmatch(r"(?:exit|return)\s+0", line)
                for line in lines[: invocation_indexes[0]]
            ):
                errors.append("verification workflow verifier execution is unreachable")
            for marker in (
                "verifier_status=$?",
                "status == 0",
                'report.get("compliance_asserted") is True',
                'report.get("anchor_finalized") is True',
            ):
                if not any(marker in line for line in lines):
                    errors.append(
                        f"verification workflow verifier contract missing `{marker}`"
                    )

    enforce_step = by_name.get("Fail closed until the external CAS is finalized")
    if enforce_step is not None:
        enforce_run = enforce_step.get("run")
        if not isinstance(enforce_run, str):
            errors.append("verification workflow compliance enforcement is missing")
        else:
            lines = [line.strip() for line in enforce_run.splitlines() if line.strip()]
            exits_zero = [index for index, line in enumerate(lines) if line == "exit 0"]
            exits_one = [index for index, line in enumerate(lines) if line == "exit 1"]
            if_indexes = [
                index for index, line in enumerate(lines) if line.startswith("if [[")
            ]
            fi_indexes = [index for index, line in enumerate(lines) if line == "fi"]
            if not (
                len(exits_zero)
                == len(exits_one)
                == len(if_indexes)
                == len(fi_indexes)
                == 1
                and if_indexes[0] < exits_zero[0] < fi_indexes[0] < exits_one[0]
            ):
                errors.append(
                    "verification workflow compliance enforcement can exit early"
                )
            condition = " ".join(lines)
            for marker in (
                '"${VERIFY_JOB_RESULT}" == "success"',
                '"${REQUESTED_PHASE}" == "finalize"',
                '"${PHASE_RESULT}" == "finalized"',
            ):
                if marker not in condition:
                    errors.append(
                        f"verification workflow enforcement missing `{marker}`"
                    )


def _between(text: str, start: str, end: str) -> str:
    try:
        start_index = text.index(start)
        end_index = text.index(end, start_index)
    except ValueError:
        return ""
    return text[start_index:end_index]


def load_current_workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def validate_release_encryption_workflow_wiring(
    *,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    if "release-encryption-workflow-config:" not in makefile_text:
        errors.append("Makefile must expose release-encryption-workflow-config")
    if GATE_PATH not in makefile_text.partition("security-check:")[2]:
        errors.append("Makefile security-check must run the release encryption gate")
    if GATE_PATH not in ci_workflow_text:
        errors.append("CI workflow must run the release encryption gate")
    if GATE_PATH not in security_workflow_text:
        errors.append("security workflow must run the release encryption gate")
    if errors:
        raise ReleaseEncryptionWorkflowError("\n".join(errors))


def load_current_wiring() -> tuple[str, str, str]:
    return (
        MAKEFILE_PATH.read_text(encoding="utf-8"),
        CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )


def main() -> None:
    validate_release_encryption_workflow(load_current_workflow())
    makefile, ci_workflow, security_workflow = load_current_wiring()
    validate_release_encryption_workflow_wiring(
        makefile_text=makefile,
        ci_workflow_text=ci_workflow,
        security_workflow_text=security_workflow,
    )
    print("Validated protected two-phase release encryption verification workflow.")


if __name__ == "__main__":
    main()
