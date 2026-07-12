from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import tarfile
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = ROOT / "Makefile"
RELEASE_DOC = ROOT / "docs" / "security" / "release-process.md"

REMOTE_ACTION_RE = re.compile(
    r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
    re.MULTILINE,
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RUNTIME_CHECK = "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"
CONTROL_REF_CONDITION = (
    "github.ref_protected && github.ref_type == 'branch' && "
    "github.ref_name == github.event.repository.default_branch && "
    "(github.ref_name == 'main' || github.ref_name == 'master')"
)
BUILD_CONTROL_RUN = f"""set -euo pipefail
[[ "${{RELEASE_TAG}}" =~ {SEMVER_RUNTIME_CHECK} ]]
test "${{GITHUB_REF_PROTECTED}}" = "true"
test "${{GITHUB_REF_TYPE}}" = "branch"
test "${{GITHUB_REF_NAME}}" = "main" -o "${{GITHUB_REF_NAME}}" = "master"
"""
BUILD_HANDOFF_RUN = f"""set -euo pipefail
[[ "${{RELEASE_TAG}}" =~ {SEMVER_RUNTIME_CHECK} ]]
[[ "${{VERIFIED_SOURCE_COMMIT}}" =~ ^[0-9a-f]{{40}}$ ]]
[[ "${{VERIFIED_TAG_OBJECT}}" =~ ^[0-9a-f]{{40}}$ ]]
test "${{GITHUB_REF_PROTECTED}}" = "true"
test "${{GITHUB_REF_TYPE}}" = "branch"
test "${{GITHUB_REF_NAME}}" = "main" -o "${{GITHUB_REF_NAME}}" = "master"
"""
SCAN_HANDOFF_RUN = f"""set -euo pipefail
[[ "${{BUILD_ARTIFACT_ID}}" =~ ^[1-9][0-9]*$ ]]
[[ "${{BUILD_ARTIFACT_DIGEST}}" =~ ^[0-9a-f]{{64}}$ ]]
[[ "${{RELEASE_TAG}}" =~ {SEMVER_RUNTIME_CHECK} ]]
test "${{GITHUB_REF_PROTECTED}}" = "true"
test "${{GITHUB_REF_TYPE}}" = "branch"
test "${{GITHUB_REF_NAME}}" = "main" -o "${{GITHUB_REF_NAME}}" = "master"
"""
ATTEST_HANDOFF_RUN = f"""set -euo pipefail
[[ "${{RELEASE_ARTIFACT_ID}}" =~ ^[1-9][0-9]*$ ]]
[[ "${{RELEASE_ARTIFACT_DIGEST}}" =~ ^[0-9a-f]{{64}}$ ]]
[[ "${{BUILD_ARTIFACT_ID}}" =~ ^[1-9][0-9]*$ ]]
[[ "${{BUILD_ARTIFACT_DIGEST}}" =~ ^[0-9a-f]{{64}}$ ]]
[[ "${{RELEASE_TAG}}" =~ {SEMVER_RUNTIME_CHECK} ]]
test "${{GITHUB_REF_PROTECTED}}" = "true"
test "${{GITHUB_REF_TYPE}}" = "branch"
test "${{GITHUB_REF_NAME}}" = "main" -o "${{GITHUB_REF_NAME}}" = "master"
"""
FINAL_VERDICT_RUN = """set -euo pipefail
if [[ "${VERIFY_TAG_RESULT}" != "success" ||
      "${BUILD_RELEASE_RESULT}" != "success" ||
      "${SCAN_RELEASE_RESULT}" != "success" ||
      "${ATTEST_RELEASE_RESULT}" != "success" ]]; then
  printf 'Release incomplete: verify-tag=%s build-release=%s scan-release=%s attest-release=%s\\n' \\
    "${VERIFY_TAG_RESULT}" "${BUILD_RELEASE_RESULT}" \\
    "${SCAN_RELEASE_RESULT}" "${ATTEST_RELEASE_RESULT}" >&2
  exit 1
fi
"""
EXPECTED_IMAGES = {
    "api": "infra/docker/api.Dockerfile",
    "console": "infra/docker/console.Dockerfile",
    "sandbox": "infra/docker/sandbox.Dockerfile",
    "pgvector": "infra/docker/pgvector.Dockerfile",
    "keycloak": "infra/docker/keycloak.Dockerfile",
    "grafana": "infra/docker/grafana.Dockerfile",
    "opensearch": "infra/docker/opensearch.Dockerfile",
    "seaweedfs": "infra/docker/seaweedfs.Dockerfile",
}
EXPECTED_ACTION_REFS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-python": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
    "actions/setup-node": "48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "actions/attest-build-provenance": "977bb373ede98d70efdf65b84cb5f73e068dcc2a",
    "actions/attest-sbom": "4651f806c01d8637787e274ac3bdf724ef169f34",
}
EXPECTED_GLOBAL_ENV = {
    "GITLEAKS_VERSION": "8.30.1",
    "GITLEAKS_LINUX_X64_SHA256": (
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ),
    "TRIVY_VERSION": "0.72.0",
    "TRIVY_LINUX_X64_SHA256": (
        "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea"
    ),
}
EXPECTED_VERIFY_SUBJECT_RUN_SHA256 = (
    "572cd1fe3d7b2a2824097844b3d125bcefab05aefcd97e8124e0d0b441d9da52"
)
EXPECTED_VERIFY_TAG_RUN_SHA256 = (
    "f0867e77920d104187672dc7ea296fe5804f4462a7a6ea3c0dad6f41c067313f"
)
EXPECTED_SCAN_FINALIZER_RUN_SHA256 = (
    "bd21136efaa9f31416229b52194c6aa814e9e7f5b443782b143e422f6a9ffd30"
)


class ReleaseSecurityConfigError(ValueError):
    pass


def validate_release_security_config(
    *,
    release_workflow_text: str,
    security_workflow_text: str,
    ci_workflow_text: str,
    makefile_text: str,
    release_doc_text: str,
) -> None:
    errors: list[str] = []
    _validate_forbidden_workflow_text(release_workflow_text, errors)
    workflow = _parse_workflow(release_workflow_text, errors)
    if workflow is not None:
        _validate_workflow_shape(workflow, release_workflow_text, errors)
    _validate_remote_actions(release_workflow_text, errors)
    _validate_gate_wiring(
        security_workflow_text=security_workflow_text,
        ci_workflow_text=ci_workflow_text,
        makefile_text=makefile_text,
        errors=errors,
    )
    _validate_documentation(release_doc_text, errors)
    if errors:
        raise ReleaseSecurityConfigError("\n".join(errors))


def _parse_workflow(text: str, errors: list[str]) -> Mapping[str, object] | None:
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f"release workflow must be valid YAML: {exc}")
        return None
    if not isinstance(parsed, Mapping):
        errors.append("release workflow root must be a mapping")
        return None
    return parsed


def _validate_workflow_shape(
    workflow: Mapping[str, object],
    workflow_text: str,
    errors: list[str],
) -> None:
    common_keys: set[object] = {
        "name",
        "permissions",
        "concurrency",
        "env",
        "jobs",
    }
    if set(workflow) not in (common_keys | {"on"}, common_keys | {True}):
        errors.append("release workflow top-level key inventory is not exact")
    if workflow.get("name") != "release" or workflow.get("env") != EXPECTED_GLOBAL_ENV:
        errors.append("release workflow name/tool pin environment is not exact")
    if workflow.get("permissions") != {"contents": "read"}:
        errors.append(
            "release workflow top-level permissions must be contents: read only"
        )
    trigger = workflow.get("on", workflow.get(True))  # type: ignore[call-overload]
    if not isinstance(trigger, Mapping) or set(trigger) != {"workflow_dispatch"}:
        errors.append(
            "release workflow must have workflow_dispatch as its only trigger"
        )
    concurrency = workflow.get("concurrency")
    if concurrency != {
        "group": "release-${{ inputs.release_tag }}",
        "cancel-in-progress": False,
    }:
        errors.append("release workflow must serialize each immutable release tag")
    if workflow_text.count(SEMVER_RUNTIME_CHECK) != 4:
        errors.append(
            "all four release jobs must enforce canonical semantic-version tags at runtime"
        )

    jobs = workflow.get("jobs")
    if not isinstance(jobs, Mapping) or set(jobs) != {
        "verify-tag",
        "build-release",
        "scan-release",
        "attest-release",
        "release-verdict",
    }:
        errors.append(
            "release workflow must contain exactly verify-tag, build-release, "
            "scan-release, attest-release, and release-verdict jobs"
        )
        return
    verify_job = jobs.get("verify-tag")
    build_job = jobs.get("build-release")
    scan_job = jobs.get("scan-release")
    attest_job = jobs.get("attest-release")
    verdict_job = jobs.get("release-verdict")
    if (
        not isinstance(verify_job, Mapping)
        or not isinstance(build_job, Mapping)
        or not isinstance(scan_job, Mapping)
        or not isinstance(attest_job, Mapping)
        or not isinstance(verdict_job, Mapping)
    ):
        errors.append("release jobs must be mappings")
        return
    _validate_verify_tag_job(verify_job, errors)
    _validate_build_job(build_job, errors)
    _validate_scan_job(scan_job, errors)
    _validate_attestation_job(attest_job, errors)
    _validate_release_verdict_job(verdict_job, errors)


def _validate_forbidden_workflow_text(text: str, errors: list[str]) -> None:
    for forbidden in (
        "  push:",
        "pull_request_target:",
        "permissions: write-all",
        "persist-credentials: true",
        "continue-on-error:",
        "--ignore-unfixed",
        "ignore-unfixed: true",
        "packages: write",
        "push-to-registry: true",
    ):
        if forbidden in text:
            errors.append(f"release workflow contains forbidden setting `{forbidden}`")


def _validate_verify_tag_job(job: Mapping[str, object], errors: list[str]) -> None:
    if set(job) != {
        "if",
        "runs-on",
        "timeout-minutes",
        "environment",
        "permissions",
        "outputs",
        "env",
        "steps",
    }:
        errors.append("verify-tag job key inventory is not exact")
    if job.get("if") != CONTROL_REF_CONDITION:
        errors.append("verify-tag protected-ref condition is not exact")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 15:
        errors.append("verify-tag must use the exact trusted runner limits")
    if job.get("environment") != "release":
        errors.append("verify-tag must use the protected release Environment")
    if job.get("permissions") != {"contents": "read"}:
        errors.append("verify-tag permissions must be contents: read only")
    if job.get("outputs") != {
        "source-commit": "${{ steps.verified-tag.outputs.source-commit }}",
        "tag-object": "${{ steps.verified-tag.outputs.tag-object }}",
    }:
        errors.append("verify-tag must export only the peeled commit and tag-object SHA")
    if job.get("env") != {"RELEASE_TAG": "${{ inputs.release_tag }}"}:
        errors.append("verify-tag environment is not exact")
    serialized = yaml.safe_dump(dict(job), sort_keys=False)
    for forbidden in ("id-token", "attestations", "actions/checkout", "container:"):
        if forbidden in serialized:
            errors.append(f"verify-tag must not expose or execute {forbidden}")
    steps = _steps(job, "verify-tag", errors)
    if steps is None:
        return
    _validate_ordered_step_inventory(
        steps,
        label="verify-tag",
        expected=(
            (None, "Validate protected control ref and canonical tag input", "run"),
            (
                "verified-tag",
                "Verify signed tag without checking out subject code",
                "run",
            ),
        ),
        errors=errors,
    )
    _validate_exact_run_step(
        steps,
        label="verify-tag protected-ref validation",
        name="Validate protected control ref and canonical tag input",
        expected=BUILD_CONTROL_RUN,
        errors=errors,
    )
    _validate_step_metadata(
        steps,
        label="verify-tag",
        expected_run_env={
            "verified-tag": {
                "RELEASE_SIGNING_PUBLIC_KEYS_B64": (
                    "${{ secrets.RELEASE_SIGNING_PUBLIC_KEYS_B64 }}"
                ),
                "GITHUB_TOKEN": "${{ github.token }}",
            }
        },
        errors=errors,
    )
    if _action_names(steps):
        errors.append("verify-tag must not invoke any action or checkout subject code")
    if serialized.count("secrets.") != 1:
        errors.append("verify-tag must expose exactly one external public trust bundle")
    verify_step = _step_by_id(steps, "verified-tag")
    if verify_step is None or verify_step.get("env") != {
        "RELEASE_SIGNING_PUBLIC_KEYS_B64": (
            "${{ secrets.RELEASE_SIGNING_PUBLIC_KEYS_B64 }}"
        ),
        "GITHUB_TOKEN": "${{ github.token }}",
    }:
        errors.append("verify-tag must use protected external signing trust roots")
    run = str(verify_step.get("run", "")) if verify_step is not None else ""
    if hashlib.sha256(run.encode("utf-8")).hexdigest() != EXPECTED_VERIFY_TAG_RUN_SHA256:
        errors.append("verify-tag trusted verification run block changed")
    _require(
        run,
        {
            "--with-colons --show-keys",
            "grep -Eq '^(sec|ssb):'",
            "--list-secret-keys",
            "git init --bare",
            '"${control_commit}:refs/release-control/dispatch"',
            'verify-tag "refs/tags/${RELEASE_TAG}"',
            '[[ "${tag_object}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]]',
            "trap cleanup EXIT",
            "rm -rf --",
            "source-commit=%s",
            "tag-object=%s",
        },
        "verify-tag",
        errors,
    )
    _validate_immutable_control_ancestry(
        run,
        label="verify-tag",
        source_variable="source_commit",
        errors=errors,
    )
    for forbidden in (
        "git checkout",
        "git worktree",
        "scripts/",
        "apps/",
        "python ",
        "npm ",
        "docker ",
        "source ",
        "eval ",
        "exec ",
    ):
        if forbidden in run:
            errors.append(f"verify-tag must not execute subject code {forbidden}")


def _validate_build_job(job: Mapping[str, object], errors: list[str]) -> None:
    if set(job) != {
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "outputs",
        "env",
        "steps",
    }:
        errors.append("build-release job key inventory is not exact")
    if job.get("needs") != "verify-tag":
        errors.append("build-release must depend only on successful verify-tag")
    if job.get("permissions") != {"contents": "read"}:
        errors.append("build-release permissions must be contents: read only")
    if "environment" in job:
        errors.append("build-release must not access a protected Environment")
    serialized = yaml.safe_dump(dict(job), sort_keys=False)
    for forbidden in ("id-token", "attestations", "secrets."):
        if forbidden in serialized:
            errors.append(f"build-release must not expose `{forbidden}`")
    if "strategy" in job or "matrix" in serialized:
        errors.append(
            "release images must be built and scanned sequentially, not by matrix"
        )
    _validate_job_env(
        job,
        label="build-release",
        expected={
            "RELEASE_TAG": "${{ inputs.release_tag }}",
            "VERIFIED_SOURCE_COMMIT": (
                "${{ needs.verify-tag.outputs.source-commit }}"
            ),
            "VERIFIED_TAG_OBJECT": "${{ needs.verify-tag.outputs.tag-object }}",
        },
        errors=errors,
    )
    if job.get("runs-on") != "ubuntu-24.04" or not isinstance(
        job.get("timeout-minutes"), int
    ):
        errors.append("build-release must pin ubuntu-24.04 and a numeric timeout")
    if (
        job.get("if")
        != "needs.verify-tag.result == 'success' && " + CONTROL_REF_CONDITION
    ):
        errors.append("build-release verified-tag/protected-ref condition is not exact")
    outputs = job.get("outputs")
    expected_outputs = {
        "build-artifact-id": "${{ steps.build-upload.outputs.artifact-id }}",
        "build-artifact-digest": "${{ steps.build-upload.outputs.artifact-digest }}",
    }
    if outputs != expected_outputs:
        errors.append("build-release must export immutable artifact id and digest only")

    image_rows = _parse_image_rows(job, errors, label="build-release")
    if image_rows != EXPECTED_IMAGES:
        errors.append(
            "build-release must cover all eight current Dockerfiles exactly once"
        )
    steps = _steps(job, "build-release", errors)
    if steps is None:
        return
    _validate_ordered_step_inventory(
        steps,
        label="build-release",
        expected=(
            (None, "Validate protected control ref and verified tag handoff", "run"),
            (None, None, "actions/checkout"),
            ("release-subject", "Bind verified release subject metadata", "run"),
            (None, None, "actions/setup-python"),
            (None, None, "actions/setup-node"),
            (None, "Install exact locked toolchains", "run"),
            (None, "Install pinned Gitleaks", "run"),
            (None, "Run release security gates", "run"),
            (None, "Verify release tests and builds", "run"),
            (None, "Build reproducible package subjects", "run"),
            (
                None,
                "Export all release images as classic Docker archives sequentially",
                "run",
            ),
            (None, "Bind build archives and create build checksums", "run"),
            (
                "build-upload",
                "Upload immutable build artifact envelope",
                "actions/upload-artifact",
            ),
        ),
        errors=errors,
    )
    _validate_exact_run_step(
        steps,
        label="build-release verified tag handoff validation",
        name="Validate protected control ref and verified tag handoff",
        expected=BUILD_HANDOFF_RUN,
        errors=errors,
    )
    _validate_step_metadata(
        steps,
        label="build-release",
        expected_run_env={
            "Build reproducible package subjects": {
                "SOURCE_COMMIT": "${{ steps.release-subject.outputs.source-commit }}",
                "TAG_OBJECT": "${{ steps.release-subject.outputs.tag-object }}",
            },
            "Export all release images as classic Docker archives sequentially": {
                "SOURCE_COMMIT": "${{ steps.release-subject.outputs.source-commit }}"
            },
            "Bind build archives and create build checksums": {
                "SOURCE_COMMIT": "${{ steps.release-subject.outputs.source-commit }}",
                "RELEASE_ROOT": "${{ runner.temp }}/release-build",
            },
        },
        errors=errors,
    )
    actions = _action_names(steps)
    expected_actions = Counter(
        {
            "actions/checkout": 1,
            "actions/setup-python": 1,
            "actions/setup-node": 1,
            "actions/upload-artifact": 1,
        }
    )
    if Counter(actions) != expected_actions:
        errors.append(
            "build-release must use only checkout, setup, and one upload action"
        )
    checkout = _single_action_step(steps, "actions/checkout")
    checkout_inputs = checkout.get("with") if checkout is not None else None
    if not isinstance(checkout_inputs, Mapping) or checkout_inputs != {
        "ref": "${{ env.VERIFIED_SOURCE_COMMIT }}",
        "fetch-depth": 1,
        "fetch-tags": False,
        "persist-credentials": False,
    }:
        errors.append(
            "build-release checkout must fetch only the verified peeled commit"
        )
    setup_python = _single_action_step(steps, "actions/setup-python")
    if setup_python is None or setup_python.get("with") != {
        "python-version": "3.12.13",
        "pip-version": "26.1.2",
    }:
        errors.append("build-release Python toolchain action inputs are not exact")
    setup_node = _single_action_step(steps, "actions/setup-node")
    if setup_node is None or setup_node.get("with") != {
        "node-version": "24.18.0",
        "cache": "npm",
    }:
        errors.append("build-release Node toolchain action inputs are not exact")

    run_text = _run_text(steps)
    _require(
        run_text,
        {
            'test "$(git rev-parse HEAD)" = "${VERIFIED_SOURCE_COMMIT}"',
            "python scripts/ci/run_gitleaks.py",
            "python scripts/ci/check_release_security_config.py",
            "python scripts/ci/check_encryption_config.py",
            "python scripts/ci/check_container_scan_config.py",
            'test "$("${RUNNER_TEMP}/gitleaks-bin/gitleaks" version)" = "${GITLEAKS_VERSION}"',
            "sha256sum --check",
            'python scripts/ci/build_reproducible_wheel.py --output-dir "${release_root}"',
            "${RUNNER_TEMP}/release-build",
            "${release_root}/RELEASE_SOURCE",
            "${release_root}/api-runtime.cdx.json",
            "${release_root}/api-runtime-lock.txt",
            "${release_root}/node-runtime.cdx.json",
            "${release_root}/node-runtime-lock.json",
            "docker buildx build",
            '--tag "${image_ref}"',
            "type=docker,oci-mediatypes=false,compression=uncompressed,force-compression=true",
            "name=${image_ref},dest=${release_root}/images/${name}.docker.tar",
            "test ! -e release",
            "test ! -e scan-input",
            "test ! -e attestation-input",
            'done <<< "${RELEASE_IMAGE_ROWS}"',
            "buildx-type-docker-v1-uncompressed",
            "docker-image-config",
            ".image-config-digest",
            'cd "${RELEASE_ROOT}"',
            "find . -type f ! -name BUILD_SHA256SUMS",
            "xargs -0 sha256sum > BUILD_SHA256SUMS",
        },
        "build-release",
        errors,
    )
    if re.search(r"(?m)(?<![>&])&\s*$", run_text):
        errors.append("release Docker builds/saves must not run in the background")
    for forbidden in (
        "xargs -P",
        "parallel ",
        "trivy image",
        "--ignore-unfixed",
    ):
        if forbidden in run_text:
            errors.append(
                f"build-release contains forbidden parallel/static scan marker `{forbidden}`"
            )

    upload = _step_by_id(steps, "build-upload")
    if upload is None or "if" in upload:
        errors.append("build artifact upload must be success-only")
    elif upload.get("uses") != (
        "actions/upload-artifact@" + EXPECTED_ACTION_REFS["actions/upload-artifact"]
    ):
        errors.append("build artifact upload action pin is invalid")
    else:
        upload_inputs = upload.get("with")
        required_upload = {
            "name": "hallu-defense-${{ env.RELEASE_TAG }}-build-${{ github.run_id }}",
            "path": "${{ runner.temp }}/release-build/",
            "if-no-files-found": "error",
            "include-hidden-files": False,
            "compression-level": 1,
            "overwrite": False,
            "retention-days": 1,
        }
        if upload_inputs != required_upload:
            errors.append(
                "build artifact upload must preserve exact immutable subjects"
            )


def _validate_scan_job(job: Mapping[str, object], errors: list[str]) -> None:
    if set(job) != {
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "outputs",
        "env",
        "steps",
    }:
        errors.append("scan-release job key inventory is not exact")
    if job.get("needs") != "build-release":
        errors.append("scan-release must depend only on successful build-release")
    if job.get("permissions") != {}:
        errors.append("scan-release must have no repository token permissions")
    if "environment" in job:
        errors.append("scan-release must not access a protected Environment")
    serialized = yaml.safe_dump(dict(job), sort_keys=False)
    for forbidden in ("id-token", "attestations", "secrets."):
        if forbidden in serialized:
            errors.append(f"scan-release must not expose `{forbidden}`")
    if "strategy" in job or "matrix" in serialized:
        errors.append("release archive scans must run sequentially, not by matrix")
    _validate_job_env(
        job,
        label="scan-release",
        expected={
            "RELEASE_TAG": "${{ inputs.release_tag }}",
            "BUILD_ARTIFACT_ID": (
                "${{ needs.build-release.outputs.build-artifact-id }}"
            ),
            "BUILD_ARTIFACT_DIGEST": (
                "${{ needs.build-release.outputs.build-artifact-digest }}"
            ),
        },
        errors=errors,
    )
    if job.get("runs-on") != "ubuntu-24.04" or not isinstance(
        job.get("timeout-minutes"), int
    ):
        errors.append("scan-release must pin ubuntu-24.04 and a numeric timeout")
    if (
        job.get("if")
        != "needs.build-release.result == 'success' && " + CONTROL_REF_CONDITION
    ):
        errors.append("scan-release dependency/protected-ref condition is not exact")
    outputs = job.get("outputs")
    expected_outputs = {
        "release-artifact-id": "${{ steps.scan-upload.outputs.artifact-id }}",
        "release-artifact-digest": "${{ steps.scan-upload.outputs.artifact-digest }}",
        "build-artifact-id": "${{ needs.build-release.outputs.build-artifact-id }}",
        "build-artifact-digest": (
            "${{ needs.build-release.outputs.build-artifact-digest }}"
        ),
    }
    if outputs != expected_outputs:
        errors.append("scan-release must export only immutable artifact ids/digests")
    image_rows = _parse_image_rows(job, errors, label="scan-release")
    if image_rows != EXPECTED_IMAGES:
        errors.append("scan-release must cover all eight image archives exactly once")
    steps = _steps(job, "scan-release", errors)
    if steps is None:
        return
    _validate_ordered_step_inventory(
        steps,
        label="scan-release",
        expected=(
            (None, "Validate immutable build artifact handoff", "run"),
            (
                None,
                "Download exact immutable build artifact",
                "actions/download-artifact",
            ),
            (None, "Validate inert build subjects and checksums", "run"),
            (None, "Install pinned Trivy on the fresh scan runner", "run"),
            (
                None,
                "Scan every inert Docker archive sequentially and finalize evidence",
                "run",
            ),
            (
                "scan-upload",
                "Upload immutable scanned release artifact envelope",
                "actions/upload-artifact",
            ),
            (None, "Clean only fresh scanner scratch state", "run"),
        ),
        errors=errors,
    )
    _validate_exact_run_step(
        steps,
        label="scan-release immutable handoff validation",
        name="Validate immutable build artifact handoff",
        expected=SCAN_HANDOFF_RUN,
        errors=errors,
    )
    _validate_step_metadata(
        steps,
        label="scan-release",
        expected_run_env={},
        errors=errors,
    )
    actions = Counter(_action_names(steps))
    if actions != Counter(
        {"actions/download-artifact": 1, "actions/upload-artifact": 1}
    ):
        errors.append("scan-release may only download and upload immutable artifacts")
    if actions["actions/checkout"]:
        errors.append("scan-release must never check out repository or tag code")
    download = _single_action_step(steps, "actions/download-artifact")
    download_inputs = download.get("with") if download is not None else None
    if not isinstance(download_inputs, Mapping) or download_inputs != {
        "artifact-ids": "${{ env.BUILD_ARTIFACT_ID }}",
        "path": "scan-input/release",
    }:
        errors.append("scan-release must download only the exact build artifact id")
    run_text = _run_text(steps)
    _require(
        run_text,
        {
            '[[ "${BUILD_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
            '[[ "${BUILD_ARTIFACT_DIGEST}" =~ ^[0-9a-f]{64}$ ]]',
            "build checksum manifest coverage is not exact",
            "build artifact file inventory is not exact",
            "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz",
            "${TRIVY_LINUX_X64_SHA256}",
            "sha256sum --check",
            "printf '{}\\n' > scan-input/release/trivy-config.yaml",
            ": > scan-input/release/trivy-ignorefile",
            "--config trivy-config.yaml --ignorefile trivy-ignorefile",
            "/usr/bin/env -i",
            "--scanners vuln",
            "--vuln-type os,library",
            "--severity CRITICAL,HIGH",
            "--format json",
            '--exit-code 1 --input "${archive}"',
            'done <<< "${RELEASE_IMAGE_ROWS}"',
            "release-image-scan-status.v2",
            "release-image-evidence.v2",
            "classic-docker-archive",
            "config_sha256",
            "ignorefile_sha256",
            'metadata.get("ImageID")',
            'metadata.get("RepoTags")',
            'metadata.get("DiffIDs")',
            "validate_trivy_report_binding",
            'expected_archive = f"images/{name}.docker.tar"',
            "Trivy ArtifactName/archive path mismatch",
            "Trivy RepoTags binding mismatch",
            'built.get("archive") != expected_archive',
            "trivy_report_sha256",
            "BUILD_ARTIFACT",
            "find . -type f ! -name SHA256SUMS",
            "xargs -0 sha256sum > SHA256SUMS",
            'exit "${scan_status}"',
        },
        "scan-release",
        errors,
    )
    scan_steps = [
        step
        for step in steps
        if step.get("name")
        == "Scan every inert Docker archive sequentially and finalize evidence"
    ]
    if len(scan_steps) != 1:
        errors.append("scan-release finalizer step is missing")
    else:
        scan_run = str(scan_steps[0].get("run", ""))
        if (
            hashlib.sha256(scan_run.encode("utf-8")).hexdigest()
            != EXPECTED_SCAN_FINALIZER_RUN_SHA256
        ):
            errors.append("scan-release trusted finalizer run block changed")
        _validate_embedded_trivy_report_verifier(
            scan_run,
            errors,
            label="scan-release",
        )
    if re.search(r"(?m)(?<![>&])&\s*$", run_text):
        errors.append("release archive scans must not run in the background")
    for forbidden in (
        "xargs -P",
        "parallel ",
        "--ignore-unfixed",
        "git checkout",
        "git archive",
        "docker load",
        "docker run",
        "python scan-input",
        "bash scan-input",
        "sh scan-input",
    ):
        if forbidden in run_text:
            errors.append(
                f"scan-release must not execute tag/artifact code `{forbidden}`"
            )
    upload = _step_by_id(steps, "scan-upload")
    if upload is None or upload.get("if") != "${{ always() }}":
        errors.append("scan artifact upload must persist reports with if: always()")
    elif upload.get("uses") != (
        "actions/upload-artifact@" + EXPECTED_ACTION_REFS["actions/upload-artifact"]
    ):
        errors.append("scan artifact upload action pin is invalid")
    else:
        inputs = upload.get("with")
        required = {
            "name": (
                "hallu-defense-${{ env.RELEASE_TAG }}-scanned-${{ github.run_id }}"
            ),
            "path": "scan-input/release/",
            "if-no-files-found": "error",
            "include-hidden-files": False,
            "compression-level": 1,
            "overwrite": False,
            "retention-days": 30,
        }
        if inputs != required:
            errors.append("scan artifact upload must preserve exact immutable evidence")


def _validate_attestation_job(job: Mapping[str, object], errors: list[str]) -> None:
    if set(job) != {
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "environment",
        "permissions",
        "env",
        "steps",
    }:
        errors.append("attest-release job key inventory is not exact")
    if job.get("needs") != "scan-release":
        errors.append("attest-release must depend only on successful scan-release")
    if job.get("environment") != "release":
        errors.append("attest-release must be the only release Environment job")
    if job.get("permissions") != {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }:
        errors.append(
            "attest-release must have only contents/id-token/attestations permissions"
        )
    if job.get("runs-on") != "ubuntu-24.04" or not isinstance(
        job.get("timeout-minutes"), int
    ):
        errors.append("attest-release must pin ubuntu-24.04 and a numeric timeout")
    if (
        job.get("if")
        != "needs.scan-release.result == 'success' && " + CONTROL_REF_CONDITION
    ):
        errors.append("attest-release dependency/protected-ref condition is not exact")
    image_rows = _parse_image_rows(job, errors, label="attest-release")
    if image_rows != EXPECTED_IMAGES:
        errors.append("attest-release must independently expect exactly eight images")

    job_env = job.get("env")
    if not isinstance(job_env, Mapping):
        errors.append("attest-release immutable handoff env is missing")
    else:
        expected_handoff = {
            "RELEASE_ARTIFACT_ID": (
                "${{ needs.scan-release.outputs.release-artifact-id }}"
            ),
            "RELEASE_ARTIFACT_DIGEST": (
                "${{ needs.scan-release.outputs.release-artifact-digest }}"
            ),
            "BUILD_ARTIFACT_ID": (
                "${{ needs.scan-release.outputs.build-artifact-id }}"
            ),
            "BUILD_ARTIFACT_DIGEST": (
                "${{ needs.scan-release.outputs.build-artifact-digest }}"
            ),
        }
        for key, value in expected_handoff.items():
            if job_env.get(key) != value:
                errors.append(f"attest-release immutable handoff is missing {key}")
        if "secrets." in yaml.safe_dump(dict(job_env), sort_keys=False):
            errors.append(
                "attest-release secrets must be scoped to the verification step"
            )
    _validate_job_env(
        job,
        label="attest-release",
        expected={
            "RELEASE_TAG": "${{ inputs.release_tag }}",
            "RELEASE_ARTIFACT_ID": (
                "${{ needs.scan-release.outputs.release-artifact-id }}"
            ),
            "RELEASE_ARTIFACT_DIGEST": (
                "${{ needs.scan-release.outputs.release-artifact-digest }}"
            ),
            "BUILD_ARTIFACT_ID": (
                "${{ needs.scan-release.outputs.build-artifact-id }}"
            ),
            "BUILD_ARTIFACT_DIGEST": (
                "${{ needs.scan-release.outputs.build-artifact-digest }}"
            ),
        },
        errors=errors,
    )

    steps = _steps(job, "attest-release", errors)
    if steps is None:
        return
    _validate_ordered_step_inventory(
        steps,
        label="attest-release",
        expected=(
            (None, "Validate immutable artifact handoff", "run"),
            (
                None,
                "Download exact immutable release artifact",
                "actions/download-artifact",
            ),
            (
                "verify-subject",
                "Verify external tag trust and inert release subjects",
                "run",
            ),
            (
                "envelope-provenance",
                "Attest immutable upload-artifact envelope",
                "actions/attest-build-provenance",
            ),
            (
                "build-envelope-provenance",
                "Attest immutable build upload-artifact envelope",
                "actions/attest-build-provenance",
            ),
            (
                "subject-provenance",
                "Attest every checksummed release subject",
                "actions/attest-build-provenance",
            ),
            ("api-sbom", "Attest API runtime SBOM", "actions/attest-sbom"),
            ("node-sbom", "Attest Node runtime SBOM", "actions/attest-sbom"),
            (
                None,
                "Upload immutable attested release evidence",
                "actions/upload-artifact",
            ),
        ),
        errors=errors,
    )
    _validate_exact_run_step(
        steps,
        label="attest-release immutable handoff validation",
        name="Validate immutable artifact handoff",
        expected=ATTEST_HANDOFF_RUN,
        errors=errors,
    )
    _validate_step_metadata(
        steps,
        label="attest-release",
        expected_run_env={
            "verify-subject": {
                "RELEASE_SIGNING_PUBLIC_KEYS_B64": (
                    "${{ secrets.RELEASE_SIGNING_PUBLIC_KEYS_B64 }}"
                ),
                "GITHUB_TOKEN": "${{ github.token }}",
            }
        },
        errors=errors,
    )
    serialized_job = yaml.safe_dump(dict(job), sort_keys=False)
    if serialized_job.count("secrets.") != 1:
        errors.append(
            "attest-release must expose exactly one protected trust-root secret"
        )
    actions = Counter(_action_names(steps))
    expected_actions = Counter(
        {
            "actions/download-artifact": 1,
            "actions/attest-build-provenance": 3,
            "actions/attest-sbom": 2,
            "actions/upload-artifact": 1,
        }
    )
    if actions != expected_actions:
        errors.append(
            "attest-release must only download, attest envelope/subjects/SBOMs, and upload"
        )
    if actions["actions/checkout"]:
        errors.append("attest-release must never check out repository or tag code")

    download = _single_action_step(steps, "actions/download-artifact")
    download_inputs = download.get("with") if download is not None else None
    if not isinstance(download_inputs, Mapping) or download_inputs != {
        "artifact-ids": "${{ env.RELEASE_ARTIFACT_ID }}",
        "path": "attestation-input/release",
    }:
        errors.append(
            "attest-release must download only the exact immutable artifact id"
        )

    verify_step = _step_by_id(steps, "verify-subject")
    if verify_step is None:
        errors.append("attest-release external trust verification step is missing")
        return
    verify_env = verify_step.get("env")
    if verify_env != {
        "RELEASE_SIGNING_PUBLIC_KEYS_B64": (
            "${{ secrets.RELEASE_SIGNING_PUBLIC_KEYS_B64 }}"
        ),
        "GITHUB_TOKEN": "${{ github.token }}",
    }:
        errors.append("attest-release must use protected external signing trust roots")
    verify_run = str(verify_step.get("run", ""))
    _validate_privileged_verifier_integrity(verify_run, errors)
    _require(
        verify_run,
        {
            "git init --bare",
            '"${control_commit}:refs/release-control/dispatch"',
            'git --git-dir="${bare_repo}" cat-file -e',
            'git --git-dir="${bare_repo}" verify-tag',
            "--with-colons --show-keys",
            "grep -Eq '^(sec|ssb):'",
            "--list-secret-keys",
            "cleanup_trust",
            "unset RELEASE_SIGNING_PUBLIC_KEYS_B64 GITHUB_TOKEN GNUPGHOME GIT_ASKPASS",
            "SHA256SUMS contains an unsafe or malformed entry",
            "SHA256SUMS must cover every subject exactly once",
            "while chunk := handle.read(1024 * 1024)",
            "parsed release subject exceeds size limit",
            "python -I -S - <<'PY'",
            "RELEASE_SOURCE is not bound to signed/control metadata",
            "API SBOM lock subject is not bound to the signed source",
            "Node SBOM lock subject is not bound to the signed source",
            "scanned subjects are not bound to the build artifact",
            "build subject changed after the immutable build upload",
            'tarfile.open(path, mode="r:")',
            "safe_tar_member_name(member.name)",
            "if not (member.isdir() or member.isreg())",
            "if observed_digest != expected_config_digest",
            "observed_diff_id != expected_diff_id",
            "Docker archive contains unsafe member path",
            "Docker archive contains a link, device, or special member",
            "Docker archive exceeds its member-count bound",
            "Docker archive exceeds its uncompressed-size bound",
            "Docker archive compression ratio exceeds its bound",
            "Docker archive must contain exactly one manifest entry",
            "Docker archive RepoTags binding is invalid",
            "Docker archive config JSON does not match the image config digest",
            "Docker archive config labels are not bound to source/tag",
            ") != expected_revision or labels.get(",
            ") != expected_version:",
            "Docker archive rootfs diff_ids do not match the layer inventory",
            'rootfs.get("type") != "layers"',
            "Docker archive layer content does not match rootfs diff_id",
            "sha256_tar_member",
            "release image evidence contains a duplicate/unknown image",
            "len(images) != len(image_names)",
            "name in evidence_by_name",
            "release image scan status contains a duplicate/unknown image",
            "status_name in status_by_name",
            'status_item.get("image_config_digest")',
            "release image scan status binding is invalid",
            'item.get("image_reference") != expected_image_reference',
            "image reference binding is invalid",
            "invalid CycloneDX SBOM",
            "Dockerfile is not bound to the signed source",
            "validate_trivy_report_binding",
            "Trivy ArtifactName/archive path mismatch",
            'expected_archive = f"images/{name}.docker.tar"',
            'item.get("trivy_artifact_name") != expected_archive',
            "release image scan policy was weakened",
            "release artifact contains missing or unexpected subjects",
            "image build metadata is not bound to the peeled commit",
            "Trivy config is not the trusted empty policy",
            "Trivy ignore file must be empty",
        },
        "attest-release verification",
        errors,
    )
    _validate_immutable_control_ancestry(
        verify_run,
        label="attest-release",
        source_variable="expected_source_commit",
        errors=errors,
    )
    secret_guard = verify_run.find("if grep -Eq '^(sec|ssb):'")
    actual_import = verify_run.find('--import "${trust_bundle}"')
    if secret_guard < 0 or actual_import < 0 or secret_guard > actual_import:
        errors.append("attest-release must reject secret-key packets before GPG import")
    verify_tag = verify_run.find('verify-tag "refs/tags/${RELEASE_TAG}"')
    cleanup_call = verify_run.find(
        "cleanup_trust\nunset RELEASE_SIGNING_PUBLIC_KEYS_B64"
    )
    parser_start = verify_run.find("python -I -S - <<'PY'")
    if verify_tag < 0 or cleanup_call < verify_tag or parser_start < cleanup_call:
        errors.append(
            "attest-release must remove trust material before parsing/attesting"
        )

    _validate_embedded_archive_verifier(verify_run, errors)
    _validate_embedded_trivy_report_verifier(
        verify_run,
        errors,
        label="attest-release",
    )

    all_run = _run_text(steps)
    for forbidden in (
        "git checkout",
        "git worktree",
        "git archive",
        "scripts/",
        "apps/",
        "npm ",
        "pytest",
        "mypy",
        "ruff",
        "docker ",
        "chmod +x attestation-input",
        "python attestation-input",
        "bash attestation-input",
        "sh attestation-input",
        "./attestation-input",
        "tar -x",
        "unzip ",
        "curl ",
        "wget ",
        "Invoke-WebRequest",
        "nc ",
    ):
        if forbidden in all_run:
            errors.append(
                f"attest-release must not execute subject/repository code `{forbidden}`"
            )

    _validate_attestation_inputs(steps, errors)


def _validate_release_verdict_job(
    job: Mapping[str, object], errors: list[str]
) -> None:
    if set(job) != {
        "needs",
        "if",
        "runs-on",
        "timeout-minutes",
        "permissions",
        "steps",
    }:
        errors.append("release-verdict job key inventory is not exact")
    if job.get("needs") != [
        "verify-tag",
        "build-release",
        "scan-release",
        "attest-release",
    ]:
        errors.append("release-verdict must observe all four release stages directly")
    if job.get("if") != "${{ always() }}":
        errors.append("release-verdict must run with an exact always() condition")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 5:
        errors.append("release-verdict must use the exact unprivileged runner limits")
    if job.get("permissions") != {}:
        errors.append("release-verdict must have no token permissions")
    steps = _steps(job, "release-verdict", errors)
    if steps is None:
        return
    _validate_ordered_step_inventory(
        steps,
        label="release-verdict",
        expected=((None, "Fail unless every release stage completed", "run"),),
        errors=errors,
    )
    _validate_exact_run_step(
        steps,
        label="release-verdict",
        name="Fail unless every release stage completed",
        expected=FINAL_VERDICT_RUN,
        errors=errors,
    )
    _validate_step_metadata(
        steps,
        label="release-verdict",
        expected_run_env={
            "Fail unless every release stage completed": {
                "VERIFY_TAG_RESULT": "${{ needs.verify-tag.result }}",
                "BUILD_RELEASE_RESULT": "${{ needs.build-release.result }}",
                "SCAN_RELEASE_RESULT": "${{ needs.scan-release.result }}",
                "ATTEST_RELEASE_RESULT": "${{ needs.attest-release.result }}",
            }
        },
        errors=errors,
    )
    if _action_names(steps):
        errors.append("release-verdict must not invoke actions or subject code")


def _validate_attestation_inputs(
    steps: list[Mapping[str, object]], errors: list[str]
) -> None:
    provenance_steps = [
        step
        for step in steps
        if _action_name(str(step.get("uses", ""))) == "actions/attest-build-provenance"
    ]
    expected_provenance = {
        (
            ("subject-name", "github-actions-artifact-${{ env.RELEASE_ARTIFACT_ID }}"),
            ("subject-digest", "sha256:${{ env.RELEASE_ARTIFACT_DIGEST }}"),
        ),
        (
            ("subject-name", "github-actions-artifact-${{ env.BUILD_ARTIFACT_ID }}"),
            ("subject-digest", "sha256:${{ env.BUILD_ARTIFACT_DIGEST }}"),
        ),
        (("subject-checksums", "attestation-input/release/SHA256SUMS"),),
    }
    observed_provenance: set[tuple[tuple[str, object], ...]] = set()
    for step in provenance_steps:
        inputs = step.get("with")
        if (
            not isinstance(inputs, Mapping)
            or inputs.get("push-to-registry") is not False
        ):
            errors.append("every provenance attestation must avoid registry pushes")
            continue
        allowed_keys = (
            {"subject-checksums", "push-to-registry"}
            if "subject-checksums" in inputs
            else {"subject-name", "subject-digest", "push-to-registry"}
        )
        if set(inputs) != allowed_keys:
            errors.append("provenance attestation input inventory is not exact")
        subjects = tuple(
            (key, inputs[key])
            for key in ("subject-name", "subject-digest", "subject-checksums")
            if key in inputs
        )
        observed_provenance.add(subjects)
    if observed_provenance != expected_provenance:
        errors.append(
            "attest-release must attest both artifact envelopes and subject checksums"
        )

    sbom_steps = [
        step
        for step in steps
        if _action_name(str(step.get("uses", ""))) == "actions/attest-sbom"
    ]
    expected_sboms = {
        (
            "attestation-input/release/api-runtime-lock.txt",
            "attestation-input/release/api-runtime.cdx.json",
        ),
        (
            "attestation-input/release/node-runtime-lock.json",
            "attestation-input/release/node-runtime.cdx.json",
        ),
    }
    observed_sboms: set[tuple[object, object]] = set()
    for step in sbom_steps:
        inputs = step.get("with")
        if (
            not isinstance(inputs, Mapping)
            or inputs.get("push-to-registry") is not False
        ):
            errors.append("every SBOM attestation must avoid registry pushes")
            continue
        if set(inputs) != {"subject-path", "sbom-path", "push-to-registry"}:
            errors.append("SBOM attestation input inventory is not exact")
        observed_sboms.add((inputs.get("subject-path"), inputs.get("sbom-path")))
    if observed_sboms != expected_sboms:
        errors.append("attest-release must attest API and Node SBOM subjects")

    upload = _single_action_step(steps, "actions/upload-artifact")
    expected_upload = {
        "name": (
            "hallu-defense-${{ env.RELEASE_TAG }}-attested-evidence-${{ github.run_id }}"
        ),
        "path": (
            "attestation-input/release/\n"
            "${{ steps.envelope-provenance.outputs.bundle-path }}\n"
            "${{ steps.build-envelope-provenance.outputs.bundle-path }}\n"
            "${{ steps.subject-provenance.outputs.bundle-path }}\n"
            "${{ steps.api-sbom.outputs.bundle-path }}\n"
            "${{ steps.node-sbom.outputs.bundle-path }}\n"
        ),
        "if-no-files-found": "error",
        "include-hidden-files": False,
        "compression-level": 0,
        "overwrite": False,
        "retention-days": 30,
    }
    if upload is None or upload.get("with") != expected_upload:
        errors.append("attest-release evidence upload input inventory is not exact")


def _extract_privileged_python_source(verify_run: str) -> str:
    marker = "python -I -S - <<'PY'"
    start = verify_run.find(marker)
    if start < 0:
        raise ValueError("isolated verifier heredoc is missing")
    start = verify_run.find("\n", start + len(marker)) + 1
    terminator = re.search(r"(?m)^PY[ \t]*$", verify_run[start:])
    if start <= 0 or terminator is None:
        raise ValueError("isolated verifier heredoc terminator is missing")
    return verify_run[start : start + terminator.start()]


def _validate_privileged_verifier_integrity(
    verify_run: str,
    errors: list[str],
) -> None:
    if hashlib.sha256(verify_run.encode("utf-8")).hexdigest() != (
        EXPECTED_VERIFY_SUBJECT_RUN_SHA256
    ):
        errors.append("attest-release full privileged verifier run block changed")
    try:
        tree = ast.parse(
            _extract_privileged_python_source(verify_run),
            filename="release-inline-verifier.py",
        )
    except (SyntaxError, ValueError) as exc:
        errors.append(f"attest-release privileged verifier cannot be parsed: {exc}")
        return

    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id
            in {"validate_docker_archive", "validate_trivy_report_binding"}
        ):
            errors.append(
                "attest-release privileged verifier must not be reassigned"
            )
        call: ast.Call | None = None
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            call = node.exc
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
        if call is not None:
            if isinstance(call.func, ast.Name):
                function_name = call.func.id
            elif isinstance(call.func, ast.Attribute):
                function_name = call.func.attr
            else:
                function_name = ""
            if function_name in {"SystemExit", "exit", "quit", "_exit"} and (
                not call.args
                or (
                    len(call.args) == 1
                    and isinstance(call.args[0], ast.Constant)
                    and call.args[0].value in {None, False, 0}
                )
            ):
                errors.append(
                    "attest-release privileged verifier can exit successfully early"
                )
        if not isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            pending.extend(ast.iter_child_nodes(node))


def _extract_archive_verifier(verify_run: str) -> Callable[..., object]:
    source = _extract_privileged_python_source(verify_run)
    tree = ast.parse(source, filename="release-inline-verifier.py")
    names = {
        "safe_tar_member_name",
        "read_bounded_tar_member",
        "sha256_tar_member",
        "validate_docker_archive",
    }
    definition_nodes = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    ]
    if (
        len(definition_nodes) != len(names)
        or {node.name for node in definition_nodes} != names
        or any(
            isinstance(node, ast.AsyncFunctionDef)
            or node.decorator_list
            or node.args.defaults
            or any(default is not None for default in node.args.kw_defaults)
            for node in definition_nodes
        )
    ):
        raise ValueError("archive verifier function inventory is not exact")
    definitions: list[ast.stmt] = list(definition_nodes)
    module = ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[]))
    safe_builtins = {
        "SystemExit": SystemExit,
        "OSError": OSError,
        "all": all,
        "dict": dict,
        "isinstance": isinstance,
        "len": len,
        "list": list,
        "set": set,
        "str": str,
        "zip": zip,
    }
    namespace: dict[str, object] = {
        "__builtins__": safe_builtins,
        "hashlib": hashlib,
        "json": json,
        "re": re,
        "tarfile": tarfile,
        "Path": Path,
        "PurePosixPath": PurePosixPath,
    }
    exec(compile(module, "release-inline-verifier.py", "exec"), namespace)
    verifier = namespace["validate_docker_archive"]
    if not callable(verifier):
        raise ValueError("archive verifier is not callable")
    return verifier


def _extract_trivy_report_verifier(run: str) -> Callable[..., object]:
    source = _extract_privileged_python_source(run)
    tree = ast.parse(source, filename="release-inline-trivy-verifier.py")
    if any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == "validate_trivy_report_binding"
        for node in ast.walk(tree)
    ):
        raise ValueError("Trivy report verifier must not be reassigned")
    definitions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "validate_trivy_report_binding"
    ]
    if (
        len(definitions) != 1
        or isinstance(definitions[0], ast.AsyncFunctionDef)
        or definitions[0].decorator_list
        or definitions[0].args.defaults
        or any(default is not None for default in definitions[0].args.kw_defaults)
    ):
        raise ValueError("Trivy report verifier function inventory is not exact")
    module = ast.fix_missing_locations(
        ast.Module(body=[definitions[0]], type_ignores=[])
    )
    namespace: dict[str, object] = {
        "__builtins__": {
            "ValueError": ValueError,
            "dict": dict,
            "int": int,
            "isinstance": isinstance,
            "list": list,
            "object": object,
            "str": str,
        },
        "re": re,
    }
    exec(
        compile(module, "release-inline-trivy-verifier.py", "exec"),
        namespace,
    )
    verifier = namespace["validate_trivy_report_binding"]
    if not callable(verifier):
        raise ValueError("Trivy report verifier is not callable")
    return verifier


def _validate_embedded_trivy_report_verifier(
    run: str,
    errors: list[str],
    *,
    label: str,
) -> None:
    try:
        verifier = _extract_trivy_report_verifier(run)
    except (SyntaxError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"{label} Trivy report verifier cannot be isolated: {exc}")
        return
    expected_archive = "images/api.docker.tar"
    expected_tag = "hallu-defense-api:v1.2.3"
    expected_digest = "sha256:" + "1" * 64
    expected_diff_ids = ["sha256:" + "2" * 64]
    baseline: dict[str, object] = {
        "SchemaVersion": 2,
        "ArtifactName": expected_archive,
        "Metadata": {
            "ImageID": expected_digest,
            "RepoTags": [expected_tag],
            "DiffIDs": expected_diff_ids,
        },
        "Results": [],
    }

    def invoke(report: object, archive_path: str = expected_archive) -> None:
        verifier(
            report,
            expected_archive_path=archive_path,
            expected_repo_tag=expected_tag,
            expected_image_config_digest=expected_digest,
            expected_diff_ids=expected_diff_ids,
        )

    try:
        invoke(baseline)
    except BaseException as exc:  # noqa: BLE001 - gate reports fail-closed cause
        errors.append(f"{label} Trivy report verifier rejects valid report: {exc}")
        return

    cases: list[tuple[str, dict[str, object], str]] = []
    for case_name, artifact_name in (
        ("absolute ArtifactName", "/tmp/images/api.docker.tar"),
        ("Windows ArtifactName", r"C:\images\api.docker.tar"),
        ("traversing ArtifactName", "images/../api.docker.tar"),
        ("parent ArtifactName", "../images/api.docker.tar"),
        ("dot ArtifactName", "./images/api.docker.tar"),
        ("double-slash ArtifactName", "images//api.docker.tar"),
        ("wrong-name ArtifactName", "images/console.docker.tar"),
        ("wrong-extension ArtifactName", "images/api.docker.tar.gz"),
    ):
        report = json.loads(json.dumps(baseline))
        report["ArtifactName"] = artifact_name
        cases.append((case_name, report, expected_archive))
    for case_name, repo_tags in (
        ("missing RepoTags", None),
        ("scalar RepoTags", expected_tag),
        ("empty RepoTags", []),
        ("extra RepoTags", [expected_tag, "hallu-defense-extra:v1.2.3"]),
        ("duplicate RepoTags", [expected_tag, expected_tag]),
        ("wrong RepoTags", ["hallu-defense-other:v1.2.3"]),
    ):
        report = json.loads(json.dumps(baseline))
        metadata = report["Metadata"]
        if isinstance(metadata, dict):
            if repo_tags is None:
                metadata.pop("RepoTags", None)
            else:
                metadata["RepoTags"] = repo_tags
        cases.append((case_name, report, expected_archive))
    wrong_image = json.loads(json.dumps(baseline))
    if isinstance(wrong_image["Metadata"], dict):
        wrong_image["Metadata"]["ImageID"] = "sha256:" + "3" * 64
    cases.append(("wrong ImageID", wrong_image, expected_archive))
    wrong_diff_ids = json.loads(json.dumps(baseline))
    if isinstance(wrong_diff_ids["Metadata"], dict):
        wrong_diff_ids["Metadata"]["DiffIDs"] = ["sha256:" + "4" * 64]
    cases.append(("wrong DiffIDs", wrong_diff_ids, expected_archive))
    cases.append(("invalid trusted archive path", baseline, "./images/api.docker.tar"))

    for case_name, report, archive_path in cases:
        try:
            invoke(report, archive_path)
        except BaseException:  # noqa: BLE001 - every failure is fail-closed here
            continue
        errors.append(f"{label} Trivy report verifier accepts forged {case_name}")


def _add_tar_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name=name)
    member.size = len(content)
    member.mode = 0o444
    member.mtime = 0
    archive.addfile(member, io.BytesIO(content))


def _write_synthetic_docker_archive(
    path: Path,
    *,
    repo_tag: str,
    revision: str,
    version: str,
    manifest_layers: list[str] | None = None,
    diff_ids: list[str] | None = None,
    rootfs_type: str = "layers",
    manifest_repo_tags: object | None = None,
    include_repo_tags: bool = True,
) -> tuple[str, str]:
    layer_name = "synthetic-layer/layer.tar"
    layer_bytes = b"synthetic uncompressed release layer\n"
    observed_diff_id = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    layers = [layer_name] if manifest_layers is None else manifest_layers
    rootfs_diff_ids = [observed_diff_id] if diff_ids is None else diff_ids
    config = {
        "config": {
            "Labels": {
                "org.opencontainers.image.revision": revision,
                "org.opencontainers.image.version": version,
            }
        },
        "rootfs": {"type": rootfs_type, "diff_ids": rootfs_diff_ids},
    }
    config_bytes = json.dumps(config, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    config_name = config_digest.removeprefix("sha256:") + ".json"
    manifest_entry: dict[str, object] = {
        "Config": config_name,
        "Layers": layers,
    }
    if include_repo_tags:
        manifest_entry["RepoTags"] = (
            [repo_tag] if manifest_repo_tags is None else manifest_repo_tags
        )
    manifest_bytes = json.dumps(
        [manifest_entry], separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    with tarfile.open(path, mode="w:") as archive:
        _add_tar_bytes(archive, "manifest.json", manifest_bytes)
        _add_tar_bytes(archive, config_name, config_bytes)
        _add_tar_bytes(archive, layer_name, layer_bytes)
    return config_digest, observed_diff_id


def _validate_embedded_archive_verifier(verify_run: str, errors: list[str]) -> None:
    try:
        verifier = _extract_archive_verifier(verify_run)
    except (SyntaxError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"attest-release archive verifier cannot be isolated: {exc}")
        return
    expected_tag = "hallu-defense-api:v1.2.3"
    expected_revision = "1" * 40

    with ExitStack() as scratch:
        def archive_path(label: str) -> Path:
            handle = tempfile.NamedTemporaryFile(
                prefix=f"release-archive-gate-{label}-",
                suffix=".docker.tar",
                delete=False,
            )
            path = Path(handle.name)
            handle.close()
            scratch.callback(path.unlink, missing_ok=True)
            return path

        baseline = archive_path("baseline")
        digest, diff_id = _write_synthetic_docker_archive(
            baseline,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
        )
        try:
            result = verifier(
                baseline,
                expected_config_digest=digest,
                expected_repo_tag=expected_tag,
                expected_revision=expected_revision,
                expected_version="v1.2.3",
            )
        except BaseException as exc:  # noqa: BLE001 - gate reports fail-closed cause
            errors.append(
                f"attest-release archive verifier rejects valid archive: {exc}"
            )
            return
        if result != [diff_id]:
            errors.append(
                "attest-release archive verifier did not bind baseline layers"
            )
            return

        cases: list[tuple[str, Path, str, str, str, str]] = []
        wrong_tag = archive_path("wrong-tag")
        wrong_tag_digest, _ = _write_synthetic_docker_archive(
            wrong_tag,
            repo_tag="hallu-defense-other:v1.2.3",
            revision=expected_revision,
            version="v1.2.3",
        )
        cases.append(
            (
                "RepoTags",
                wrong_tag,
                wrong_tag_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        missing_tags = archive_path("missing-tags")
        missing_tags_digest, _ = _write_synthetic_docker_archive(
            missing_tags,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            include_repo_tags=False,
        )
        cases.append(
            (
                "missing RepoTags",
                missing_tags,
                missing_tags_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        extra_tags = archive_path("extra-tags")
        extra_tags_digest, _ = _write_synthetic_docker_archive(
            extra_tags,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            manifest_repo_tags=[expected_tag, "hallu-defense-extra:v1.2.3"],
        )
        cases.append(
            (
                "extra RepoTags",
                extra_tags,
                extra_tags_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        duplicate_tags = archive_path("duplicate-tags")
        duplicate_tags_digest, _ = _write_synthetic_docker_archive(
            duplicate_tags,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            manifest_repo_tags=[expected_tag, expected_tag],
        )
        cases.append(
            (
                "duplicate RepoTags",
                duplicate_tags,
                duplicate_tags_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        cases.append(
            (
                "config digest",
                baseline,
                "sha256:" + "0" * 64,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        cases.append(
            ("revision label", baseline, digest, expected_tag, "2" * 40, "v1.2.3")
        )
        cases.append(
            (
                "version label",
                baseline,
                digest,
                expected_tag,
                expected_revision,
                "v9.9.9",
            )
        )
        no_layers = archive_path("no-layers")
        no_layers_digest, _ = _write_synthetic_docker_archive(
            no_layers,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            manifest_layers=[],
            diff_ids=[],
        )
        cases.append(
            (
                "layer inventory",
                no_layers,
                no_layers_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        wrong_type = archive_path("wrong-rootfs-type")
        wrong_type_digest, _ = _write_synthetic_docker_archive(
            wrong_type,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            rootfs_type="not-layers",
        )
        cases.append(
            (
                "rootfs.type",
                wrong_type,
                wrong_type_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )
        wrong_diff = archive_path("wrong-diff-id")
        wrong_diff_digest, _ = _write_synthetic_docker_archive(
            wrong_diff,
            repo_tag=expected_tag,
            revision=expected_revision,
            version="v1.2.3",
            diff_ids=["sha256:" + "f" * 64],
        )
        cases.append(
            (
                "rootfs.diff_ids",
                wrong_diff,
                wrong_diff_digest,
                expected_tag,
                expected_revision,
                "v1.2.3",
            )
        )

        for label, path, expected_digest, repo_tag, revision, version in cases:
            try:
                verifier(
                    path,
                    expected_config_digest=expected_digest,
                    expected_repo_tag=repo_tag,
                    expected_revision=revision,
                    expected_version=version,
                )
            except BaseException:  # noqa: BLE001 - every failure is fail-closed here
                continue
            errors.append(f"attest-release archive verifier accepts forged {label}")


def _validate_job_env(
    job: Mapping[str, object],
    *,
    label: str,
    expected: Mapping[str, str],
    errors: list[str],
) -> None:
    env = job.get("env")
    if not isinstance(env, Mapping):
        errors.append(f"{label} environment is missing")
        return
    expected_keys = set(expected) | {"RELEASE_IMAGE_ROWS"}
    if set(env) != expected_keys or any(
        env.get(key) != value for key, value in expected.items()
    ):
        errors.append(f"{label} environment key/value inventory is not exact")


def _validate_step_metadata(
    steps: list[Mapping[str, object]],
    *,
    label: str,
    expected_run_env: Mapping[str, Mapping[str, str]],
    errors: list[str],
) -> None:
    observed_env_steps: set[str] = set()
    for step in steps:
        is_run = "run" in step
        is_action = "uses" in step
        if is_run == is_action:
            errors.append(f"{label} step must contain exactly one of run/uses")
            continue
        allowed = (
            {"name", "id", "shell", "run", "if", "env"}
            if is_run
            else {"name", "id", "uses", "with", "if"}
        )
        if not set(step).issubset(allowed):
            errors.append(f"{label} step metadata key inventory is not exact")
        if is_run and step.get("shell") != "bash":
            errors.append(f"{label} run steps must use the reviewed bash shell")
        identifier_obj = step.get("id", step.get("name", ""))
        identifier = identifier_obj if isinstance(identifier_obj, str) else ""
        env = step.get("env")
        expected_env = expected_run_env.get(identifier)
        if expected_env is None:
            if env is not None:
                errors.append(
                    f"{label} step `{identifier}` has an unexpected environment"
                )
        elif env != expected_env:
            errors.append(f"{label} step `{identifier}` environment is not exact")
        else:
            observed_env_steps.add(identifier)
        if "if" in step:
            allowed_always = label == "scan-release" and (
                identifier == "scan-upload"
                or identifier == "Clean only fresh scanner scratch state"
            )
            if not allowed_always or step.get("if") != "${{ always() }}":
                errors.append(
                    f"{label} step `{identifier}` has an unexpected condition"
                )
    if observed_env_steps != set(expected_run_env):
        errors.append(f"{label} reviewed step environments are incomplete")


def _validate_ordered_step_inventory(
    steps: list[Mapping[str, object]],
    *,
    label: str,
    expected: tuple[tuple[str | None, str | None, str], ...],
    errors: list[str],
) -> None:
    observed: list[tuple[object, object, str]] = []
    for step in steps:
        kind = _action_name(str(step["uses"])) if "uses" in step else "run"
        observed.append((step.get("id"), step.get("name"), kind))
    if tuple(observed) != expected:
        errors.append(f"{label} ordered step inventory is not exact")


def _validate_exact_run_step(
    steps: list[Mapping[str, object]],
    *,
    label: str,
    name: str,
    expected: str,
    errors: list[str],
) -> None:
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1 or matches[0].get("run") != expected:
        errors.append(f"{label} run block is not exact")


def _parse_image_rows(
    job: Mapping[str, object], errors: list[str], *, label: str
) -> dict[str, str]:
    env = job.get("env")
    raw_rows = env.get("RELEASE_IMAGE_ROWS") if isinstance(env, Mapping) else None
    if not isinstance(raw_rows, str):
        errors.append(f"{label} RELEASE_IMAGE_ROWS is missing")
        return {}
    rows: dict[str, str] = {}
    for raw_line in raw_rows.splitlines():
        parts = raw_line.split("|")
        if len(parts) != 2 or not all(parts):
            errors.append(f"{label} has a malformed release image row")
            continue
        name, dockerfile = parts
        if name in rows:
            errors.append(f"{label} duplicates release image {name}")
        rows[name] = dockerfile
    return rows


def _steps(
    job: Mapping[str, object], label: str, errors: list[str]
) -> list[Mapping[str, object]] | None:
    raw_steps = job.get("steps")
    if not isinstance(raw_steps, list) or not all(
        isinstance(step, Mapping) for step in raw_steps
    ):
        errors.append(f"{label} steps must be a list of mappings")
        return None
    return list(raw_steps)


def _run_text(steps: list[Mapping[str, object]]) -> str:
    return "\n".join(str(step.get("run", "")) for step in steps if "run" in step)


def _action_name(action_ref: str) -> str:
    return action_ref.rsplit("@", 1)[0] if "@" in action_ref else action_ref


def _action_names(steps: list[Mapping[str, object]]) -> list[str]:
    return [
        _action_name(str(step["uses"]))
        for step in steps
        if isinstance(step.get("uses"), str)
    ]


def _single_action_step(
    steps: list[Mapping[str, object]], action_name: str
) -> Mapping[str, object] | None:
    matches = [
        step for step in steps if _action_name(str(step.get("uses", ""))) == action_name
    ]
    return matches[0] if len(matches) == 1 else None


def _step_by_id(
    steps: list[Mapping[str, object]], step_id: str
) -> Mapping[str, object] | None:
    return next((step for step in steps if step.get("id") == step_id), None)


def _validate_remote_actions(workflow_text: str, errors: list[str]) -> None:
    observed: Counter[str] = Counter()
    for action, ref in REMOTE_ACTION_RE.findall(workflow_text):
        observed[action] += 1
        if FULL_SHA_RE.fullmatch(ref) is None:
            errors.append(
                f"release workflow action {action} must use a full commit SHA"
            )
            continue
        expected = EXPECTED_ACTION_REFS.get(action)
        if expected is None:
            errors.append(f"release workflow uses unapproved remote action {action}")
        elif ref != expected:
            errors.append(
                f"release workflow action {action} is not at the approved pin"
            )
    expected_counts = Counter(
        {
            "actions/checkout": 1,
            "actions/setup-python": 1,
            "actions/setup-node": 1,
            "actions/upload-artifact": 3,
            "actions/download-artifact": 2,
            "actions/attest-build-provenance": 3,
            "actions/attest-sbom": 2,
        }
    )
    if observed != expected_counts:
        errors.append("release workflow remote action inventory is not exact")


def _validate_gate_wiring(
    *,
    security_workflow_text: str,
    ci_workflow_text: str,
    makefile_text: str,
    errors: list[str],
) -> None:
    gate_path = "scripts/ci/check_release_security_config.py"
    workflow_gate = f"python {gate_path}"
    if workflow_gate not in security_workflow_text:
        errors.append("security workflow must run the release security config gate")
    if workflow_gate not in ci_workflow_text:
        errors.append("CI workflow must run the release security config gate")
    if (
        "release-security-config:" not in makefile_text
        or gate_path not in makefile_text
    ):
        errors.append("Makefile must expose the release-security-config gate")
    security_target = re.search(
        r"(?ms)^security-check:\s*\n(?P<body>(?:\t[^\n]*(?:\n|$))*)",
        makefile_text,
    )
    make_command = "$(PY) scripts/ci/check_release_security_config.py"
    if security_target is None or make_command not in security_target.group("body"):
        errors.append(
            "Makefile security-check must run the release security config gate"
        )


def _validate_documentation(text: str, errors: list[str]) -> None:
    _require(
        text,
        {
            "cannot be proven by the",
            "protect `v*` tags",
            "required independent reviewers",
            "prevent self-review",
            "only from the protected default branch",
            "signer-workflow",
            "compliance_asserted: false",
            "verify-tag -> build-release -> scan-release -> attest-release",
            "immutable workflow-dispatch control commit",
            "ancestor of that exact control commit",
            "revalidates the same ancestry",
            "release-verdict",
            "`if: always()`",
            "skipped, cancelled, or failed",
            "unprivileged build job",
            "fresh unprivileged scan job",
            "`permissions: {}`",
            "privileged attestation job",
            "never checks out or executes the signed tag",
            "exact normalized relative archive path `images/<name>.docker.tar`",
            "`Metadata.RepoTags` independently must",
            "singleton exact",
            "secret-key packets (`sec`/`ssb`)",
            "eight current first-party Dockerfiles",
            "sequentially",
            "machine-readable Trivy JSON",
            "immutable upload-artifact ID and digest",
            "rootfs.type: layers",
            "forged `RepoTags`",
            "SHA256SUMS",
        },
        "release process documentation",
        errors,
    )


def _validate_immutable_control_ancestry(
    run: str,
    *,
    label: str,
    source_variable: str,
    errors: list[str],
) -> None:
    assignment = 'control_commit="${GITHUB_SHA}"'
    immutable_fetch = '"${control_commit}:refs/release-control/dispatch"'
    fetched_binding = (
        '"refs/release-control/dispatch^{commit}")" = "${control_commit}"'
    )
    type_check = 'cat-file -t "${control_commit}")" = commit'
    signature_check = 'verify-tag "refs/tags/${RELEASE_TAG}"'
    source_resolution = f'{source_variable}="$(git --git-dir="${{bare_repo}}" rev-parse '
    ancestry_pattern = re.compile(
        re.escape('git --git-dir="${bare_repo}" merge-base --is-ancestor ')
        + r"\\\n\s+"
        + re.escape(f'"${{{source_variable}}}" "${{control_commit}}"')
    )
    required = (
        assignment,
        immutable_fetch,
        fetched_binding,
        type_check,
        signature_check,
        source_resolution,
    )
    positions = [run.find(snippet) for snippet in required]
    ancestry_matches = list(ancestry_pattern.finditer(run))
    ancestry_position = ancestry_matches[0].start() if ancestry_matches else -1
    positions.append(ancestry_position)
    if any(position < 0 for position in positions):
        errors.append(
            f"{label} must bind signed-source ancestry to the immutable control commit"
        )
    elif positions != sorted(positions):
        errors.append(
            f"{label} must verify signature and immutable control ancestry in order"
        )
    if len(ancestry_matches) != 1:
        errors.append(f"{label} must perform exactly one control ancestry decision")
    for mutable_ref in (
        "refs/heads/",
        "refs/remotes/",
        "origin/",
        "git ls-remote",
        '"${GITHUB_REF}:',
        '"${GITHUB_REF_NAME}:',
        "--depth",
        "--shallow",
    ):
        if mutable_ref in run:
            errors.append(
                f"{label} control ancestry must not depend on mutable/shallow ref "
                f"`{mutable_ref}`"
            )


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in sorted(snippets):
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def load_current_config() -> tuple[str, str, str, str, str]:
    return (
        RELEASE_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        RELEASE_DOC.read_text(encoding="utf-8"),
    )


def main() -> None:
    release, security, ci, makefile, release_doc = load_current_config()
    validate_release_security_config(
        release_workflow_text=release,
        security_workflow_text=security,
        ci_workflow_text=ci,
        makefile_text=makefile,
        release_doc_text=release_doc,
    )
    print("Validated split, fail-closed release security configuration.")


if __name__ == "__main__":
    main()
