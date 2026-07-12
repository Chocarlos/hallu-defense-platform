from __future__ import annotations

import re

import pytest

from scripts.ci.check_release_security_config import (
    ReleaseSecurityConfigError,
    load_current_config,
    validate_release_security_config,
)


def _validate(config: list[str]) -> None:
    validate_release_security_config(
        release_workflow_text=config[0],
        security_workflow_text=config[1],
        ci_workflow_text=config[2],
        makefile_text=config[3],
        release_doc_text=config[4],
    )


def _mutate_workflow(old: str, new: str) -> list[str]:
    config = list(load_current_config())
    assert old in config[0]
    config[0] = config[0].replace(old, new, 1)
    return config


def _mutate_workflow_occurrence(old: str, new: str, occurrence: int) -> list[str]:
    config = list(load_current_config())
    parts = config[0].split(old)
    assert 0 <= occurrence < len(parts) - 1
    config[0] = old.join(parts[: occurrence + 1]) + new + old.join(parts[occurrence + 1 :])
    return config


def test_release_security_config_validates_current_artifacts() -> None:
    _validate(list(load_current_config()))


def test_release_security_config_rejects_unpinned_action() -> None:
    config = _mutate_workflow(
        "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
        "actions/download-artifact@v6",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="full commit SHA"):
        _validate(config)


@pytest.mark.parametrize(
    "unsafe",
    [
        "permissions: write-all",
        "persist-credentials: true",
        "continue-on-error: true",
        "--ignore-unfixed",
        "push-to-registry: true",
        "  push:",
    ],
)
def test_release_security_config_rejects_unsafe_overrides(unsafe: str) -> None:
    config = list(load_current_config())
    config[0] += f"\n{unsafe}\n"

    with pytest.raises(ReleaseSecurityConfigError, match="forbidden"):
        _validate(config)


def test_release_security_config_rejects_build_job_privilege() -> None:
    config = _mutate_workflow(
        "  build-release:\n",
        "  build-release:\n    environment: release\n",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="must not access"):
        _validate(config)


@pytest.mark.parametrize("privilege", ["id-token: write", "attestations: write"])
def test_release_security_config_rejects_build_oidc_or_attestations(
    privilege: str,
) -> None:
    config = _mutate_workflow(
        "    timeout-minutes: 180\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:",
        "    timeout-minutes: 180\n"
        "    permissions:\n"
        "      contents: read\n"
        f"      {privilege}\n"
        "    outputs:",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="build-release permissions"):
        _validate(config)


def test_release_security_config_rejects_build_secret_exposure() -> None:
    config = _mutate_workflow(
        "    env:\n"
        "      RELEASE_TAG: ${{ inputs.release_tag }}\n"
        "      VERIFIED_SOURCE_COMMIT:",
        "    env:\n"
        "      RELEASE_TAG: ${{ secrets.RELEASE_TAG }}\n"
        "      VERIFIED_SOURCE_COMMIT:",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="must not expose `secrets"):
        _validate(config)


def test_release_security_config_requires_four_exact_jobs() -> None:
    config = _mutate_workflow(
        "jobs:\n  verify-tag:",
        "jobs:\n  hidden-privileged:\n    runs-on: ubuntu-24.04\n  verify-tag:",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="exactly verify-tag"):
        _validate(config)


def test_release_security_config_rejects_checkout_in_privileged_job() -> None:
    config = _mutate_workflow(
        "    steps:\n      - name: Validate immutable artifact handoff",
        "    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Validate immutable artifact handoff",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="never check out"):
        _validate(config)


def test_release_security_config_rejects_checkout_in_verify_tag_job() -> None:
    config = _mutate_workflow(
        "    steps:\n"
        "      - name: Validate protected control ref and canonical tag input",
        "    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Validate protected control ref and canonical tag input",
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="verify-tag.*action|remote action inventory",
    ):
        _validate(config)


def test_release_security_config_build_checks_out_verified_peeled_commit() -> None:
    config = _mutate_workflow(
        "          ref: ${{ env.VERIFIED_SOURCE_COMMIT }}",
        "          ref: refs/tags/${{ env.RELEASE_TAG }}",
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="fetch only the verified peeled commit",
    ):
        _validate(config)


@pytest.mark.parametrize(
    "subject_execution",
    [
        "python attestation-input/release/tool.py",
        "bash attestation-input/release/tool.sh",
        "tar -xf attestation-input/release/image.tar",
        "npm test",
    ],
)
def test_release_security_config_rejects_subject_execution(
    subject_execution: str,
) -> None:
    config = _mutate_workflow(
        '          set -euo pipefail\n          [[ "${RELEASE_ARTIFACT_ID}"',
        f"          set -euo pipefail\n          {subject_execution}\n"
        '          [[ "${RELEASE_ARTIFACT_ID}"',
    )

    with pytest.raises(ReleaseSecurityConfigError, match="must not execute"):
        _validate(config)


@pytest.mark.parametrize("occurrence", [0, 1])
def test_release_security_config_requires_external_tag_trust_roots(
    occurrence: int,
) -> None:
    config = _mutate_workflow_occurrence(
        "${{ secrets.RELEASE_SIGNING_PUBLIC_KEYS_B64 }}",
        "${{ env.LOCAL_KEY }}",
        occurrence,
    )

    with pytest.raises(ReleaseSecurityConfigError, match="external signing trust roots"):
        _validate(config)


def test_release_security_config_rejects_verify_tag_secret_key_guard_after_import() -> None:
    config = list(load_current_config())
    workflow = config[0]
    guard = """          if grep -Eq '^(sec|ssb):' <<< "${inspection}"; then
            echo "Release trust bundle contains forbidden secret-key packets." >&2
            exit 1
          fi
"""
    assert guard in workflow
    config[0] = workflow.replace(guard, "", 1).replace(
        '          gpg --batch --no-options --homedir "${gnupg_home}" --import "${trust_bundle}"\n',
        '          gpg --batch --no-options --homedir "${gnupg_home}" --import "${trust_bundle}"\n'
        + guard,
        1,
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="verify-tag trusted verification run block changed",
    ):
        _validate(config)


def test_release_security_config_requires_trust_cleanup_before_attestation() -> None:
    config = _mutate_workflow(
        "          cleanup_trust\n          unset RELEASE_SIGNING_PUBLIC_KEYS_B64",
        "          unset RELEASE_SIGNING_PUBLIC_KEYS_B64",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="remove trust material"):
        _validate(config)


def test_release_security_config_requires_exact_image_coverage_in_both_jobs() -> None:
    config = _mutate_workflow(
        "        seaweedfs|infra/docker/seaweedfs.Dockerfile",
        "        duplicate|infra/docker/api.Dockerfile",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="eight current Dockerfiles"):
        _validate(config)


def test_release_security_config_rejects_parallel_docker_build() -> None:
    config = _mutate_workflow(
        '-f "${dockerfile}" .',
        '-f "${dockerfile}" . &',
    )

    with pytest.raises(ReleaseSecurityConfigError, match="background"):
        _validate(config)


@pytest.mark.parametrize(
    ("marker", "error"),
    [
        ("--format json", "scan-release missing"),
        ('metadata.get("ImageID")', "scan-release Trivy report verifier"),
        ("trivy_report_sha256", "scan-release missing"),
        ('exit "${scan_status}"', "scan-release missing"),
        ("xargs -0 sha256sum > SHA256SUMS", "scan-release missing"),
    ],
)
def test_release_security_config_requires_digest_bound_scan_evidence(
    marker: str,
    error: str,
) -> None:
    config = _mutate_workflow(marker, "REMOVED-MANDATORY-MARKER")

    with pytest.raises(ReleaseSecurityConfigError, match=error):
        _validate(config)


@pytest.mark.parametrize(
    "mandatory_logic",
    [
        "safe_tar_member_name(member.name)",
        "if not (member.isdir() or member.isreg())",
        "if observed_digest != expected_config_digest",
        "observed_diff_id != expected_diff_id",
        ") != expected_revision or labels.get(",
        ") != expected_version:",
        "len(images) != len(image_names)",
        "name in evidence_by_name",
        "status_name in status_by_name",
        'status_item.get("image_config_digest")',
        'item.get("image_reference") != expected_image_reference',
        "parsed release subject exceeds size limit",
        "invalid CycloneDX SBOM",
    ],
)
def test_release_security_config_requires_privileged_forgery_defenses(
    mandatory_logic: str,
) -> None:
    config = _mutate_workflow(mandatory_logic, "REMOVED-MANDATORY-LOGIC")

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="attest-release verification missing",
    ):
        _validate(config)


@pytest.mark.parametrize(
    ("old", "new", "forgery"),
    [
        (
            "if repo_tags != [expected_repo_tag]:",
            "if False and repo_tags != [expected_repo_tag]:",
            "RepoTags",
        ),
        (
            "if observed_digest != expected_config_digest:",
            "if False and observed_digest != expected_config_digest:",
            "config digest",
        ),
        (
            "if (\n                          not isinstance(layers, list)",
            "if False and (\n                          not isinstance(layers, list)",
            "layer inventory",
        ),
        (
            "if (\n                          not isinstance(rootfs, dict)",
            "if False and (\n                          not isinstance(rootfs, dict)",
            "rootfs.type",
        ),
        (
            "if observed_diff_id != expected_diff_id:",
            "if False and observed_diff_id != expected_diff_id:",
            "rootfs.diff_ids",
        ),
    ],
)
def test_release_security_config_executes_archive_forgery_regressions(
    old: str,
    new: str,
    forgery: str,
) -> None:
    config = _mutate_workflow(old, new)

    with pytest.raises(
        ReleaseSecurityConfigError,
        match=rf"archive verifier accepts forged {re.escape(forgery)}",
    ):
        _validate(config)


@pytest.mark.parametrize(
    ("old", "new", "forgery"),
    [
        (
            'if report.get("ArtifactName") != expected_archive_path:',
            'if False and report.get("ArtifactName") != expected_archive_path:',
            "absolute ArtifactName",
        ),
        (
            'if metadata.get("RepoTags") != [expected_repo_tag]:',
            'if False and metadata.get("RepoTags") != [expected_repo_tag]:',
            "missing RepoTags",
        ),
    ],
)
@pytest.mark.parametrize(
    ("occurrence", "job"),
    [(0, "scan-release"), (1, "attest-release")],
)
def test_release_security_config_executes_trivy_report_forgery_regressions(
    old: str,
    new: str,
    forgery: str,
    occurrence: int,
    job: str,
) -> None:
    config = _mutate_workflow_occurrence(old, new, occurrence)

    with pytest.raises(
        ReleaseSecurityConfigError,
        match=rf"{job} Trivy report verifier accepts forged {re.escape(forgery)}",
    ):
        _validate(config)


def test_release_security_config_rejects_tag_as_trivy_artifact_name() -> None:
    config = _mutate_workflow_occurrence(
        'expected_archive = f"images/{name}.docker.tar"',
        'expected_archive = built["image_reference"]',
        0,
    )

    with pytest.raises(ReleaseSecurityConfigError, match="scan-release missing"):
        _validate(config)


def test_release_security_config_rejects_scan_report_verifier_reassignment() -> None:
    config = _mutate_workflow_occurrence(
        '          root = Path(os.environ["RELEASE_ROOT"])',
        "          validate_trivy_report_binding = lambda *args, **kwargs: None\n"
        '          root = Path(os.environ["RELEASE_ROOT"])',
        0,
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="scan-release trusted finalizer run block changed|must not be reassigned",
    ):
        _validate(config)


def test_release_security_config_executes_label_forgery_regression() -> None:
    old = """if not isinstance(labels, dict) or labels.get(
                          "org.opencontainers.image.revision"
                      ) != expected_revision or labels.get(
                          "org.opencontainers.image.version"
                      ) != expected_version:"""
    new = """if False and (
                          not isinstance(labels, dict) or labels.get(
                              "org.opencontainers.image.revision"
                          ) != expected_revision or labels.get(
                              "org.opencontainers.image.version"
                          ) != expected_version
                      ):"""
    config = _mutate_workflow(old, new)

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="archive verifier accepts forged revision label",
    ):
        _validate(config)


@pytest.mark.parametrize(
    ("marker", "replacement", "error"),
    [
        ('--tag "${image_ref}"', "REMOVED-TAG", "build-release missing"),
        (
            "name=${image_ref},dest=${release_root}/images/${name}.docker.tar",
            "dest=${release_root}/images/${name}.docker.tar",
            "build-release missing",
        ),
        (
            "oci-mediatypes=false,compression=uncompressed,force-compression=true",
            "oci-mediatypes=true,compression=gzip,force-compression=false",
            "build-release missing",
        ),
        (
            "--config trivy-config.yaml --ignorefile trivy-ignorefile",
            "--config supplied.yaml --ignorefile supplied.ignore",
            "scan-release missing",
        ),
    ],
)
def test_release_security_config_rejects_ambiguous_image_or_scan_binding(
    marker: str,
    replacement: str,
    error: str,
) -> None:
    config = _mutate_workflow(marker, replacement)

    with pytest.raises(ReleaseSecurityConfigError, match=error):
        _validate(config)


def test_release_security_config_rejects_checkout_in_fresh_scan_job() -> None:
    config = _mutate_workflow(
        "    steps:\n      - name: Validate immutable build artifact handoff",
        "    steps:\n"
        "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Validate immutable build artifact handoff",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="scan-release"):
        _validate(config)


def test_release_security_config_rejects_artifact_code_execution_in_scan_job() -> None:
    config = _mutate_workflow(
        '          [[ "${BUILD_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
        "          python scan-input/release/tool.py\n"
        '          [[ "${BUILD_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
    )

    with pytest.raises(ReleaseSecurityConfigError, match="must not execute"):
        _validate(config)


@pytest.mark.parametrize(
    ("anchor", "injected", "error"),
    [
        (
            "  verify-tag:\n",
            "  verify-tag:\n    container: attacker-controlled:latest\n",
            "verify-tag job key inventory",
        ),
        (
            "  build-release:\n",
            "  build-release:\n    defaults:\n      run:\n        shell: bash\n",
            "build-release job key inventory",
        ),
        (
            "  scan-release:\n",
            "  scan-release:\n    container: attacker-controlled:latest\n",
            "scan-release job key inventory",
        ),
        (
            "  attest-release:\n",
            "  attest-release:\n    services:\n      helper:\n        image: attacker-controlled:latest\n",
            "attest-release job key inventory",
        ),
    ],
)
def test_release_security_config_rejects_unreviewed_job_execution_surfaces(
    anchor: str,
    injected: str,
    error: str,
) -> None:
    config = _mutate_workflow(anchor, injected)

    with pytest.raises(ReleaseSecurityConfigError, match=error):
        _validate(config)


def test_release_security_config_rejects_scan_job_env_expansion() -> None:
    config = _mutate_workflow(
        "      RELEASE_TAG: ${{ inputs.release_tag }}\n      BUILD_ARTIFACT_ID:",
        "      RELEASE_TAG: ${{ inputs.release_tag }}\n"
        "      PATH: /attacker/bin\n"
        "      BUILD_ARTIFACT_ID:",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="scan-release environment"):
        _validate(config)


def test_release_security_config_counts_secrets_across_entire_attestation_job() -> None:
    config = _mutate_workflow_occurrence(
        "    environment: release\n    permissions:",
        "    environment: release\n"
        "    container:\n"
        "      image: trusted.invalid/helper\n"
        "      credentials: ${{ secrets.EXTRA_CONTAINER_CREDENTIAL }}\n"
        "    permissions:",
        1,
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="exactly one protected trust-root secret",
    ):
        _validate(config)


def test_release_security_config_rejects_unreviewed_scan_step_environment() -> None:
    config = _mutate_workflow(
        "      - name: Validate immutable build artifact handoff\n        shell: bash",
        "      - name: Validate immutable build artifact handoff\n"
        "        env:\n"
        "          PATH: /attacker/bin\n"
        "        shell: bash",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="unexpected environment"):
        _validate(config)


@pytest.mark.parametrize(
    "injected_step",
    [
        "      - name: Unreviewed privileged command\n"
        "        shell: bash\n"
        "        run: python -c \"print('unexpected')\"\n",
        "      - name: Unreviewed local action\n        uses: ./attestation-input/release/action\n",
    ],
)
def test_release_security_config_rejects_extra_privileged_step(
    injected_step: str,
) -> None:
    anchor = "      - name: Verify external tag trust and inert release subjects\n"
    config = _mutate_workflow(anchor, injected_step + anchor)

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="attest-release ordered step inventory is not exact",
    ):
        _validate(config)


@pytest.mark.parametrize(
    ("old", "new", "occurrence", "error"),
    [
        (
            "github.ref_protected && github.ref_type == 'branch'",
            "true || github.ref_protected && github.ref_type == 'branch'",
            0,
            "verify-tag protected-ref condition is not exact",
        ),
        (
            "needs.verify-tag.result == 'success' &&",
            "true || needs.verify-tag.result == 'success' &&",
            0,
            "build-release verified-tag/protected-ref condition is not exact",
        ),
        (
            "needs.build-release.result == 'success' &&",
            "true || needs.build-release.result == 'success' &&",
            0,
            "scan-release dependency/protected-ref condition is not exact",
        ),
        (
            "needs.scan-release.result == 'success' &&",
            "true || needs.scan-release.result == 'success' &&",
            0,
            "attest-release dependency/protected-ref condition is not exact",
        ),
    ],
)
def test_release_security_config_rejects_job_condition_or_true_bypass(
    old: str,
    new: str,
    occurrence: int,
    error: str,
) -> None:
    config = _mutate_workflow_occurrence(old, new, occurrence)

    with pytest.raises(ReleaseSecurityConfigError, match=error):
        _validate(config)


def test_release_security_config_rejects_early_success_in_attestation_handoff() -> None:
    config = _mutate_workflow(
        '          set -euo pipefail\n          [[ "${RELEASE_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
        "          set -euo pipefail\n"
        "          exit 0\n"
        '          [[ "${RELEASE_ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="attest-release immutable handoff validation run block is not exact",
    ):
        _validate(config)


def test_release_security_config_rejects_early_success_in_privileged_python() -> None:
    config = _mutate_workflow(
        "          from __future__ import annotations\n\n          import hashlib",
        "          from __future__ import annotations\n\n"
        "          raise SystemExit(0)\n\n"
        "          import hashlib",
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="full privileged verifier run block changed|exit successfully early",
    ):
        _validate(config)


def test_release_security_config_rejects_early_success_in_privileged_shell() -> None:
    config = _mutate_workflow_occurrence(
        "          set -euo pipefail\n          umask 077",
        "          set -euo pipefail\n          exit 0\n          umask 077",
        1,
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="full privileged verifier run block changed",
    ):
        _validate(config)


def test_release_security_config_rejects_early_success_in_verify_tag() -> None:
    config = _mutate_workflow_occurrence(
        "          set -euo pipefail\n          umask 077",
        "          set -euo pipefail\n          exit 0\n          umask 077",
        0,
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="verify-tag trusted verification run block changed",
    ):
        _validate(config)


def test_release_security_config_rejects_archive_verifier_reassignment() -> None:
    config = _mutate_workflow(
        '          manifest_path = root / "SHA256SUMS"',
        "          validate_docker_archive = lambda *args, **kwargs: []\n\n"
        '          manifest_path = root / "SHA256SUMS"',
    )

    with pytest.raises(
        ReleaseSecurityConfigError,
        match="full privileged verifier run block changed|must not be reassigned",
    ):
        _validate(config)


def test_release_security_config_rejects_stale_workspace_release_path() -> None:
    config = _mutate_workflow('cd "${RELEASE_ROOT}"', "cd release")

    with pytest.raises(ReleaseSecurityConfigError, match="build-release missing"):
        _validate(config)


def test_release_security_config_requires_immutable_artifact_handoff() -> None:
    config = _mutate_workflow(
        "artifact-ids: ${{ env.RELEASE_ARTIFACT_ID }}",
        "name: release-subjects",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="exact immutable artifact id"):
        _validate(config)


def test_release_security_config_requires_envelope_and_subject_attestations() -> None:
    config = _mutate_workflow(
        "subject-digest: sha256:${{ env.RELEASE_ARTIFACT_DIGEST }}",
        "subject-digest: sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="artifact envelope"):
        _validate(config)


def test_release_security_config_requires_both_runtime_sboms() -> None:
    config = _mutate_workflow(
        "sbom-path: attestation-input/release/node-runtime.cdx.json",
        "sbom-path: attestation-input/release/api-runtime.cdx.json",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="API and Node SBOM"):
        _validate(config)


def test_release_security_config_requires_canonical_semver_runtime_check() -> None:
    config = _mutate_workflow(
        "^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
        "^v.*$",
    )

    with pytest.raises(ReleaseSecurityConfigError, match="semantic"):
        _validate(config)


def test_release_security_config_requires_ci_security_and_make_wiring() -> None:
    config = list(load_current_config())
    gate = "python scripts/ci/check_release_security_config.py"
    config[1] = config[1].replace(gate, "")
    config[2] = config[2].replace(gate, "")
    config[3] = config[3].replace("scripts/ci/check_release_security_config.py", "")

    with pytest.raises(ReleaseSecurityConfigError, match="security workflow"):
        _validate(config)


def test_release_security_config_requires_gate_inside_make_security_check() -> None:
    config = list(load_current_config())
    old = (
        "\t$(PY) scripts/ci/check_encryption_config.py\n"
        "\t$(PY) scripts/ci/check_release_security_config.py\n"
        "\t$(PY) scripts/ci/check_release_encryption_workflow.py"
    )
    new = (
        "\t$(PY) scripts/ci/check_encryption_config.py\n"
        "\t$(PY) scripts/ci/check_release_encryption_workflow.py"
    )
    assert old in config[3]
    config[3] = config[3].replace(old, new, 1)

    with pytest.raises(ReleaseSecurityConfigError, match="security-check must run"):
        _validate(config)


def test_release_security_config_requires_external_environment_policy_docs() -> None:
    config = list(load_current_config())
    config[4] = config[4].replace("required independent reviewers", "optional reviewers")

    with pytest.raises(ReleaseSecurityConfigError, match="release process documentation"):
        _validate(config)
