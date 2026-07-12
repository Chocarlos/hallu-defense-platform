from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.ci import verify_release_encryption_evidence as verifier

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 7, 11, 12, 2, tzinfo=UTC)


@dataclass
class EvidenceFixture:
    bundle_path: Path
    report_path: Path
    manifest_path: Path
    trust_store_path: Path
    keyring_path: Path
    replay_path: Path
    environ: dict[str, str]
    bundle: dict[str, object]
    trust_store: dict[str, object]
    keyring: dict[str, object]
    replay_state: dict[str, object]
    auth_private_keys: dict[str, Ed25519PrivateKey]
    commitment_keys: dict[str, bytes]
    state_keys: dict[str, bytes]
    report_keys: dict[str, bytes]

    def sign_and_write_bundle(self) -> None:
        self.bundle["commitments"] = []
        self.bundle["authenticators"] = []
        commitment_payload = verifier.canonical_commitment_payload(self.bundle)
        commitments = [
            {
                "algorithm": "hmac-sha256",
                "key_id": key_id,
                "value": hmac.new(key, commitment_payload, hashlib.sha256).hexdigest(),
            }
            for key_id, key in self.commitment_keys.items()
        ]
        self.bundle["commitments"] = commitments
        authenticator_payload = verifier.canonical_authenticator_payload(self.bundle)
        self.bundle["authenticators"] = [
            {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value": base64.b64encode(private.sign(authenticator_payload)).decode("ascii"),
            }
            for key_id, private in self.auth_private_keys.items()
        ]
        _write_json(self.bundle_path, self.bundle)

    def write_replay_state(self) -> None:
        self.replay_state["state_mac"] = ""
        state_key_id = cast(str, self.replay_state["state_key_id"])
        self.replay_state["state_mac"] = hmac.new(
            self.state_keys[state_key_id],
            verifier.canonical_replay_state_payload(self.replay_state),
            hashlib.sha256,
        ).hexdigest()
        _write_json(self.replay_path, self.replay_state)
        self.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] = _sha256(
            self.replay_path.read_bytes()
        )


def test_valid_evidence_asserts_compliance_and_advances_replay_state(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    prepared = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=fixture.environ,
        now=NOW,
    )

    assert prepared["compliance_asserted"] is False
    assert prepared["anchor_update_required"] is True
    assert prepared["anchor_finalized"] is False
    assert prepared["failure_codes"] == ["anchor.update_required"]
    fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] = cast(
        str,
        prepared["replay_state_next_sha256"],
    )
    report = _verify(fixture)

    assert report["compliance_asserted"] is True
    assert report["anchor_update_required"] is False
    assert report["anchor_finalized"] is True
    assert all(cast(dict[str, bool], report["checks"]).values())
    assert report["failure_codes"] == []
    written_report = json.loads(fixture.report_path.read_text(encoding="utf-8"))
    assert written_report == report
    state = json.loads(fixture.replay_path.read_text(encoding="utf-8"))
    binding = state["bindings"][0]
    assert binding["highest_sequence"] == 41
    assert binding["highest_deployment_revision"] == 42
    assert binding["highest_rotation_epoch"] == 7
    assert binding["current_rotation_phase"] == "stable"


def test_empty_replay_state_bootstraps_only_the_expected_scope(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.replay_state["bindings"] = []
    fixture.write_replay_state()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["anchor.update_required"]
    state = json.loads(fixture.replay_path.read_text(encoding="utf-8"))
    assert len(state["bindings"]) == 1
    assert state["bindings"][0]["tenant_id"] == "tenant-example"
    assert state["bindings"][0]["environment"] == "production"


def test_replay_state_rejects_a_foreign_tenant_environment_scope(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    binding = cast(list[dict[str, object]], fixture.replay_state["bindings"])[0]
    binding.update({"tenant_id": "tenant-other", "environment": "staging"})
    fixture.write_replay_state()
    state_before = fixture.replay_path.read_bytes()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["replay.state_binding_invalid"]
    assert fixture.replay_path.read_bytes() == state_before


def test_replay_state_schema_rejects_mixed_tenant_bindings(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    foreign = copy.deepcopy(cast(list[dict[str, object]], fixture.replay_state["bindings"])[0])
    foreign.update({"tenant_id": "tenant-other", "environment": "staging"})
    cast(list[dict[str, object]], fixture.replay_state["bindings"]).append(foreign)
    fixture.write_replay_state()
    state_before = fixture.replay_path.read_bytes()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["replay.invalid_state"]
    assert fixture.replay_path.read_bytes() == state_before


def test_same_bundle_finalization_is_idempotent_but_changed_replay_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    first, second = _finalize(fixture)
    third = _verify(fixture)

    assert first["anchor_update_required"] is True
    assert second["compliance_asserted"] is True
    assert third["compliance_asserted"] is True

    fixture.bundle["bundle_id"] = "bundle-example-0002"
    fixture.bundle["nonce"] = "1123456789abcdef0123456789abcdef"
    fixture.sign_and_write_bundle()
    replay = _verify(fixture)
    assert replay["compliance_asserted"] is False
    assert replay["failure_codes"] == ["replay.detected"]


def test_phase_one_retry_is_idempotent_until_external_cas_advances(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    external_old = fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256]

    first = _verify(fixture)
    first_state = fixture.replay_path.read_bytes()
    second = _verify(fixture)

    assert fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] == external_old
    assert fixture.replay_path.read_bytes() == first_state
    assert first["compliance_asserted"] is False
    assert second["compliance_asserted"] is False
    assert first["replay_state_previous_sha256"] == external_old
    assert second["replay_state_previous_sha256"] == external_old
    assert first["replay_state_next_sha256"] == second["replay_state_next_sha256"]
    assert first["failure_codes"] == ["anchor.update_required"]
    assert second["failure_codes"] == ["anchor.update_required"]


def test_expected_anchor_is_mandatory_and_never_inferred_from_local_state(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    state_before = fixture.replay_path.read_bytes()
    del fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256]

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["external.missing_context"]
    assert fixture.replay_path.read_bytes() == state_before


def test_finalized_transition_cannot_replay_after_a_newer_transition(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first_bundle = copy.deepcopy(fixture.bundle)
    _finalize(fixture)

    fixture.bundle["bundle_id"] = "bundle-example-0002"
    fixture.bundle["sequence"] = 42
    fixture.bundle["nonce"] = "1123456789abcdef0123456789abcdef"
    fixture.bundle["issued_at"] = "2026-07-11T12:01:30Z"
    fixture.bundle["expires_at"] = "2026-07-11T12:06:30Z"
    fixture.sign_and_write_bundle()
    _finalize(fixture)

    fixture.bundle = first_bundle
    fixture.sign_and_write_bundle()
    replay = _verify(fixture)

    assert replay["compliance_asserted"] is False
    assert replay["failure_codes"] == ["replay.detected"]


def test_external_anchor_detects_restored_valid_mac_snapshot(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    old_snapshot = fixture.replay_path.read_bytes()
    prepared = _verify(fixture)
    next_anchor = cast(str, prepared["replay_state_next_sha256"])
    fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] = next_anchor

    fixture.replay_path.write_bytes(old_snapshot)
    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["replay.anchor_mismatch"]


def test_report_hmac_detects_portable_report_tampering(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    prepared, report = _finalize(fixture)
    active_key_id = "report-epoch-7"
    active_key = fixture.report_keys[active_key_id]

    assert verifier.report_authenticator_is_valid(
        prepared,
        key_id=active_key_id,
        key_material=active_key,
    )
    assert verifier.report_authenticator_is_valid(
        report,
        key_id=active_key_id,
        key_material=active_key,
    )
    forged = copy.deepcopy(report)
    forged["bundle_id"] = "bundle-forged-0001"
    assert not verifier.report_authenticator_is_valid(
        forged,
        key_id=active_key_id,
        key_material=active_key,
    )
    assert not verifier.report_authenticator_is_valid(
        report,
        key_id=active_key_id,
        key_material=b"short",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"compliance_asserted": True},
        {"anchor_finalized": True},
        {"failure_codes": ["different.failure"]},
    ],
)
def test_phase_one_report_schema_rejects_impossible_compliance_states(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    fixture = _fixture(tmp_path)
    prepared = _verify(fixture)
    impossible = copy.deepcopy(prepared)
    impossible.update(mutation)

    with pytest.raises(verifier.EvidenceVerificationError, match="report.schema_invalid"):
        verifier._validate_report(impossible)


def test_report_path_must_be_absolute_and_outside_untrusted_bundle(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    with pytest.raises(verifier.ReportWriteError):
        verifier.verify_bundle(
            fixture.bundle_path,
            "relative-report.json",
            environ=fixture.environ,
            now=NOW,
        )

    bundled_report = fixture.bundle_path.parent / "forged-report.json"
    with pytest.raises(verifier.ReportWriteError):
        verifier.verify_bundle(
            fixture.bundle_path,
            bundled_report,
            environ=fixture.environ,
            now=NOW,
        )
    assert not bundled_report.exists()

    state_before = fixture.replay_path.read_bytes()
    with pytest.raises(verifier.ReportWriteError):
        verifier.verify_bundle(
            fixture.bundle_path,
            fixture.replay_path,
            environ=fixture.environ,
            now=NOW,
        )
    assert fixture.replay_path.read_bytes() == state_before


@pytest.mark.parametrize("field", ["keyring", "policy", "schema", "trust_store"])
def test_bundle_cannot_embed_its_own_trust_material(tmp_path: Path, field: str) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle[field] = {"attacker": True}
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["bundle.embedded_trust_material"]


def test_missing_attestation_never_asserts_compliance(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle["attestations"] = [cast(list[object], fixture.bundle["attestations"])[0]]
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["bundle.schema_invalid"]
    assert cast(dict[str, bool], report["checks"])["controls_attested"] is False


def test_duplicate_at_rest_attestation_is_rejected_even_when_schema_shape_is_valid(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    at_rest = cast(list[object], fixture.bundle["attestations"])[0]
    fixture.bundle["attestations"] = [copy.deepcopy(at_rest), copy.deepcopy(at_rest)]
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["provenance.material_mismatch"]


def test_forged_ed25519_signature_is_rejected_without_secret_disclosure(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    authenticators = cast(list[dict[str, str]], fixture.bundle["authenticators"])
    authenticators[0]["value"] = base64.b64encode(b"x" * 64).decode("ascii")
    _write_json(fixture.bundle_path, fixture.bundle)

    report = _verify(fixture)
    report_text = fixture.report_path.read_text(encoding="utf-8")

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["signature.invalid"]
    for secret in (*fixture.state_keys.values(), *fixture.report_keys.values()):
        assert base64.b64encode(secret).decode("ascii") not in report_text
    for secret in fixture.commitment_keys.values():
        assert base64.b64encode(secret).decode("ascii") not in report_text


def test_tampered_hmac_commitment_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    commitments = cast(list[dict[str, str]], fixture.bundle["commitments"])
    commitments[0]["value"] = "0" * 64
    _write_json(fixture.bundle_path, fixture.bundle)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["commitment.invalid"]


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("tenant_id", "tenant-attacker", "binding.tenant_mismatch"),
        ("environment", "staging", "binding.environment_mismatch"),
    ],
)
def test_bundle_is_bound_to_external_tenant_and_environment(
    tmp_path: Path,
    field: str,
    value: str,
    code: str,
) -> None:
    fixture = _fixture(tmp_path)
    cast(dict[str, object], fixture.bundle["subject"])[field] = value
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == [code]


def test_trust_root_and_signing_principal_are_unambiguous_external_context(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    wrong_root = fixture.environ | {verifier.ENV_EXPECTED_TRUST_ROOT_ID: "tenant-example-attacker"}
    root_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=wrong_root,
        now=NOW,
    )
    assert root_report["failure_codes"] == ["binding.trust_root_mismatch"]

    binding = cast(dict[str, object], cast(list[object], fixture.trust_store["bindings"])[0])
    binding["allowed_issuers"] = [
        "release-attestor.example.invalid",
        "attacker.example.invalid",
    ]
    _rewrite_trust_manifest_and_bundle(fixture)
    principal_report = _verify(fixture)
    assert principal_report["failure_codes"] == ["binding.ambiguous_signing_principal"]


def test_postgres_ca_secret_subpath_and_rollout_are_bound_to_manifest(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    manifest = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
    manifest["postgres_tls"]["mount_path"] = "/var/run/secrets/postgres/not-ca.crt"
    _write_json(fixture.manifest_path, manifest)
    _rewrite_trust_manifest_and_bundle(fixture)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["binding.postgres_tls_invalid"]


def test_provenance_source_commit_must_match_external_deployment(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    cast(dict[str, object], fixture.bundle["provenance"])["source_commit"] = "b" * 40
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["provenance.deployment_mismatch"]


def test_provenance_requires_exact_material_set_without_duplicates(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    materials = cast(
        list[object], cast(dict[str, object], fixture.bundle["provenance"])["materials"]
    )
    materials[1] = copy.deepcopy(materials[0])
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["provenance.duplicate_material"]


def test_provenance_binds_external_workflow_definition_hash(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    materials = cast(
        list[dict[str, object]],
        cast(dict[str, object], fixture.bundle["provenance"])["materials"],
    )
    workflow_material = next(
        material for material in materials if material["uri"] == "workflow-definition"
    )
    workflow_material["sha256"] = "0" * 64
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["provenance.material_mismatch"]


def test_policy_minimum_tls_and_all_algorithms_are_enforced(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    in_transit = cast(dict[str, object], cast(list[object], fixture.bundle["attestations"])[1])
    cast(dict[str, object], in_transit["claims"])["minimum_tls_version"] = "1.2"
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["controls.tls_too_old"]


def test_encryption_policy_rejects_unknown_component_profile() -> None:
    policy = json.loads(
        (ROOT / "infra/security/encryption-policy.json").read_text(encoding="utf-8")
    )
    policy["components"]["postgres"]["profile"] = "actve"

    with pytest.raises(verifier.EvidenceVerificationError) as raised:
        verifier._validate_encryption_policy(policy)

    assert raised.value.code == "external.policy_invalid"


@pytest.mark.parametrize(
    ("path", "unsafe_value"),
    [
        (("defaults", "at_rest", "algorithm"), "BROKEN-AES-256-PLAINTEXT"),
        (("defaults", "at_rest", "key_management"), "plaintext-file"),
        (("components", "postgres", "at_rest", "algorithm"), "AES-256-WEAK"),
        (("components", "postgres", "at_rest", "key_management"), "plaintext-file"),
    ],
)
def test_encryption_policy_rejects_unapproved_algorithm_or_key_management(
    path: tuple[str, ...],
    unsafe_value: str,
) -> None:
    policy = json.loads(
        (ROOT / "infra/security/encryption-policy.json").read_text(encoding="utf-8")
    )
    target = policy
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = unsafe_value

    with pytest.raises(verifier.EvidenceVerificationError) as raised:
        verifier._validate_encryption_policy(policy)

    assert raised.value.code == "external.policy_invalid"


def test_expired_bundle_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle["expires_at"] = "2026-07-11T12:00:00Z"
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["timestamp.bundle_not_current"]


def test_attestation_must_be_observed_after_provenance_finishes(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    attestation = cast(list[dict[str, object]], fixture.bundle["attestations"])[0]
    attestation["observed_at"] = "2026-07-11T12:00:20Z"
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["timestamp.attestation_invalid"]


def test_attestation_observation_cannot_postdate_bundle_issue(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle["issued_at"] = "2026-07-11T12:02:30Z"
    fixture.bundle["expires_at"] = "2026-07-11T12:07:30Z"
    attestations = cast(list[dict[str, object]], fixture.bundle["attestations"])
    attestations[0]["observed_at"] = "2026-07-11T12:03:00Z"
    attestations[1]["observed_at"] = "2026-07-11T12:03:00Z"
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["timestamp.attestation_invalid"]


def test_replay_timestamp_preserves_fractional_precision(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle["issued_at"] = "2026-07-11T12:01:00.900000Z"
    fixture.bundle["expires_at"] = "2026-07-11T12:06:00.900000Z"
    fixture.sign_and_write_bundle()
    prepared = _verify(fixture)
    state = json.loads(fixture.replay_path.read_text(encoding="utf-8"))
    assert state["bindings"][0]["last_issued_at"] == "2026-07-11T12:01:00.900000Z"
    fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] = cast(
        str,
        prepared["replay_state_next_sha256"],
    )

    fixture.bundle["bundle_id"] = "bundle-example-0002"
    fixture.bundle["sequence"] = 42
    fixture.bundle["nonce"] = "1123456789abcdef0123456789abcdef"
    fixture.bundle["issued_at"] = "2026-07-11T12:01:00.100000Z"
    fixture.bundle["expires_at"] = "2026-07-11T12:06:00.100000Z"
    fixture.sign_and_write_bundle()
    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["rollback.timestamp"]


def test_timestamp_precision_beyond_microseconds_is_rejected_not_truncated(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle["issued_at"] = "2026-07-11T12:01:00.1234567Z"
    fixture.sign_and_write_bundle()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["timestamp.invalid"]


def test_invalid_replay_state_mac_fails_closed_without_overwrite(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.replay_state["state_mac"] = "0" * 64
    _write_json(fixture.replay_path, fixture.replay_state)
    before = fixture.replay_path.read_bytes()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["replay.state_mac_invalid"]
    assert fixture.replay_path.read_bytes() == before


@pytest.mark.parametrize(
    ("state_change", "code"),
    [
        ({"highest_deployment_revision": 43}, "rollback.deployment_revision"),
        ({"highest_rotation_epoch": 8}, "rollback.rotation_epoch"),
        ({"last_issued_at": "2026-07-11T12:01:00Z"}, "rollback.timestamp"),
        ({"recent_nonces": ["0123456789abcdef0123456789abcdef"]}, "replay.detected"),
    ],
)
def test_replay_state_rejects_rollback_dimensions(
    tmp_path: Path,
    state_change: dict[str, object],
    code: str,
) -> None:
    fixture = _fixture(tmp_path)
    binding = cast(list[dict[str, object]], fixture.replay_state["bindings"])[0]
    binding.update(state_change)
    fixture.write_replay_state()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == [code]


def test_overlap_rotation_requires_old_and_new_authentication_material(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)

    _, report = _finalize(fixture)

    assert report["compliance_asserted"] is True
    assert len(cast(list[object], fixture.bundle["commitments"])) == 2
    assert len(cast(list[object], fixture.bundle["authenticators"])) == 2
    migrated_state = json.loads(fixture.replay_path.read_text(encoding="utf-8"))
    assert migrated_state["state_key_id"] == "state-epoch-8"


def test_overlap_rotation_rejects_missing_retiring_signature(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)
    authenticators = cast(list[dict[str, str]], fixture.bundle["authenticators"])
    fixture.bundle["authenticators"] = authenticators[:1]
    _write_json(fixture.bundle_path, fixture.bundle)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["signature.key_set_invalid"]


def test_overlap_rotation_rejects_nonadjacent_retiring_epoch(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)
    binding = cast(
        dict[str, object],
        cast(list[object], fixture.trust_store["bindings"])[0],
    )
    for field in (
        "authenticator_keys",
        "commitment_keys",
        "replay_state_keys",
        "report_authenticator_keys",
    ):
        for descriptor in cast(list[dict[str, object]], binding[field]):
            if descriptor["status"] == "retiring":
                descriptor["epoch"] = 1
    _rewrite_trust_manifest_and_bundle(fixture)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["rotation.previous_key_invalid"]


def test_expired_overlap_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)
    rotation = cast(dict[str, object], cast(list[object], fixture.trust_store["bindings"])[0])[
        "rotation"
    ]
    cast(dict[str, object], rotation)["overlap_not_after"] = "2026-07-11T12:01:59Z"
    _rewrite_trust_manifest_and_bundle(fixture)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["rotation.overlap_expired"]


def test_bundle_ttl_cannot_outlive_rotation_overlap(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)
    binding = cast(dict[str, object], cast(list[object], fixture.trust_store["bindings"])[0])
    cast(dict[str, object], binding["rotation"])["overlap_not_after"] = "2026-07-11T12:05:00Z"
    _rewrite_trust_manifest_and_bundle(fixture)

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["rotation.bundle_outlives_overlap"]


def test_same_epoch_cannot_roll_back_from_stable_to_overlap(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, overlap=True)
    binding = cast(list[dict[str, object]], fixture.replay_state["bindings"])[0]
    binding.update({"highest_rotation_epoch": 8, "current_rotation_phase": "stable"})
    fixture.write_replay_state()

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["rollback.rotation_phase"]


def test_external_inputs_must_be_absolute_distinct_and_outside_bundle(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    relative_env = fixture.environ | {verifier.ENV_KEYRING_PATH: fixture.keyring_path.name}
    relative_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=relative_env,
        now=NOW,
    )
    assert relative_report["failure_codes"] == ["external.path_invalid"]

    collision_env = fixture.environ | {verifier.ENV_KEYRING_PATH: str(fixture.trust_store_path)}
    collision_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=collision_env,
        now=NOW,
    )
    assert collision_report["failure_codes"] == ["external.path_collision"]

    bundled_manifest = fixture.bundle_path.parent / "deployment.json"
    bundled_manifest.write_bytes(fixture.manifest_path.read_bytes())
    bundled_env = fixture.environ | {
        verifier.ENV_DEPLOYMENT_SUBJECT_PATH: str(bundled_manifest.resolve())
    }
    bundled_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=bundled_env,
        now=NOW,
    )
    assert bundled_report["failure_codes"] == ["external.bundle_owned"]


@pytest.mark.posix
def test_external_path_traversal_and_symlink_are_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    traversal = str(fixture.keyring_path.parent / ".." / "trusted" / fixture.keyring_path.name)
    traversal_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=fixture.environ | {verifier.ENV_KEYRING_PATH: traversal},
        now=NOW,
    )
    assert traversal_report["failure_codes"] == ["external.path_traversal"]

    symlink = fixture.keyring_path.with_name("keyring-link.json")
    symlink.symlink_to(fixture.keyring_path)
    symlink_report = verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=fixture.environ | {verifier.ENV_KEYRING_PATH: str(symlink.absolute())},
        now=NOW,
    )
    assert symlink_report["failure_codes"] == ["external.path_symlink"]


def test_replay_update_failure_cannot_produce_compliant_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    before = fixture.replay_path.read_bytes()
    real_replace = os.replace

    def fail_state_replace(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == fixture.replay_path:
            raise OSError("injected state write failure")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_state_replace)
    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["replay.update_failed"]
    assert fixture.replay_path.read_bytes() == before


def test_duplicate_json_members_fail_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.bundle_path.write_text(
        '{"schema_version":"release-encryption-evidence.v1",'
        '"schema_version":"release-encryption-evidence.v1"}',
        encoding="utf-8",
    )

    report = _verify(fixture)

    assert report["compliance_asserted"] is False
    assert report["failure_codes"] == ["bundle.invalid_json"]


def test_cli_exposes_no_trust_override_options() -> None:
    parser = verifier.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--bundle",
                "evidence.json",
                "--report",
                "report.json",
                "--schema",
                "attacker.json",
            ]
        )


def test_cli_exit_codes_distinguish_anchor_preparation_and_finalization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reports = iter(
        [
            {"compliance_asserted": False, "anchor_update_required": True},
            {"compliance_asserted": True, "anchor_finalized": True},
        ]
    )
    monkeypatch.setattr(verifier, "verify_bundle", lambda *_args, **_kwargs: next(reports))
    arguments = [
        "--bundle",
        str((tmp_path / "bundle.json").resolve()),
        "--report",
        str((tmp_path / "report.json").resolve()),
    ]

    assert verifier.main(arguments) == 1
    assert verifier.main(arguments) == 0


def _verify(fixture: EvidenceFixture) -> dict[str, object]:
    return verifier.verify_bundle(
        fixture.bundle_path,
        fixture.report_path,
        environ=fixture.environ,
        now=NOW,
    )


def _finalize(fixture: EvidenceFixture) -> tuple[dict[str, object], dict[str, object]]:
    prepared = _verify(fixture)
    assert prepared["compliance_asserted"] is False
    assert prepared["anchor_update_required"] is True
    fixture.environ[verifier.ENV_EXPECTED_REPLAY_STATE_SHA256] = cast(
        str,
        prepared["replay_state_next_sha256"],
    )
    finalized = _verify(fixture)
    return prepared, finalized


def _fixture(tmp_path: Path, *, overlap: bool = False) -> EvidenceFixture:
    untrusted = tmp_path / "untrusted"
    trusted = tmp_path / "trusted"
    reports = tmp_path / "reports"
    untrusted.mkdir()
    trusted.mkdir()
    reports.mkdir()

    current_auth = Ed25519PrivateKey.generate()
    current_commitment = b"current-commitment-key-material!"
    auth_keys: dict[str, Ed25519PrivateKey]
    commitment_keys: dict[str, bytes]
    if overlap:
        previous_auth = Ed25519PrivateKey.generate()
        previous_commitment = b"previous-commitment-key-material"
        auth_keys = {"auth-epoch-8": current_auth, "auth-epoch-7": previous_auth}
        commitment_keys = {
            "commit-epoch-8": current_commitment,
            "commit-epoch-7": previous_commitment,
        }
        state_keys = {
            "state-epoch-8": b"current-state-key-material-epoch-8",
            "state-epoch-7": b"previous-state-key-material-epoch7",
        }
        report_keys = {
            "report-epoch-8": b"current-report-key-material-epoch8",
            "report-epoch-7": b"previous-report-key-material-epoch7",
        }
        epoch = 8
        phase = "overlap"
    else:
        auth_keys = {"auth-epoch-7": current_auth}
        commitment_keys = {"commit-epoch-7": current_commitment}
        state_keys = {"state-epoch-7": b"current-state-key-material-epoch-7"}
        report_keys = {"report-epoch-7": b"current-report-key-material-epoch7"}
        epoch = 7
        phase = "stable"

    auth_descriptors: list[dict[str, object]] = []
    commitment_descriptors: list[dict[str, object]] = []
    keyring_entries: list[dict[str, object]] = []
    for key_id, private in auth_keys.items():
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_epoch = int(key_id.rsplit("-", maxsplit=1)[1])
        auth_descriptors.append(
            _descriptor(
                key_id,
                public,
                epoch=key_epoch,
                status="active" if key_epoch == epoch else "retiring",
            )
        )
        keyring_entries.append(_keyring_entry(key_id, "authenticator-ed25519-public", public))
    for key_id, key in commitment_keys.items():
        key_epoch = int(key_id.rsplit("-", maxsplit=1)[1])
        commitment_descriptors.append(
            _descriptor(
                key_id,
                key,
                epoch=key_epoch,
                status="active" if key_epoch == epoch else "retiring",
            )
        )
        keyring_entries.append(_keyring_entry(key_id, "commitment-hmac-sha256", key))
    replay_descriptors: list[dict[str, object]] = []
    for key_id, key in state_keys.items():
        key_epoch = int(key_id.rsplit("-", maxsplit=1)[1])
        replay_descriptors.append(
            _descriptor(
                key_id,
                key,
                epoch=key_epoch,
                status="active" if key_epoch == epoch else "retiring",
            )
        )
        keyring_entries.append(_keyring_entry(key_id, "replay-state-hmac-sha256", key))
    report_descriptors: list[dict[str, object]] = []
    for key_id, key in report_keys.items():
        key_epoch = int(key_id.rsplit("-", maxsplit=1)[1])
        report_descriptors.append(
            _descriptor(
                key_id,
                key,
                epoch=key_epoch,
                status="active" if key_epoch == epoch else "retiring",
            )
        )
        keyring_entries.append(_keyring_entry(key_id, "verification-report-hmac-sha256", key))

    current_auth_id = f"auth-epoch-{epoch}"
    current_commitment_id = f"commit-epoch-{epoch}"
    previous_auth_id = "auth-epoch-7" if overlap else None
    previous_commitment_id = "commit-epoch-7" if overlap else None
    current_state_id = f"state-epoch-{epoch}"
    previous_state_id = "state-epoch-7" if overlap else None
    current_report_id = f"report-epoch-{epoch}"
    previous_report_id = "report-epoch-7" if overlap else None
    rotation: dict[str, object] = {
        "epoch": epoch,
        "phase": phase,
        "active_authenticator_key_id": current_auth_id,
        "active_commitment_key_id": current_commitment_id,
        "previous_authenticator_key_id": previous_auth_id,
        "previous_commitment_key_id": previous_commitment_id,
        "required_authenticator_key_ids": list(auth_keys),
        "required_commitment_key_ids": list(commitment_keys),
        "active_replay_state_key_id": current_state_id,
        "previous_replay_state_key_id": previous_state_id,
        "required_replay_state_key_ids": list(state_keys),
        "active_report_authenticator_key_id": current_report_id,
        "previous_report_authenticator_key_id": previous_report_id,
        "required_report_authenticator_key_ids": list(report_keys),
        "overlap_not_after": "2026-07-12T00:00:00Z" if overlap else None,
    }
    binding: dict[str, object] = {
        "tenant_id": "tenant-example",
        "environment": "production",
        "trust_root_id": "tenant-example-production",
        "allowed_issuers": ["release-attestor.example.invalid"],
        "allowed_builders": ["builder.example.invalid/hallu-defense"],
        "allowed_workflows": ["release.yml@refs/tags/v1.2.3"],
        "allowed_source_repositories": ["https://example.invalid/hallu-defense"],
        "allowed_kms_authorities": ["vault://example/transit/release"],
        "allowed_tls_ca_sha256": ["1" * 64],
        "sequence_floor": 40,
        "deployment_revision_floor": 41,
        "freshness": {
            "max_bundle_age_seconds": 600,
            "max_attestation_age_seconds": 300,
            "max_clock_skew_seconds": 30,
        },
        "authenticator_keys": auth_descriptors,
        "commitment_keys": commitment_descriptors,
        "replay_state_keys": replay_descriptors,
        "report_authenticator_keys": report_descriptors,
        "rotation": rotation,
    }
    trust_store: dict[str, object] = {
        "schema_version": "release-encryption-trust-store.v1",
        "trust_store_id": "release-trust-example",
        "generated_at": "2026-07-11T00:00:00Z",
        "valid_until": "2027-07-11T00:00:00Z",
        "bindings": [binding],
    }
    trust_store_path = trusted / "trust-store.json"
    _write_json(trust_store_path, trust_store)
    keyring: dict[str, object] = {
        "schema_version": "release-encryption-keyring.v1",
        "trust_store_id": "release-trust-example",
        "keys": keyring_entries,
    }
    keyring_path = trusted / "keyring.json"
    _write_json(keyring_path, keyring)

    policy_hash = _sha256((ROOT / "infra/security/encryption-policy.json").read_bytes())
    trust_hash = _sha256(trust_store_path.read_bytes())
    manifest: dict[str, object] = {
        "schema_version": "release-deployment-subject.v1",
        "tenant_id": "tenant-example",
        "environment": "production",
        "release_id": "release-2026-07-11",
        "deployment_revision": 42,
        "source_repository": "https://example.invalid/hallu-defense",
        "source_commit": "a" * 40,
        "workflow_ref": "release.yml@refs/tags/v1.2.3",
        "workflow_sha256": "9" * 64,
        "encryption_policy_sha256": policy_hash,
        "trust_store_sha256": trust_hash,
        "postgres_tls": {
            "secret_resource_uid": "postgres-ca-uid-0001",
            "secret_name": "postgres-client-ca",
            "ca_key": "ca.crt",
            "bundle_sha256": "1" * 64,
            "mount_path": "/var/run/secrets/hallu-defense/postgres/ca.crt",
            "sub_path": True,
            "rollout_revision": 42,
            "rollout_sha256": "f" * 64,
        },
        "artifacts": [
            {
                "name": "api",
                "image_digest": f"sha256:{'d' * 64}",
                "configuration_sha256": "e" * 64,
            }
        ],
    }
    manifest_path = trusted / "deployment-subject.json"
    _write_json(manifest_path, manifest)
    deployment_hash = _sha256(manifest_path.read_bytes())
    schema_hash = _sha256(
        (ROOT / "packages/contracts/schemas/release-encryption-evidence.schema.json").read_bytes()
    )
    bundle: dict[str, object] = {
        "schema_version": "release-encryption-evidence.v1",
        "bundle_id": "bundle-example-0001",
        "sequence": 41,
        "nonce": "0123456789abcdef0123456789abcdef",
        "issued_at": "2026-07-11T12:01:00Z",
        "expires_at": "2026-07-11T12:06:00Z",
        "subject": {
            "tenant_id": "tenant-example",
            "environment": "production",
            "release_id": "release-2026-07-11",
            "deployment_revision": 42,
            "deployment_sha256": deployment_hash,
            "encryption_policy_sha256": policy_hash,
            "evidence_schema_sha256": schema_hash,
            "trust_store_sha256": trust_hash,
        },
        "provenance": {
            "issuer": "release-attestor.example.invalid",
            "builder_id": "builder.example.invalid/hallu-defense",
            "workflow_ref": "release.yml@refs/tags/v1.2.3",
            "source_repository": "https://example.invalid/hallu-defense",
            "source_commit": "a" * 40,
            "invocation_id": "invocation-example-0001",
            "started_at": "2026-07-11T11:59:00Z",
            "finished_at": "2026-07-11T12:00:30Z",
            "materials": [
                {"uri": "deployment-subject", "sha256": deployment_hash},
                {"uri": "workflow-definition", "sha256": "9" * 64},
                {"uri": "artifact:api", "sha256": "d" * 64},
                {"uri": "attestation:encryption.at-rest", "sha256": "7" * 64},
                {"uri": "attestation:encryption.in-transit", "sha256": "8" * 64},
                {"uri": "postgres-ca-rollout", "sha256": "f" * 64},
            ],
        },
        "attestations": [
            {
                "control": "encryption.at-rest",
                "result": "pass",
                "subject_sha256": deployment_hash,
                "observed_at": "2026-07-11T12:00:45Z",
                "claims": {
                    "persistent_resources_verified": 9,
                    "resource_ids": [
                        "api",
                        "console",
                        "grafana",
                        "minio",
                        "opensearch",
                        "otel-collector",
                        "postgres",
                        "prometheus",
                        "redis",
                    ],
                    "unencrypted_persistent_resources": 0,
                    "algorithms": ["AES-256", "AES-256-GCM", "SSE-KMS-AES-256"],
                    "kms_authority_ids": ["vault://example/transit/release"],
                    "deployment_hash_observed": True,
                    "evidence_sha256": "7" * 64,
                },
            },
            {
                "control": "encryption.in-transit",
                "result": "pass",
                "subject_sha256": deployment_hash,
                "observed_at": "2026-07-11T12:00:50Z",
                "claims": {
                    "external_endpoints_verified": 9,
                    "endpoint_ids": [
                        "api",
                        "console",
                        "grafana",
                        "minio",
                        "opensearch",
                        "otel-collector",
                        "postgres",
                        "prometheus",
                        "redis",
                    ],
                    "plaintext_external_endpoints": 0,
                    "minimum_tls_version": "1.3",
                    "trust_chain_validated": True,
                    "peer_ca_sha256": ["1" * 64],
                    "deployment_hash_observed": True,
                    "evidence_sha256": "8" * 64,
                },
            },
        ],
        "rotation": {"epoch": epoch, "phase": phase},
        "commitments": [],
        "authenticators": [],
    }
    replay_state: dict[str, object] = {
        "schema_version": "release-encryption-replay-state.v1",
        "trust_store_id": "release-trust-example",
        "state_key_id": previous_state_id or current_state_id,
        "bindings": [
            {
                "tenant_id": "tenant-example",
                "environment": "production",
                "highest_sequence": 40,
                "highest_deployment_revision": 41,
                "current_deployment_sha256": "5" * 64,
                "highest_rotation_epoch": epoch - 1,
                "current_rotation_phase": "stable",
                "last_issued_at": "2026-07-11T11:00:00Z",
                "recent_nonces": [],
                "last_transition": None,
            }
        ],
        "state_mac": "",
    }
    fixture = EvidenceFixture(
        bundle_path=untrusted / "evidence.json",
        report_path=reports / "report.json",
        manifest_path=manifest_path,
        trust_store_path=trust_store_path,
        keyring_path=keyring_path,
        replay_path=trusted / "replay-state.json",
        environ={
            verifier.ENV_DEPLOYMENT_SUBJECT_PATH: str(manifest_path.resolve()),
            verifier.ENV_TRUST_STORE_PATH: str(trust_store_path.resolve()),
            verifier.ENV_KEYRING_PATH: str(keyring_path.resolve()),
            verifier.ENV_REPLAY_STATE_PATH: str((trusted / "replay-state.json").resolve()),
            verifier.ENV_EXPECTED_TENANT_ID: "tenant-example",
            verifier.ENV_EXPECTED_ENVIRONMENT: "production",
            verifier.ENV_EXPECTED_TRUST_STORE_ID: "release-trust-example",
            verifier.ENV_EXPECTED_TRUST_ROOT_ID: "tenant-example-production",
            verifier.ENV_EXPECTED_REPLAY_STATE_SHA256: "0" * 64,
        },
        bundle=bundle,
        trust_store=trust_store,
        keyring=keyring,
        replay_state=replay_state,
        auth_private_keys=auth_keys,
        commitment_keys=commitment_keys,
        state_keys=state_keys,
        report_keys=report_keys,
    )
    fixture.write_replay_state()
    fixture.sign_and_write_bundle()
    return fixture


def _rewrite_trust_manifest_and_bundle(fixture: EvidenceFixture) -> None:
    _write_json(fixture.trust_store_path, fixture.trust_store)
    manifest = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
    trust_hash = _sha256(fixture.trust_store_path.read_bytes())
    manifest["trust_store_sha256"] = trust_hash
    _write_json(fixture.manifest_path, manifest)
    deployment_hash = _sha256(fixture.manifest_path.read_bytes())
    subject = cast(dict[str, object], fixture.bundle["subject"])
    subject["trust_store_sha256"] = trust_hash
    subject["deployment_sha256"] = deployment_hash
    provenance = cast(dict[str, object], fixture.bundle["provenance"])
    cast(list[dict[str, object]], provenance["materials"])[0]["sha256"] = deployment_hash
    for raw_attestation in cast(list[dict[str, object]], fixture.bundle["attestations"]):
        raw_attestation["subject_sha256"] = deployment_hash
    fixture.sign_and_write_bundle()


def _descriptor(
    key_id: str,
    material: bytes,
    *,
    epoch: int,
    status: str,
) -> dict[str, object]:
    return {
        "key_id": key_id,
        "key_reference": f"release/{key_id}",
        "material_sha256": _sha256(material),
        "epoch": epoch,
        "status": status,
        "not_before": "2026-07-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }


def _keyring_entry(key_id: str, purpose: str, material: bytes) -> dict[str, object]:
    return {
        "key_id": key_id,
        "purpose": purpose,
        "encoding": "base64",
        "material": base64.b64encode(material).decode("ascii"),
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_bytes(verifier.canonical_json_bytes(payload) + b"\n")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
