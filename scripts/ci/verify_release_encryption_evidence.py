from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "packages" / "contracts" / "schemas"
POLICY_PATH = ROOT / "infra" / "security" / "encryption-policy.json"
BUNDLE_SCHEMA_PATH = SCHEMA_DIR / "release-encryption-evidence.schema.json"
DEPLOYMENT_SCHEMA_PATH = SCHEMA_DIR / "release-deployment-subject.schema.json"
TRUST_STORE_SCHEMA_PATH = SCHEMA_DIR / "release-encryption-trust-store.schema.json"
KEYRING_SCHEMA_PATH = SCHEMA_DIR / "release-encryption-keyring.schema.json"
REPLAY_SCHEMA_PATH = SCHEMA_DIR / "release-encryption-replay-state.schema.json"
REPORT_SCHEMA_PATH = SCHEMA_DIR / "release-encryption-verification-report.schema.json"

ENV_DEPLOYMENT_SUBJECT_PATH = "HALLU_DEFENSE_RELEASE_DEPLOYMENT_SUBJECT_PATH"
ENV_TRUST_STORE_PATH = "HALLU_DEFENSE_RELEASE_TRUST_STORE_PATH"
ENV_KEYRING_PATH = "HALLU_DEFENSE_RELEASE_KEYRING_PATH"
ENV_REPLAY_STATE_PATH = "HALLU_DEFENSE_RELEASE_REPLAY_STATE_PATH"
ENV_EXPECTED_TENANT_ID = "HALLU_DEFENSE_RELEASE_EXPECTED_TENANT_ID"
ENV_EXPECTED_ENVIRONMENT = "HALLU_DEFENSE_RELEASE_EXPECTED_ENVIRONMENT"
ENV_EXPECTED_TRUST_STORE_ID = "HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_STORE_ID"
ENV_EXPECTED_TRUST_ROOT_ID = "HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_ROOT_ID"
ENV_EXPECTED_REPLAY_STATE_SHA256 = "HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256"

CHECK_NAMES = (
    "schema_valid",
    "external_inputs_bound",
    "tenant_environment_bound",
    "timestamps_valid",
    "provenance_valid",
    "controls_attested",
    "rotation_valid",
    "commitments_valid",
    "authenticators_valid",
    "replay_rollback_safe",
)

MAX_BUNDLE_BYTES = 1_048_576
MAX_EXTERNAL_JSON_BYTES = 2_097_152
MAX_KEYRING_BYTES = 262_144
MAX_ROTATION_OVERLAP = timedelta(days=7)
ALLOWED_AT_REST_ALGORITHMS = frozenset({"AES-256", "AES-256-GCM", "SSE-KMS-AES-256"})
LOCK_TIMEOUT_SECONDS = 5.0
COMMITMENT_DOMAIN = b"hallu-defense.release-encryption.commitment.v1\x00"
AUTHENTICATOR_DOMAIN = b"hallu-defense.release-encryption.authenticator.v1\x00"
REPLAY_STATE_DOMAIN = b"hallu-defense.release-encryption.replay-state.v1\x00"
REPORT_AUTHENTICATOR_DOMAIN = b"hallu-defense.release-encryption.report.v1\x00"
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
TRUST_STORE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
FORBIDDEN_BUNDLE_FIELDS = frozenset(
    {
        "deployment_subject",
        "keyring",
        "keys",
        "manifest",
        "policy",
        "public_keys",
        "replay_state",
        "schema",
        "trust_root",
        "trust_store",
    }
)

JsonObject = dict[str, object]


class _FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, file_descriptor: int, operation: int) -> None: ...


class EvidenceVerificationError(ValueError):
    def __init__(self, code: str, check: str) -> None:
        super().__init__(code)
        self.code = code
        self.check = check


class ReportWriteError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProtectedPaths:
    deployment_subject: Path
    trust_store: Path
    keyring: Path
    replay_state: Path


@dataclass(frozen=True)
class KeyMaterial:
    purpose: str
    material: bytes


@dataclass(frozen=True)
class VerificationInputs:
    bundle_path: Path
    report_path: Path
    protected_paths: ProtectedPaths
    expected_tenant_id: str
    expected_environment: str
    expected_trust_store_id: str
    expected_trust_root_id: str
    expected_replay_state_sha256: str


@dataclass(frozen=True)
class AnchorOutcome:
    previous_sha256: str
    next_sha256: str
    update_required: bool
    finalized: bool


@dataclass
class VerificationContext:
    inputs: VerificationInputs
    now: datetime
    bundle: JsonObject
    bundle_bytes: bytes
    deployment: JsonObject
    deployment_bytes: bytes
    trust_store: JsonObject
    trust_store_bytes: bytes
    keyring: JsonObject
    policy: JsonObject
    binding: JsonObject
    key_material: dict[str, KeyMaterial]


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_commitment_payload(bundle: Mapping[str, object]) -> bytes:
    unsigned = copy.deepcopy(dict(bundle))
    unsigned["commitments"] = []
    unsigned["authenticators"] = []
    return COMMITMENT_DOMAIN + canonical_json_bytes(unsigned)


def canonical_authenticator_payload(bundle: Mapping[str, object]) -> bytes:
    unsigned = copy.deepcopy(dict(bundle))
    unsigned["authenticators"] = []
    return AUTHENTICATOR_DOMAIN + canonical_json_bytes(unsigned)


def canonical_replay_state_payload(state: Mapping[str, object]) -> bytes:
    unsigned = copy.deepcopy(dict(state))
    unsigned["state_mac"] = ""
    return REPLAY_STATE_DOMAIN + canonical_json_bytes(unsigned)


def canonical_report_payload(report: Mapping[str, object]) -> bytes:
    unsigned = copy.deepcopy(dict(report))
    unsigned["report_authenticator"] = None
    return REPORT_AUTHENTICATOR_DOMAIN + canonical_json_bytes(unsigned)


def report_authenticator_is_valid(
    report: Mapping[str, object],
    *,
    key_id: str,
    key_material: bytes,
) -> bool:
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", key_id) is None
        or not 32 <= len(key_material) <= 128
    ):
        return False
    authenticator = report.get("report_authenticator")
    if not isinstance(authenticator, dict):
        return False
    if (
        authenticator.get("algorithm") != "hmac-sha256"
        or authenticator.get("key_id") != key_id
    ):
        return False
    value = authenticator.get("value")
    if not isinstance(value, str):
        return False
    try:
        expected = hmac.new(
            key_material,
            canonical_report_payload(report),
            hashlib.sha256,
        ).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return False
    return hmac.compare_digest(expected, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify externally rooted release encryption evidence.",
        allow_abbrev=False,
    )
    parser.add_argument("--bundle", required=True, help="Untrusted evidence JSON path")
    parser.add_argument("--report", required=True, help="Verification report JSON path")
    return parser


def verify_bundle(
    bundle_path: str | Path,
    report_path: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> JsonObject:
    verification_time = _normalize_now(now)
    report = _new_report(verification_time)
    safe_report: Path | None = None
    report_authenticator: tuple[str, bytes] | None = None

    try:
        safe_report = _resolve_report_path(report_path)
        inputs = _load_inputs(
            bundle_path=bundle_path,
            report_path=safe_report,
            environ=os.environ if environ is None else environ,
        )
        bundle, bundle_bytes = _load_json_object(
            inputs.bundle_path,
            max_bytes=MAX_BUNDLE_BYTES,
            code="bundle.invalid_json",
            check="schema_valid",
        )
        report["bundle_sha256"] = _sha256(bundle_bytes)
        bundle_id = bundle.get("bundle_id")
        if isinstance(bundle_id, str) and len(bundle_id) <= 127:
            report["bundle_id"] = bundle_id

        _reject_embedded_trust_material(bundle)
        bundle_schema = _load_anchored_schema(BUNDLE_SCHEMA_PATH)
        _validate_schema(
            bundle,
            bundle_schema,
            code="bundle.schema_invalid",
            check="schema_valid",
        )
        _mark_check(report, "schema_valid")

        context = _load_external_context(
            inputs=inputs,
            bundle=bundle,
            bundle_bytes=bundle_bytes,
            now=verification_time,
        )
        _mark_check(report, "external_inputs_bound")

        _verify_tenant_environment_binding(context)
        _mark_check(report, "tenant_environment_bound")

        _verify_timestamps(context)
        _mark_check(report, "timestamps_valid")

        _verify_provenance(context)
        _mark_check(report, "provenance_valid")

        _verify_control_attestations(context)
        _mark_check(report, "controls_attested")

        _verify_rotation(context)
        _mark_check(report, "rotation_valid")
        rotation = cast(JsonObject, context.binding["rotation"])
        report_key_id = cast(str, rotation["active_report_authenticator_key_id"])
        report_key = context.key_material[report_key_id]
        report_authenticator = (report_key_id, report_key.material)

        _verify_commitments(context)
        _mark_check(report, "commitments_valid")

        _verify_authenticators(context)
        _mark_check(report, "authenticators_valid")

        anchor = _verify_and_advance_replay_state(context)
        _mark_check(report, "replay_rollback_safe")
        report["replay_state_previous_sha256"] = anchor.previous_sha256
        report["replay_state_next_sha256"] = anchor.next_sha256
        report["anchor_update_required"] = anchor.update_required
        report["anchor_finalized"] = anchor.finalized

        if anchor.update_required:
            report["failure_codes"] = ["anchor.update_required"]
            _authenticate_report(report, report_authenticator)
            _validate_report(report)
            _atomic_write_json(inputs.report_path, report, preserve_mode=False)
            return report

        report["compliance_asserted"] = True
        _authenticate_report(report, report_authenticator)
        _validate_report(report)
        _atomic_write_json(inputs.report_path, report, preserve_mode=False)
        return report
    except EvidenceVerificationError as exc:
        _record_failure(report, exc)
    except (OSError, ValueError, TypeError, RecursionError, SchemaError):
        _record_failure(
            report,
            EvidenceVerificationError("verification.internal_error", "schema_valid"),
        )

    if safe_report is None:
        raise ReportWriteError("verification report path is not safe")
    try:
        if report_authenticator is not None:
            _authenticate_report(report, report_authenticator)
        _validate_report(report)
        _atomic_write_json(safe_report, report, preserve_mode=False)
    except (OSError, ValueError, TypeError, SchemaError) as exc:
        raise ReportWriteError("verification report could not be written") from exc
    return report


def _normalize_now(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("verification time must be timezone-aware")
    return current.astimezone(UTC)


def _new_report(now: datetime) -> JsonObject:
    return {
        "schema_version": "release-encryption-verification-report.v1",
        "verified_at": _format_datetime(now),
        "bundle_sha256": None,
        "bundle_id": None,
        "replay_state_previous_sha256": None,
        "replay_state_next_sha256": None,
        "anchor_update_required": False,
        "anchor_finalized": False,
        "report_authenticator": None,
        "compliance_asserted": False,
        "checks": {name: False for name in CHECK_NAMES},
        "failure_codes": [],
    }


def _mark_check(report: JsonObject, check: str) -> None:
    checks = cast(JsonObject, report["checks"])
    checks[check] = True


def _record_failure(report: JsonObject, error: EvidenceVerificationError) -> None:
    checks = cast(JsonObject, report["checks"])
    if error.check in checks:
        checks[error.check] = False
    report["compliance_asserted"] = False
    codes = cast(list[object], report["failure_codes"])
    if error.code not in codes:
        codes.append(error.code)


def _authenticate_report(report: JsonObject, authenticator: tuple[str, bytes]) -> None:
    key_id, key_material = authenticator
    report["report_authenticator"] = None
    report["report_authenticator"] = {
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "value": hmac.new(
            key_material,
            canonical_report_payload(report),
            hashlib.sha256,
        ).hexdigest(),
    }


def _load_inputs(
    *,
    bundle_path: str | Path,
    report_path: Path,
    environ: Mapping[str, str],
) -> VerificationInputs:
    bundle = _resolve_existing_cli_path(bundle_path)
    protected = ProtectedPaths(
        deployment_subject=_resolve_protected_env_path(
            environ, ENV_DEPLOYMENT_SUBJECT_PATH
        ),
        trust_store=_resolve_protected_env_path(environ, ENV_TRUST_STORE_PATH),
        keyring=_resolve_protected_env_path(environ, ENV_KEYRING_PATH),
        replay_state=_resolve_protected_env_path(environ, ENV_REPLAY_STATE_PATH),
    )
    expected_tenant = _required_env(environ, ENV_EXPECTED_TENANT_ID)
    expected_environment = _required_env(environ, ENV_EXPECTED_ENVIRONMENT)
    expected_trust_store_id = _required_env(environ, ENV_EXPECTED_TRUST_STORE_ID)
    expected_trust_root_id = _required_env(environ, ENV_EXPECTED_TRUST_ROOT_ID)
    expected_replay_state_sha256 = _required_env(
        environ,
        ENV_EXPECTED_REPLAY_STATE_SHA256,
    )
    if TENANT_RE.fullmatch(expected_tenant) is None:
        raise EvidenceVerificationError(
            "binding.invalid_context", "external_inputs_bound"
        )
    if expected_environment not in {"staging", "production"}:
        raise EvidenceVerificationError(
            "binding.invalid_context", "external_inputs_bound"
        )
    if TRUST_STORE_ID_RE.fullmatch(expected_trust_store_id) is None:
        raise EvidenceVerificationError(
            "binding.invalid_context", "external_inputs_bound"
        )
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", expected_trust_root_id)
        is None
    ):
        raise EvidenceVerificationError(
            "binding.invalid_context", "external_inputs_bound"
        )
    if re.fullmatch(r"[0-9a-f]{64}", expected_replay_state_sha256) is None:
        raise EvidenceVerificationError(
            "binding.invalid_context", "external_inputs_bound"
        )

    input_paths = {
        bundle,
        protected.deployment_subject,
        protected.trust_store,
        protected.keyring,
        protected.replay_state,
    }
    if report_path in input_paths or _is_relative_to(report_path, bundle.parent):
        raise ReportWriteError("verification report path is not trusted")
    if len(input_paths) != 5:
        raise EvidenceVerificationError(
            "external.path_collision", "external_inputs_bound"
        )
    input_identities = {_file_identity(path) for path in input_paths}
    if len(input_identities) != 5:
        raise EvidenceVerificationError(
            "external.path_collision", "external_inputs_bound"
        )
    if report_path.exists() and _file_identity(report_path) in input_identities:
        raise ReportWriteError("verification report path aliases a protected input")
    for external_path in (
        protected.deployment_subject,
        protected.trust_store,
        protected.keyring,
        protected.replay_state,
    ):
        if _is_relative_to(external_path, bundle.parent):
            raise EvidenceVerificationError(
                "external.bundle_owned", "external_inputs_bound"
            )

    return VerificationInputs(
        bundle_path=bundle,
        report_path=report_path,
        protected_paths=protected,
        expected_tenant_id=expected_tenant,
        expected_environment=expected_environment,
        expected_trust_store_id=expected_trust_store_id,
        expected_trust_root_id=expected_trust_root_id,
        expected_replay_state_sha256=expected_replay_state_sha256,
    )


def _resolve_existing_cli_path(raw_path: str | Path) -> Path:
    path = _path_without_traversal(raw_path, check="schema_valid")
    _reject_symlink_or_reparse(path, include_leaf=True, check="schema_valid")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceVerificationError("bundle.path_invalid", "schema_valid") from exc
    if not resolved.is_file():
        raise EvidenceVerificationError("bundle.path_invalid", "schema_valid")
    return resolved


def _resolve_report_path(raw_path: str | Path) -> Path:
    path = _path_without_traversal(raw_path, check="schema_valid")
    if not path.is_absolute():
        raise ReportWriteError("verification report path must be absolute")
    _reject_symlink_or_reparse(path, include_leaf=True, check="schema_valid")
    try:
        resolved = path.resolve(strict=False)
        parent = resolved.parent.resolve(strict=True)
    except OSError as exc:
        raise ReportWriteError("verification report path is not safe") from exc
    if not parent.is_dir() or resolved.parent != parent:
        raise ReportWriteError("verification report path is not safe")
    if resolved.exists() and not resolved.is_file():
        raise ReportWriteError("verification report path is not safe")
    return resolved


def _resolve_protected_env_path(environ: Mapping[str, str], name: str) -> Path:
    raw = _required_env(environ, name)
    path = _path_without_traversal(raw, check="external_inputs_bound")
    if not path.is_absolute():
        raise EvidenceVerificationError(
            "external.path_invalid", "external_inputs_bound"
        )
    _reject_symlink_or_reparse(path, include_leaf=True, check="external_inputs_bound")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceVerificationError(
            "external.path_invalid", "external_inputs_bound"
        ) from exc
    if not resolved.is_file():
        raise EvidenceVerificationError(
            "external.path_invalid", "external_inputs_bound"
        )
    return resolved


def _path_without_traversal(raw_path: str | Path, *, check: str) -> Path:
    raw = os.fspath(raw_path)
    if not raw or "\x00" in raw:
        raise EvidenceVerificationError("external.path_invalid", check)
    if os.name == "nt":
        windows_raw = raw.replace("/", "\\")
        if windows_raw.startswith(("\\\\?\\", "\\\\.\\")):
            raise EvidenceVerificationError("external.path_invalid", check)
    path = Path(raw)
    if ".." in path.parts:
        raise EvidenceVerificationError("external.path_traversal", check)
    if os.name == "nt":
        for index, part in enumerate(path.parts):
            if ":" in part and not (index == 0 and re.fullmatch(r"[A-Za-z]:\\", part)):
                raise EvidenceVerificationError("external.path_invalid", check)
    return path


def _reject_symlink_or_reparse(path: Path, *, include_leaf: bool, check: str) -> None:
    candidate = path.absolute()
    chain = list(candidate.parents)
    chain.reverse()
    if include_leaf:
        chain.append(candidate)
    for entry in chain:
        try:
            metadata = os.lstat(entry)
        except FileNotFoundError:
            continue
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag):
            raise EvidenceVerificationError("external.path_symlink", check)


def _required_env(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise EvidenceVerificationError(
            "external.missing_context", "external_inputs_bound"
        )
    return value


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = os.stat(path, follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def _load_external_context(
    *,
    inputs: VerificationInputs,
    bundle: JsonObject,
    bundle_bytes: bytes,
    now: datetime,
) -> VerificationContext:
    deployment, deployment_bytes = _load_json_object(
        inputs.protected_paths.deployment_subject,
        max_bytes=MAX_EXTERNAL_JSON_BYTES,
        code="external.invalid_manifest",
        check="external_inputs_bound",
    )
    trust_store, trust_store_bytes = _load_json_object(
        inputs.protected_paths.trust_store,
        max_bytes=MAX_EXTERNAL_JSON_BYTES,
        code="external.invalid_trust_store",
        check="external_inputs_bound",
    )
    keyring, _ = _load_json_object(
        inputs.protected_paths.keyring,
        max_bytes=MAX_KEYRING_BYTES,
        code="external.invalid_keyring",
        check="external_inputs_bound",
    )
    policy, _ = _load_json_object(
        _resolve_anchored_file(POLICY_PATH),
        max_bytes=MAX_EXTERNAL_JSON_BYTES,
        code="external.invalid_policy",
        check="external_inputs_bound",
    )

    for payload, schema_path in (
        (deployment, DEPLOYMENT_SCHEMA_PATH),
        (trust_store, TRUST_STORE_SCHEMA_PATH),
        (keyring, KEYRING_SCHEMA_PATH),
    ):
        _validate_schema(
            payload,
            _load_anchored_schema(schema_path),
            code="external.schema_invalid",
            check="external_inputs_bound",
        )
    _validate_encryption_policy(policy)

    trust_store_id = cast(str, trust_store["trust_store_id"])
    if trust_store_id != inputs.expected_trust_store_id:
        raise EvidenceVerificationError(
            "binding.trust_store_mismatch", "external_inputs_bound"
        )
    if keyring.get("trust_store_id") != trust_store_id:
        raise EvidenceVerificationError(
            "binding.keyring_mismatch", "external_inputs_bound"
        )

    bindings = cast(list[object], trust_store["bindings"])
    matching = [
        cast(JsonObject, value)
        for value in bindings
        if isinstance(value, dict)
        and value.get("tenant_id") == inputs.expected_tenant_id
        and value.get("environment") == inputs.expected_environment
    ]
    if len(matching) != 1:
        raise EvidenceVerificationError("binding.not_unique", "external_inputs_bound")
    binding = matching[0]
    if binding.get("trust_root_id") != inputs.expected_trust_root_id:
        raise EvidenceVerificationError(
            "binding.trust_root_mismatch", "external_inputs_bound"
        )
    for singleton_field in (
        "allowed_issuers",
        "allowed_builders",
        "allowed_workflows",
        "allowed_source_repositories",
    ):
        if len(cast(list[object], binding[singleton_field])) != 1:
            raise EvidenceVerificationError(
                "binding.ambiguous_signing_principal",
                "external_inputs_bound",
            )
    if len(
        {
            (
                cast(JsonObject, item).get("tenant_id"),
                cast(JsonObject, item).get("environment"),
            )
            for item in bindings
            if isinstance(item, dict)
        }
    ) != len(bindings):
        raise EvidenceVerificationError("binding.duplicate", "external_inputs_bound")

    key_material = _load_key_material(keyring, binding)
    return VerificationContext(
        inputs=inputs,
        now=now,
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        deployment=deployment,
        deployment_bytes=deployment_bytes,
        trust_store=trust_store,
        trust_store_bytes=trust_store_bytes,
        keyring=keyring,
        policy=policy,
        binding=binding,
        key_material=key_material,
    )


def _load_key_material(
    keyring: JsonObject, binding: JsonObject
) -> dict[str, KeyMaterial]:
    entries = cast(list[object], keyring["keys"])
    materials: dict[str, KeyMaterial] = {}
    for raw_entry in entries:
        entry = cast(JsonObject, raw_entry)
        key_id = cast(str, entry["key_id"])
        purpose = cast(str, entry["purpose"])
        if key_id in materials:
            raise EvidenceVerificationError(
                "external.duplicate_key", "external_inputs_bound"
            )
        try:
            encoded = cast(str, entry["material"])
            material = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise EvidenceVerificationError(
                "external.invalid_keyring", "external_inputs_bound"
            ) from exc
        if base64.b64encode(material).decode("ascii") != encoded:
            raise EvidenceVerificationError(
                "external.invalid_keyring", "external_inputs_bound"
            )
        if purpose == "authenticator-ed25519-public" and len(material) != 32:
            raise EvidenceVerificationError(
                "external.invalid_keyring", "external_inputs_bound"
            )
        if purpose.endswith("hmac-sha256") and not 32 <= len(material) <= 128:
            raise EvidenceVerificationError(
                "external.invalid_keyring", "external_inputs_bound"
            )
        materials[key_id] = KeyMaterial(purpose=purpose, material=material)

    descriptors: list[tuple[JsonObject, str]] = []
    descriptors.extend(
        (cast(JsonObject, item), "authenticator-ed25519-public")
        for item in cast(list[object], binding["authenticator_keys"])
    )
    descriptors.extend(
        (cast(JsonObject, item), "commitment-hmac-sha256")
        for item in cast(list[object], binding["commitment_keys"])
    )
    descriptors.extend(
        (cast(JsonObject, item), "replay-state-hmac-sha256")
        for item in cast(list[object], binding["replay_state_keys"])
    )
    descriptors.extend(
        (cast(JsonObject, item), "verification-report-hmac-sha256")
        for item in cast(list[object], binding["report_authenticator_keys"])
    )
    descriptor_ids: set[str] = set()
    references: set[str] = set()
    hashes: set[str] = set()
    for descriptor, purpose in descriptors:
        key_id = cast(str, descriptor["key_id"])
        reference = cast(str, descriptor["key_reference"])
        material_hash = cast(str, descriptor["material_sha256"])
        if (
            key_id in descriptor_ids
            or reference in references
            or material_hash in hashes
        ):
            raise EvidenceVerificationError(
                "external.key_collision", "external_inputs_bound"
            )
        descriptor_ids.add(key_id)
        references.add(reference)
        hashes.add(material_hash)
        bound_material = materials.get(key_id)
        if bound_material is None or bound_material.purpose != purpose:
            raise EvidenceVerificationError(
                "external.key_binding_invalid", "external_inputs_bound"
            )
        if not hmac.compare_digest(_sha256(bound_material.material), material_hash):
            raise EvidenceVerificationError(
                "external.key_binding_invalid", "external_inputs_bound"
            )
    if set(materials) != descriptor_ids:
        raise EvidenceVerificationError("external.unbound_key", "external_inputs_bound")
    return materials


def _verify_tenant_environment_binding(context: VerificationContext) -> None:
    bundle_subject = cast(JsonObject, context.bundle["subject"])
    deployment = context.deployment
    expected_tenant = context.inputs.expected_tenant_id
    expected_environment = context.inputs.expected_environment
    for payload in (bundle_subject, deployment, context.binding):
        if payload.get("tenant_id") != expected_tenant:
            raise EvidenceVerificationError(
                "binding.tenant_mismatch", "tenant_environment_bound"
            )
        if payload.get("environment") != expected_environment:
            raise EvidenceVerificationError(
                "binding.environment_mismatch",
                "tenant_environment_bound",
            )
    for field in ("release_id", "deployment_revision"):
        if bundle_subject.get(field) != deployment.get(field):
            raise EvidenceVerificationError(
                "binding.deployment_mismatch", "tenant_environment_bound"
            )
    _verify_postgres_tls_subject(deployment)

    actual_deployment_hash = _sha256(context.deployment_bytes)
    actual_policy_hash = _sha256(_resolve_anchored_file(POLICY_PATH).read_bytes())
    actual_schema_hash = _sha256(
        _resolve_anchored_file(BUNDLE_SCHEMA_PATH).read_bytes()
    )
    actual_trust_hash = _sha256(context.trust_store_bytes)
    expected_hashes = {
        "deployment_sha256": actual_deployment_hash,
        "encryption_policy_sha256": actual_policy_hash,
        "evidence_schema_sha256": actual_schema_hash,
        "trust_store_sha256": actual_trust_hash,
    }
    for field, expected in expected_hashes.items():
        value = bundle_subject.get(field)
        if not isinstance(value, str) or not hmac.compare_digest(value, expected):
            raise EvidenceVerificationError(
                "binding.hash_mismatch", "tenant_environment_bound"
            )
    for field, expected in (
        ("encryption_policy_sha256", actual_policy_hash),
        ("trust_store_sha256", actual_trust_hash),
    ):
        value = deployment.get(field)
        if not isinstance(value, str) or not hmac.compare_digest(value, expected):
            raise EvidenceVerificationError(
                "binding.hash_mismatch", "tenant_environment_bound"
            )


def _verify_timestamps(context: VerificationContext) -> None:
    freshness = cast(JsonObject, context.binding["freshness"])
    skew = timedelta(seconds=cast(int, freshness["max_clock_skew_seconds"]))
    max_bundle_age = timedelta(seconds=cast(int, freshness["max_bundle_age_seconds"]))
    max_attestation_age = timedelta(
        seconds=cast(int, freshness["max_attestation_age_seconds"])
    )

    issued_at = _parse_datetime(context.bundle["issued_at"], "timestamps_valid")
    expires_at = _parse_datetime(context.bundle["expires_at"], "timestamps_valid")
    if issued_at > context.now + skew or context.now > expires_at + skew:
        raise EvidenceVerificationError(
            "timestamp.bundle_not_current", "timestamps_valid"
        )
    if expires_at <= issued_at or expires_at - issued_at > max_bundle_age:
        raise EvidenceVerificationError("timestamp.invalid_ttl", "timestamps_valid")
    if context.now - issued_at > max_bundle_age + skew:
        raise EvidenceVerificationError("timestamp.bundle_stale", "timestamps_valid")

    provenance = cast(JsonObject, context.bundle["provenance"])
    started_at = _parse_datetime(provenance["started_at"], "timestamps_valid")
    finished_at = _parse_datetime(provenance["finished_at"], "timestamps_valid")
    if not started_at <= finished_at <= issued_at:
        raise EvidenceVerificationError(
            "timestamp.provenance_invalid", "timestamps_valid"
        )

    for raw_attestation in cast(list[object], context.bundle["attestations"]):
        attestation = cast(JsonObject, raw_attestation)
        observed_at = _parse_datetime(attestation["observed_at"], "timestamps_valid")
        if not finished_at <= observed_at <= issued_at:
            raise EvidenceVerificationError(
                "timestamp.attestation_invalid", "timestamps_valid"
            )
        if context.now - observed_at > max_attestation_age + skew:
            raise EvidenceVerificationError(
                "timestamp.attestation_stale", "timestamps_valid"
            )

    generated_at = _parse_datetime(
        context.trust_store["generated_at"], "timestamps_valid"
    )
    valid_until = _parse_datetime(
        context.trust_store["valid_until"], "timestamps_valid"
    )
    if generated_at > issued_at or valid_until <= generated_at:
        raise EvidenceVerificationError(
            "timestamp.trust_store_invalid", "timestamps_valid"
        )
    if context.now > valid_until + skew or expires_at > valid_until:
        raise EvidenceVerificationError(
            "timestamp.trust_store_expired", "timestamps_valid"
        )


def _verify_provenance(context: VerificationContext) -> None:
    provenance = cast(JsonObject, context.bundle["provenance"])
    binding = context.binding
    deployment = context.deployment
    allowed_fields = (
        ("issuer", "allowed_issuers"),
        ("builder_id", "allowed_builders"),
        ("workflow_ref", "allowed_workflows"),
        ("source_repository", "allowed_source_repositories"),
    )
    for field, allowed_field in allowed_fields:
        allowed = cast(list[object], binding[allowed_field])
        if provenance.get(field) not in allowed:
            raise EvidenceVerificationError("provenance.untrusted", "provenance_valid")
    for field in ("workflow_ref", "source_repository", "source_commit"):
        if provenance.get(field) != deployment.get(field):
            raise EvidenceVerificationError(
                "provenance.deployment_mismatch", "provenance_valid"
            )

    expected_materials: dict[str, str] = {
        "deployment-subject": _sha256(context.deployment_bytes),
        "workflow-definition": cast(str, deployment["workflow_sha256"]),
    }
    postgres_tls = cast(JsonObject, deployment["postgres_tls"])
    expected_materials["postgres-ca-rollout"] = cast(
        str, postgres_tls["rollout_sha256"]
    )
    artifacts = cast(list[object], deployment["artifacts"])
    artifact_names: set[str] = set()
    for raw_artifact in artifacts:
        artifact = cast(JsonObject, raw_artifact)
        name = cast(str, artifact["name"])
        if name in artifact_names:
            raise EvidenceVerificationError(
                "provenance.duplicate_artifact", "provenance_valid"
            )
        artifact_names.add(name)
        image_digest = cast(str, artifact["image_digest"])
        expected_materials[f"artifact:{name}"] = image_digest.removeprefix("sha256:")
    for raw_attestation in cast(list[object], context.bundle["attestations"]):
        attestation = cast(JsonObject, raw_attestation)
        control = cast(str, attestation["control"])
        claims = cast(JsonObject, attestation["claims"])
        expected_materials[f"attestation:{control}"] = cast(
            str, claims["evidence_sha256"]
        )

    actual_materials: dict[str, str] = {}
    for raw_material in cast(list[object], provenance["materials"]):
        material = cast(JsonObject, raw_material)
        uri = cast(str, material["uri"])
        if uri in actual_materials:
            raise EvidenceVerificationError(
                "provenance.duplicate_material", "provenance_valid"
            )
        actual_materials[uri] = cast(str, material["sha256"])
    if actual_materials != expected_materials:
        raise EvidenceVerificationError(
            "provenance.material_mismatch", "provenance_valid"
        )


def _verify_control_attestations(context: VerificationContext) -> None:
    attestations: dict[str, JsonObject] = {}
    for raw_attestation in cast(list[object], context.bundle["attestations"]):
        attestation = cast(JsonObject, raw_attestation)
        control = cast(str, attestation["control"])
        if control in attestations:
            raise EvidenceVerificationError("controls.duplicate", "controls_attested")
        attestations[control] = attestation
    if set(attestations) != {"encryption.at-rest", "encryption.in-transit"}:
        raise EvidenceVerificationError("controls.missing", "controls_attested")

    subject = cast(JsonObject, context.bundle["subject"])
    deployment_hash = cast(str, subject["deployment_sha256"])
    for attestation in attestations.values():
        if (
            attestation.get("result") != "pass"
            or attestation.get("subject_sha256") != deployment_hash
        ):
            raise EvidenceVerificationError(
                "controls.subject_mismatch", "controls_attested"
            )

    components = cast(JsonObject, context.policy["components"])
    required_algorithms: set[str] = set()
    at_rest_resource_ids: set[str] = set()
    in_transit_endpoint_ids: set[str] = set()
    for component_name, raw_component in components.items():
        component = cast(JsonObject, raw_component)
        if component.get("profile") != "active":
            continue
        at_rest = cast(JsonObject, component["at_rest"])
        in_transit = cast(JsonObject, component["in_transit"])
        if at_rest.get("required") is True:
            at_rest_resource_ids.add(component_name)
            required_algorithms.add(cast(str, at_rest["algorithm"]))
        if in_transit.get("required") is True:
            in_transit_endpoint_ids.add(component_name)

    at_rest_claims = cast(JsonObject, attestations["encryption.at-rest"]["claims"])
    observed_resources = set(cast(list[str], at_rest_claims["resource_ids"]))
    if (
        cast(int, at_rest_claims["persistent_resources_verified"])
        != len(observed_resources)
        or observed_resources != at_rest_resource_ids
    ):
        raise EvidenceVerificationError(
            "controls.at_rest_incomplete", "controls_attested"
        )
    if set(cast(list[str], at_rest_claims["algorithms"])) != required_algorithms:
        raise EvidenceVerificationError(
            "controls.algorithm_mismatch", "controls_attested"
        )
    allowed_kms = set(cast(list[str], context.binding["allowed_kms_authorities"]))
    observed_kms = set(cast(list[str], at_rest_claims["kms_authority_ids"]))
    if not observed_kms or not observed_kms.issubset(allowed_kms):
        raise EvidenceVerificationError("controls.kms_untrusted", "controls_attested")

    in_transit_claims = cast(
        JsonObject, attestations["encryption.in-transit"]["claims"]
    )
    observed_endpoints = set(cast(list[str], in_transit_claims["endpoint_ids"]))
    if (
        cast(int, in_transit_claims["external_endpoints_verified"])
        != len(observed_endpoints)
        or observed_endpoints != in_transit_endpoint_ids
    ):
        raise EvidenceVerificationError(
            "controls.in_transit_incomplete", "controls_attested"
        )
    defaults = cast(JsonObject, context.policy["defaults"])
    policy_tls = cast(
        str, cast(JsonObject, defaults["in_transit"])["minimum_tls_version"]
    )
    observed_tls = cast(str, in_transit_claims["minimum_tls_version"])
    if _tls_tuple(observed_tls) < _tls_tuple(policy_tls):
        raise EvidenceVerificationError("controls.tls_too_old", "controls_attested")
    allowed_ca = set(cast(list[str], context.binding["allowed_tls_ca_sha256"]))
    observed_ca = set(cast(list[str], in_transit_claims["peer_ca_sha256"]))
    if not observed_ca or not observed_ca.issubset(allowed_ca):
        raise EvidenceVerificationError("controls.ca_untrusted", "controls_attested")
    postgres_tls = cast(JsonObject, context.deployment["postgres_tls"])
    if postgres_tls.get("bundle_sha256") not in observed_ca:
        raise EvidenceVerificationError(
            "controls.postgres_ca_unobserved", "controls_attested"
        )


def _verify_postgres_tls_subject(deployment: JsonObject) -> None:
    postgres_tls = cast(JsonObject, deployment["postgres_tls"])
    mount_value = cast(str, postgres_tls["mount_path"])
    mount_path = PurePosixPath(mount_value)
    if (
        not mount_path.is_absolute()
        or "//" in mount_value
        or "/./" in mount_value
        or ".." in mount_path.parts
        or mount_path.name != postgres_tls.get("ca_key")
        or postgres_tls.get("sub_path") is not True
        or postgres_tls.get("rollout_revision") != deployment.get("deployment_revision")
    ):
        raise EvidenceVerificationError(
            "binding.postgres_tls_invalid",
            "tenant_environment_bound",
        )


def _verify_rotation(context: VerificationContext) -> None:
    rotation = cast(JsonObject, context.binding["rotation"])
    bundle_rotation = cast(JsonObject, context.bundle["rotation"])
    if bundle_rotation.get("epoch") != rotation.get("epoch"):
        raise EvidenceVerificationError("rotation.epoch_mismatch", "rotation_valid")
    if bundle_rotation.get("phase") != rotation.get("phase"):
        raise EvidenceVerificationError("rotation.phase_mismatch", "rotation_valid")

    auth_descriptors = cast(list[object], context.binding["authenticator_keys"])
    commitment_descriptors = cast(list[object], context.binding["commitment_keys"])
    _verify_rotation_key_set(
        descriptors=auth_descriptors,
        rotation=rotation,
        active_field="active_authenticator_key_id",
        previous_field="previous_authenticator_key_id",
        required_field="required_authenticator_key_ids",
        now=context.now,
        bundle=context.bundle,
    )
    _verify_rotation_key_set(
        descriptors=commitment_descriptors,
        rotation=rotation,
        active_field="active_commitment_key_id",
        previous_field="previous_commitment_key_id",
        required_field="required_commitment_key_ids",
        now=context.now,
        bundle=context.bundle,
    )
    _verify_rotation_key_set(
        descriptors=cast(list[object], context.binding["replay_state_keys"]),
        rotation=rotation,
        active_field="active_replay_state_key_id",
        previous_field="previous_replay_state_key_id",
        required_field="required_replay_state_key_ids",
        now=context.now,
        bundle=context.bundle,
    )
    _verify_rotation_key_set(
        descriptors=cast(list[object], context.binding["report_authenticator_keys"]),
        rotation=rotation,
        active_field="active_report_authenticator_key_id",
        previous_field="previous_report_authenticator_key_id",
        required_field="required_report_authenticator_key_ids",
        now=context.now,
        bundle=context.bundle,
    )

    phase = cast(str, rotation["phase"])
    overlap_not_after_value = rotation.get("overlap_not_after")
    generated_at = _parse_datetime(
        context.trust_store["generated_at"], "rotation_valid"
    )
    if phase == "stable":
        if overlap_not_after_value is not None:
            raise EvidenceVerificationError(
                "rotation.stable_has_overlap", "rotation_valid"
            )
        if rotation.get("previous_authenticator_key_id") is not None:
            raise EvidenceVerificationError(
                "rotation.stable_has_previous", "rotation_valid"
            )
        if rotation.get("previous_commitment_key_id") is not None:
            raise EvidenceVerificationError(
                "rotation.stable_has_previous", "rotation_valid"
            )
        if rotation.get("previous_replay_state_key_id") is not None:
            raise EvidenceVerificationError(
                "rotation.stable_has_previous", "rotation_valid"
            )
        if rotation.get("previous_report_authenticator_key_id") is not None:
            raise EvidenceVerificationError(
                "rotation.stable_has_previous", "rotation_valid"
            )
    else:
        if overlap_not_after_value is None:
            raise EvidenceVerificationError(
                "rotation.overlap_unbounded", "rotation_valid"
            )
        overlap_not_after = _parse_datetime(overlap_not_after_value, "rotation_valid")
        if overlap_not_after <= context.now:
            raise EvidenceVerificationError(
                "rotation.overlap_expired", "rotation_valid"
            )
        if (
            overlap_not_after <= generated_at
            or overlap_not_after - generated_at > MAX_ROTATION_OVERLAP
        ):
            raise EvidenceVerificationError(
                "rotation.overlap_unbounded", "rotation_valid"
            )
        bundle_expires_at = _parse_datetime(
            context.bundle["expires_at"], "rotation_valid"
        )
        if bundle_expires_at > overlap_not_after:
            raise EvidenceVerificationError(
                "rotation.bundle_outlives_overlap", "rotation_valid"
            )


def _verify_rotation_key_set(
    *,
    descriptors: list[object],
    rotation: JsonObject,
    active_field: str,
    previous_field: str,
    required_field: str,
    now: datetime,
    bundle: JsonObject,
) -> None:
    descriptor_map: dict[str, JsonObject] = {}
    for raw_descriptor in descriptors:
        descriptor = cast(JsonObject, raw_descriptor)
        key_id = cast(str, descriptor["key_id"])
        if key_id in descriptor_map:
            raise EvidenceVerificationError("rotation.duplicate_key", "rotation_valid")
        descriptor_map[key_id] = descriptor

    active = cast(str, rotation[active_field])
    previous = rotation.get(previous_field)
    required = cast(list[str], rotation[required_field])
    expected = {active}
    phase = cast(str, rotation["phase"])
    if phase == "overlap":
        if not isinstance(previous, str) or previous == active:
            raise EvidenceVerificationError(
                "rotation.previous_invalid", "rotation_valid"
            )
        expected.add(previous)
    elif previous is not None:
        raise EvidenceVerificationError("rotation.previous_invalid", "rotation_valid")
    if len(required) != len(set(required)) or set(required) != expected:
        raise EvidenceVerificationError(
            "rotation.required_keys_invalid", "rotation_valid"
        )
    if set(descriptor_map) != expected:
        raise EvidenceVerificationError(
            "rotation.descriptor_set_invalid", "rotation_valid"
        )

    epoch = cast(int, rotation["epoch"])
    active_descriptor = descriptor_map[active]
    if (
        active_descriptor.get("status") != "active"
        or active_descriptor.get("epoch") != epoch
    ):
        raise EvidenceVerificationError("rotation.active_key_invalid", "rotation_valid")
    issued_at = _parse_datetime(bundle["issued_at"], "rotation_valid")
    expires_at = _parse_datetime(bundle["expires_at"], "rotation_valid")
    _verify_descriptor_window(active_descriptor, issued_at, expires_at)
    if isinstance(previous, str):
        previous_descriptor = descriptor_map[previous]
        if previous_descriptor.get("status") != "retiring":
            raise EvidenceVerificationError(
                "rotation.previous_key_invalid", "rotation_valid"
            )
        if cast(int, previous_descriptor["epoch"]) != epoch - 1:
            raise EvidenceVerificationError(
                "rotation.previous_key_invalid", "rotation_valid"
            )
        _verify_descriptor_window(previous_descriptor, issued_at, expires_at)


def _verify_descriptor_window(
    descriptor: JsonObject, start: datetime, end: datetime
) -> None:
    not_before = _parse_datetime(descriptor["not_before"], "rotation_valid")
    not_after = _parse_datetime(descriptor["not_after"], "rotation_valid")
    if not_before > start or not_after < end or not_after <= not_before:
        raise EvidenceVerificationError("rotation.key_not_current", "rotation_valid")


def _verify_commitments(context: VerificationContext) -> None:
    rotation = cast(JsonObject, context.binding["rotation"])
    required = set(cast(list[str], rotation["required_commitment_key_ids"]))
    commitments = cast(list[object], context.bundle["commitments"])
    actual: dict[str, JsonObject] = {}
    for raw_commitment in commitments:
        commitment = cast(JsonObject, raw_commitment)
        key_id = cast(str, commitment["key_id"])
        if key_id in actual:
            raise EvidenceVerificationError("commitment.duplicate", "commitments_valid")
        actual[key_id] = commitment
    if set(actual) != required:
        raise EvidenceVerificationError(
            "commitment.key_set_invalid", "commitments_valid"
        )
    payload = canonical_commitment_payload(context.bundle)
    for key_id, commitment in actual.items():
        material = context.key_material[key_id]
        if material.purpose != "commitment-hmac-sha256":
            raise EvidenceVerificationError(
                "commitment.key_invalid", "commitments_valid"
            )
        expected = hmac.new(material.material, payload, hashlib.sha256).hexdigest()
        value = cast(str, commitment["value"])
        if not hmac.compare_digest(expected, value):
            raise EvidenceVerificationError("commitment.invalid", "commitments_valid")


def _verify_authenticators(context: VerificationContext) -> None:
    rotation = cast(JsonObject, context.binding["rotation"])
    required = set(cast(list[str], rotation["required_authenticator_key_ids"]))
    authenticators = cast(list[object], context.bundle["authenticators"])
    actual: dict[str, JsonObject] = {}
    for raw_authenticator in authenticators:
        authenticator = cast(JsonObject, raw_authenticator)
        key_id = cast(str, authenticator["key_id"])
        if key_id in actual:
            raise EvidenceVerificationError(
                "signature.duplicate", "authenticators_valid"
            )
        actual[key_id] = authenticator
    if set(actual) != required:
        raise EvidenceVerificationError(
            "signature.key_set_invalid", "authenticators_valid"
        )

    payload = canonical_authenticator_payload(context.bundle)
    for key_id, authenticator in actual.items():
        material = context.key_material[key_id]
        if material.purpose != "authenticator-ed25519-public":
            raise EvidenceVerificationError(
                "signature.key_invalid", "authenticators_valid"
            )
        try:
            signature = base64.b64decode(
                cast(str, authenticator["value"]), validate=True
            )
            if len(signature) != 64:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material.material).verify(
                signature, payload
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise EvidenceVerificationError(
                "signature.invalid", "authenticators_valid"
            ) from exc


def _verify_and_advance_replay_state(context: VerificationContext) -> AnchorOutcome:
    state_path = context.inputs.protected_paths.replay_state
    with _exclusive_state_lock(state_path):
        state, state_bytes = _load_json_object(
            state_path,
            max_bytes=MAX_EXTERNAL_JSON_BYTES,
            code="replay.invalid_state",
            check="replay_rollback_safe",
        )
        current_state_sha256 = _sha256(state_bytes)
        _validate_schema(
            state,
            _load_anchored_schema(REPLAY_SCHEMA_PATH),
            code="replay.invalid_state",
            check="replay_rollback_safe",
        )
        trust_store_id = cast(str, context.trust_store["trust_store_id"])
        rotation = cast(JsonObject, context.binding["rotation"])
        allowed_state_key_ids = set(
            cast(list[str], rotation["required_replay_state_key_ids"])
        )
        active_state_key_id = cast(str, rotation["active_replay_state_key_id"])
        state_key_id = state.get("state_key_id")
        if (
            state.get("trust_store_id") != trust_store_id
            or not isinstance(state_key_id, str)
            or state_key_id not in allowed_state_key_ids
        ):
            raise EvidenceVerificationError(
                "replay.state_binding_invalid", "replay_rollback_safe"
            )
        key = context.key_material[state_key_id]
        expected_mac = hmac.new(
            key.material,
            canonical_replay_state_payload(state),
            hashlib.sha256,
        ).hexdigest()
        state_mac = cast(str, state["state_mac"])
        if not hmac.compare_digest(expected_mac, state_mac):
            raise EvidenceVerificationError(
                "replay.state_mac_invalid", "replay_rollback_safe"
            )

        bindings = cast(list[object], state["bindings"])
        state_key = (
            context.inputs.expected_tenant_id,
            context.inputs.expected_environment,
        )
        if len(bindings) > 1:
            raise EvidenceVerificationError(
                "replay.state_binding_invalid",
                "replay_rollback_safe",
            )
        previous: JsonObject | None = None
        if bindings:
            candidate = cast(JsonObject, bindings[0])
            candidate_key = (
                cast(str, candidate["tenant_id"]),
                cast(str, candidate["environment"]),
            )
            if candidate_key != state_key:
                raise EvidenceVerificationError(
                    "replay.state_binding_invalid",
                    "replay_rollback_safe",
                )
            previous = candidate
        expected_anchor = context.inputs.expected_replay_state_sha256
        if hmac.compare_digest(current_state_sha256, expected_anchor):
            if previous is not None and _transition_matches_bundle(context, previous):
                transition = cast(JsonObject, previous["last_transition"])
                return AnchorOutcome(
                    previous_sha256=cast(str, transition["previous_state_sha256"]),
                    next_sha256=current_state_sha256,
                    update_required=False,
                    finalized=True,
                )
        elif previous is not None and _transition_matches_bundle(context, previous):
            transition = cast(JsonObject, previous["last_transition"])
            transition_previous = cast(str, transition["previous_state_sha256"])
            if hmac.compare_digest(transition_previous, expected_anchor):
                return AnchorOutcome(
                    previous_sha256=transition_previous,
                    next_sha256=current_state_sha256,
                    update_required=True,
                    finalized=False,
                )
            raise EvidenceVerificationError(
                "replay.anchor_mismatch", "replay_rollback_safe"
            )
        else:
            raise EvidenceVerificationError(
                "replay.anchor_mismatch", "replay_rollback_safe"
            )

        updated = _next_replay_binding(
            context,
            previous,
            previous_state_sha256=current_state_sha256,
        )
        active_key = context.key_material[active_state_key_id]
        next_state: JsonObject = {
            "schema_version": "release-encryption-replay-state.v1",
            "trust_store_id": trust_store_id,
            "state_key_id": active_state_key_id,
            "bindings": [updated],
            "state_mac": "",
        }
        next_state["state_mac"] = hmac.new(
            active_key.material,
            canonical_replay_state_payload(next_state),
            hashlib.sha256,
        ).hexdigest()
        _validate_schema(
            next_state,
            _load_anchored_schema(REPLAY_SCHEMA_PATH),
            code="replay.update_invalid",
            check="replay_rollback_safe",
        )
        try:
            next_state_sha256 = _atomic_write_json(
                state_path, next_state, preserve_mode=True
            )
        except OSError as exc:
            raise EvidenceVerificationError(
                "replay.update_failed", "replay_rollback_safe"
            ) from exc
        return AnchorOutcome(
            previous_sha256=current_state_sha256,
            next_sha256=next_state_sha256,
            update_required=True,
            finalized=False,
        )


def _next_replay_binding(
    context: VerificationContext,
    previous: JsonObject | None,
    *,
    previous_state_sha256: str,
) -> JsonObject:
    subject = cast(JsonObject, context.bundle["subject"])
    rotation = cast(JsonObject, context.bundle["rotation"])
    sequence = cast(int, context.bundle["sequence"])
    revision = cast(int, subject["deployment_revision"])
    deployment_hash = cast(str, subject["deployment_sha256"])
    epoch = cast(int, rotation["epoch"])
    phase = cast(str, rotation["phase"])
    issued_at = _parse_datetime(context.bundle["issued_at"], "replay_rollback_safe")
    nonce = cast(str, context.bundle["nonce"])
    sequence_floor = cast(int, context.binding["sequence_floor"])
    revision_floor = cast(int, context.binding["deployment_revision_floor"])

    if sequence <= sequence_floor or revision < revision_floor:
        raise EvidenceVerificationError(
            "rollback.below_trust_floor", "replay_rollback_safe"
        )
    recent_nonces: list[str] = []
    if previous is not None:
        highest_sequence = cast(int, previous["highest_sequence"])
        highest_revision = cast(int, previous["highest_deployment_revision"])
        highest_epoch = cast(int, previous["highest_rotation_epoch"])
        previous_phase = previous.get("current_rotation_phase")
        previous_hash = previous.get("current_deployment_sha256")
        last_issued_value = previous.get("last_issued_at")
        recent_nonces = list(cast(list[str], previous["recent_nonces"]))
        if sequence <= highest_sequence or nonce in recent_nonces:
            raise EvidenceVerificationError("replay.detected", "replay_rollback_safe")
        if revision < highest_revision:
            raise EvidenceVerificationError(
                "rollback.deployment_revision", "replay_rollback_safe"
            )
        if revision == highest_revision and previous_hash != deployment_hash:
            raise EvidenceVerificationError(
                "rollback.deployment_identity", "replay_rollback_safe"
            )
        if epoch < highest_epoch:
            raise EvidenceVerificationError(
                "rollback.rotation_epoch", "replay_rollback_safe"
            )
        if epoch == highest_epoch and previous_phase == "stable" and phase == "overlap":
            raise EvidenceVerificationError(
                "rollback.rotation_phase", "replay_rollback_safe"
            )
        if isinstance(last_issued_value, str):
            last_issued = _parse_datetime(last_issued_value, "replay_rollback_safe")
            if issued_at <= last_issued:
                raise EvidenceVerificationError(
                    "rollback.timestamp", "replay_rollback_safe"
                )

    recent_nonces.append(nonce)
    return {
        "tenant_id": context.inputs.expected_tenant_id,
        "environment": context.inputs.expected_environment,
        "highest_sequence": sequence,
        "highest_deployment_revision": revision,
        "current_deployment_sha256": deployment_hash,
        "highest_rotation_epoch": epoch,
        "current_rotation_phase": phase,
        "last_issued_at": _format_datetime(issued_at),
        "recent_nonces": recent_nonces[-256:],
        "last_transition": {
            "bundle_id": cast(str, context.bundle["bundle_id"]),
            "bundle_sha256": _sha256(context.bundle_bytes),
            "previous_state_sha256": previous_state_sha256,
        },
    }


def _transition_matches_bundle(
    context: VerificationContext, binding: JsonObject
) -> bool:
    transition = binding.get("last_transition")
    if not isinstance(transition, dict):
        return False
    subject = cast(JsonObject, context.bundle["subject"])
    rotation = cast(JsonObject, context.bundle["rotation"])
    return (
        transition.get("bundle_id") == context.bundle.get("bundle_id")
        and transition.get("bundle_sha256") == _sha256(context.bundle_bytes)
        and binding.get("highest_sequence") == context.bundle.get("sequence")
        and binding.get("highest_deployment_revision")
        == subject.get("deployment_revision")
        and binding.get("current_deployment_sha256") == subject.get("deployment_sha256")
        and binding.get("highest_rotation_epoch") == rotation.get("epoch")
        and binding.get("current_rotation_phase") == rotation.get("phase")
        and binding.get("last_issued_at")
        == _format_datetime(
            _parse_datetime(context.bundle["issued_at"], "replay_rollback_safe")
        )
    )


@contextmanager
def _exclusive_state_lock(state_path: Path) -> Iterator[None]:
    lock_path = state_path.with_name(f".{state_path.name}.lock")
    _reject_symlink_or_reparse(
        lock_path,
        include_leaf=True,
        check="replay_rollback_safe",
    )
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise EvidenceVerificationError(
            "replay.lock_failed", "replay_rollback_safe"
        ) from exc
    handle = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        if os.name == "nt":
            _lock_windows(handle)
        else:
            _lock_posix(handle)
        try:
            yield
        finally:
            if os.name == "nt":
                _unlock_windows(handle)
            else:
                _unlock_posix(handle)
    finally:
        handle.close()


def _lock_windows(handle: BinaryIO) -> None:
    import msvcrt

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\x00")
        handle.flush()
    handle.seek(0)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise EvidenceVerificationError(
                    "replay.lock_timeout", "replay_rollback_safe"
                ) from exc
            time.sleep(0.05)


def _unlock_windows(handle: BinaryIO) -> None:
    import msvcrt

    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _lock_posix(handle: BinaryIO) -> None:
    fcntl = cast(_FcntlModule, __import__("fcntl"))

    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                raise EvidenceVerificationError(
                    "replay.lock_timeout", "replay_rollback_safe"
                ) from exc
            time.sleep(0.05)


def _unlock_posix(handle: BinaryIO) -> None:
    fcntl = cast(_FcntlModule, __import__("fcntl"))

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _load_json_object(
    path: Path,
    *,
    max_bytes: int,
    code: str,
    check: str,
) -> tuple[JsonObject, bytes]:
    try:
        raw = _read_regular_file_no_follow(path, max_bytes=max_bytes)
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except EvidenceVerificationError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise EvidenceVerificationError(code, check) from exc
    if not isinstance(payload, dict):
        raise EvidenceVerificationError(code, check)
    return cast(JsonObject, payload), raw


def _read_regular_file_no_follow(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > max_bytes
        ):
            raise ValueError("input is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(max_bytes + 1)
        current = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != opened.st_dev
            or current.st_ino != opened.st_ino
            or len(raw) != opened.st_size
        ):
            raise ValueError("input changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _unique_object(pairs: Sequence[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _load_anchored_schema(path: Path) -> JsonObject:
    resolved = _resolve_anchored_file(path)
    schema, _ = _load_json_object(
        resolved,
        max_bytes=MAX_EXTERNAL_JSON_BYTES,
        code="external.invalid_schema",
        check="external_inputs_bound",
    )
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise EvidenceVerificationError(
            "external.invalid_schema", "external_inputs_bound"
        ) from exc
    return schema


def _resolve_anchored_file(path: Path) -> Path:
    expected = path.absolute()
    _reject_symlink_or_reparse(
        expected,
        include_leaf=True,
        check="external_inputs_bound",
    )
    try:
        resolved = expected.resolve(strict=True)
    except OSError as exc:
        raise EvidenceVerificationError(
            "external.anchor_missing", "external_inputs_bound"
        ) from exc
    if not _is_relative_to(resolved, ROOT) or not resolved.is_file():
        raise EvidenceVerificationError(
            "external.anchor_invalid", "external_inputs_bound"
        )
    return resolved


def _validate_schema(
    payload: JsonObject,
    schema: JsonObject,
    *,
    code: str,
    check: str,
) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    if next(validator.iter_errors(payload), None) is not None:
        raise EvidenceVerificationError(code, check)


def _validate_encryption_policy(policy: JsonObject) -> None:
    try:
        if policy.get("schema_version") != "encryption-policy.v1":
            raise ValueError
        defaults = cast(JsonObject, policy["defaults"])
        in_transit = cast(JsonObject, defaults["in_transit"])
        at_rest = cast(JsonObject, defaults["at_rest"])
        if in_transit.get("required") is not True:
            raise ValueError
        if in_transit.get("external_plaintext_allowed") is not False:
            raise ValueError
        if _tls_tuple(cast(str, in_transit["minimum_tls_version"])) < (1, 3):
            raise ValueError
        if at_rest.get("required") is not True:
            raise ValueError
        if at_rest.get("plaintext_persistent_volumes_allowed") is not False:
            raise ValueError
        if at_rest.get("algorithm") not in ALLOWED_AT_REST_ALGORITHMS:
            raise ValueError
        if at_rest.get("key_management") != "vault-compatible-kms":
            raise ValueError
        components = cast(JsonObject, policy["components"])
        if not components:
            raise ValueError
        for raw_component in components.values():
            component = cast(JsonObject, raw_component)
            if component.get("profile") != "active":
                raise ValueError
            component_at_rest = cast(JsonObject, component["at_rest"])
            component_in_transit = cast(JsonObject, component["in_transit"])
            if component_at_rest.get("required") is not True:
                raise ValueError
            if component_at_rest.get("algorithm") not in ALLOWED_AT_REST_ALGORITHMS:
                raise ValueError
            if component_at_rest.get("key_management") != "vault-compatible-kms":
                raise ValueError
            if component_in_transit.get("required") is not True:
                raise ValueError
            if component_in_transit.get("external_plaintext_allowed") is not False:
                raise ValueError
            if _tls_tuple(cast(str, component_in_transit["minimum_tls_version"])) < (
                1,
                3,
            ):
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise EvidenceVerificationError(
            "external.policy_invalid", "external_inputs_bound"
        ) from None


def _reject_embedded_trust_material(bundle: JsonObject) -> None:
    if FORBIDDEN_BUNDLE_FIELDS.intersection(bundle):
        raise EvidenceVerificationError(
            "bundle.embedded_trust_material", "schema_valid"
        )


def _validate_report(report: JsonObject) -> None:
    _validate_schema(
        report,
        _load_anchored_schema(REPORT_SCHEMA_PATH),
        code="report.schema_invalid",
        check="schema_valid",
    )


def _atomic_write_json(path: Path, payload: JsonObject, *, preserve_mode: bool) -> str:
    _reject_symlink_or_reparse(path, include_leaf=True, check="replay_rollback_safe")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir() or path.parent != parent:
        raise OSError("unsafe parent directory")
    mode = 0o600
    if preserve_mode and path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
    body = canonical_json_bytes(payload) + b"\n"
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.chmod(temp_path, mode)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        _reject_symlink_or_reparse(
            path, include_leaf=True, check="replay_rollback_safe"
        )
        os.replace(temp_path, path)
        temp_path = None
        _fsync_directory(parent)
        return _sha256(body)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse_datetime(value: object, check: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise EvidenceVerificationError("timestamp.invalid", check)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError("timestamp.invalid", check) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceVerificationError("timestamp.invalid", check)
    return parsed.astimezone(UTC)


def _format_datetime(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _tls_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except (AttributeError, ValueError):
        return (0,)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = verify_bundle(args.bundle, args.report)
    except ReportWriteError:
        print(
            "Release encryption evidence verification failed; no safe report could be written.",
            file=sys.stderr,
        )
        return 2
    if report["compliance_asserted"] is True:
        print("Release encryption evidence verified.")
        return 0
    print(
        "Release encryption evidence verification failed; inspect the sanitized report.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
