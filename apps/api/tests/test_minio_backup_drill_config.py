from __future__ import annotations

import copy
import json

import pytest

from scripts.ci import check_minio_backup_drill as gate


def test_minio_backup_drill_repository_gate_passes() -> None:
    gate.validate_repository()


def test_gate_rejects_manifest_with_raw_source_key() -> None:
    values = _values()
    values["core_text"] = values["core_text"].replace(
        '"encrypted_size": self.encrypted_size,',
        '"source_key": self.encrypted_size,',
    )

    with pytest.raises(gate.MinioBackupDrillConfigError, match="manifest fields"):
        gate.validate_sources(**values)


def test_gate_rejects_subprocess_based_object_client() -> None:
    values = _values()
    values["cli_text"] = "import subprocess\n" + str(values["cli_text"])

    with pytest.raises(gate.MinioBackupDrillConfigError, match="in-process SigV4"):
        gate.validate_sources(**values)


def test_gate_rejects_unbounded_sigv4_client() -> None:
    values = _values()
    values["s3_client_text"] = str(values["s3_client_text"]).replace(
        "_read_bounded",
        "read_unbounded",
    )

    with pytest.raises(gate.MinioBackupDrillConfigError, match="_read_bounded"):
        gate.validate_sources(**values)


def test_gate_rejects_wrong_backup_target() -> None:
    values = _values()
    policy = copy.deepcopy(values["policy"])
    assert isinstance(policy, dict)
    components = policy["components"]
    assert isinstance(components, dict)
    minio = components["minio"]
    assert isinstance(minio, dict)
    backup = minio["backup"]
    assert isinstance(backup, dict)
    backup["target"] = "primary-data-bucket"
    values["policy"] = policy

    with pytest.raises(gate.MinioBackupDrillConfigError, match="backup target"):
        gate.validate_sources(**values)


def test_gate_requires_ci_and_security_workflow_wiring() -> None:
    values = _values()
    values["security_text"] = "jobs: {}"

    with pytest.raises(gate.MinioBackupDrillConfigError, match="security workflow"):
        gate.validate_sources(**values)


def test_gate_requires_live_minio_lane_wiring() -> None:
    values = _values()
    values["live_workflow_text"] = "jobs: {}"

    with pytest.raises(gate.MinioBackupDrillConfigError, match="live workflow"):
        gate.validate_sources(**values)


def test_gate_requires_live_minio_test() -> None:
    values = _values()
    values["live_test_text"] = ""

    with pytest.raises(gate.MinioBackupDrillConfigError, match="MinIO live test"):
        gate.validate_sources(**values)


def _values() -> dict[str, object]:
    return {
        "core_text": gate.CORE_PATH.read_text(encoding="utf-8"),
        "cli_text": gate.CLI_PATH.read_text(encoding="utf-8"),
        "s3_client_text": gate.S3_CLIENT_PATH.read_text(encoding="utf-8"),
        "policy": json.loads(gate.POLICY_PATH.read_text(encoding="utf-8")),
        "docs_text": gate.DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": gate.MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_text": gate.CI_PATH.read_text(encoding="utf-8"),
        "security_text": gate.SECURITY_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": gate.LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_test_text": gate.LIVE_TEST_PATH.read_text(encoding="utf-8"),
    }
