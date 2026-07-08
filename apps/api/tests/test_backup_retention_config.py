from __future__ import annotations

import copy

import pytest

from scripts.ci.check_backup_retention_config import (
    POLICY_PATH,
    BackupRetentionConfigError,
    load_policy,
    validate_policy,
    validate_supporting_files,
)


def test_backup_retention_policy_validates_enterprise_defaults() -> None:
    policy = load_policy(POLICY_PATH)

    validate_policy(policy)

    components = policy["components"]
    assert isinstance(components, dict)
    assert {"postgres", "minio", "opensearch", "sandbox-artifacts"}.issubset(components)
    postgres = components["postgres"]
    assert isinstance(postgres, dict)
    assert postgres["backup"]["enabled"] is True
    assert postgres["retention"]["tenant_scoped_deletion"] is True


def test_backup_retention_policy_rejects_disabled_persistent_backup() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    postgres = components["postgres"]
    assert isinstance(postgres, dict)
    backup = postgres["backup"]
    assert isinstance(backup, dict)
    backup["enabled"] = False

    with pytest.raises(BackupRetentionConfigError, match="enabled"):
        validate_policy(policy)


def test_backup_retention_policy_rejects_unencrypted_backups() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    minio = components["minio"]
    assert isinstance(minio, dict)
    backup = minio["backup"]
    assert isinstance(backup, dict)
    backup["encrypted"] = False

    with pytest.raises(BackupRetentionConfigError, match="encrypted"):
        validate_policy(policy)


def test_backup_retention_policy_rejects_retention_below_minimum() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    opensearch = components["opensearch"]
    assert isinstance(opensearch, dict)
    retention = opensearch["retention"]
    assert isinstance(retention, dict)
    classes = retention["classes"]
    assert isinstance(classes, dict)
    evidence_indexes = classes["evidence_indexes"]
    assert isinstance(evidence_indexes, dict)
    evidence_indexes["days"] = 7

    with pytest.raises(BackupRetentionConfigError, match="at least 90"):
        validate_policy(policy)


def test_backup_retention_policy_rejects_non_tenant_scoped_deletion() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    artifacts = components["sandbox-artifacts"]
    assert isinstance(artifacts, dict)
    retention = artifacts["retention"]
    assert isinstance(retention, dict)
    retention["tenant_scoped_deletion"] = False

    with pytest.raises(BackupRetentionConfigError, match="tenant_scoped_deletion"):
        validate_policy(policy)


def test_supporting_files_must_wire_backup_retention_gate() -> None:
    with pytest.raises(BackupRetentionConfigError, match="Makefile"):
        validate_supporting_files(
            docs_text="backup-retention-policy.json restore drill",
            security_text="backup/restore and retention policy",
            makefile_text="security-check:\n\tpython scripts/ci/secret_scan.py\n",
            ci_workflow_text="python scripts/ci/check_backup_retention_config.py",
            security_workflow_text="python scripts/ci/check_backup_retention_config.py",
        )
