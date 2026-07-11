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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source", None, "source must be primary-data-bucket"),
        ("source", "cross-bucket-encrypted-replica", "source must be primary-data-bucket"),
        ("target", "primary-data-bucket", "target must be cross-bucket-encrypted-replica"),
    ],
)
def test_minio_backup_policy_requires_distinct_primary_source_and_encrypted_replica(
    field: str,
    value: object,
    message: str,
) -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    minio = components["minio"]
    assert isinstance(minio, dict)
    backup = minio["backup"]
    assert isinstance(backup, dict)
    backup[field] = value

    with pytest.raises(BackupRetentionConfigError, match=message):
        validate_policy(policy)


def test_non_minio_backup_policy_remains_compatible_without_source_field() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    postgres = components["postgres"]
    assert isinstance(postgres, dict)
    backup = postgres["backup"]
    assert isinstance(backup, dict)
    assert "source" not in backup

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
            docs_text=(
                "backup-retention-policy.json restore drill "
                "run_retention_execution.py backup_restore_drill.py"
            ),
            security_text="backup/restore and retention policy",
            makefile_text="security-check:\n\tpython scripts/ci/secret_scan.py\n",
            ci_workflow_text="python scripts/ci/check_backup_retention_config.py",
            security_workflow_text="python scripts/ci/check_backup_retention_config.py",
            data_lifecycle_text=_valid_data_lifecycle_text(),
            retention_execution_text=_valid_retention_script_text(),
            backup_restore_drill_text=_valid_backup_drill_text(),
            api_pyproject_text="cryptography",
        )


def test_supporting_files_require_retention_script_safeguards() -> None:
    with pytest.raises(BackupRetentionConfigError, match="confirm-tenant-id"):
        validate_supporting_files(
            docs_text=(
                "backup-retention-policy.json restore drill "
                "run_retention_execution.py backup_restore_drill.py"
            ),
            security_text="backup/restore and retention policy",
            makefile_text=_valid_makefile_text(),
            ci_workflow_text="python scripts/ci/check_backup_retention_config.py",
            security_workflow_text="python scripts/ci/check_backup_retention_config.py",
            data_lifecycle_text=_valid_data_lifecycle_text(),
            retention_execution_text="HALLU_DEFENSE_RETENTION_EXECUTION_ENABLED",
            backup_restore_drill_text=_valid_backup_drill_text(),
            api_pyproject_text="cryptography",
        )


def test_supporting_files_require_backup_restore_drill_safeguards() -> None:
    with pytest.raises(BackupRetentionConfigError, match="pg_restore"):
        validate_supporting_files(
            docs_text=(
                "backup-retention-policy.json restore drill "
                "run_retention_execution.py backup_restore_drill.py"
            ),
            security_text="backup/restore and retention policy",
            makefile_text=_valid_makefile_text(),
            ci_workflow_text="python scripts/ci/check_backup_retention_config.py",
            security_workflow_text="python scripts/ci/check_backup_retention_config.py",
            data_lifecycle_text=_valid_data_lifecycle_text(),
            retention_execution_text=_valid_retention_script_text(),
            backup_restore_drill_text="HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED pg_dump",
            api_pyproject_text="cryptography",
        )


def test_supporting_files_require_cross_store_lifecycle_coordinator() -> None:
    with pytest.raises(BackupRetentionConfigError, match="rag_lifecycle.py"):
        validate_supporting_files(
            docs_text=(
                "backup-retention-policy.json restore drill run_retention_execution.py "
                "backup_restore_drill.py rag_lifecycle_operations parity verification"
            ),
            security_text="backup/restore and retention policy",
            makefile_text=_valid_makefile_text(),
            ci_workflow_text="python scripts/ci/check_backup_retention_config.py",
            security_workflow_text="python scripts/ci/check_backup_retention_config.py",
            data_lifecycle_text=_valid_data_lifecycle_text(),
            rag_lifecycle_text="",
            retention_execution_text=_valid_retention_script_text(),
            backup_restore_drill_text=_valid_backup_drill_text(),
            api_pyproject_text="cryptography",
        )


def _valid_makefile_text() -> str:
    return (
        "backup-retention-config:\n\tpython scripts/ci/check_backup_retention_config.py\n"
        "retention-execution:\n\tpython scripts/dev/run_retention_execution.py\n"
        "backup-restore-drill:\n\tpython scripts/dev/backup_restore_drill.py\n"
    )


def _valid_data_lifecycle_text() -> str:
    return (
        "POSTGRES_LIFECYCLE_TABLES minimum_days retention_execution "
        "tenant_data_deletion delete_tenant_data tenant_id = %s DELETE FROM append_event "
        "RagLifecycleCoordinator acquire_target_locks delete_external mark_completed "
        "rag_external_parity_verified"
    )


def _valid_retention_script_text() -> str:
    return (
        "HALLU_DEFENSE_RETENTION_EXECUTION_ENABLED "
        "HALLU_DEFENSE_TENANT_DATA_DELETION_ENABLED --confirm-tenant-id "
        "execute_retention delete_tenant_data sys.exit(main())"
    )


def _valid_backup_drill_text() -> str:
    return (
        "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED docker compose exec -T "
        "pg_dump pg_restore Fernet create_secret_manager S3SigV4Client upload_file "
        "DEFAULT_MINIO_CREDENTIALS_SECRET_NAME field=\"access_key\" field=\"secret_key\" "
        "PRODUCTION_LIKE_ENVIRONMENTS minio_allowed_origins minio_allow_private_endpoint "
        "get_bytes max_backup_bytes _download_from_minio "
        "restored_from_object_storage encrypted_sha256 "
        "backup-drills parity report_path sys.exit(main())"
    )
