from __future__ import annotations

import pytest

from scripts.ci.check_audit_ledger_config import (
    AuditLedgerConfigError,
    load_current_config,
    validate_audit_ledger_config,
)


def test_audit_ledger_config_validates_current_artifacts() -> None:
    (
        env_example_text,
        audit_doc_text,
        audit_service_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()

    validate_audit_ledger_config(
        env_example_text=env_example_text,
        audit_doc_text=audit_doc_text,
        audit_service_text=audit_service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )


def test_audit_ledger_config_requires_env_keys() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace("HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=memory", "")

    with pytest.raises(AuditLedgerConfigError, match="AUDIT_LEDGER_BACKEND"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_production_memory_rejection() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "Production and staging must configure a persistent audit ledger backend",
        "",
    )

    with pytest.raises(AuditLedgerConfigError, match="persistent"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_ci_wiring() -> None:
    config = list(load_current_config())
    config[4] = config[4].replace("python scripts/ci/check_audit_ledger_config.py", "")

    with pytest.raises(AuditLedgerConfigError, match="CI workflow"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )
