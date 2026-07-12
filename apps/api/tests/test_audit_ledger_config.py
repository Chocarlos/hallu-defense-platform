from __future__ import annotations

import re

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


def test_audit_ledger_config_requires_request_commitment_boundary() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "AUDIT_REQUEST_COMMITMENT_DOMAIN",
        "UNKEYED_REQUEST_DIGEST_DOMAIN",
    )

    with pytest.raises(AuditLedgerConfigError, match="AUDIT_REQUEST_COMMITMENT_DOMAIN"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_production_postgres_rejection() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "Production and staging require the PostgreSQL persistent audit ledger backend.",
        "",
    )

    with pytest.raises(AuditLedgerConfigError, match="PostgreSQL"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_atomic_completion_boundary() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("append_run_with_event", "split_run_and_event")

    with pytest.raises(AuditLedgerConfigError, match="append_run_with_event"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_atomic_replay_boundary() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("append_replayed_run", "append_replay_event_later")

    with pytest.raises(AuditLedgerConfigError, match="append_replayed_run"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_coherent_export_snapshot() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("export_snapshot", "split_export_reads")

    with pytest.raises(AuditLedgerConfigError, match="export_snapshot"):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


@pytest.mark.parametrize(
    ("marker", "replacement"),
    [
        ("find_replay_source", "capped_replay_source"),
        ("load_replay_source_candidates", "load_one_replay_source"),
        (
            "ORDER BY created_at DESC, id DESC LIMIT 2",
            "ORDER BY created_at DESC, id DESC LIMIT 1",
        ),
        ("ReplaySourceConflictError", "ReplaySourceSelectionError"),
        ("model_copy(deep=True)", "model_copy(deep=False)"),
    ],
)
def test_audit_ledger_config_requires_owned_cardinality_checked_replay_lookup(
    marker: str,
    replacement: str,
) -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(marker, replacement)

    with pytest.raises(AuditLedgerConfigError, match=re.escape(marker)):
        validate_audit_ledger_config(
            env_example_text=config[0],
            audit_doc_text=config[1],
            audit_service_text=config[2],
            makefile_text=config[3],
            ci_workflow_text=config[4],
            security_workflow_text=config[5],
        )


def test_audit_ledger_config_requires_bounded_snapshot_lookahead() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("limit=limit + 1", "limit=limit")

    with pytest.raises(AuditLedgerConfigError, match=r"limit=limit \+ 1"):
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
