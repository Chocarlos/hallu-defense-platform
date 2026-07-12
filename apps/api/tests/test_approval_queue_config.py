from __future__ import annotations

import pytest

from scripts.ci.check_approval_queue_config import (
    ApprovalQueueConfigError,
    load_current_config,
    validate_approval_queue_config,
)


def test_approval_queue_config_validates_current_artifacts() -> None:
    (
        env_example_text,
        approval_doc_text,
        approval_service_text,
        api_dependencies_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()

    validate_approval_queue_config(
        env_example_text=env_example_text,
        approval_doc_text=approval_doc_text,
        approval_service_text=approval_service_text,
        api_dependencies_text=api_dependencies_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )


def test_approval_queue_config_requires_env_keys() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace("HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND=memory", "")

    with pytest.raises(ApprovalQueueConfigError, match="APPROVAL_QUEUE_BACKEND"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_execution_grant_ttl_env_key() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace(
        "HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS=900",
        "",
    )

    with pytest.raises(ApprovalQueueConfigError, match="APPROVAL_EXECUTION_GRANT_TTL"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_logical_commitment_secret_name() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace(
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME=",
        "",
    )

    with pytest.raises(ApprovalQueueConfigError, match="COMMITMENT_SECRET_NAME"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


@pytest.mark.parametrize(
    "variable",
    [
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID=",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_SECRET_NAME=",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_KEY_ID=",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_VALID_UNTIL=",
    ],
)
def test_approval_queue_config_requires_v3_rotation_environment_surface(
    variable: str,
) -> None:
    config = list(load_current_config())
    config[0] = config[0].replace(variable, "")

    with pytest.raises(ApprovalQueueConfigError, match=variable.split("=")[0]):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_production_postgres_rejection() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "Production and staging require the PostgreSQL approval queue backend",
        "",
    )

    with pytest.raises(ApprovalQueueConfigError, match="PostgreSQL"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_atomic_decision_and_grant_transaction() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "with self._connection.transaction() as transaction",
        "transaction = self._connection",
    )

    with pytest.raises(ApprovalQueueConfigError, match="transaction"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_original_payload_commitment() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "TOOL_CALL_COMMITMENT_DOMAIN",
        "REMOVED_COMMITMENT_DOMAIN",
    )

    with pytest.raises(ApprovalQueueConfigError, match="TOOL_CALL_COMMITMENT_DOMAIN"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_factory_wiring() -> None:
    config = list(load_current_config())
    config[3] = config[3].replace(
        "secret_manager=secret_manager",
        "secret_manager=None",
    )

    with pytest.raises(ApprovalQueueConfigError, match="API dependencies"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )


def test_approval_queue_config_requires_ci_wiring() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace("python scripts/ci/check_approval_queue_config.py", "")

    with pytest.raises(ApprovalQueueConfigError, match="CI workflow"):
        validate_approval_queue_config(
            env_example_text=config[0],
            approval_doc_text=config[1],
            approval_service_text=config[2],
            api_dependencies_text=config[3],
            makefile_text=config[4],
            ci_workflow_text=config[5],
            security_workflow_text=config[6],
        )
