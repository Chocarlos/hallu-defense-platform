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


def test_approval_queue_config_requires_production_memory_rejection() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "Production and staging must configure a persistent approval queue backend",
        "",
    )

    with pytest.raises(ApprovalQueueConfigError, match="persistent"):
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
        "create_approval_queue(settings, sql_provider=_sql_provider)", "ApprovalQueue()"
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
