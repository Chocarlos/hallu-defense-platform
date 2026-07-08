from __future__ import annotations

import copy

import pytest

from scripts.ci.check_rag_persistence_config import (
    RagPersistenceConfigError,
    load_current_config,
    validate_rag_persistence_config,
)


def test_rag_persistence_config_validates_current_artifacts() -> None:
    (
        migration_sql,
        opensearch_template,
        compose_text,
        env_example_text,
        docs_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()

    validate_rag_persistence_config(
        migration_sql=migration_sql,
        opensearch_template=opensearch_template,
        compose_text=compose_text,
        env_example_text=env_example_text,
        docs_text=docs_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )


def test_rag_persistence_config_requires_tenant_primary_key() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace("PRIMARY KEY (tenant_id, evidence_id)", "PRIMARY KEY (evidence_id)")

    with pytest.raises(RagPersistenceConfigError, match="PRIMARY KEY"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_requires_opensearch_tenant_filter_metadata() -> None:
    config = list(load_current_config())
    template = copy.deepcopy(config[1])
    assert isinstance(template, dict)
    metadata = template["_meta"]
    assert isinstance(metadata, dict)
    metadata["required_query_filter"] = "source_ref"

    with pytest.raises(RagPersistenceConfigError, match="tenant_id"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=template,
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_rejects_unpinned_opensearch_image() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "opensearchproject/opensearch:2.15.0",
        "opensearchproject/opensearch:latest",
    )

    with pytest.raises(RagPersistenceConfigError, match="latest"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_requires_compose_backend_wiring() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("HALLU_DEFENSE_RAG_INDEX_BACKEND: opensearch", "")

    with pytest.raises(RagPersistenceConfigError, match="RAG_INDEX_BACKEND"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_requires_makefile_gate() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace("rag-persistence-config:", "rag-persistence-disabled:")

    with pytest.raises(RagPersistenceConfigError, match="Makefile"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_requires_ci_wiring() -> None:
    config = list(load_current_config())
    config[6] = config[6].replace("python scripts/ci/check_rag_persistence_config.py", "")

    with pytest.raises(RagPersistenceConfigError, match="CI workflow"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )


def test_rag_persistence_config_requires_opensearch_bootstrap_dry_run() -> None:
    config = list(load_current_config())
    config[6] = config[6].replace(
        "python scripts/dev/bootstrap_opensearch_template.py --dry-run",
        "",
    )

    with pytest.raises(RagPersistenceConfigError, match="bootstrap dry-run"):
        validate_rag_persistence_config(
            migration_sql=config[0],
            opensearch_template=config[1],
            compose_text=config[2],
            env_example_text=config[3],
            docs_text=config[4],
            makefile_text=config[5],
            ci_workflow_text=config[6],
            security_workflow_text=config[7],
        )
