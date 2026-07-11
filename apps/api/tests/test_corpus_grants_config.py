from __future__ import annotations

import pytest

from scripts.ci.check_corpus_grants_config import (
    CorpusGrantsConfigError,
    load_current_config,
    validate_corpus_grants_config,
)


def test_corpus_grants_config_validates_current_artifacts() -> None:
    (
        env_example_text,
        corpus_grants_doc_text,
        config_text,
        corpus_grants_service_text,
        corpus_grants_migration_text,
        api_dependencies_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()

    validate_corpus_grants_config(
        env_example_text=env_example_text,
        corpus_grants_doc_text=corpus_grants_doc_text,
        config_text=config_text,
        corpus_grants_service_text=corpus_grants_service_text,
        corpus_grants_migration_text=corpus_grants_migration_text,
        api_dependencies_text=api_dependencies_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )


def test_corpus_grants_config_requires_env_keys() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace("HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=memory", "")

    with pytest.raises(CorpusGrantsConfigError, match="CORPUS_GRANTS_BACKEND"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_requires_production_memory_rejection() -> None:
    config = list(load_current_config())
    config[3] = config[3].replace(
        "Production and staging must configure a persistent corpus grants backend.",
        "",
    )

    with pytest.raises(CorpusGrantsConfigError, match="persistent"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_requires_lifecycle_docs() -> None:
    config = list(load_current_config())
    config[1] = config[1].replace("`POST /rag/corpus-grants/disable`", "")

    with pytest.raises(CorpusGrantsConfigError, match="disable"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_requires_postgres_migration() -> None:
    config = list(load_current_config())
    config[4] = config[4].replace("CREATE TABLE IF NOT EXISTS rag_corpus_grants", "")

    with pytest.raises(CorpusGrantsConfigError, match="rag_corpus_grants"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_requires_factory_wiring() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        "postgres_connection=_sql_provider",
        "postgres_connection=None",
    )

    with pytest.raises(CorpusGrantsConfigError, match="API dependencies"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_rejects_cross_tenant_postgres_preload() -> None:
    config = list(load_current_config())
    config[3] += '\nstatement = f"SELECT payload FROM {self._table_name} ORDER BY sequence_id ASC"\n'

    with pytest.raises(CorpusGrantsConfigError, match="cross-tenant full table cache"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_corpus_grants_config_requires_ci_wiring() -> None:
    config = list(load_current_config())
    config[7] = config[7].replace("python scripts/ci/check_corpus_grants_config.py", "")

    with pytest.raises(CorpusGrantsConfigError, match="CI workflow"):
        validate_corpus_grants_config(
            env_example_text=config[0],
            corpus_grants_doc_text=config[1],
            config_text=config[2],
            corpus_grants_service_text=config[3],
            corpus_grants_migration_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )
