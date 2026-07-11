from __future__ import annotations

import copy

import pytest

from scripts.ci.check_rag_persistence_config import (
    LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT,
    LIVE_OPENSEARCH_RAG_SMOKE_TARGET,
    LIVE_PGVECTOR_RAG_SMOKE_SCRIPT,
    LIVE_PGVECTOR_RAG_SMOKE_TARGET,
    LIVE_HYBRID_RAG_SMOKE_SCRIPT,
    LIVE_HYBRID_RAG_SMOKE_TARGET,
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


def test_rag_persistence_config_requires_persisted_retrieval_time() -> None:
    config = list(load_current_config())
    config[0] = config[0].replace(
        "ADD COLUMN IF NOT EXISTS retrieved_at TIMESTAMPTZ",
        "ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ",
    )

    with pytest.raises(RagPersistenceConfigError, match="retrieved_at"):
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


def test_rag_persistence_config_requires_schema_v3_on_concrete_mapping() -> None:
    config = list(load_current_config())
    template = copy.deepcopy(config[1])
    assert isinstance(template, dict)
    body = template["template"]
    assert isinstance(body, dict)
    mappings = body["mappings"]
    assert isinstance(mappings, dict)
    mappings.pop("_meta")

    with pytest.raises(RagPersistenceConfigError, match="mappings.*schema v3"):
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


def test_rag_persistence_config_requires_replica_and_opaque_metadata() -> None:
    config = list(load_current_config())
    template = copy.deepcopy(config[1])
    assert isinstance(template, dict)
    body = template["template"]
    assert isinstance(body, dict)
    settings = body["settings"]
    mappings = body["mappings"]
    assert isinstance(settings, dict)
    assert isinstance(mappings, dict)
    properties = mappings["properties"]
    assert isinstance(properties, dict)
    metadata = properties["metadata"]
    assert isinstance(metadata, dict)
    settings["number_of_replicas"] = 0
    metadata["enabled"] = True

    with pytest.raises(RagPersistenceConfigError, match="replicas|enabled=false"):
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


def test_rag_persistence_config_requires_automatic_local_bootstrap() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace("condition: service_completed_successfully", "")

    with pytest.raises(RagPersistenceConfigError, match="service_completed_successfully"):
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


def test_rag_persistence_config_rejects_unpinned_opensearch_image() -> None:
    config = list(load_current_config())
    config[2] = config[2].replace(
        "hallu-defense-opensearch:ci",
        "hallu-defense-opensearch:latest",
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
    config[2] = config[2].replace("HALLU_DEFENSE_RAG_INDEX_BACKEND: hybrid", "")

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


def test_rag_persistence_config_requires_live_smoke_makefile_target() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        f"{LIVE_OPENSEARCH_RAG_SMOKE_TARGET}:",
        f"{LIVE_OPENSEARCH_RAG_SMOKE_TARGET}-disabled:",
    )

    with pytest.raises(RagPersistenceConfigError, match="live OpenSearch RAG smoke target"):
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


def test_rag_persistence_config_requires_live_smoke_script_path_in_makefile() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT,
        "scripts/dev/not_the_live_rag_smoke.py",
    )

    with pytest.raises(RagPersistenceConfigError, match="live_opensearch_rag_smoke.py"):
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


def test_rag_persistence_config_requires_live_smoke_docs_markers() -> None:
    config = list(load_current_config())
    config[4] = config[4].replace("HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED=true", "")
    config[4] = config[4].replace("hallu_evidence_smoke", "hallu_evidence")

    with pytest.raises(RagPersistenceConfigError, match="RAG docs missing"):
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


def test_rag_persistence_config_rejects_live_smoke_in_security_check() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        "security-check:\n",
        f"security-check:\n\t$(PY) {LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT}\n",
    )

    with pytest.raises(RagPersistenceConfigError, match="security-check"):
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


def test_rag_persistence_config_rejects_live_smoke_in_default_ci() -> None:
    config = list(load_current_config())
    config[6] = config[6] + f"\n      - run: python {LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT}\n"

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


def test_rag_persistence_config_requires_live_pgvector_smoke_makefile_target() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        f"{LIVE_PGVECTOR_RAG_SMOKE_TARGET}:",
        f"{LIVE_PGVECTOR_RAG_SMOKE_TARGET}-disabled:",
    )

    with pytest.raises(RagPersistenceConfigError, match="live pgvector RAG smoke target"):
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


def test_rag_persistence_config_requires_live_pgvector_smoke_script_path_in_makefile() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        LIVE_PGVECTOR_RAG_SMOKE_SCRIPT,
        "scripts/dev/not_the_live_pgvector_rag_smoke.py",
    )

    with pytest.raises(RagPersistenceConfigError, match="live_pgvector_rag_smoke.py"):
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


def test_rag_persistence_config_requires_live_pgvector_smoke_docs_markers() -> None:
    config = list(load_current_config())
    config[4] = config[4].replace("HALLU_DEFENSE_LIVE_PGVECTOR_RAG_SMOKE_ENABLED=true", "")
    config[4] = config[4].replace("current smoke run", "smoke run")

    with pytest.raises(RagPersistenceConfigError, match="RAG docs missing"):
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


def test_rag_persistence_config_requires_combined_hybrid_smoke_target() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        f"{LIVE_HYBRID_RAG_SMOKE_TARGET}:",
        f"{LIVE_HYBRID_RAG_SMOKE_TARGET}-disabled:",
    ).replace(
        LIVE_HYBRID_RAG_SMOKE_SCRIPT,
        "scripts/dev/not_the_hybrid_smoke.py",
    )

    with pytest.raises(RagPersistenceConfigError, match="live hybrid RAG smoke"):
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


def test_rag_persistence_config_rejects_live_pgvector_smoke_in_security_check() -> None:
    config = list(load_current_config())
    config[5] = config[5].replace(
        "security-check:\n",
        f"security-check:\n\t$(PY) {LIVE_PGVECTOR_RAG_SMOKE_SCRIPT}\n",
    )

    with pytest.raises(RagPersistenceConfigError, match="security-check"):
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


def test_rag_persistence_config_rejects_live_pgvector_smoke_in_default_ci() -> None:
    config = list(load_current_config())
    config[6] = config[6] + f"\n      - run: python {LIVE_PGVECTOR_RAG_SMOKE_SCRIPT}\n"

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
