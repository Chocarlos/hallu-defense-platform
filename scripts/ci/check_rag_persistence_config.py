from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PGVECTOR_MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "001_rag_evidence_chunks.sql"
PGVECTOR_EXACT_MIGRATION = (
    ROOT / "infra" / "rag" / "pgvector" / "009_drop_unsafe_ivfflat.sql"
)
PGVECTOR_FRESHNESS_MIGRATION = (
    ROOT / "infra" / "rag" / "pgvector" / "010_add_retrieved_at.sql"
)
OPENSEARCH_TEMPLATE = ROOT / "infra" / "rag" / "opensearch" / "evidence-index-template.json"
DOCKER_COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
RAG_DOC = ROOT / "docs" / "rag" / "persistent-indexes.md"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "live.yml"
API_DOCKERFILE = ROOT / "infra" / "docker" / "api.Dockerfile"
OPENSEARCH_BOOTSTRAP = ROOT / "scripts" / "dev" / "bootstrap_opensearch_template.py"
LIVE_HYBRID_RAG_SMOKE = ROOT / "scripts" / "dev" / "live_hybrid_rag_smoke.py"
LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT = "scripts/dev/live_opensearch_rag_smoke.py"
LIVE_OPENSEARCH_RAG_SMOKE_TARGET = "rag-opensearch-live-smoke"
LIVE_OPENSEARCH_RAG_SMOKE_ENV = "HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED=true"
LIVE_PGVECTOR_RAG_SMOKE_SCRIPT = "scripts/dev/live_pgvector_rag_smoke.py"
LIVE_PGVECTOR_RAG_SMOKE_TARGET = "rag-pgvector-live-smoke"
LIVE_PGVECTOR_RAG_SMOKE_ENV = "HALLU_DEFENSE_LIVE_PGVECTOR_RAG_SMOKE_ENABLED=true"
LIVE_HYBRID_RAG_SMOKE_SCRIPT = "scripts/dev/live_hybrid_rag_smoke.py"
LIVE_HYBRID_RAG_SMOKE_TARGET = "rag-hybrid-live-smoke"
LIVE_HYBRID_RAG_SMOKE_ENV = "HALLU_DEFENSE_LIVE_HYBRID_RAG_SMOKE_ENABLED=true"

REQUIRED_SQL_SNIPPETS = {
    "CREATE EXTENSION IF NOT EXISTS vector",
    "CREATE TABLE IF NOT EXISTS rag_evidence_chunks",
    "PRIMARY KEY (tenant_id, evidence_id)",
    "embedding VECTOR(16) NOT NULL",
    "USING gin (metadata)",
    "USING ivfflat (embedding vector_cosine_ops)",
    "DROP INDEX IF EXISTS idx_rag_evidence_chunks_embedding",
    "ADD COLUMN IF NOT EXISTS retrieved_at TIMESTAMPTZ",
    "ALTER COLUMN retrieved_at SET NOT NULL",
    "idx_rag_evidence_chunks_tenant_source",
}
REQUIRED_TEMPLATE_PROPERTIES = {
    "tenant_id",
    "evidence_id",
    "source_ref",
    "corpus_id",
    "document_revision",
    "content",
    "authority",
    "freshness",
    "metadata",
    "metadata_filter_tokens",
    "document_index",
    "chunk_index",
}


class RagPersistenceConfigError(ValueError):
    pass


def validate_rag_persistence_config(
    *,
    migration_sql: str,
    opensearch_template: Mapping[str, object],
    compose_text: str,
    env_example_text: str,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_pgvector_migration(migration_sql, errors)
    _validate_opensearch_template(opensearch_template, errors)
    _validate_compose(compose_text, errors)
    _validate_supporting_files(
        env_example_text=env_example_text,
        docs_text=docs_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        errors=errors,
    )
    if errors:
        raise RagPersistenceConfigError("\n".join(errors))


def load_current_config() -> tuple[str, dict[str, object], str, str, str, str, str, str]:
    template = json.loads(OPENSEARCH_TEMPLATE.read_text(encoding="utf-8"))
    if not isinstance(template, dict):
        raise RagPersistenceConfigError("OpenSearch template must be a JSON object")
    return (
        (
            PGVECTOR_MIGRATION.read_text(encoding="utf-8")
            + "\n"
            + PGVECTOR_EXACT_MIGRATION.read_text(encoding="utf-8")
            + "\n"
            + PGVECTOR_FRESHNESS_MIGRATION.read_text(encoding="utf-8")
        ),
        template,
        DOCKER_COMPOSE.read_text(encoding="utf-8"),
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        RAG_DOC.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def _validate_pgvector_migration(sql: str, errors: list[str]) -> None:
    normalized = re.sub(r"\s+", " ", sql)
    for snippet in REQUIRED_SQL_SNIPPETS:
        if snippet not in sql and snippet not in normalized:
            errors.append(f"pgvector migration missing `{snippet}`")
    if "tenant_id TEXT NOT NULL" not in sql:
        errors.append("pgvector migration must make tenant_id NOT NULL")
    if re.search(r"(?i)DROP\s+TABLE", sql):
        errors.append("pgvector migration must not contain DROP TABLE")


def _validate_opensearch_template(template: Mapping[str, object], errors: list[str]) -> None:
    index_patterns = template.get("index_patterns")
    if not isinstance(index_patterns, list) or "hallu_evidence*" not in index_patterns:
        errors.append("OpenSearch template must target hallu_evidence* index patterns")

    metadata = _mapping(template.get("_meta"), "_meta", errors)
    if metadata.get("schema_version") != "rag-opensearch-template.v3":
        errors.append("OpenSearch template _meta.schema_version must be rag-opensearch-template.v3")
    if metadata.get("tenant_scoped") is not True:
        errors.append("OpenSearch template _meta.tenant_scoped must be true")
    if metadata.get("required_query_filter") != "tenant_id":
        errors.append("OpenSearch template must declare tenant_id as the required query filter")

    template_body = _mapping(template.get("template"), "template", errors)
    settings = _mapping(template_body.get("settings"), "template.settings", errors)
    if settings.get("number_of_replicas") != 1:
        errors.append("OpenSearch schema v3 must configure number_of_replicas=1")
    mappings = _mapping(template_body.get("mappings"), "template.mappings", errors)
    mappings_metadata = _mapping(mappings.get("_meta"), "template.mappings._meta", errors)
    if mappings_metadata.get("schema_version") != "rag-opensearch-template.v3":
        errors.append("OpenSearch index mappings must declare schema v3")
    if mappings.get("dynamic") is not False:
        errors.append("OpenSearch mappings.dynamic must be false")
    properties = _mapping(mappings.get("properties"), "template.mappings.properties", errors)
    missing_properties = REQUIRED_TEMPLATE_PROPERTIES - set(properties)
    if missing_properties:
        errors.append(
            "OpenSearch template missing properties: " + ", ".join(sorted(missing_properties))
        )
    tenant = _mapping(properties.get("tenant_id"), "tenant_id mapping", errors)
    if tenant.get("type") != "keyword":
        errors.append("OpenSearch tenant_id must be mapped as keyword")
    content = _mapping(properties.get("content"), "content mapping", errors)
    if content.get("type") != "text":
        errors.append("OpenSearch content must be mapped as text")
    for field_name in (
        "evidence_id",
        "source_ref",
        "corpus_id",
        "document_revision",
        "metadata_filter_tokens",
    ):
        field_mapping = _mapping(properties.get(field_name), f"{field_name} mapping", errors)
        if field_mapping.get("type") != "keyword":
            errors.append(f"OpenSearch {field_name} must be mapped as keyword")
    metadata_mapping = _mapping(properties.get("metadata"), "metadata mapping", errors)
    if metadata_mapping.get("type") != "object" or metadata_mapping.get("enabled") is not False:
        errors.append("OpenSearch metadata must be an object with enabled=false")
    if metadata_mapping.get("dynamic") is True or "properties" in metadata_mapping:
        errors.append("OpenSearch opaque metadata must not create dynamic subfield mappings")


def _validate_compose(compose_text: str, errors: list[str]) -> None:
    required_snippets = {
        "opensearch:",
        "image: hallu-defense-opensearch:ci",
        "dockerfile: infra/docker/opensearch.Dockerfile",
        "DISABLE_SECURITY_PLUGIN: \"true\"",
        "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI: \"true\"",
        "opensearch-data:/usr/share/opensearch/data",
        "./infra/rag/pgvector:/docker-entrypoint-initdb.d:ro",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND: hybrid",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT: http://opensearch:9200",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME: hallu_evidence",
        "opensearch-bootstrap:",
        "scripts/dev/bootstrap_opensearch_template.py",
        "condition: service_completed_successfully",
        "opensearch-data:",
    }
    for snippet in required_snippets:
        if snippet not in compose_text:
            errors.append(f"docker-compose.yml missing `{snippet}`")
    if "hallu-defense-opensearch:latest" in compose_text:
        errors.append("OpenSearch image must be pinned and must not use latest")


def _validate_supporting_files(
    *,
    env_example_text: str,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    for key in (
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT=",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME=",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@postgres:5432/hallu_defense",
        "HALLU_DEFENSE_PGVECTOR_TABLE_NAME=",
        "HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION=16",
    ):
        if key not in env_example_text:
            errors.append(f".env.example missing {key}")
    if any(
        marker not in docs_text
        for marker in (
            "001_rag_evidence_chunks.sql",
            "009_drop_unsafe_ivfflat.sql",
            "010_add_retrieved_at.sql",
            "evidence-index-template.json",
            "metadata_filter_tokens",
        )
    ):
        errors.append("RAG docs must describe exact pgvector search and OpenSearch schema v3")
    script = "scripts/ci/check_rag_persistence_config.py"
    bootstrap = "scripts/dev/bootstrap_opensearch_template.py --dry-run"
    if "rag-persistence-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the rag-persistence-config gate")
    if bootstrap not in makefile_text:
        errors.append("Makefile must expose the OpenSearch template bootstrap dry-run")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_rag_persistence_config.py")
    if bootstrap not in ci_workflow_text:
        errors.append("CI workflow must run the OpenSearch template bootstrap dry-run")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_rag_persistence_config.py")
    if bootstrap not in security_workflow_text:
        errors.append("security workflow must run the OpenSearch template bootstrap dry-run")
    _validate_live_opensearch_smoke_wiring(
        docs_text=docs_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        errors=errors,
    )
    _validate_live_pgvector_smoke_wiring(
        docs_text=docs_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        errors=errors,
    )
    _validate_live_hybrid_smoke_wiring(
        docs_text=docs_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        errors=errors,
    )
    _validate_runtime_provisioning(errors)


def _validate_live_opensearch_smoke_wiring(
    *,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    live_target = LIVE_OPENSEARCH_RAG_SMOKE_TARGET
    live_script = LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT
    required_doc_markers = {
        live_target,
        live_script,
        LIVE_OPENSEARCH_RAG_SMOKE_ENV,
        "hallu_evidence_smoke",
        "docker compose up -d opensearch",
        "http://localhost:9200",
    }
    missing_doc_markers = sorted(marker for marker in required_doc_markers if marker not in docs_text)
    if missing_doc_markers:
        errors.append(
            "RAG docs missing live OpenSearch RAG smoke markers: "
            + ", ".join(missing_doc_markers)
        )

    if not _makefile_phony_includes(makefile_text, live_target):
        errors.append("Makefile .PHONY must include the live OpenSearch RAG smoke target")
    live_target_body = _makefile_target_body(makefile_text, live_target)
    if not live_target_body:
        errors.append("Makefile must expose the live OpenSearch RAG smoke target")
    elif live_script not in live_target_body:
        errors.append("live OpenSearch RAG smoke target must run live_opensearch_rag_smoke.py")

    for target in ("rag-persistence-config", "security-check"):
        target_body = _makefile_target_body(makefile_text, target)
        if live_target in target_body or live_script in target_body:
            errors.append(f"Makefile {target} must not run the live OpenSearch RAG smoke")

    for workflow_name, workflow_text in (
        ("CI workflow", ci_workflow_text),
        ("security workflow", security_workflow_text),
    ):
        if live_target in workflow_text or live_script in workflow_text:
            errors.append(f"{workflow_name} must not run the live OpenSearch RAG smoke by default")


def _validate_live_pgvector_smoke_wiring(
    *,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    live_target = LIVE_PGVECTOR_RAG_SMOKE_TARGET
    live_script = LIVE_PGVECTOR_RAG_SMOKE_SCRIPT
    required_doc_markers = {
        live_target,
        live_script,
        LIVE_PGVECTOR_RAG_SMOKE_ENV,
        "rag_evidence_chunks",
        "docker compose up -d postgres",
        "HALLU_DEFENSE_POSTGRES_DSN",
        "current smoke run",
    }
    missing_doc_markers = sorted(marker for marker in required_doc_markers if marker not in docs_text)
    if missing_doc_markers:
        errors.append(
            "RAG docs missing live pgvector RAG smoke markers: "
            + ", ".join(missing_doc_markers)
        )

    if not _makefile_phony_includes(makefile_text, live_target):
        errors.append("Makefile .PHONY must include the live pgvector RAG smoke target")
    live_target_body = _makefile_target_body(makefile_text, live_target)
    if not live_target_body:
        errors.append("Makefile must expose the live pgvector RAG smoke target")
    elif live_script not in live_target_body:
        errors.append("live pgvector RAG smoke target must run live_pgvector_rag_smoke.py")

    for target in ("rag-persistence-config", "security-check"):
        target_body = _makefile_target_body(makefile_text, target)
        if live_target in target_body or live_script in target_body:
            errors.append(f"Makefile {target} must not run the live pgvector RAG smoke")

    for workflow_name, workflow_text in (
        ("CI workflow", ci_workflow_text),
        ("security workflow", security_workflow_text),
    ):
        if live_target in workflow_text or live_script in workflow_text:
            errors.append(f"{workflow_name} must not run the live pgvector RAG smoke by default")


def _validate_live_hybrid_smoke_wiring(
    *,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    required_doc_markers = {
        LIVE_HYBRID_RAG_SMOKE_TARGET,
        LIVE_HYBRID_RAG_SMOKE_SCRIPT,
        LIVE_HYBRID_RAG_SMOKE_ENV,
        "HALLU_DEFENSE_LIVE_HYBRID_RAG_ADMIN_DSN",
        "scratch database",
        "schema v3",
        "reindex",
    }
    missing = sorted(marker for marker in required_doc_markers if marker not in docs_text)
    if missing:
        errors.append("RAG docs missing hybrid live smoke markers: " + ", ".join(missing))

    if not _makefile_phony_includes(makefile_text, LIVE_HYBRID_RAG_SMOKE_TARGET):
        errors.append("Makefile .PHONY must include the live hybrid RAG smoke target")
    target_body = _makefile_target_body(makefile_text, LIVE_HYBRID_RAG_SMOKE_TARGET)
    if LIVE_HYBRID_RAG_SMOKE_SCRIPT not in target_body:
        errors.append("live hybrid RAG smoke target must run live_hybrid_rag_smoke.py")
    for workflow_name, workflow_text in (
        ("CI workflow", ci_workflow_text),
        ("security workflow", security_workflow_text),
    ):
        if (
            LIVE_HYBRID_RAG_SMOKE_TARGET in workflow_text
            or LIVE_HYBRID_RAG_SMOKE_SCRIPT in workflow_text
        ):
            errors.append(f"{workflow_name} must not run the live hybrid RAG smoke by default")

    smoke_text = LIVE_HYBRID_RAG_SMOKE.read_text(encoding="utf-8")
    for marker in (
        "CREATE DATABASE",
        "DROP DATABASE IF EXISTS",
        "WITH (FORCE)",
        "EXPECTED_MIGRATION_COUNT = 14",
        "persistent_hybrid_rrf_v1",
        "template_cleaned",
        "finally:",
    ):
        if marker not in smoke_text:
            errors.append(f"hybrid live smoke missing `{marker}`")
    live_workflow_text = LIVE_WORKFLOW.read_text(encoding="utf-8")
    for marker in (
        "hybrid-rag-live:",
        LIVE_HYBRID_RAG_SMOKE_SCRIPT,
        "HALLU_DEFENSE_LIVE_HYBRID_RAG_ADMIN_DSN",
        "docker compose up -d postgres opensearch",
        "COMPOSE_PROJECT_NAME: hallu-hybrid-rag-",
        "docker compose down -v",
    ):
        if marker not in live_workflow_text:
            errors.append(f"live workflow missing hybrid smoke marker `{marker}`")


def _validate_runtime_provisioning(errors: list[str]) -> None:
    dockerfile_text = API_DOCKERFILE.read_text(encoding="utf-8")
    bootstrap_text = OPENSEARCH_BOOTSTRAP.read_text(encoding="utf-8")
    for marker in (
        "COPY scripts/dev/bootstrap_opensearch_template.py",
        "COPY infra/rag/opensearch",
    ):
        if marker not in dockerfile_text:
            errors.append(f"API image missing OpenSearch provisioning asset `{marker}`")
    for marker in (
        "create_secret_manager(settings)",
        "create_opensearch_rag_backend",
        "provision_index_schema",
        "schema_ready",
        "index_state",
    ):
        if marker not in bootstrap_text:
            errors.append(f"OpenSearch provisioning bootstrap missing `{marker}`")


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    for line in makefile_text.splitlines():
        if line.startswith(".PHONY:"):
            return target in line.split()
    return False


def _makefile_target_body(makefile_text: str, target: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target)}:\s*$", makefile_text)
    if match is None:
        return ""
    body_lines: list[str] = []
    for line in makefile_text[match.end() :].splitlines():
        if not line:
            if body_lines:
                break
            continue
        if not line.startswith("\t"):
            break
        body_lines.append(line)
    return "\n".join(body_lines)


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def main() -> None:
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
    print("Validated RAG persistence configuration.")


if __name__ == "__main__":
    main()
