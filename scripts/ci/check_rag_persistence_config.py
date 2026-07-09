from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PGVECTOR_MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "001_rag_evidence_chunks.sql"
OPENSEARCH_TEMPLATE = ROOT / "infra" / "rag" / "opensearch" / "evidence-index-template.json"
DOCKER_COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
RAG_DOC = ROOT / "docs" / "rag" / "persistent-indexes.md"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
LIVE_OPENSEARCH_RAG_SMOKE_SCRIPT = "scripts/dev/live_opensearch_rag_smoke.py"
LIVE_OPENSEARCH_RAG_SMOKE_TARGET = "rag-opensearch-live-smoke"
LIVE_OPENSEARCH_RAG_SMOKE_ENV = "HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED=true"

REQUIRED_SQL_SNIPPETS = {
    "CREATE EXTENSION IF NOT EXISTS vector",
    "CREATE TABLE IF NOT EXISTS rag_evidence_chunks",
    "PRIMARY KEY (tenant_id, evidence_id)",
    "embedding VECTOR(16) NOT NULL",
    "USING gin (metadata)",
    "USING ivfflat (embedding vector_cosine_ops)",
    "idx_rag_evidence_chunks_tenant_source",
}
REQUIRED_TEMPLATE_PROPERTIES = {
    "tenant_id",
    "evidence_id",
    "source_ref",
    "content",
    "authority",
    "freshness",
    "metadata",
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
        PGVECTOR_MIGRATION.read_text(encoding="utf-8"),
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
    if metadata.get("schema_version") != "rag-opensearch-template.v1":
        errors.append("OpenSearch template _meta.schema_version must be rag-opensearch-template.v1")
    if metadata.get("tenant_scoped") is not True:
        errors.append("OpenSearch template _meta.tenant_scoped must be true")
    if metadata.get("required_query_filter") != "tenant_id":
        errors.append("OpenSearch template must declare tenant_id as the required query filter")

    template_body = _mapping(template.get("template"), "template", errors)
    mappings = _mapping(template_body.get("mappings"), "template.mappings", errors)
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


def _validate_compose(compose_text: str, errors: list[str]) -> None:
    required_snippets = {
        "opensearch:",
        "image: opensearchproject/opensearch:2.15.0",
        "plugins.security.disabled: \"true\"",
        "opensearch-data:/usr/share/opensearch/data",
        "./infra/rag/pgvector:/docker-entrypoint-initdb.d:ro",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND: opensearch",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT: http://opensearch:9200",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME: hallu_evidence",
        "- opensearch",
        "opensearch-data:",
    }
    for snippet in required_snippets:
        if snippet not in compose_text:
            errors.append(f"docker-compose.yml missing `{snippet}`")
    if "opensearchproject/opensearch:latest" in compose_text:
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
        "HALLU_DEFENSE_PGVECTOR_TABLE_NAME=",
    ):
        if key not in env_example_text:
            errors.append(f".env.example missing {key}")
    if "001_rag_evidence_chunks.sql" not in docs_text or "evidence-index-template.json" not in docs_text:
        errors.append("RAG docs must mention pgvector migration and OpenSearch template")
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
