from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
CORPUS_GRANTS_DOC = ROOT / "docs" / "security" / "auth-rbac.md"
CONFIG = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
CORPUS_GRANTS_SERVICE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "corpus_grants.py"
CORPUS_GRANTS_MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "002_rag_corpus_grants.sql"
API_DEPENDENCIES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


class CorpusGrantsConfigError(ValueError):
    pass


def validate_corpus_grants_config(
    *,
    env_example_text: str,
    corpus_grants_doc_text: str,
    config_text: str,
    corpus_grants_service_text: str,
    corpus_grants_migration_text: str,
    api_dependencies_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _require(
        env_example_text,
        {
            "HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@postgres:5432/hallu_defense",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=memory",
            "HALLU_DEFENSE_CORPUS_GRANTS_PATH=var/rag/corpus-grants.jsonl",
            "HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME=rag_corpus_grants",
        },
        ".env.example",
        errors,
    )
    _require(
        corpus_grants_doc_text,
        {
            "`POST /rag/corpus-grants/upsert`",
            "`POST /rag/corpus-grants/disable`",
            "`POST /rag/corpus-grants/list`",
            "`POST /rag/corpus-grants/history`",
            "`POST /rag/corpus-grants/history/diff`",
            "`include_disabled`",
            "`actor_id`",
            "`updated_at_from`",
            "`updated_at_to`",
            "`previous_version`",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=jsonl",
            "HALLU_DEFENSE_CORPUS_GRANTS_PATH=var/rag/corpus-grants.jsonl",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=postgres",
            "HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@postgres:5432/hallu_defense",
            "HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME=rag_corpus_grants",
            "Production and staging reject the `memory` backend",
            "PsycopgCorpusGrantSqlConnection",
            "pool-backed adapter",
            "`expected_version`",
            "`409 Conflict`",
            "fails closed",
            "append-only",
            "PostgreSQL",
        },
        "docs/security/auth-rbac.md",
        errors,
    )
    _require(
        config_text,
        {
            'corpus_grants_backend: str = "memory"',
            'corpus_grants_path: Path = Path("var/rag/corpus-grants.jsonl")',
            'corpus_grants_table_name: str = "rag_corpus_grants"',
            "postgres_dsn: str | None = None",
            "HALLU_DEFENSE_POSTGRES_DSN",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND",
            "HALLU_DEFENSE_CORPUS_GRANTS_PATH",
            "HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME",
        },
        "API settings",
        errors,
    )
    _require(
        corpus_grants_service_text,
        {
            "CorpusGrantStorageError",
            "CorpusGrantPaginationError",
            "CorpusGrantVersionConflictError",
            "PostgresCorpusGrantStorage",
            "PsycopgCorpusGrantSqlConnection",
            "CorpusGrantSqlConnection",
            "history_for_tenant",
            "history_diffs_for_tenant",
            "CorpusGrantHistoryDiff",
            "previous_version",
            "request.actor_id",
            "request.updated_at_from",
            "request.updated_at_to",
            "Production and staging must configure a persistent corpus grants backend.",
            'if backend == "jsonl"',
            'backend in {"postgres", "postgresql"}',
            "storage_path=settings.corpus_grants_path",
            "table_name=settings.corpus_grants_table_name",
            "postgres_connection",
            "settings.postgres_dsn",
            "psycopg",
            "ORDER BY sequence_id ASC",
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
            "expected_version",
            "disabled_at is not None",
            'model_dump(mode="json")',
        },
        "corpus grants service",
        errors,
    )
    _require(
        corpus_grants_migration_text,
        {
            "CREATE TABLE IF NOT EXISTS rag_corpus_grants",
            "sequence_id BIGINT GENERATED ALWAYS AS IDENTITY",
            "PRIMARY KEY (tenant_id, corpus_id, version)",
            "payload JSONB NOT NULL",
            "CHECK ((disabled_by IS NULL) = (disabled_at IS NULL))",
            "idx_rag_corpus_grants_tenant_corpus_latest",
            "idx_rag_corpus_grants_tenant_updated_at",
            "idx_rag_corpus_grants_tenant_updated_by",
        },
        "Postgres corpus grants migration",
        errors,
    )
    if "DROP TABLE" in corpus_grants_migration_text.upper():
        errors.append("Postgres corpus grants migration must not contain DROP TABLE")
    _require(
        api_dependencies_text,
        {
            "create_corpus_grant_registry(settings)",
            '"POST /rag/corpus-grants/upsert": frozenset({RAG_WRITER_ROLE})',
            '"POST /rag/corpus-grants/disable": frozenset({RAG_WRITER_ROLE})',
            '"POST /rag/corpus-grants/list": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE})',
            '"POST /rag/corpus-grants/history": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE})',
            '"POST /rag/corpus-grants/history/diff": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE})',
        },
        "API dependencies",
        errors,
    )
    script = "scripts/ci/check_corpus_grants_config.py"
    if "corpus-grants-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the corpus-grants-config gate")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_corpus_grants_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_corpus_grants_config.py")
    if errors:
        raise CorpusGrantsConfigError("\n".join(errors))


def load_current_config() -> tuple[str, str, str, str, str, str, str, str, str]:
    return (
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        CORPUS_GRANTS_DOC.read_text(encoding="utf-8"),
        CONFIG.read_text(encoding="utf-8"),
        CORPUS_GRANTS_SERVICE.read_text(encoding="utf-8"),
        CORPUS_GRANTS_MIGRATION.read_text(encoding="utf-8"),
        API_DEPENDENCIES.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def main() -> None:
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
    print("Validated corpus grants configuration.")


if __name__ == "__main__":
    main()
