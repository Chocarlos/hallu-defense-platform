from __future__ import annotations

import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.domain.models import (  # noqa: E402
    Authority,
    Claim,
    ClaimType,
    DocumentIngestionRequest,
    DocumentInput,
    RiskLevel,
)
from hallu_defense.services.ingestion import DocumentIngestionService  # noqa: E402
from hallu_defense.services.rag_index import (  # noqa: E402
    PgVectorConnection,
    PgVectorRagIndexBackend,
    PsycopgPgVectorConnection,
)
from hallu_defense.services.retrieval import HybridRetriever  # noqa: E402

ENABLED_ENV = "HALLU_DEFENSE_LIVE_PGVECTOR_RAG_SMOKE_ENABLED"
DSN_ENV = "HALLU_DEFENSE_POSTGRES_DSN"
TABLE_NAME_ENV = "HALLU_DEFENSE_PGVECTOR_TABLE_NAME"
TIMEOUT_ENV = "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS"

DEFAULT_DSN = "postgresql://hallu:hallu@localhost:5432/hallu_defense"
DEFAULT_TABLE_NAME = "rag_evidence_chunks"
SMOKE_KIND = "live_pgvector_rag_smoke"
SMOKE_TENANT_A = "tenant-live-pgvector-smoke-a"
SMOKE_TENANT_B = "tenant-live-pgvector-smoke-b"
SMOKE_TENANTS = (SMOKE_TENANT_A, SMOKE_TENANT_B)
EXPECTED_EMBEDDING_TYPE = "vector(16)"
SAFE_TABLE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class LivePgVectorRagSmokeConfig:
    dsn: str
    table_name: str
    timeout_seconds: float


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    connection: PgVectorConnection | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env or os.environ
    dsn = effective_env.get(DSN_ENV, DEFAULT_DSN).strip() or DEFAULT_DSN
    table_name = (
        effective_env.get(TABLE_NAME_ENV, DEFAULT_TABLE_NAME).strip() or DEFAULT_TABLE_NAME
    )

    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live pgvector RAG smoke",
            "dsn": _redact_dsn(dsn),
            "table_name": table_name,
            "backend": "pgvector",
            "indexed_count": 0,
            "tenant_isolation": False,
        }

    config = LivePgVectorRagSmokeConfig(
        dsn=dsn,
        table_name=validate_smoke_table_name(table_name),
        timeout_seconds=_parse_timeout(effective_env.get(TIMEOUT_ENV, "5")),
    )
    return run_live_smoke(config, connection=connection, run_id=run_id)


def run_live_smoke(
    config: LivePgVectorRagSmokeConfig,
    *,
    connection: PgVectorConnection | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    table_name = validate_smoke_table_name(config.table_name)
    active_connection = connection or PsycopgPgVectorConnection(dsn=config.dsn)
    should_close = connection is None and hasattr(active_connection, "close")
    smoke_run_id = run_id or uuid.uuid4().hex[:12]

    try:
        verify_pgvector_schema(connection=active_connection, table_name=table_name)
        cleanup_smoke_rows(
            connection=active_connection,
            table_name=table_name,
            run_id=smoke_run_id,
        )

        backend = PgVectorRagIndexBackend(table_name=table_name, connection=active_connection)
        retriever = HybridRetriever(index_backend=backend)
        ingestor = DocumentIngestionService(retriever)
        documents = _smoke_documents(smoke_run_id)

        tenant_a_response = ingestor.ingest(
            DocumentIngestionRequest(documents=[documents["tenant_a"]], corpus_id="live_smoke"),
            tenant_id=SMOKE_TENANT_A,
            trace_id=f"tr_live_pgvector_rag_smoke_{smoke_run_id}_a",
        )
        tenant_b_response = ingestor.ingest(
            DocumentIngestionRequest(documents=[documents["tenant_b"]], corpus_id="live_smoke"),
            tenant_id=SMOKE_TENANT_B,
            trace_id=f"tr_live_pgvector_rag_smoke_{smoke_run_id}_b",
        )
        _assert_same_generated_evidence_id(
            tenant_a_response.evidence_ids,
            tenant_b_response.evidence_ids,
        )

        tenant_isolation = _assert_tenant_isolation(
            retriever=retriever,
            smoke_run_id=smoke_run_id,
            shared_source_ref=documents["tenant_a"].source_ref,
        )
        indexed_count = tenant_a_response.indexed_count + tenant_b_response.indexed_count
        return {
            "status": "passed",
            "dsn": _redact_dsn(config.dsn),
            "table_name": table_name,
            "backend": tenant_a_response.backend,
            "indexed_count": indexed_count,
            "tenant_isolation": tenant_isolation,
        }
    finally:
        try:
            cleanup_smoke_rows(
                connection=active_connection,
                table_name=table_name,
                run_id=smoke_run_id,
            )
        finally:
            if should_close:
                close = getattr(active_connection, "close", None)
                if callable(close):
                    close()


def validate_smoke_table_name(table_name: str) -> str:
    normalized = table_name.strip()
    if not SAFE_TABLE_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"refusing unsafe pgvector smoke table name {table_name!r}; use a plain SQL "
            "identifier without separators, quoting, wildcards, or punctuation"
        )
    return normalized


def verify_pgvector_schema(*, connection: PgVectorConnection, table_name: str) -> None:
    safe_table_name = validate_smoke_table_name(table_name)
    extension_rows = connection.fetch_all(
        "SELECT extname FROM pg_extension WHERE extname = %s",
        ["vector"],
    )
    if not extension_rows:
        raise RuntimeError(
            "pgvector extension is missing; initialize the database with "
            "infra/rag/pgvector/001_rag_evidence_chunks.sql"
        )

    embedding_rows = connection.fetch_all(
        "SELECT format_type(attribute.atttypid, attribute.atttypmod) AS embedding_type "
        "FROM pg_attribute attribute "
        "JOIN pg_class class ON class.oid = attribute.attrelid "
        "JOIN pg_namespace namespace ON namespace.oid = class.relnamespace "
        "WHERE namespace.nspname = %s "
        "AND class.relname = %s "
        "AND attribute.attname = %s "
        "AND attribute.attnum > 0 "
        "AND NOT attribute.attisdropped",
        ["public", safe_table_name, "embedding"],
    )
    embedding_type = embedding_rows[0].get("embedding_type") if embedding_rows else None
    if embedding_type != EXPECTED_EMBEDDING_TYPE:
        raise RuntimeError(
            f"pgvector table {safe_table_name!r} must have embedding column "
            f"{EXPECTED_EMBEDDING_TYPE}; found {embedding_type!r}"
        )


def cleanup_smoke_rows(
    *,
    connection: PgVectorConnection,
    table_name: str,
    run_id: str,
) -> int:
    safe_table_name = validate_smoke_table_name(table_name)
    metadata_filter = json.dumps(
        {"smoke_kind": SMOKE_KIND, "smoke_run_id": run_id},
        sort_keys=True,
    )
    rows = connection.fetch_all(
        f"DELETE FROM {safe_table_name} "
        "WHERE tenant_id = ANY(%s) AND metadata @> %s::jsonb "
        "RETURNING tenant_id, evidence_id",
        [list(SMOKE_TENANTS), metadata_filter],
    )
    return len(rows)


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    connection: PgVectorConnection | None = None,
) -> int:
    del argv
    try:
        result = run_from_env(env, connection=connection)
    except Exception as exc:
        result = {
            "status": "failed",
            "error": str(exc),
            "backend": "pgvector",
            "tenant_isolation": False,
        }
        print(_json_result(result))
        return 1
    print(_json_result(result))
    return 0


def _enabled(value: str) -> bool:
    return value.strip().lower() == "true"


def _parse_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise ValueError(f"{TIMEOUT_ENV} must be a positive number") from exc
    if timeout <= 0:
        raise ValueError(f"{TIMEOUT_ENV} must be positive")
    return timeout


def _smoke_documents(run_id: str) -> dict[str, DocumentInput]:
    shared_source_ref = f"live-pgvector-smoke-{run_id}-shared-policy"
    return {
        "tenant_a": DocumentInput(
            source_ref=shared_source_ref,
            content=(
                f"Live pgvector RAG smoke {run_id} alpha policy belongs only to tenant A. "
                "The alpha entitlement is approved for tenant A."
            ),
            authority=Authority.INTERNAL,
            metadata={
                "smoke_kind": SMOKE_KIND,
                "smoke_run_id": run_id,
                "smoke_tenant": "a",
            },
        ),
        "tenant_b": DocumentInput(
            source_ref=shared_source_ref,
            content=(
                f"Live pgvector RAG smoke {run_id} beta policy belongs only to tenant B. "
                "The beta entitlement is approved for tenant B."
            ),
            authority=Authority.INTERNAL,
            metadata={
                "smoke_kind": SMOKE_KIND,
                "smoke_run_id": run_id,
                "smoke_tenant": "b",
            },
        ),
    }


def _assert_same_generated_evidence_id(
    tenant_a_evidence_ids: Sequence[str],
    tenant_b_evidence_ids: Sequence[str],
) -> None:
    if len(tenant_a_evidence_ids) != 1:
        raise AssertionError(f"tenant A smoke indexed unexpected evidence IDs: {tenant_a_evidence_ids}")
    if len(tenant_b_evidence_ids) != 1:
        raise AssertionError(f"tenant B smoke indexed unexpected evidence IDs: {tenant_b_evidence_ids}")
    if tenant_a_evidence_ids != tenant_b_evidence_ids:
        raise AssertionError(
            "tenant-scoped pgvector primary keys must allow the same public evidence ID "
            f"across tenants: {tenant_a_evidence_ids} != {tenant_b_evidence_ids}"
        )


def _assert_tenant_isolation(
    *,
    retriever: HybridRetriever,
    smoke_run_id: str,
    shared_source_ref: str,
) -> bool:
    tenant_a_own = _retrieve_evidence(
        retriever,
        tenant_id=SMOKE_TENANT_A,
        claim_id="clm_live_pgvector_smoke_a",
        query_text=f"alpha entitlement approved tenant A {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_b_own = _retrieve_evidence(
        retriever,
        tenant_id=SMOKE_TENANT_B,
        claim_id="clm_live_pgvector_smoke_b",
        query_text=f"beta entitlement approved tenant B {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_a_cross = _retrieve_evidence(
        retriever,
        tenant_id=SMOKE_TENANT_A,
        claim_id="clm_live_pgvector_smoke_cross_a",
        query_text=f"beta entitlement approved tenant B {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_b_cross = _retrieve_evidence(
        retriever,
        tenant_id=SMOKE_TENANT_B,
        claim_id="clm_live_pgvector_smoke_cross_b",
        query_text=f"alpha entitlement approved tenant A {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )

    tenant_isolation = (
        _has_content_marker(tenant_a_own, "alpha", SMOKE_TENANT_A)
        and _has_content_marker(tenant_b_own, "beta", SMOKE_TENANT_B)
        and not _has_content_marker(tenant_a_cross, "beta", SMOKE_TENANT_B)
        and not _has_content_marker(tenant_b_cross, "alpha", SMOKE_TENANT_A)
    )
    if not tenant_isolation:
        raise AssertionError(
            "pgvector RAG tenant isolation failed: "
            f"tenant_a_own={_evidence_debug(tenant_a_own)}, "
            f"tenant_b_own={_evidence_debug(tenant_b_own)}, "
            f"tenant_a_cross={_evidence_debug(tenant_a_cross)}, "
            f"tenant_b_cross={_evidence_debug(tenant_b_cross)}"
        )
    return True


def _retrieve_evidence(
    retriever: HybridRetriever,
    *,
    tenant_id: str,
    claim_id: str,
    query_text: str,
    smoke_run_id: str,
    source_ref: str,
) -> list[object]:
    evidence, _claim_map = retriever.retrieve(
        [
            Claim(
                claim_id=claim_id,
                text=query_text,
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            )
        ],
        [],
        max_evidence_per_claim=3,
        tenant_id=tenant_id,
        context_refs=[source_ref],
        metadata_filter={"smoke_kind": SMOKE_KIND, "smoke_run_id": smoke_run_id},
    )
    return list(evidence)


def _has_content_marker(evidence: Sequence[object], marker: str, tenant_id: str) -> bool:
    for item in evidence:
        content = getattr(item, "content", "")
        structured_content = getattr(item, "structured_content", {})
        metadata = structured_content.get("metadata") if isinstance(structured_content, Mapping) else {}
        if (
            isinstance(content, str)
            and marker in content
            and isinstance(metadata, Mapping)
            and metadata.get("owner_tenant_id") == tenant_id
        ):
            return True
    return False


def _evidence_debug(evidence: Sequence[object]) -> list[dict[str, object]]:
    debug: list[dict[str, object]] = []
    for item in evidence:
        structured_content = getattr(item, "structured_content", {})
        metadata = structured_content.get("metadata") if isinstance(structured_content, Mapping) else {}
        debug.append(
            {
                "source_ref": getattr(item, "source_ref", ""),
                "content": getattr(item, "content", ""),
                "metadata": dict(metadata) if isinstance(metadata, Mapping) else {},
            }
        )
    return debug


def _redact_dsn(dsn: str) -> str:
    masked = re.sub(r"(?i)(password=)([^\s]+)", r"\1***", dsn)
    masked = re.sub(r"://([^:/\s]+):([^@\s]+)@", r"://\1:***@", masked)
    try:
        parsed = urlsplit(masked)
    except ValueError:
        return masked
    if parsed.password is None:
        return masked
    username = parsed.username or ""
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = ""
    try:
        if parsed.port is not None:
            port = f":{parsed.port}"
    except ValueError:
        return masked
    credentials = f"{username}:***@" if username else ""
    return urlunsplit(
        (
            parsed.scheme,
            f"{credentials}{hostname}{port}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
