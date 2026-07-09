from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import Settings, load_settings  # noqa: E402
from hallu_defense.domain.models import (  # noqa: E402
    Authority,
    Claim,
    ClaimType,
    DocumentIngestionRequest,
    DocumentInput,
    RiskLevel,
)
from hallu_defense.services.ingestion_jobs import (  # noqa: E402
    IngestionJobStatus,
    IngestionJobType,
    PostgresIngestionJobQueue,
)
from hallu_defense.services.postgres import PooledPostgresProvider, build_postgres_provider  # noqa: E402
from hallu_defense.services.rag_index import create_rag_index_backend  # noqa: E402
from hallu_defense.services.retrieval import HybridRetriever  # noqa: E402
from hallu_defense.worker import build_worker_from_settings  # noqa: E402
from scripts.dev.apply_postgres_migrations import MIGRATIONS_DIR, apply_migrations  # noqa: E402

ENABLED_ENV = "HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED"
DEFAULT_TENANT_ID = "tenant-live-ingestion-worker"
DEFAULT_CORPUS_ID = "live_ingestion_worker"
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = env or os.environ
    if effective_env.get(ENABLED_ENV, "").strip().lower() != "true":
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live ingestion worker smoke",
        }
    settings = load_settings()
    sql_provider = build_postgres_provider(settings)
    apply_migrations(sql_provider, migrations_dir=MIGRATIONS_DIR)
    run_id = uuid.uuid4().hex[:12]
    return run_live_smoke(settings_provider=sql_provider, run_id=run_id)


def run_live_smoke(
    *,
    settings_provider: PooledPostgresProvider,
    run_id: str,
) -> dict[str, object]:
    settings = load_settings()
    table_name = _safe_table(settings.pgvector_table_name)
    tenant_id = os.environ.get("HALLU_DEFENSE_LIVE_INGESTION_WORKER_TENANT_ID", DEFAULT_TENANT_ID)
    corpus_id = os.environ.get("HALLU_DEFENSE_LIVE_INGESTION_WORKER_CORPUS_ID", DEFAULT_CORPUS_ID)
    queue = PostgresIngestionJobQueue(
        connection=settings_provider,
        max_attempts=settings.ingestion_worker_max_attempts,
        backoff_base_seconds=settings.ingestion_worker_backoff_base_seconds,
    )
    worker = build_worker_from_settings(settings)
    try:
        _cleanup(settings_provider, table_name=table_name, tenant_id=tenant_id, run_id=run_id)
        first_job = queue.enqueue(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            trace_id=f"tr_live_ingestion_worker_{run_id}_first",
            job_type=IngestionJobType.INGEST,
            payload=_ingest_payload(run_id, corpus_id, tenant_id),
        )
        claimed = queue.claim_batch(worker_id="abandoned-live-smoke-worker", batch_size=1)
        if [job.job_id for job in claimed] != [first_job.job_id]:
            raise RuntimeError("failed to simulate an abandoned running ingestion job")
        time.sleep(settings.ingestion_worker_lock_timeout_seconds + 0.05)
        worker.run_once()
        first_status = queue.get(job_id=first_job.job_id, tenant_id=tenant_id)
        if first_status is None or first_status.status is not IngestionJobStatus.SUCCEEDED:
            raise RuntimeError("abandoned ingestion job did not recover to succeeded")

        second_job = queue.enqueue(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            trace_id=f"tr_live_ingestion_worker_{run_id}_second",
            job_type=IngestionJobType.INGEST,
            payload=_ingest_payload(run_id, corpus_id, tenant_id),
        )
        worker.run_once()
        second_status = queue.get(job_id=second_job.job_id, tenant_id=tenant_id)
        if second_status is None or second_status.status is not IngestionJobStatus.SUCCEEDED:
            raise RuntimeError("repeat ingestion job did not succeed")

        chunk_count = _chunk_count(
            settings_provider,
            table_name=table_name,
            tenant_id=tenant_id,
            run_id=run_id,
        )
        if chunk_count != 1:
            raise RuntimeError(f"expected idempotent upsert to leave 1 chunk, found {chunk_count}")
        if not _retrieve_smoke_document(settings=settings, tenant_id=tenant_id, run_id=run_id):
            raise RuntimeError("worker-indexed document was not retrievable for the tenant")

        return {
            "status": "passed",
            "tenant_id": tenant_id,
            "corpus_id": corpus_id,
            "job_ids": [first_job.job_id, second_job.job_id],
            "terminal_status": IngestionJobStatus.SUCCEEDED.value,
            "chunk_count": chunk_count,
            "tenant_retrieval": True,
            "duplicates": False,
        }
    finally:
        _cleanup(settings_provider, table_name=table_name, tenant_id=tenant_id, run_id=run_id)


def _ingest_payload(run_id: str, corpus_id: str, tenant_id: str) -> dict[str, object]:
    request = DocumentIngestionRequest(
        corpus_id=corpus_id,
        documents=[
            DocumentInput(
                source_ref=f"live-ingestion-worker-{run_id}",
                content=f"Live ingestion worker smoke {run_id} document is recoverable.",
                authority=Authority.INTERNAL,
                metadata={
                    "smoke_kind": "live_ingestion_worker",
                    "smoke_run_id": run_id,
                    "owner_tenant_id": tenant_id,
                    "corpus_id": corpus_id,
                },
            )
        ],
    )
    return request.model_dump(mode="json")


def _retrieve_smoke_document(*, settings: Settings, tenant_id: str, run_id: str) -> bool:
    backend = create_rag_index_backend(settings)
    retriever = HybridRetriever(index_backend=backend)
    evidence, _claim_map = retriever.retrieve(
        [
            Claim(
                claim_id=f"clm_live_ingestion_worker_{run_id}",
                text=f"Live ingestion worker smoke {run_id} document is recoverable.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            )
        ],
        [],
        max_evidence_per_claim=1,
        tenant_id=tenant_id,
        context_refs=[f"live-ingestion-worker-{run_id}"],
        metadata_filter={"smoke_kind": "live_ingestion_worker", "smoke_run_id": run_id},
    )
    return bool(evidence)


def _chunk_count(
    provider: PooledPostgresProvider,
    *,
    table_name: str,
    tenant_id: str,
    run_id: str,
) -> int:
    rows = provider.fetch_all(
        f"SELECT count(*) AS chunk_count FROM {table_name} "
        "WHERE tenant_id = %s AND metadata @> %s::jsonb",
        (
            tenant_id,
            json.dumps(
                {"smoke_kind": "live_ingestion_worker", "smoke_run_id": run_id},
                sort_keys=True,
            ),
        ),
    )
    value = rows[0].get("chunk_count") if rows else 0
    return int(value) if isinstance(value, int) else 0


def _cleanup(
    provider: PooledPostgresProvider,
    *,
    table_name: str,
    tenant_id: str,
    run_id: str,
) -> None:
    provider.execute(
        f"DELETE FROM {table_name} WHERE tenant_id = %s AND metadata @> %s::jsonb",
        (
            tenant_id,
            json.dumps(
                {"smoke_kind": "live_ingestion_worker", "smoke_run_id": run_id},
                sort_keys=True,
            ),
        ),
    )


def _safe_table(table_name: str) -> str:
    if not SAFE_IDENTIFIER.fullmatch(table_name):
        raise ValueError("HALLU_DEFENSE_PGVECTOR_TABLE_NAME must be a safe SQL identifier")
    return table_name


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        result = run_from_env()
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
