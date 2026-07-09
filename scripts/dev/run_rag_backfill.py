"""Enqueue tenant-scoped RAG corpus reindex jobs."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import load_settings  # noqa: E402
from hallu_defense.services.ingestion_jobs import (  # noqa: E402
    IngestionJobType,
    PostgresIngestionJobQueue,
)
from hallu_defense.services.postgres import build_postgres_provider  # noqa: E402
from hallu_defense.worker import build_worker_from_settings  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enqueue an idempotent tenant/corpus RAG reindex job."
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--corpus-id", required=True)
    parser.add_argument("--trace-id")
    parser.add_argument("--page-size", type=int)
    parser.add_argument(
        "--run-worker-once",
        action="store_true",
        help="Run one inline ingestion-worker pass after enqueueing.",
    )
    args = parser.parse_args(argv)

    settings = load_settings()
    sql_provider = build_postgres_provider(settings)
    queue = PostgresIngestionJobQueue(
        connection=sql_provider,
        max_attempts=settings.ingestion_worker_max_attempts,
        backoff_base_seconds=settings.ingestion_worker_backoff_base_seconds,
    )
    page_size = args.page_size or settings.ingestion_backfill_page_size
    if page_size <= 0:
        raise SystemExit("--page-size must be positive")
    trace_id = args.trace_id or f"tr_rag_backfill_{uuid.uuid4().hex[:16]}"
    job = queue.enqueue(
        tenant_id=args.tenant_id,
        corpus_id=args.corpus_id,
        trace_id=trace_id,
        job_type=IngestionJobType.REINDEX_CORPUS,
        payload={"corpus_id": args.corpus_id, "page_size": page_size},
    )
    worker_processed = 0
    if args.run_worker_once:
        worker_processed = build_worker_from_settings(settings).run_once()
    print(
        json.dumps(
            {
                "status": "enqueued",
                "tenant_id": args.tenant_id,
                "corpus_id": args.corpus_id,
                "job_id": job.job_id,
                "job_status": job.status.value,
                "trace_id": trace_id,
                "worker_processed": worker_processed,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
