from __future__ import annotations

import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

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
    OpenSearchRagIndexBackend,
    OpenSearchTransport,
    RagIndexTransportError,
    UrlLibOpenSearchTransport,
)
from hallu_defense.services.retrieval import HybridRetriever  # noqa: E402
from scripts.dev.bootstrap_opensearch_template import (  # noqa: E402
    DEFAULT_TEMPLATE_NAME,
    DEFAULT_TEMPLATE_PATH,
    bootstrap_opensearch_template,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED"
ENDPOINT_ENV = "HALLU_DEFENSE_OPENSEARCH_ENDPOINT"
TIMEOUT_ENV = "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS"
SMOKE_INDEX_ENV = "HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_INDEX_NAME"

DEFAULT_ENDPOINT = "http://localhost:9200"
DEFAULT_SMOKE_INDEX_NAME = "hallu_evidence_live_smoke"
SMOKE_INDEX_PREFIX = "hallu_evidence"
SAFE_INDEX_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class LiveOpenSearchRagSmokeConfig:
    endpoint: str
    index_name: str
    timeout_seconds: float


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    transport: OpenSearchTransport | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env or os.environ
    endpoint = effective_env.get(ENDPOINT_ENV, DEFAULT_ENDPOINT).strip() or DEFAULT_ENDPOINT
    index_name = (
        effective_env.get(SMOKE_INDEX_ENV, DEFAULT_SMOKE_INDEX_NAME).strip()
        or DEFAULT_SMOKE_INDEX_NAME
    )

    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live OpenSearch RAG smoke",
            "endpoint": endpoint,
            "index_name": index_name,
            "backend": "opensearch",
            "indexed_count": 0,
            "tenant_isolation": False,
        }

    config = LiveOpenSearchRagSmokeConfig(
        endpoint=endpoint,
        index_name=validate_smoke_index_name(index_name),
        timeout_seconds=_parse_timeout(effective_env.get(TIMEOUT_ENV, "5")),
    )
    return run_live_smoke(config, transport=transport, run_id=run_id)


def run_live_smoke(
    config: LiveOpenSearchRagSmokeConfig,
    *,
    transport: OpenSearchTransport | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    index_name = validate_smoke_index_name(config.index_name)
    active_transport = transport or UrlLibOpenSearchTransport(config.endpoint)

    try:
        cleanup_smoke_index(
            transport=active_transport,
            index_name=index_name,
            timeout_seconds=config.timeout_seconds,
        )
        bootstrap_opensearch_template(
            endpoint=config.endpoint,
            index_name=index_name,
            template_name=DEFAULT_TEMPLATE_NAME,
            template_path=DEFAULT_TEMPLATE_PATH,
            timeout_seconds=config.timeout_seconds,
            transport=active_transport,
        )
        reset_smoke_index(
            transport=active_transport,
            index_name=index_name,
            timeout_seconds=config.timeout_seconds,
        )

        backend = OpenSearchRagIndexBackend(
            endpoint=config.endpoint,
            index_name=index_name,
            timeout_seconds=config.timeout_seconds,
            transport=active_transport,
        )
        retriever = HybridRetriever(index_backend=backend)
        ingestor = DocumentIngestionService(retriever)
        smoke_run_id = run_id or uuid.uuid4().hex[:12]
        documents = _smoke_documents(smoke_run_id)

        tenant_a_response = ingestor.ingest(
            DocumentIngestionRequest(documents=[documents["tenant_a"]], corpus_id="live_smoke"),
            tenant_id="tenant-live-smoke-a",
            trace_id=f"tr_live_opensearch_rag_smoke_{smoke_run_id}_a",
        )
        tenant_b_response = ingestor.ingest(
            DocumentIngestionRequest(documents=[documents["tenant_b"]], corpus_id="live_smoke"),
            tenant_id="tenant-live-smoke-b",
            trace_id=f"tr_live_opensearch_rag_smoke_{smoke_run_id}_b",
        )
        _assert_same_generated_evidence_id(
            tenant_a_response.evidence_ids,
            tenant_b_response.evidence_ids,
        )
        refresh_smoke_index(
            transport=active_transport,
            index_name=index_name,
            timeout_seconds=config.timeout_seconds,
        )

        tenant_isolation = _assert_tenant_isolation(
            retriever=retriever,
            smoke_run_id=smoke_run_id,
            shared_source_ref=documents["tenant_a"].source_ref,
        )
        indexed_count = tenant_a_response.indexed_count + tenant_b_response.indexed_count
        return {
            "status": "passed",
            "endpoint": config.endpoint,
            "index_name": index_name,
            "backend": tenant_a_response.backend,
            "indexed_count": indexed_count,
            "tenant_isolation": tenant_isolation,
        }
    finally:
        cleanup_smoke_index(
            transport=active_transport,
            index_name=index_name,
            timeout_seconds=config.timeout_seconds,
        )


def validate_smoke_index_name(index_name: str) -> str:
    normalized = index_name.strip()
    if not SAFE_INDEX_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"refusing unsafe OpenSearch smoke index name {index_name!r}; use a lowercase "
            "identifier without wildcards, separators, or punctuation"
        )
    if not normalized.startswith(SMOKE_INDEX_PREFIX):
        raise ValueError(
            f"refusing OpenSearch smoke index name {index_name!r}; it must start with "
            f"{SMOKE_INDEX_PREFIX!r} so the existing template applies"
        )
    if "smoke" not in normalized.split("_"):
        raise ValueError(
            f"refusing non-smoke OpenSearch index name {index_name!r}; set {SMOKE_INDEX_ENV} "
            "to a dedicated hallu_evidence_*_smoke index"
        )
    return normalized


def reset_smoke_index(
    *,
    transport: OpenSearchTransport,
    index_name: str,
    timeout_seconds: float,
) -> None:
    safe_index_name = validate_smoke_index_name(index_name)
    delete_response: Mapping[str, object]
    try:
        delete_response = transport.request_json(
            "DELETE",
            f"/{safe_index_name}?ignore_unavailable=true",
            {},
            timeout_seconds=timeout_seconds,
        )
    except RagIndexTransportError as exc:
        if "404" not in str(exc):
            raise
        delete_response = {}
    if delete_response.get("acknowledged") is False:
        raise RagIndexTransportError(f"OpenSearch did not acknowledge deleting {safe_index_name}")

    create_response = transport.request_json(
        "PUT",
        f"/{safe_index_name}",
        {},
        timeout_seconds=timeout_seconds,
    )
    if create_response.get("acknowledged") is not True:
        raise RagIndexTransportError(f"OpenSearch did not acknowledge creating {safe_index_name}")


def cleanup_smoke_index(
    *,
    transport: OpenSearchTransport,
    index_name: str,
    timeout_seconds: float,
) -> None:
    safe_index_name = validate_smoke_index_name(index_name)
    try:
        response = transport.request_json(
            "DELETE",
            f"/{safe_index_name}?ignore_unavailable=true",
            {},
            timeout_seconds=timeout_seconds,
        )
    except RagIndexTransportError as exc:
        if "status 404" in str(exc):
            return
        raise
    if response.get("acknowledged") is False:
        raise RagIndexTransportError(f"OpenSearch did not acknowledge deleting {safe_index_name}")


def refresh_smoke_index(
    *,
    transport: OpenSearchTransport,
    index_name: str,
    timeout_seconds: float,
) -> None:
    safe_index_name = validate_smoke_index_name(index_name)
    transport.request_json(
        "POST",
        f"/{safe_index_name}/_refresh",
        {},
        timeout_seconds=timeout_seconds,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: OpenSearchTransport | None = None,
) -> int:
    del argv
    try:
        result = run_from_env(env, transport=transport)
    except Exception as exc:
        result = {
            "status": "failed",
            "error": str(exc),
            "backend": "opensearch",
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
    shared_source_ref = f"live-smoke-{run_id}-shared-policy"
    return {
        "tenant_a": DocumentInput(
            source_ref=shared_source_ref,
            content=(
                f"Live OpenSearch RAG smoke {run_id} alpha policy belongs only to tenant A. "
                "The alpha entitlement is approved for tenant A."
            ),
            authority=Authority.INTERNAL,
            metadata={"smoke_run_id": run_id, "smoke_tenant": "a"},
        ),
        "tenant_b": DocumentInput(
            source_ref=shared_source_ref,
            content=(
                f"Live OpenSearch RAG smoke {run_id} beta policy belongs only to tenant B. "
                "The beta entitlement is approved for tenant B."
            ),
            authority=Authority.INTERNAL,
            metadata={"smoke_run_id": run_id, "smoke_tenant": "b"},
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
            "tenant-scoped OpenSearch document IDs must allow the same public evidence ID "
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
        tenant_id="tenant-live-smoke-a",
        claim_id="clm_live_smoke_a",
        query_text=f"alpha entitlement approved tenant A {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_b_own = _retrieve_evidence(
        retriever,
        tenant_id="tenant-live-smoke-b",
        claim_id="clm_live_smoke_b",
        query_text=f"beta entitlement approved tenant B {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_a_cross = _retrieve_evidence(
        retriever,
        tenant_id="tenant-live-smoke-a",
        claim_id="clm_live_smoke_cross_a",
        query_text=f"beta entitlement approved tenant B {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )
    tenant_b_cross = _retrieve_evidence(
        retriever,
        tenant_id="tenant-live-smoke-b",
        claim_id="clm_live_smoke_cross_b",
        query_text=f"alpha entitlement approved tenant A {smoke_run_id}",
        smoke_run_id=smoke_run_id,
        source_ref=shared_source_ref,
    )

    tenant_isolation = (
        _has_content_marker(tenant_a_own, "alpha", "tenant-live-smoke-a")
        and _has_content_marker(tenant_b_own, "beta", "tenant-live-smoke-b")
        and not _has_content_marker(tenant_a_cross, "beta", "tenant-live-smoke-b")
        and not _has_content_marker(tenant_b_cross, "alpha", "tenant-live-smoke-a")
    )
    if not tenant_isolation:
        raise AssertionError(
            "OpenSearch RAG tenant isolation failed: "
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
        metadata_filter={"smoke_run_id": smoke_run_id},
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


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
