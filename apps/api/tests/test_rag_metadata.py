from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from hallu_defense.domain.models import (
    Authority,
    Claim,
    DocumentIngestionRequest,
    DocumentInput,
    Evidence,
    EvidenceRetrievalRequest,
    Freshness,
    StalenessClass,
)
from hallu_defense.services.ingestion import DocumentIngestionService
from hallu_defense.services.rag_index import RagChunk, RagIndexWriteResult, RagSearchRequest
from hallu_defense.services.retrieval import HybridRetriever
from hallu_defense.domain.rag_metadata import (
    MAX_METADATA_FILTER_KEY_LENGTH,
    MAX_METADATA_FILTERS,
    MAX_METADATA_TOP_LEVEL_KEYS,
    MAX_SIGNED_INT64,
    RagMetadataValidationError,
    canonical_json,
    metadata_filter_token,
    metadata_filter_tokens,
    metadata_values_equal,
    reject_reserved_ingestion_metadata,
    validate_metadata,
    validate_metadata_filter,
)


def test_canonical_json_is_stable_and_normalizes_equivalent_numbers() -> None:
    assert canonical_json({"z": 1.0, "a": {"b": -0.0}}) == '{"a":{"b":0},"z":1}'
    assert metadata_values_equal({"b": 1.0, "a": True}, {"a": True, "b": 1})
    assert not metadata_values_equal(True, 1)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_metadata_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(RagMetadataValidationError, match="finite"):
        validate_metadata({"value": value})


@pytest.mark.parametrize("value", [MAX_SIGNED_INT64 + 1, -(2**63) - 1])
def test_metadata_rejects_integers_outside_signed_64_bit(value: int) -> None:
    with pytest.raises(RagMetadataValidationError, match="signed 64-bit"):
        validate_metadata({"value": value})


def test_metadata_rejects_non_json_values() -> None:
    with pytest.raises(RagMetadataValidationError, match="non-JSON"):
        validate_metadata({"value": {"not", "json"}})


@pytest.mark.parametrize(
    "metadata",
    [
        {"bad\x00key": "value"},
        {"bad\ud800key": "value"},
        {"key": "bad\x00value"},
        {"key": "bad\ud800value"},
    ],
)
def test_metadata_rejects_postgres_incompatible_unicode_before_write(
    metadata: dict[str, object],
) -> None:
    backend = _CapturingBackend()
    with pytest.raises(ValidationError, match="NUL or surrogate"):
        request = DocumentIngestionRequest(
            corpus_id="hr",
            documents=[
                DocumentInput(
                    source_ref="policy",
                    content="Policy text",
                    authority=Authority.INTERNAL,
                    metadata=metadata,
                )
            ],
        )
        DocumentIngestionService(HybridRetriever(index_backend=backend)).ingest(
            request,
            tenant_id="tenant-a",
            trace_id="trace-invalid-unicode",
        )
    assert backend.batches == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("source_ref", ""),
        ("source_ref", "bad\x00source"),
        ("source_ref", "bad\ud800source"),
        ("content", "bad\x00content"),
        ("content", "bad\ud800content"),
    ],
)
def test_document_rejects_unpersistable_text_before_write(
    field_name: str,
    value: str,
) -> None:
    payload = {
        "source_ref": "policy",
        "content": "Policy text",
        "authority": Authority.INTERNAL,
        field_name: value,
    }

    with pytest.raises(ValidationError):
        DocumentInput(**payload)


def test_metadata_enforces_top_level_key_limit() -> None:
    accepted = {f"key_{index}": index for index in range(MAX_METADATA_TOP_LEVEL_KEYS)}
    assert validate_metadata(accepted) == accepted

    rejected = {**accepted, "overflow": 1}
    with pytest.raises(RagMetadataValidationError, match="top-level keys"):
        validate_metadata(rejected)


def test_metadata_enforces_depth_and_node_limits() -> None:
    assert validate_metadata({"a": {"b": {"c": 1}}})
    with pytest.raises(RagMetadataValidationError, match="depth"):
        validate_metadata({"a": {"b": {"c": {"d": 1}}}})

    assert validate_metadata({"items": [0] * 254})
    with pytest.raises(RagMetadataValidationError, match="JSON nodes"):
        validate_metadata({"items": [0] * 255})


def test_metadata_enforces_canonical_utf8_byte_limit() -> None:
    assert validate_metadata({"payload": "é" * 8_000})
    with pytest.raises(RagMetadataValidationError, match="canonical UTF-8 bytes"):
        validate_metadata({"payload": "é" * 8_200})


def test_metadata_filter_accepts_arbitrary_exact_json_values() -> None:
    value = {"roles": ["writer", "reviewer"], "enabled": True, "weight": 1.0}
    normalized = validate_metadata_filter({"access_policy": value})

    assert normalized == {
        "access_policy": {
            "enabled": True,
            "roles": ["writer", "reviewer"],
            "weight": 1,
        }
    }


def test_metadata_filter_enforces_count_key_and_value_limits() -> None:
    accepted = {f"key_{index}": index for index in range(MAX_METADATA_FILTERS)}
    assert validate_metadata_filter(accepted) == accepted
    with pytest.raises(RagMetadataValidationError, match="entries"):
        validate_metadata_filter({**accepted, "overflow": True})

    assert validate_metadata_filter({"a" * MAX_METADATA_FILTER_KEY_LENGTH: "value"})
    for invalid_key in (
        "a" * (MAX_METADATA_FILTER_KEY_LENGTH + 1),
        "nested.key",
        "hyphen-key",
        "1starts_with_number",
    ):
        with pytest.raises(RagMetadataValidationError, match="metadata_filter keys"):
            validate_metadata_filter({invalid_key: "value"})

    assert validate_metadata_filter({"value": "é" * 255})
    with pytest.raises(RagMetadataValidationError, match="value.*canonical UTF-8 bytes"):
        validate_metadata_filter({"value": "é" * 256})


def test_metadata_filter_enforces_total_canonical_size() -> None:
    with pytest.raises(RagMetadataValidationError, match="metadata_filter exceeds"):
        validate_metadata_filter({f"key_{index}": "x" * 500 for index in range(5)})


def test_metadata_filter_tokens_are_order_independent_and_type_exact() -> None:
    left = metadata_filter_token("policy", {"b": 1.0, "a": [True, None]})
    right = metadata_filter_token("policy", {"a": [True, None], "b": 1})

    assert left == right
    assert metadata_filter_token("policy", True) != metadata_filter_token("policy", 1)
    assert metadata_filter_token("policy", ["a", "b"]) != metadata_filter_token(
        "policy", ["b", "a"]
    )
    assert not metadata_values_equal(["a", "b"], ["a"])
    assert not metadata_values_equal({"a": 1, "b": 2}, {"a": 1})


def test_ingestion_tokens_skip_unfilterable_opaque_keys_and_large_values() -> None:
    tokens = metadata_filter_tokens(
        {
            "department": "hr",
            "opaque.key": "preserved but not filterable",
            "large_value": "x" * 600,
        }
    )

    assert tokens == [metadata_filter_token("department", "hr")]


@pytest.mark.parametrize(
    "metadata",
    [
        {"tenant_id": "tenant-a"},
        {"owner_tenant_id": "tenant-a"},
        {"corpus_id": "hr"},
        {"document_revision": "sha256:abc"},
        {"structural_section_path": "Policies"},
    ],
)
def test_ingestion_rejects_server_managed_metadata_keys(
    metadata: dict[str, object],
) -> None:
    with pytest.raises(RagMetadataValidationError, match="server-managed"):
        reject_reserved_ingestion_metadata(metadata)


def test_document_and_retrieval_models_apply_metadata_limits() -> None:
    with pytest.raises(ValidationError, match="authority"):
        DocumentInput(source_ref="policy", content="Policy text")  # type: ignore[call-arg]

    with pytest.raises(ValidationError, match="finite"):
        DocumentInput(
            source_ref="policy",
            content="Policy text",
            authority=Authority.INTERNAL,
            metadata={"score": math.nan},
        )

    with pytest.raises(ValidationError, match="metadata_filter keys"):
        EvidenceRetrievalRequest(
            claims=[Claim(claim_id="clm_1", text="Policy claim")],
            metadata_filter={"unsafe.key": "value"},
        )


@pytest.mark.parametrize("field_name", ["source_ref", "content"])
@pytest.mark.parametrize("invalid_suffix", ["\x00forged", "\ud800forged"])
def test_persistent_document_and_evidence_text_rejects_unsafe_unicode(
    field_name: str,
    invalid_suffix: str,
) -> None:
    document_payload: dict[str, object] = {
        "source_ref": "policy",
        "content": "Policy text",
        "authority": Authority.INTERNAL,
    }
    document_payload[field_name] = f"policy{invalid_suffix}"
    with pytest.raises(ValidationError, match="NUL|surrogate|unicode"):
        DocumentInput.model_validate(document_payload)

    evidence_payload: dict[str, object] = {
        "evidence_id": "ev_1",
        "kind": "document_chunk",
        "source_ref": "policy",
        "content": "Policy text",
        "structured_content": {},
        "authority": Authority.INTERNAL,
        "freshness": {
            "retrieved_at": "2026-01-01T00:00:00Z",
            "staleness_class": "fresh",
        },
    }
    evidence_payload[field_name] = f"policy{invalid_suffix}"
    with pytest.raises(ValidationError, match="NUL|surrogate|unicode"):
        Evidence.model_validate(evidence_payload)


@pytest.mark.parametrize(
    "metadata",
    [
        {"published_at": "not-a-date"},
        {"published_at": "2026-07-10T12:00:00"},
        {"published_at": 123},
        {"staleness_class": "recent"},
        {"staleness_class": None},
    ],
)
def test_document_freshness_metadata_fails_closed(metadata: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="published_at|staleness_class"):
        DocumentInput(
            source_ref="policy",
            content="Policy text",
            authority=Authority.INTERNAL,
            metadata=metadata,
        )


def test_absent_freshness_metadata_is_unknown_and_chunks_share_retrieval_time() -> None:
    backend = _CapturingBackend()
    retriever = HybridRetriever(index_backend=backend)

    retriever.index_documents(
        tenant_id="tenant-a",
        documents=[
            DocumentInput(
                source_ref="policy",
                content="First paragraph.\n\nSecond paragraph.",
                authority=Authority.INTERNAL,
            )
        ],
    )

    assert len(backend.batches) == 1
    assert [chunk.freshness.staleness_class for chunk in backend.batches[0]] == [
        StalenessClass.UNKNOWN,
        StalenessClass.UNKNOWN,
    ]
    assert len({chunk.freshness.retrieved_at for chunk in backend.batches[0]}) == 1


@pytest.mark.parametrize(
    "missing_field",
    ["source_ref", "structured_content", "authority", "freshness"],
)
def test_evidence_contract_fields_are_required(missing_field: str) -> None:
    payload: dict[str, object] = {
        "evidence_id": "ev_1",
        "kind": "document_chunk",
        "source_ref": "policy",
        "content": "Policy text",
        "structured_content": {},
        "authority": "internal",
        "freshness": {
            "retrieved_at": "2026-01-01T00:00:00Z",
            "staleness_class": "fresh",
        },
    }
    del payload[missing_field]

    with pytest.raises(ValidationError, match=missing_field):
        Evidence.model_validate(payload)


def test_depth_limit_metadata_ingests_and_produces_stable_revision() -> None:
    backend = _CapturingBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))
    request = DocumentIngestionRequest(
        corpus_id="hr",
        documents=[
            DocumentInput(
                source_ref="policy",
                content="A bounded metadata document.",
                authority=Authority.INTERNAL,
                metadata={"level_1": {"level_2": {"level_3": "value"}}},
            )
        ],
    )

    first = ingestor.ingest(
        request,
        tenant_id="tenant-a",
        trace_id="trace-1",
    )
    second = ingestor.ingest(
        request,
        tenant_id="tenant-a",
        trace_id="trace-2",
    )

    assert first.indexed_count == second.indexed_count == 1
    revisions = [batch[0].metadata["document_revision"] for batch in backend.batches]
    assert revisions[0] == revisions[1]
    assert isinstance(revisions[0], str) and revisions[0].startswith("sha256:")


@pytest.mark.parametrize("field_name", ["retrieved_at", "published_at"])
def test_freshness_rejects_naive_datetimes(field_name: str) -> None:
    with pytest.raises(ValidationError, match="timezone offset"):
        Freshness(**{field_name: datetime(2026, 7, 10, 12, 0)})


def test_freshness_accepts_utc_and_explicit_offsets() -> None:
    freshness = Freshness(
        retrieved_at=datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc),
        published_at=datetime(
            2026,
            7,
            10,
            7,
            0,
            tzinfo=timezone(timedelta(hours=-5)),
        ),
        staleness_class=StalenessClass.FRESH,
    )

    assert freshness.retrieved_at.utcoffset() == timedelta(0)
    assert freshness.published_at is not None
    assert freshness.published_at.utcoffset() == timedelta(hours=-5)


class _CapturingBackend:
    backend_name = "capture"

    def __init__(self) -> None:
        self.batches: list[list[RagChunk]] = []

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        self.batches.append(list(chunks))
        return RagIndexWriteResult(
            indexed_count=len(chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        del search_request
        return []
