from __future__ import annotations

import copy
import json
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from scripts.dev import run_rag_backfill as backfill_cli
from hallu_defense.domain.models import Authority, Freshness, StalenessClass
from hallu_defense.services.postgres import RecordingSqlProvider
from hallu_defense.services.rag_backfill import (
    PgVectorRagBackfillSource,
    RagBackfillError,
    RagCorpusReindexer,
)
from hallu_defense.services.rag_index import (
    DeterministicHashEmbedder,
    HybridRagIndexBackend,
    PgVectorRagIndexBackend,
    RagChunk,
    RagIndexConfigurationError,
    RagIndexWriteResult,
)

TEST_RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_pgvector_backfill_source_reads_tenant_corpus_with_keyset_cursor() -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[_row(evidence_id="ev_1")])
    source = PgVectorRagBackfillSource(table_name="rag_evidence_chunks", connection=provider)

    pages = list(
        source.iter_corpus_chunk_pages(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=50,
        )
    )

    assert len(pages) == 1
    chunk = pages[0][0]
    assert chunk.tenant_id == "tenant-a"
    assert chunk.evidence_id == "ev_1"
    assert chunk.metadata == {"corpus_id": "hr", "department": "hr"}
    statement = provider.calls[0][1]
    parameters = provider.calls[0][2]
    assert "metadata @> %s::jsonb" in statement
    assert "evidence_id > %s" in statement
    assert "ORDER BY evidence_id ASC" in statement
    assert "OFFSET" not in statement
    assert parameters == ("tenant-a", '{"corpus_id": "hr"}', "", 50)


def test_pgvector_backfill_streams_multiple_keyset_pages() -> None:
    provider = MutableKeysetSqlProvider(
        [_row(evidence_id=f"ev_{index:03d}") for index in range(1, 6)]
    )
    source = PgVectorRagBackfillSource(table_name="rag_evidence_chunks", connection=provider)

    pages = list(
        source.iter_corpus_chunk_pages(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=2,
        )
    )

    assert [[chunk.evidence_id for chunk in page] for page in pages] == [
        ["ev_001", "ev_002"],
        ["ev_003", "ev_004"],
        ["ev_005"],
    ]
    assert [call[2][2] for call in provider.calls] == ["", "ev_002", "ev_004"]
    assert all("OFFSET" not in call[1] for call in provider.calls)


def test_keyset_backfill_does_not_skip_rows_after_concurrent_mutation() -> None:
    def mutate(rows: list[dict[str, object]]) -> None:
        rows[:] = [row for row in rows if row["evidence_id"] != "ev_001"]
        rows.append(_row(evidence_id="ev_000", content="Inserted before the cursor."))
        for row in rows:
            if row["evidence_id"] == "ev_004":
                row["content"] = "Updated while the backfill was running."

    provider = MutableKeysetSqlProvider(
        [_row(evidence_id=f"ev_{index:03d}") for index in range(1, 6)],
        mutate_after_first=mutate,
    )
    source = PgVectorRagBackfillSource(table_name="rag_evidence_chunks", connection=provider)

    chunks = [
        chunk
        for page in source.iter_corpus_chunk_pages(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=2,
        )
        for chunk in page
    ]

    assert [chunk.evidence_id for chunk in chunks] == [
        "ev_001",
        "ev_002",
        "ev_003",
        "ev_004",
        "ev_005",
    ]
    assert chunks[3].content == "Updated while the backfill was running."
    assert "ev_000" not in {chunk.evidence_id for chunk in chunks}


def test_pgvector_backfill_source_rejects_cross_tenant_rows() -> None:
    source = PgVectorRagBackfillSource(
        table_name="rag_evidence_chunks",
        connection=RecordingSqlProvider(
            fetch_all_rows=[_row(tenant_id="tenant-b", evidence_id="ev_1")]
        ),
    )

    with pytest.raises(RagBackfillError, match="another tenant"):
        list(
            source.iter_corpus_chunk_pages(
                tenant_id="tenant-a",
                corpus_id="hr",
                page_size=50,
            )
        )


def test_reindexer_rerun_reuses_stable_ids_without_accumulating_result_ids() -> None:
    source = RecordingBackfillSource(pages=[[_rag_chunk(evidence_id="ev_stable")]])
    target = RecordingRagIndexBackend()
    reindexer = RagCorpusReindexer(source=source, target=target)

    first = reindexer.reindex_corpus(tenant_id="tenant-a", corpus_id="hr", page_size=10)
    second = reindexer.reindex_corpus(tenant_id="tenant-a", corpus_id="hr", page_size=10)

    assert first.indexed_count == second.indexed_count == 1
    assert first.page_count == second.page_count == 1
    assert not hasattr(first, "evidence_ids")
    assert [chunk.evidence_id for page in target.pages for chunk in page] == [
        "ev_stable",
        "ev_stable",
    ]


def test_reindexer_keeps_memory_bounded_to_one_page() -> None:
    source = GeneratedBackfillSource(page_count=250, page_size=4)
    target = CountingRagIndexBackend()

    result = RagCorpusReindexer(source=source, target=target).reindex_corpus(
        tenant_id="tenant-a",
        corpus_id="hr",
        page_size=4,
    )

    assert result.indexed_count == 1_000
    assert result.page_count == 250
    assert target.max_batch_size == 4
    assert target.indexed_count == 1_000
    assert not hasattr(result, "evidence_ids")


def test_reindexer_rejects_same_pgvector_source_and_target() -> None:
    source_connection = RecordingSqlProvider(fetch_all_rows=[_row(evidence_id="ev_1")])
    target_connection = StatefulPgVectorConnection()
    source = PgVectorRagBackfillSource(
        table_name="rag_evidence_chunks",
        connection=source_connection,
    )
    target = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=target_connection,
    )

    with pytest.raises(RagBackfillError, match="same pgvector storage"):
        RagCorpusReindexer(source=source, target=target).reindex_corpus(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=10,
        )

    assert source_connection.calls == []
    assert target_connection.transaction_calls == []


def test_reindexer_rejects_unknown_target_identity_before_source_read() -> None:
    source = RecordingBackfillSource(pages=[[_rag_chunk(evidence_id="ev_001")]])
    target = UnknownIdentityRagIndexBackend()

    with pytest.raises(RagBackfillError, match="explicit source and target"):
        RagCorpusReindexer(source=source, target=target).reindex_corpus(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=10,
        )

    assert source.calls == []
    assert target.index_calls == 0


def test_reindexer_rejects_non_page_safe_target_before_source_read() -> None:
    source_connection = RecordingSqlProvider(fetch_all_rows=[_row(evidence_id="ev_1")])
    target_connection = StatefulPgVectorConnection()
    source = PgVectorRagBackfillSource(
        table_name="rag_evidence_chunks",
        connection=source_connection,
    )
    target = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks_next",
        connection=target_connection,
    )

    with pytest.raises(RagBackfillError, match="does not declare page-safe writes"):
        RagCorpusReindexer(source=source, target=target).reindex_corpus(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=1,
        )

    assert source_connection.calls == []
    assert target_connection.transaction_calls == []


def test_reindexer_rejects_hybrid_target_overlapping_source_before_io() -> None:
    source_connection = RecordingSqlProvider(fetch_all_rows=[_row(evidence_id="ev_1")])
    source = PgVectorRagBackfillSource(
        table_name="rag_evidence_chunks",
        connection=source_connection,
    )
    opensearch = IdentityOnlyExactBackend(
        backend_name="opensearch",
        identity=("opensearch", "hallu_evidence"),
    )
    pgvector = IdentityOnlyExactBackend(
        backend_name="pgvector",
        identity=("pgvector", "rag_evidence_chunks"),
    )
    target = HybridRagIndexBackend(
        opensearch=opensearch,  # type: ignore[arg-type]
        pgvector=pgvector,  # type: ignore[arg-type]
        revision_locks=SimpleNamespace(),  # type: ignore[arg-type]
        tenant_write_fence=SimpleNamespace(),  # type: ignore[arg-type]
    )

    with pytest.raises(RagBackfillError, match="same pgvector storage"):
        RagCorpusReindexer(source=source, target=target).reindex_corpus(
            tenant_id="tenant-a",
            corpus_id="hr",
            page_size=1,
        )

    assert source_connection.calls == []
    assert opensearch.index_calls == 0
    assert pgvector.index_calls == 0


def test_backfill_cli_rejects_pgvector_noop_before_enqueue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        backfill_cli,
        "load_settings",
        lambda: SimpleNamespace(
            rag_index_backend="pgvector",
            pgvector_table_name="rag_evidence_chunks",
        ),
    )
    monkeypatch.setattr(
        backfill_cli,
        "build_postgres_provider",
        lambda _settings: pytest.fail("no-op backfill must fail before opening PostgreSQL"),
    )

    with pytest.raises(SystemExit) as exc_info:
        backfill_cli.main(["--tenant-id", "tenant-a", "--corpus-id", "hr"])

    assert exc_info.value.code == 2
    assert "same pgvector storage" in capsys.readouterr().err


def test_pgvector_revision_reconciliation_is_rerunnable_and_tenant_scoped() -> None:
    connection = StatefulPgVectorConnection()
    backend = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=connection,
        embedder=DeterministicHashEmbedder(dimension=4),
    )
    connection.rows[("tenant-b", "ev_foreign")] = {
        **_row(tenant_id="tenant-b", evidence_id="ev_foreign"),
        "metadata": {
            "corpus_id": "hr",
            "department": "hr",
            "document_revision": "rev-old",
        },
    }

    backend.index_chunks(
        [
            _rag_chunk(evidence_id="ev_001", revision="rev-1"),
            _rag_chunk(evidence_id="ev_002", revision="rev-1"),
        ]
    )
    current_revision = [_rag_chunk(evidence_id="ev_001", revision="rev-2")]
    backend.index_chunks(current_revision)
    state_after_reconciliation = copy.deepcopy(connection.rows)
    backend.index_chunks(current_revision)

    assert set(connection.rows) == {("tenant-a", "ev_001"), ("tenant-b", "ev_foreign")}
    assert connection.rows == state_after_reconciliation
    assert connection.rows[("tenant-a", "ev_001")]["metadata"] == {
        "corpus_id": "hr",
        "document_revision": "rev-2",
    }
    assert connection.rows[("tenant-b", "ev_foreign")]["metadata"] == {
        "corpus_id": "hr",
        "department": "hr",
        "document_revision": "rev-old",
    }
    assert all(
        any(
            statement.startswith("INSERT INTO") and "updated_at = now()" in statement
            for statement, _parameters in operations
        )
        for operations in connection.transaction_calls
    )
    lock_statement, lock_parameters = connection.transaction_calls[-1][0]
    assert "pg_advisory_xact_lock" in lock_statement
    assert len(lock_parameters) == 1
    delete_statement, delete_parameters = connection.transaction_calls[-1][2]
    assert "tenant_id = %s AND source_ref = %s" in delete_statement
    assert "metadata @> %s::jsonb" in delete_statement
    assert delete_parameters == [
        ["tenant-a", "policy-a", '{"corpus_id": "hr"}', "rev-2", ["ev_001"]]
    ]


def test_pgvector_reconciliation_rejects_ambiguous_source_revisions() -> None:
    connection = StatefulPgVectorConnection()
    backend = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=connection,
    )

    with pytest.raises(RagIndexConfigurationError, match="multiple revisions"):
        backend.index_chunks(
            [
                _rag_chunk(evidence_id="ev_001", revision="rev-1"),
                _rag_chunk(evidence_id="ev_002", revision="rev-2"),
            ]
        )

    assert connection.rows == {}
    assert connection.transaction_calls == []


class MutableKeysetSqlProvider:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]],
        *,
        mutate_after_first: object | None = None,
    ) -> None:
        self.rows = [dict(row) for row in rows]
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self._mutate_after_first = mutate_after_first

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        copied_parameters = tuple(parameters)
        self.calls.append(("fetch_all", statement, copied_parameters))
        tenant_id, corpus_filter_json, after_evidence_id, page_size = copied_parameters
        assert isinstance(tenant_id, str)
        assert isinstance(corpus_filter_json, str)
        assert isinstance(after_evidence_id, str)
        assert isinstance(page_size, int)
        corpus_filter = json.loads(corpus_filter_json)
        matching = [
            row
            for row in self.rows
            if row.get("tenant_id") == tenant_id
            and isinstance(row.get("evidence_id"), str)
            and row["evidence_id"] > after_evidence_id
            and isinstance(row.get("metadata"), Mapping)
            and all(row["metadata"].get(key) == value for key, value in corpus_filter.items())
        ]
        page = sorted(matching, key=lambda row: str(row["evidence_id"]))[:page_size]
        if len(self.calls) == 1 and callable(self._mutate_after_first):
            self._mutate_after_first(self.rows)
        return [dict(row) for row in page]


class RecordingBackfillSource:
    storage_identities = frozenset({("test-source", "corpus-a")})

    def __init__(self, *, pages: Sequence[Sequence[RagChunk]]) -> None:
        self.pages = [list(page) for page in pages]
        self.calls: list[tuple[str, str, int]] = []

    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Iterator[Sequence[RagChunk]]:
        self.calls.append((tenant_id, corpus_id, page_size))
        yield from self.pages


class GeneratedBackfillSource:
    storage_identities = frozenset({("test-source", "corpus-a")})

    def __init__(self, *, page_count: int, page_size: int) -> None:
        self.page_count = page_count
        self.page_size = page_size

    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Iterator[Sequence[RagChunk]]:
        assert corpus_id == "hr"
        assert page_size == self.page_size
        for page_index in range(self.page_count):
            yield tuple(
                _rag_chunk(
                    tenant_id=tenant_id,
                    evidence_id=f"ev_{page_index:04d}_{chunk_index:02d}",
                )
                for chunk_index in range(self.page_size)
            )


class RecordingRagIndexBackend:
    backend_name = "recording"
    storage_identities = frozenset({("test-target", "corpus-b")})
    backfill_page_safe = True

    def __init__(self) -> None:
        self.pages: list[list[RagChunk]] = []

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        page = list(chunks)
        self.pages.append(page)
        return RagIndexWriteResult(
            indexed_count=len(page),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in page],
        )

    def search(self, search_request: Mapping[str, object]) -> list[object]:
        del search_request
        return []


class CountingRagIndexBackend:
    backend_name = "counting"
    storage_identities = frozenset({("test-target", "corpus-b")})
    backfill_page_safe = True

    def __init__(self) -> None:
        self.indexed_count = 0
        self.max_batch_size = 0

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        self.indexed_count += len(chunks)
        self.max_batch_size = max(self.max_batch_size, len(chunks))
        return RagIndexWriteResult(indexed_count=len(chunks), backend=self.backend_name)

    def search(self, search_request: Mapping[str, object]) -> list[object]:
        del search_request
        return []


class UnknownIdentityRagIndexBackend:
    backend_name = "unknown"
    backfill_page_safe = True

    def __init__(self) -> None:
        self.index_calls = 0

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        del chunks
        self.index_calls += 1
        return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)

    def search(self, search_request: Mapping[str, object]) -> list[object]:
        del search_request
        return []


class IdentityOnlyExactBackend(UnknownIdentityRagIndexBackend):
    def __init__(self, *, backend_name: str, identity: tuple[str, str]) -> None:
        super().__init__()
        self.backend_name = backend_name
        self.storage_identities = frozenset({identity})

    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[object]:
        del tenant_id, evidence_ids
        return []


class StatefulPgVectorConnection:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.execute_many_calls: list[tuple[str, list[list[object]]]] = []
        self.transaction_calls: list[list[tuple[str, list[list[object]]]]] = []

    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        copied = [list(row) for row in parameters]
        self.execute_many_calls.append((statement, copied))
        working = copy.deepcopy(self.rows)
        self._apply(working, statement, copied)
        self.rows = working

    def execute_many_transactionally(
        self,
        operations: Sequence[tuple[str, Sequence[Sequence[object]]]],
    ) -> None:
        copied = [
            (statement, [list(row) for row in parameters])
            for statement, parameters in operations
        ]
        self.transaction_calls.append(copied)
        working = copy.deepcopy(self.rows)
        for statement, parameters in copied:
            self._apply(working, statement, parameters)
        self.rows = working

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        del statement, parameters
        return []

    def _apply(
        self,
        rows: dict[tuple[str, str], dict[str, object]],
        statement: str,
        parameters: Sequence[Sequence[object]],
    ) -> None:
        if statement.startswith("SELECT pg_advisory_xact_lock"):
            return
        if statement.startswith("INSERT INTO"):
            for values in parameters:
                tenant_id = _string(values[0])
                evidence_id = _string(values[1])
                rows[(tenant_id, evidence_id)] = {
                    "tenant_id": tenant_id,
                    "evidence_id": evidence_id,
                    "source_ref": _string(values[2]),
                    "content": _string(values[3]),
                    "authority": _string(values[4]),
                    "staleness_class": _string(values[5]),
                    "retrieved_at": values[6],
                    "published_at": values[7],
                    "metadata": json.loads(_string(values[8])),
                }
            return
        if statement.startswith("DELETE FROM"):
            for values in parameters:
                tenant_id = _string(values[0])
                source_ref = _string(values[1])
                corpus_filter = json.loads(_string(values[2]))
                revision = _string(values[3])
                current_evidence_ids = set(_strings(values[4]))
                for key, row in list(rows.items()):
                    metadata = row.get("metadata")
                    if row.get("tenant_id") != tenant_id or row.get("source_ref") != source_ref:
                        continue
                    if not isinstance(metadata, Mapping) or not all(
                        metadata.get(name) == value for name, value in corpus_filter.items()
                    ):
                        continue
                    if (
                        metadata.get("document_revision") != revision
                        or row.get("evidence_id") not in current_evidence_ids
                    ):
                        del rows[key]
            return
        raise AssertionError(f"Unexpected statement: {statement}")


def _row(
    *,
    tenant_id: str = "tenant-a",
    evidence_id: str,
    content: str = "Remote work needs approval.",
) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "evidence_id": evidence_id,
        "source_ref": "policy-a",
        "content": content,
        "authority": "internal",
        "staleness_class": "fresh",
        "retrieved_at": TEST_RETRIEVED_AT,
        "published_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
        "metadata": {"corpus_id": "hr", "department": "hr"},
    }


def _rag_chunk(
    *,
    tenant_id: str = "tenant-a",
    evidence_id: str,
    revision: str | None = None,
) -> RagChunk:
    metadata: dict[str, object] = {"corpus_id": "hr"}
    if revision is not None:
        metadata["document_revision"] = revision
    return RagChunk(
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        source_ref="policy-a",
        content="Remote work needs approval.",
        authority=Authority.INTERNAL,
        freshness=Freshness(
            retrieved_at=TEST_RETRIEVED_AT,
            staleness_class=StalenessClass.FRESH,
        ),
        metadata=metadata,
    )


def _string(value: object) -> str:
    assert isinstance(value, str)
    return value


def _strings(value: object) -> Sequence[str]:
    assert isinstance(value, Sequence)
    assert not isinstance(value, (str, bytes, bytearray))
    assert all(isinstance(item, str) for item in value)
    return value
