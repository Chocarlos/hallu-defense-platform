from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from types import TracebackType
from typing import Self

import pytest

from hallu_defense.domain.models import (
    Authority,
    Evidence,
    EvidenceKind,
    Freshness,
    StalenessClass,
)
from hallu_defense.services.rag_index import (
    RagChunk,
    RagIndexTransportError,
    RagIndexWriteResult,
    RagSearchRequest,
)
from scripts.dev import live_hybrid_rag_smoke as smoke


def test_live_hybrid_rag_smoke_skips_without_touching_admin_dsn() -> None:
    secret_dsn = "postgresql://admin:secret-value@localhost/postgres"

    result = smoke.run_from_env({smoke.ADMIN_DSN_ENV: secret_dsn})

    assert result["status"] == "skipped"
    assert result["backend"] == "hybrid"
    assert "secret-value" not in json.dumps(result)


def test_live_hybrid_rag_smoke_requires_explicit_admin_dsn_when_enabled() -> None:
    with pytest.raises(ValueError, match=smoke.ADMIN_DSN_ENV):
        smoke.run_from_env({smoke.ENABLED_ENV: "true"})


@pytest.mark.parametrize(
    "value",
    [
        "unit-smoke",
        "unit_smoke",
        "UNIT!",
        "a" * 21,
        "",
    ],
)
def test_live_hybrid_rag_smoke_rejects_unsafe_run_ids(value: str) -> None:
    with pytest.raises(ValueError, match="run ID"):
        smoke.validate_run_id(value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:secret@search.example.test",
        "https://search.example.test/path",
        "https://search.example.test?token=secret",
        "file:///tmp/opensearch",
    ],
)
def test_live_hybrid_rag_smoke_rejects_credentialed_or_non_origin_endpoint(
    endpoint: str,
) -> None:
    with pytest.raises(ValueError, match="credential-free"):
        smoke.validate_opensearch_endpoint(endpoint)


def test_live_hybrid_rag_smoke_proves_fusion_tenants_reconciliation_and_cleanup() -> None:
    backend = RecordingHybridSmokeBackend()
    provisioner = RecordingProvisioner(backend)

    result = smoke.run_from_env(
        {
            smoke.ENABLED_ENV: "true",
            smoke.ADMIN_DSN_ENV: "postgresql://admin:secret@localhost/postgres",
            smoke.OPENSEARCH_ENDPOINT_ENV: "http://localhost:9200",
            smoke.TIMEOUT_ENV: "2",
        },
        provisioner=provisioner,
        run_id="unit",
    )

    assert result == {
        "status": "passed",
        "backend": "hybrid",
        "database_name": "hallu_hybrid_smoke_unit",
        "index_name": "hallu_evidence_hybrid_smoke_unit",
        "migrations_applied": 13,
        "indexed_count": 4,
        "tenant_isolation": True,
        "fusion_proven": True,
        "scoped_reconciliation": True,
        "database_cleaned": True,
        "index_cleaned": True,
        "template_cleaned": True,
    }
    assert provisioner.run_ids == ["unit"]
    assert len(backend.index_calls) == 3
    assert backend.rows.keys() == {
        ("tenant-hybrid-smoke-unit-a", "ev_unit_a_current"),
        ("tenant-hybrid-smoke-unit-b", "ev_unit_b_old"),
    }


def test_live_hybrid_rag_smoke_cleans_resources_when_assertion_fails() -> None:
    provisioner = RecordingProvisioner(
        RecordingHybridSmokeBackend(search_error=RagIndexTransportError("down"))
    )

    with pytest.raises(RagIndexTransportError, match="down"):
        smoke.run_live_smoke(
            smoke.LiveHybridRagSmokeConfig(
                admin_dsn="postgresql://admin:secret@localhost/postgres",
                opensearch_endpoint="http://localhost:9200",
                timeout_seconds=1,
            ),
            provisioner=provisioner,
            run_id="failure",
        )

    assert provisioner.provisioned is not None
    assert provisioner.provisioned.database_cleaned is True
    assert provisioner.provisioned.index_cleaned is True
    assert provisioner.provisioned.template_cleaned is True


def test_live_hybrid_rag_smoke_main_never_prints_admin_dsn_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = smoke.main(
        env={
            smoke.ENABLED_ENV: "true",
            smoke.ADMIN_DSN_ENV: ("postgresql://admin:admin-dsn-secret@localhost/postgres"),
            smoke.OPENSEARCH_ENDPOINT_ENV: "https://user:url-secret@search.example.test",
        }
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "admin-dsn-secret" not in output
    assert "url-secret" not in output
    assert json.loads(output)["error"] == "Hybrid RAG live smoke failed."


def test_live_hybrid_rag_smoke_scratch_dsn_replaces_database_and_adds_timeouts() -> None:
    captured: dict[str, object] = {}

    def conninfo_to_dict(value: str) -> dict[str, str]:
        captured["source"] = value
        return {
            "host": "postgres",
            "dbname": "hallu_defense",
            "password": "secret",
        }

    def make_conninfo(**params: object) -> str:
        captured["params"] = params
        return "bounded-scratch-dsn"

    result = smoke._scratch_dsn(
        "postgresql://admin:secret@postgres/hallu_defense",
        database_name="hallu_hybrid_smoke_unit",
        timeout_seconds=1.25,
        conninfo_to_dict=conninfo_to_dict,
        make_conninfo=make_conninfo,
    )

    assert result == "bounded-scratch-dsn"
    parameters = captured["params"]
    assert isinstance(parameters, dict)
    assert parameters["dbname"] == "hallu_hybrid_smoke_unit"
    assert parameters["connect_timeout"] == 2
    assert parameters["options"] == ("-c lock_timeout=1250 -c statement_timeout=1250")


def test_live_hybrid_rag_smoke_admin_sql_is_exact_and_bounded() -> None:
    connect = RecordingAdminConnect()

    smoke._create_scratch_database(
        connect,
        admin_dsn="postgresql://admin:secret@postgres/postgres",
        database_name="hallu_hybrid_smoke_unit",
        timeout_seconds=1.25,
    )
    smoke._drop_scratch_database(
        connect,
        admin_dsn="postgresql://admin:secret@postgres/postgres",
        database_name="hallu_hybrid_smoke_unit",
        timeout_seconds=1.25,
    )

    assert connect.cursor.statements == [
        "CREATE DATABASE hallu_hybrid_smoke_unit",
        "DROP DATABASE IF EXISTS hallu_hybrid_smoke_unit WITH (FORCE)",
    ]
    assert all(call["connect_timeout"] == 2 for call in connect.calls)
    assert all(call["options"] == "-c statement_timeout=1250" for call in connect.calls)


@pytest.mark.parametrize("response", [{}, {"acknowledged": False}])
def test_live_hybrid_rag_smoke_cleanup_requires_positive_opensearch_ack(
    response: Mapping[str, object],
) -> None:
    transport = StaticResponseTransport(response)

    with pytest.raises(RuntimeError, match="index cleanup"):
        smoke._delete_smoke_index(
            transport,
            index_name="hallu_evidence_hybrid_smoke_unit",
            timeout_seconds=1,
        )
    with pytest.raises(RuntimeError, match="template cleanup"):
        smoke._delete_smoke_template(
            transport,
            template_name="hallu_evidence_hybrid_smoke_unit_template",
            timeout_seconds=1,
        )


def test_live_hybrid_rag_smoke_preserves_primary_and_cleanup_errors() -> None:
    primary = RagIndexTransportError("primary execution failure")
    cleanup = RuntimeError("cleanup failure")

    with pytest.raises(BaseExceptionGroup) as exc_info:
        smoke._raise_cleanup_failures(primary, [cleanup])

    assert exc_info.value.exceptions == (primary, cleanup)


def test_live_hybrid_rag_smoke_database_collision_never_drops_existing_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = CollidingAdminConnect()

    def conninfo_to_dict(_value: str) -> dict[str, str]:
        return {"host": "postgres", "dbname": "postgres"}

    def make_conninfo(**_params: object) -> str:
        return "scratch-dsn"

    monkeypatch.setattr(
        smoke,
        "_load_psycopg_runtime",
        lambda: (connect, None, conninfo_to_dict, make_conninfo),
    )
    provisioner = smoke.PsycopgOpenSearchSmokeProvisioner(
        smoke.LiveHybridRagSmokeConfig(
            admin_dsn="postgresql://admin:secret@postgres/postgres",
            opensearch_endpoint="http://opensearch:9200",
            timeout_seconds=1,
        ),
        transport=UnexpectedOpenSearchTransport(),
    )

    with pytest.raises(RuntimeError, match="already exists"):
        with provisioner.provision(run_id="collision"):
            pytest.fail("database collision must not enter the smoke body")

    assert connect.cursor.statements == ["CREATE DATABASE hallu_hybrid_smoke_collision"]


def test_live_hybrid_rag_smoke_migration_inventory_is_exact() -> None:
    migrations = tuple(sorted(smoke.MIGRATIONS_DIR.glob("*.sql")))

    assert len(migrations) == smoke.EXPECTED_MIGRATION_COUNT == 14


def test_live_hybrid_rag_smoke_provisions_exact_schema_v3_template() -> None:
    index_name = "hallu_evidence_hybrid_smoke_unit"
    template = smoke._smoke_template(index_name)

    assert template["index_patterns"] == [index_name]
    body = template["template"]
    assert isinstance(body, dict)
    mappings = body["mappings"]
    assert isinstance(mappings, dict)
    assert mappings["_meta"]["schema_version"] == "rag-opensearch-template.v3"


class RecordingProvisioner:
    def __init__(self, backend: RecordingHybridSmokeBackend) -> None:
        self.backend = backend
        self.run_ids: list[str] = []
        self.provisioned: smoke.ProvisionedHybridSmoke | None = None

    @contextmanager
    def provision(
        self,
        *,
        run_id: str,
    ) -> Iterator[smoke.ProvisionedHybridSmoke]:
        self.run_ids.append(run_id)
        self.provisioned = smoke.ProvisionedHybridSmoke(
            backend=self.backend,
            database_name=f"hallu_hybrid_smoke_{run_id}",
            index_name=f"hallu_evidence_hybrid_smoke_{run_id}",
            migrations_applied=tuple(f"{index:03}.sql" for index in range(13)),
        )
        try:
            yield self.provisioned
        finally:
            self.provisioned.database_cleaned = True
            self.provisioned.index_cleaned = True
            self.provisioned.template_cleaned = True


class RecordingHybridSmokeBackend:
    backend_name = "hybrid"

    def __init__(self, search_error: Exception | None = None) -> None:
        self.search_error = search_error
        self.index_calls: list[list[RagChunk]] = []
        self.rows: dict[tuple[str, str], RagChunk] = {}

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        copied = list(chunks)
        self.index_calls.append(copied)
        for chunk in copied:
            corpus_id = chunk.metadata.get("corpus_id")
            revision = chunk.metadata.get("document_revision")
            for key, existing in list(self.rows.items()):
                if (
                    existing.tenant_id == chunk.tenant_id
                    and existing.source_ref == chunk.source_ref
                    and existing.metadata.get("corpus_id") == corpus_id
                    and existing.metadata.get("document_revision") != revision
                ):
                    del self.rows[key]
            self.rows[(chunk.tenant_id, chunk.evidence_id)] = chunk
        return RagIndexWriteResult(
            indexed_count=len(copied),
            backend="hybrid",
            evidence_ids=[chunk.evidence_id for chunk in copied],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        if self.search_error is not None:
            raise self.search_error
        matches = [
            chunk
            for chunk in self.rows.values()
            if chunk.tenant_id == search_request.tenant_id
            and (not search_request.context_refs or chunk.source_ref in search_request.context_refs)
            and all(
                chunk.metadata.get(key) == value
                for key, value in search_request.metadata_filter.items()
            )
        ]
        return [_evidence(chunk, search_request, rank) for rank, chunk in enumerate(matches, 1)]


def _evidence(
    chunk: RagChunk,
    search_request: RagSearchRequest,
    rank: int,
) -> Evidence:
    return Evidence(
        evidence_id=chunk.evidence_id,
        kind=EvidenceKind.DOCUMENT_CHUNK,
        source_ref=chunk.source_ref,
        content=chunk.content,
        authority=Authority.INTERNAL,
        freshness=Freshness(
            retrieved_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            staleness_class=StalenessClass.FRESH,
        ),
        structured_content={
            "metadata": dict(chunk.metadata),
            "retrieval": {
                "claim_id": search_request.claim_id,
                "ranker": "persistent_hybrid_rrf_v1",
                "tenant_id": search_request.tenant_id,
                "tenant_scoped": True,
                "fused_rank": rank,
                "rankers": {
                    "opensearch_bm25_v1": {
                        "matched": True,
                        "rank": rank,
                        "score": 1.0,
                    },
                    "pgvector_cosine_v1": {
                        "matched": True,
                        "rank": rank,
                        "score": 0.9,
                    },
                },
            },
        },
    )


class RecordingAdminCursor:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        assert parameters == ()
        self.statements.append(statement)


class CollidingAdminCursor(RecordingAdminCursor):
    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        super().execute(statement, parameters)
        if statement.startswith("CREATE DATABASE"):
            raise RuntimeError("database already exists")


class RecordingAdminConnection:
    def __init__(self, cursor: RecordingAdminCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    def cursor(self) -> RecordingAdminCursor:
        return self._cursor


class RecordingAdminConnect:
    def __init__(self) -> None:
        self.cursor = RecordingAdminCursor()
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        conninfo: str,
        *,
        autocommit: bool = False,
        connect_timeout: int | None = None,
        options: str | None = None,
        row_factory: object | None = None,
    ) -> RecordingAdminConnection:
        self.calls.append(
            {
                "conninfo": conninfo,
                "autocommit": autocommit,
                "connect_timeout": connect_timeout,
                "options": options,
                "row_factory": row_factory,
            }
        )
        return RecordingAdminConnection(self.cursor)


class CollidingAdminConnect(RecordingAdminConnect):
    def __init__(self) -> None:
        super().__init__()
        self.cursor = CollidingAdminCursor()


class StaticResponseTransport:
    def __init__(self, response: Mapping[str, object]) -> None:
        self.response = response

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del method, path, body, headers, timeout_seconds
        return self.response


class UnexpectedOpenSearchTransport(StaticResponseTransport):
    def __init__(self) -> None:
        super().__init__({})

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del method, path, body, headers, timeout_seconds
        pytest.fail("OpenSearch must not be touched after a database name collision")
