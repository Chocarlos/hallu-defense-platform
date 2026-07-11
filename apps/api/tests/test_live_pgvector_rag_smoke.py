from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

import pytest

from scripts.dev import live_pgvector_rag_smoke as smoke


def test_live_pgvector_rag_smoke_skips_by_default_without_exposing_dsn_secret() -> None:
    result = smoke.run_from_env(
        {smoke.DSN_ENV: "postgresql://hallu:secret@localhost:5432/hallu_defense"}
    )

    assert result["status"] == "skipped"
    assert result["indexed_count"] == 0
    assert result["tenant_isolation"] is False
    assert result["backend"] == "pgvector"
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize(
    "table_name",
    [
        "",
        "rag-evidence-smoke",
        "rag evidence smoke",
        "rag_evidence;drop",
        "rag_evidence*",
    ],
)
def test_live_pgvector_rag_smoke_rejects_unsafe_table_names(table_name: str) -> None:
    with pytest.raises(ValueError):
        smoke.validate_smoke_table_name(table_name)


def test_live_pgvector_rag_smoke_runs_with_recording_connection() -> None:
    connection = RecordingPgVectorConnection()

    result = smoke.run_from_env(
        {
            smoke.ENABLED_ENV: "true",
            smoke.DSN_ENV: "postgresql://hallu:secret@localhost:5432/hallu_defense",
            smoke.TABLE_NAME_ENV: "rag_evidence_chunks",
            smoke.TIMEOUT_ENV: "5",
        },
        connection=connection,
        run_id="unit",
    )

    assert result == {
        "status": "passed",
        "dsn": "postgresql://hallu:***@localhost:5432/hallu_defense",
        "table_name": "rag_evidence_chunks",
        "backend": "pgvector",
        "indexed_count": 2,
        "tenant_isolation": True,
        "exact_plan": True,
        "exact_recall": True,
    }
    assert connection.rows == {}

    assert len(connection.execute_many_calls) == 2
    tenant_a_parameters = connection.execute_many_calls[0][1][0]
    tenant_b_parameters = connection.execute_many_calls[1][1][0]
    assert tenant_a_parameters[0] == smoke.SMOKE_TENANT_A
    assert tenant_b_parameters[0] == smoke.SMOKE_TENANT_B
    assert tenant_a_parameters[1] == tenant_b_parameters[1]
    for parameters in (tenant_a_parameters, tenant_b_parameters):
        metadata = json.loads(_string_parameter(parameters[8]))
        assert metadata["smoke_kind"] == smoke.SMOKE_KIND
        assert metadata["smoke_run_id"] == "unit"
        assert metadata["corpus_id"] == "live_smoke"
        assert metadata["owner_tenant_id"] == parameters[0]

    statements = [call[0] for call in connection.fetch_all_calls]
    delete_statements = [statement for statement in statements if statement.startswith("DELETE FROM")]
    search_statements = [statement for statement in statements if statement.startswith("SELECT tenant_id")]
    schema_statements = [
        statement
        for statement in statements
        if statement.startswith("SELECT extname")
        or statement.startswith("SELECT format_type")
        or statement.startswith("SELECT indexname")
    ]
    explain_statements = [statement for statement in statements if statement.startswith("EXPLAIN")]
    oracle_statements = [statement for statement in statements if statement.startswith("SELECT evidence_id")]
    assert len(delete_statements) == 2
    assert len(schema_statements) == 4
    assert len(explain_statements) == 1
    assert len(search_statements) == 6
    assert len(oracle_statements) == 2
    assert all("DROP" not in statement and "TRUNCATE" not in statement for statement in statements)
    assert all("tenant_id = ANY(%s)" in statement for statement in delete_statements)
    assert all("metadata @> %s::jsonb" in statement for statement in delete_statements)
    assert all("tenant_id = %s" in statement for statement in search_statements)
    assert all("source_ref = ANY(%s)" in statement for statement in search_statements)
    assert all(
        "1 - (embedding <=> %s::vector) AS vector_score" in statement
        and "ORDER BY vector_score DESC, evidence_id ASC" in statement
        for statement in search_statements
    )
    for statement, parameters in connection.fetch_all_calls:
        if statement.startswith("SELECT tenant_id"):
            assert isinstance(parameters[0], str) and parameters[0].startswith("[")
            assert parameters[1] in smoke.SMOKE_TENANTS


def test_pgvector_smoke_cleanup_deletes_only_current_smoke_rows() -> None:
    connection = RecordingPgVectorConnection()
    connection.rows = {
        (smoke.SMOKE_TENANT_A, "ev_current_a"): _row(
            tenant_id=smoke.SMOKE_TENANT_A,
            evidence_id="ev_current_a",
            metadata={"smoke_kind": smoke.SMOKE_KIND, "smoke_run_id": "current"},
        ),
        (smoke.SMOKE_TENANT_B, "ev_current_b"): _row(
            tenant_id=smoke.SMOKE_TENANT_B,
            evidence_id="ev_current_b",
            metadata={"smoke_kind": smoke.SMOKE_KIND, "smoke_run_id": "current"},
        ),
        (smoke.SMOKE_TENANT_A, "ev_other_run"): _row(
            tenant_id=smoke.SMOKE_TENANT_A,
            evidence_id="ev_other_run",
            metadata={"smoke_kind": smoke.SMOKE_KIND, "smoke_run_id": "other"},
        ),
        (smoke.SMOKE_TENANT_A, "ev_not_smoke"): _row(
            tenant_id=smoke.SMOKE_TENANT_A,
            evidence_id="ev_not_smoke",
            metadata={"department": "hr"},
        ),
        ("tenant-customer", "ev_customer"): _row(
            tenant_id="tenant-customer",
            evidence_id="ev_customer",
            metadata={"smoke_kind": smoke.SMOKE_KIND, "smoke_run_id": "current"},
        ),
    }

    deleted_count = smoke.cleanup_smoke_rows(
        connection=connection,
        table_name="rag_evidence_chunks",
        run_id="current",
    )

    assert deleted_count == 2
    assert set(connection.rows) == {
        (smoke.SMOKE_TENANT_A, "ev_other_run"),
        (smoke.SMOKE_TENANT_A, "ev_not_smoke"),
        ("tenant-customer", "ev_customer"),
    }


def test_pgvector_smoke_schema_verification_rejects_missing_migration() -> None:
    connection = RecordingPgVectorConnection(extension_present=False)

    with pytest.raises(RuntimeError, match="pgvector extension is missing"):
        smoke.verify_pgvector_schema(connection=connection, table_name="rag_evidence_chunks")


def test_pgvector_smoke_schema_verification_rejects_wrong_embedding_type() -> None:
    connection = RecordingPgVectorConnection(embedding_type="vector(8)")

    with pytest.raises(RuntimeError, match="vector\\(16\\)"):
        smoke.verify_pgvector_schema(connection=connection, table_name="rag_evidence_chunks")


@pytest.mark.parametrize(
    ("retrieved_at_type", "retrieved_at_not_null"),
    [
        (None, False),
        ("timestamp without time zone", True),
        (smoke.EXPECTED_RETRIEVED_AT_TYPE, False),
    ],
)
def test_pgvector_smoke_schema_verification_requires_retrieved_at_not_null(
    retrieved_at_type: str | None,
    retrieved_at_not_null: bool,
) -> None:
    connection = RecordingPgVectorConnection(
        retrieved_at_type=retrieved_at_type,
        retrieved_at_not_null=retrieved_at_not_null,
    )

    with pytest.raises(RuntimeError, match="010_add_retrieved_at"):
        smoke.verify_pgvector_schema(connection=connection, table_name="rag_evidence_chunks")


def test_pgvector_smoke_schema_verification_rejects_approximate_index() -> None:
    connection = RecordingPgVectorConnection(approximate_index_present=True)

    with pytest.raises(RuntimeError, match="approximate vector index"):
        smoke.verify_pgvector_schema(connection=connection, table_name="rag_evidence_chunks")


def test_live_pgvector_rag_smoke_main_returns_failure_for_bad_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = smoke.main(env={smoke.ENABLED_ENV: "true", smoke.TIMEOUT_ENV: "0"})

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert payload["backend"] == "pgvector"
    assert "TIMEOUT" in payload["error"]


class RecordingPgVectorConnection:
    def __init__(
        self,
        *,
        extension_present: bool = True,
        embedding_type: str | None = smoke.EXPECTED_EMBEDDING_TYPE,
        retrieved_at_type: str | None = smoke.EXPECTED_RETRIEVED_AT_TYPE,
        retrieved_at_not_null: bool = True,
        approximate_index_present: bool = False,
    ) -> None:
        self.execute_many_calls: list[tuple[str, list[list[object]]]] = []
        self.fetch_all_calls: list[tuple[str, Sequence[object]]] = []
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self._extension_present = extension_present
        self._embedding_type = embedding_type
        self._retrieved_at_type = retrieved_at_type
        self._retrieved_at_not_null = retrieved_at_not_null
        self._approximate_index_present = approximate_index_present

    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        copied_parameters = [list(row) for row in parameters]
        self.execute_many_calls.append((statement, copied_parameters))
        for row in copied_parameters:
            tenant_id = _string_parameter(row[0])
            evidence_id = _string_parameter(row[1])
            self.rows[(tenant_id, evidence_id)] = {
                "tenant_id": tenant_id,
                "evidence_id": evidence_id,
                "source_ref": _string_parameter(row[2]),
                "content": _string_parameter(row[3]),
                "authority": _string_parameter(row[4]),
                "staleness_class": _string_parameter(row[5]),
                "retrieved_at": row[6],
                "published_at": row[7],
                "metadata": json.loads(_string_parameter(row[8])),
            }

    def execute_many_transactionally(
        self,
        operations: Sequence[tuple[str, Sequence[Sequence[object]]]],
    ) -> None:
        for statement, parameters in operations:
            if statement.startswith("SELECT pg_advisory_xact_lock"):
                continue
            if statement.startswith("INSERT INTO"):
                self.execute_many(statement, parameters)
                continue
            if statement.startswith("DELETE FROM"):
                self._reconcile_source_rows(parameters)
                continue
            raise AssertionError(f"Unexpected transactional statement: {statement}")

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        self.fetch_all_calls.append((statement, list(parameters)))
        if statement.startswith("SELECT extname"):
            return [{"extname": "vector"}] if self._extension_present else []
        if statement.startswith("SELECT format_type"):
            if parameters[2] == "retrieved_at":
                return (
                    [
                        {
                            "retrieved_at_type": self._retrieved_at_type,
                            "retrieved_at_not_null": self._retrieved_at_not_null,
                        }
                    ]
                    if self._retrieved_at_type is not None
                    else []
                )
            return (
                [{"embedding_type": self._embedding_type}]
                if self._embedding_type is not None
                else []
            )
        if statement.startswith("SELECT indexname"):
            indexes: list[Mapping[str, object]] = [
                {
                    "indexname": "idx_rag_evidence_chunks_tenant_source",
                    "indexdef": "CREATE INDEX USING btree (tenant_id, source_ref)",
                }
            ]
            if self._approximate_index_present:
                indexes.append(
                    {
                        "indexname": "idx_rag_evidence_chunks_embedding",
                        "indexdef": "CREATE INDEX USING ivfflat (embedding vector_cosine_ops)",
                    }
                )
            return indexes
        if statement.startswith("EXPLAIN"):
            return [{"QUERY PLAN": [{"Plan": {"Node Type": "Sort"}}]}]
        if statement.startswith("DELETE FROM"):
            return self._delete_smoke_rows(parameters)
        if statement.startswith("SELECT "):
            return self._select_rows(statement, parameters)
        raise AssertionError(f"Unexpected pgvector statement: {statement}")

    def _delete_smoke_rows(self, parameters: Sequence[object]) -> list[Mapping[str, object]]:
        tenant_ids = set(_string_sequence_parameter(parameters[0]))
        metadata_filter = json.loads(_string_parameter(parameters[1]))
        deleted: list[Mapping[str, object]] = []
        for key, row in list(self.rows.items()):
            metadata = row.get("metadata")
            if (
                row.get("tenant_id") in tenant_ids
                and isinstance(metadata, Mapping)
                and _metadata_contains(metadata, metadata_filter)
            ):
                deleted.append(row)
                del self.rows[key]
        return deleted

    def _reconcile_source_rows(self, parameters: Sequence[Sequence[object]]) -> None:
        for values in parameters:
            tenant_id = _string_parameter(values[0])
            source_ref = _string_parameter(values[1])
            corpus_filter = json.loads(_string_parameter(values[2]))
            revision = _string_parameter(values[3])
            current_ids = set(_string_sequence_parameter(values[4]))
            for key, row in list(self.rows.items()):
                metadata = row.get("metadata")
                if row.get("tenant_id") != tenant_id or row.get("source_ref") != source_ref:
                    continue
                if not isinstance(metadata, Mapping) or not _metadata_contains(
                    metadata,
                    corpus_filter,
                ):
                    continue
                if (
                    metadata.get("document_revision") != revision
                    or row.get("evidence_id") not in current_ids
                ):
                    del self.rows[key]

    def _select_rows(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> list[Mapping[str, object]]:
        production_query = statement.startswith("SELECT tenant_id")
        parameter_index = 1 if production_query else 0
        tenant_id = _string_parameter(parameters[parameter_index])
        parameter_index += 1
        source_refs: set[str] | None = None
        metadata_filter: Mapping[str, object] = {}
        if "source_ref = ANY(%s)" in statement:
            source_refs = set(_string_sequence_parameter(parameters[parameter_index]))
            parameter_index += 1
        elif "source_ref = %s" in statement:
            source_refs = {_string_parameter(parameters[parameter_index])}
            parameter_index += 1
        filter_count = statement.count("metadata -> %s = %s::jsonb")
        parsed_filter: dict[str, object] = {}
        for _ in range(filter_count):
            if production_query:
                containment = json.loads(_string_parameter(parameters[parameter_index]))
                assert isinstance(containment, Mapping)
                parameter_index += 1
            key = _string_parameter(parameters[parameter_index])
            value = json.loads(_string_parameter(parameters[parameter_index + 1]))
            parameter_index += 2
            parsed_filter[key] = value
        metadata_filter = parsed_filter

        limit = parameters[-1]
        assert isinstance(limit, int)
        matches: list[Mapping[str, object]] = []
        for row in self.rows.values():
            metadata = row.get("metadata")
            if row.get("tenant_id") != tenant_id:
                continue
            if source_refs is not None and row.get("source_ref") not in source_refs:
                continue
            if not isinstance(metadata, Mapping) or not _metadata_contains(metadata, metadata_filter):
                continue
            matches.append(row)
        return matches[:limit]


def _row(
    *,
    tenant_id: str,
    evidence_id: str,
    metadata: Mapping[str, object],
) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "evidence_id": evidence_id,
        "source_ref": "policy",
        "content": "Smoke row content.",
        "authority": "internal",
        "staleness_class": "fresh",
        "retrieved_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "published_at": None,
        "metadata": dict(metadata),
    }


def _metadata_contains(metadata: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    return all(metadata.get(key) == value for key, value in expected.items())


def _string_parameter(value: object) -> str:
    assert isinstance(value, str)
    return value


def _string_sequence_parameter(value: object) -> Sequence[str]:
    assert isinstance(value, Sequence)
    assert not isinstance(value, str)
    assert all(isinstance(item, str) for item in value)
    return value
