from __future__ import annotations

import copy
import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from hallu_defense.services.audit import AuditLedger, PostgresAuditLedgerStorage
from hallu_defense.services.data_lifecycle import (
    POSTGRES_LIFECYCLE_TABLES,
    SYSTEM_TENANT_ID,
    TENANT_DATA_DELETION_EVENT,
    DataLifecycleError,
    DataLifecyclePolicy,
    DataLifecyclePolicyError,
    DataLifecycleService,
    RETENTION_EXECUTION_EVENT,
)
from scripts.dev import run_retention_execution as retention_cli
from scripts.ci.check_backup_retention_config import POLICY_PATH, load_policy

FIXED_NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)


class CountingSqlProvider:
    def __init__(self, affected_count: int = 2) -> None:
        self.affected_count = affected_count
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.transaction_count = 0

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        self.calls.append(("execute", statement, tuple(parameters)))

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(("fetch_all", statement, tuple(parameters)))
        return [{"affected_count": self.affected_count}]

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(("execute_returning", statement, tuple(parameters)))
        return [{"affected_count": self.affected_count}]

    @contextmanager
    def transaction(self) -> Iterator[CountingSqlProvider]:
        self.transaction_count += 1
        yield self


def _service(provider: CountingSqlProvider) -> tuple[DataLifecycleService, AuditLedger]:
    audit = AuditLedger()
    service = DataLifecycleService(
        connection=provider,
        audit=audit,
        transactional_audit_factory=lambda transaction: audit,
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="pgvector",
        clock=lambda: FIXED_NOW,
    )
    return service, audit


@pytest.mark.parametrize("operation", ["retention", "delete-tenant"])
def test_hybrid_lifecycle_mutation_fails_before_sql_or_success_audit(
    operation: str,
) -> None:
    provider = CountingSqlProvider(affected_count=3)
    audit = AuditLedger()
    service = DataLifecycleService(
        connection=provider,
        audit=audit,
        transactional_audit_factory=lambda transaction: audit,
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="hybrid",
        clock=lambda: FIXED_NOW,
    )

    with pytest.raises(DataLifecycleError, match="coordinated cross-store deletion"):
        if operation == "retention":
            service.execute_retention(actor_id="operator")
        else:
            service.delete_tenant_data("tenant-a", actor_id="privacy-admin")

    assert provider.calls == []
    assert provider.transaction_count == 0
    assert audit.export(tenant_id=SYSTEM_TENANT_ID) == []


@pytest.mark.parametrize("operation", ["retention", "delete-tenant"])
def test_opensearch_only_lifecycle_mutation_is_fail_closed(
    operation: str,
) -> None:
    provider = CountingSqlProvider(affected_count=3)
    audit = AuditLedger()
    service = DataLifecycleService(
        connection=provider,
        audit=audit,
        transactional_audit_factory=lambda transaction: audit,
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="opensearch",
        clock=lambda: FIXED_NOW,
    )

    with pytest.raises(DataLifecycleError, match="OpenSearch-only RAG"):
        if operation == "retention":
            service.execute_retention(actor_id="operator")
        else:
            service.delete_tenant_data("tenant-a", actor_id="privacy-admin")

    assert provider.calls == []
    assert provider.transaction_count == 0
    assert audit.export(tenant_id=SYSTEM_TENANT_ID) == []


def test_retention_execution_uses_policy_cutoffs_and_emits_audit_event() -> None:
    provider = CountingSqlProvider(affected_count=3)
    service, audit = _service(provider)

    report = service.execute_retention(actor_id="operator")

    assert report.total_affected == 3 * len(POSTGRES_LIFECYCLE_TABLES)
    calls_by_table = {call[1].split("DELETE FROM ")[1].split(" WHERE ")[0]: call for call in provider.calls}
    assert calls_by_table["audit_events"][2] == (FIXED_NOW - timedelta(days=365),)
    assert calls_by_table["audit_runs"][2] == (FIXED_NOW - timedelta(days=180),)
    assert calls_by_table["rag_evidence_chunks"][2] == (FIXED_NOW - timedelta(days=90),)
    assert calls_by_table["rag_ingestion_jobs"][2] == (FIXED_NOW - timedelta(days=1),)
    ingestion_sql = calls_by_table["rag_ingestion_jobs"][1]
    assert "status IN ('succeeded', 'dead')" in ingestion_sql
    assert "failed" not in ingestion_sql
    grants_sql = calls_by_table["rag_corpus_grants"][1]
    assert "newer.tenant_id = rag_corpus_grants.tenant_id" in grants_sql
    assert "newer.corpus_id = rag_corpus_grants.corpus_id" in grants_sql
    assert "newer.version > rag_corpus_grants.version" in grants_sql

    events = audit.export_events(tenant_id=SYSTEM_TENANT_ID)
    assert len(events) == 1
    assert events[0].event_type == RETENTION_EXECUTION_EVENT
    assert events[0].metadata["actor_id"] == "operator"
    assert events[0].metadata["total_affected"] == report.total_affected


def test_retention_policy_rejects_days_below_minimum_before_sql_runs() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    components = policy["components"]
    assert isinstance(components, dict)
    postgres = components["postgres"]
    assert isinstance(postgres, dict)
    retention = postgres["retention"]
    assert isinstance(retention, dict)
    classes = retention["classes"]
    assert isinstance(classes, dict)
    evidence_indexes = classes["evidence_indexes"]
    assert isinstance(evidence_indexes, dict)
    evidence_indexes["days"] = 1

    with pytest.raises(DataLifecyclePolicyError, match="at least"):
        DataLifecyclePolicy.from_mapping(policy)


def test_delete_tenant_data_deletes_only_parameterized_tenant_scope_and_audits() -> None:
    provider = CountingSqlProvider(affected_count=1)
    service, audit = _service(provider)

    report = service.delete_tenant_data(" tenant-a ", actor_id="privacy-admin")

    assert report.tenant_id == "tenant-a"
    assert report.total_affected == len(POSTGRES_LIFECYCLE_TABLES)
    assert len(provider.calls) == len(POSTGRES_LIFECYCLE_TABLES)
    for method, statement, parameters in provider.calls:
        assert method == "execute_returning"
        assert "DELETE FROM" in statement
        assert "WHERE tenant_id = %s" in statement
        assert parameters == ("tenant-a",)

    assert audit.export_events(tenant_id="tenant-a") == []
    events = audit.export_events(tenant_id=SYSTEM_TENANT_ID)
    assert len(events) == 1
    assert events[0].event_type == TENANT_DATA_DELETION_EVENT
    assert events[0].metadata["actor_id"] == "privacy-admin"
    assert events[0].metadata["deleted_tenant_id"] == "tenant-a"
    assert "tenant_id" not in events[0].metadata


def test_delete_tenant_data_dry_run_counts_without_deleting() -> None:
    provider = CountingSqlProvider(affected_count=4)
    service, _ = _service(provider)

    report = service.delete_tenant_data("tenant-a", dry_run=True)

    assert report.total_affected == 4 * len(POSTGRES_LIFECYCLE_TABLES)
    assert provider.transaction_count == 0
    assert {call[0] for call in provider.calls} == {"fetch_all"}
    assert all("SELECT count(*)" in call[1] and "DELETE FROM" not in call[1] for call in provider.calls)


def test_delete_tenant_data_rejects_reserved_system_tenant() -> None:
    provider = CountingSqlProvider()
    service, audit = _service(provider)

    with pytest.raises(DataLifecycleError, match="reserved system tenant"):
        service.delete_tenant_data(SYSTEM_TENANT_ID)

    assert provider.transaction_count == 0
    assert provider.calls == []
    assert audit.export_events(tenant_id=SYSTEM_TENANT_ID) == []


def test_retention_cli_skips_by_default_without_opening_postgres() -> None:
    result = retention_cli.run_from_env([], env={})

    assert result["status"] == "skipped"
    assert result["operation"] == "execute-retention"


def test_retention_cli_requires_matching_tenant_delete_confirmation() -> None:
    provider = CountingSqlProvider()
    with pytest.raises(ValueError, match="confirm-tenant-id"):
        retention_cli.run_from_env(
            [
                "delete-tenant",
                "--tenant-id",
                "tenant-a",
                "--confirm-tenant-id",
                "tenant-b",
            ],
            env={
                "HALLU_DEFENSE_RETENTION_EXECUTION_ENABLED": "true",
                "HALLU_DEFENSE_TENANT_DATA_DELETION_ENABLED": "true",
            },
            connection=provider,
            audit=AuditLedger(),
        )

    assert provider.calls == []


def test_mutating_retention_commits_deletes_and_audit_in_one_transaction() -> None:
    provider = AtomicSqlProvider()
    service = DataLifecycleService(
        connection=provider,
        audit=AuditLedger(),
        transactional_audit_factory=lambda transaction: AuditLedger(
            storage=PostgresAuditLedgerStorage(connection=transaction)
        ),
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="pgvector",
        clock=lambda: FIXED_NOW,
    )

    report = service.execute_retention(actor_id="operator")

    assert report.total_affected == len(POSTGRES_LIFECYCLE_TABLES)
    assert provider.transaction_count == 1
    assert provider.committed is True
    assert provider.rolled_back is False
    assert sum("DELETE FROM" in statement for _, statement, _ in provider.committed_calls) == len(
        POSTGRES_LIFECYCLE_TABLES
    )
    assert provider.committed_calls[-1][0] == "execute"
    assert "INSERT INTO audit_events" in provider.committed_calls[-1][1]


def test_audit_append_failure_rolls_back_every_lifecycle_delete() -> None:
    provider = AtomicSqlProvider(fail_on="INSERT INTO audit_events")
    service = DataLifecycleService(
        connection=provider,
        audit=AuditLedger(),
        transactional_audit_factory=lambda transaction: AuditLedger(
            storage=PostgresAuditLedgerStorage(connection=transaction)
        ),
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="pgvector",
        clock=lambda: FIXED_NOW,
    )

    with pytest.raises(RuntimeError, match="simulated transaction failure"):
        service.delete_tenant_data("tenant-a")

    assert provider.transaction_count == 1
    assert provider.committed is False
    assert provider.rolled_back is True
    assert provider.committed_calls == []


def test_tenant_deletion_persists_system_owned_audit_in_same_transaction() -> None:
    provider = AtomicSqlProvider()
    service = DataLifecycleService(
        connection=provider,
        audit=AuditLedger(),
        transactional_audit_factory=lambda transaction: AuditLedger(
            storage=PostgresAuditLedgerStorage(connection=transaction)
        ),
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        rag_index_backend="pgvector",
        clock=lambda: FIXED_NOW,
    )

    service.delete_tenant_data("tenant-a", actor_id="privacy-admin")

    audit_method, audit_statement, audit_parameters = provider.committed_calls[-1]
    assert audit_method == "execute"
    assert "INSERT INTO audit_events" in audit_statement
    assert audit_parameters[0] == SYSTEM_TENANT_ID
    payload = json.loads(str(audit_parameters[3]))
    assert payload["tenant_id"] == SYSTEM_TENANT_ID
    assert payload["metadata"]["deleted_tenant_id"] == "tenant-a"
    assert "tenant_id" not in payload["metadata"]


class AtomicSqlProvider:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self._fail_on = fail_on
        self._pending_calls: list[tuple[str, str, tuple[object, ...]]] | None = None
        self.committed_calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.transaction_count = 0
        self.committed = False
        self.rolled_back = False

    @contextmanager
    def transaction(self) -> Iterator[AtomicSqlProvider]:
        self.transaction_count += 1
        self._pending_calls = []
        try:
            yield self
        except Exception:
            self._pending_calls = None
            self.rolled_back = True
            raise
        else:
            self.committed_calls.extend(self._pending_calls)
            self._pending_calls = None
            self.committed = True

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        self._record("execute", statement, parameters)

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self._record("fetch_all", statement, parameters)
        return [{"affected_count": 1}]

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self._record("execute_returning", statement, parameters)
        return [{"affected_count": 1}]

    def _record(
        self,
        method: str,
        statement: str,
        parameters: Sequence[object],
    ) -> None:
        if self._pending_calls is None:
            raise AssertionError("mutating lifecycle SQL must run inside a transaction")
        self._pending_calls.append((method, statement, tuple(parameters)))
        if self._fail_on is not None and self._fail_on in statement:
            raise RuntimeError("simulated transaction failure")
