from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.data_lifecycle import (
    SYSTEM_TENANT_ID,
    DataLifecycleError,
    DataLifecyclePolicy,
    DataLifecycleService,
)
from scripts.ci.check_backup_retention_config import POLICY_PATH, load_policy

FIXED_NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


class RecordingDeletionBackend:
    def __init__(self, events: list[str], *, error: Exception | None = None) -> None:
        self.events = events
        self.error = error
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.tenant_calls: list[str] = []

    def delete_tenant(self, *, tenant_id: str) -> int:
        self.events.append(f"external:{tenant_id}")
        self.tenant_calls.append(tenant_id)
        if self.error is not None:
            raise self.error
        return 2

    def delete_evidence_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> int:
        self.events.append(f"external:{tenant_id}")
        self.calls.append((tenant_id, tuple(evidence_ids)))
        if self.error is not None:
            raise self.error
        return len(evidence_ids)


class StatefulLifecycleSqlProvider:
    def __init__(self, evidence: Sequence[Mapping[str, object]]) -> None:
        self.evidence = [dict(row) for row in evidence]
        self.journal: dict[str, object] | None = None
        self.tombstones: dict[str, str] = {}
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.events: list[str] = []
        self.transaction_count = 0

    @contextmanager
    def transaction(self) -> Iterator[StatefulLifecycleSqlProvider]:
        self.transaction_count += 1
        self.events.append("transaction-enter")
        try:
            yield self
        finally:
            self.events.append("transaction-exit")

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        values = tuple(parameters)
        self.calls.append(("execute", statement, values))
        if statement.startswith("INSERT INTO rag_lifecycle_operations"):
            self.journal = {
                "operation_id": values[0],
                "operation_kind": values[1],
                "target_tenant_id": values[2],
                "executed_at": values[3],
                "evidence_cutoff": values[4],
                "actor_id": values[5],
                "trace_id": values[6],
                "status": "pending",
                "attempts": 0,
                "lease_token": None,
                "locked_at": None,
                "external_deleted_count": 0,
                "created_at": values[7],
                "updated_at": values[8],
            }
        elif statement.startswith("INSERT INTO rag_tenant_deletion_tombstones"):
            tenant_id = str(values[0])
            self.tombstones.setdefault(tenant_id, str(values[1]))
            self.events.append(f"tombstone:{tenant_id}")
        elif "SET status = 'pending'" in statement:
            assert self.journal is not None
            self.journal.update(
                {
                    "status": "pending",
                    "lease_token": None,
                    "locked_at": None,
                    "last_error_code": values[0],
                    "updated_at": values[1],
                }
            )

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        values = tuple(parameters)
        self.calls.append(("fetch_all", statement, values))
        if "pg_advisory_xact_lock" in statement:
            scope = str(values[0])
            self.events.append(f"lock:{scope}")
            return [{"locked": True}]
        if "FROM rag_lifecycle_operations" in statement:
            if self.journal is None:
                return []
            if self.journal["status"] not in {"pending", "processing", "external_deleted"}:
                return []
            if (
                self.journal["operation_kind"] != values[0]
                or self.journal["target_tenant_id"] != values[1]
            ):
                return []
            return [dict(self.journal)]
        if statement.startswith("SELECT DISTINCT tenant_id"):
            cutoff = cast(datetime, values[0])
            tenant_ids = sorted(
                {
                    str(row["tenant_id"])
                    for row in self.evidence
                    if cast(datetime, row["updated_at"]) < cutoff
                }
            )
            return [{"tenant_id": tenant_id} for tenant_id in tenant_ids]
        if statement.startswith("SELECT tenant_id, evidence_id"):
            if "updated_at < %s" in statement:
                cutoff = cast(datetime, values[0])
                cursor = (str(values[1]), str(values[2]))
                limit = int(values[3])
                rows = [
                    row
                    for row in self.evidence
                    if cast(datetime, row["updated_at"]) < cutoff
                    and (str(row["tenant_id"]), str(row["evidence_id"])) > cursor
                ]
            else:
                tenant_id = str(values[0])
                last_evidence_id = str(values[1])
                limit = int(values[2])
                rows = [
                    row
                    for row in self.evidence
                    if row["tenant_id"] == tenant_id
                    and str(row["evidence_id"]) > last_evidence_id
                ]
            return sorted(
                rows,
                key=lambda row: (str(row["tenant_id"]), str(row["evidence_id"])),
            )[:limit]
        if statement.startswith("SELECT count(*) AS affected_count"):
            return [{"affected_count": 0}]
        raise AssertionError(f"unexpected fetch SQL: {statement}")

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        values = tuple(parameters)
        self.calls.append(("execute_returning", statement, values))
        if statement.startswith("UPDATE rag_lifecycle_operations"):
            assert self.journal is not None
            if "SET status = 'processing'" in statement:
                self.journal.update(
                    {
                        "status": "processing",
                        "lease_token": values[0],
                        "locked_at": values[1],
                        "attempts": int(self.journal["attempts"]) + 1,
                        "updated_at": values[2],
                    }
                )
            elif "SET status = 'external_deleted'" in statement:
                if self.journal["lease_token"] != values[3]:
                    return []
                self.journal.update(
                    {
                        "status": "external_deleted",
                        "external_deleted_count": values[0],
                        "updated_at": values[1],
                    }
                )
            elif "SET status = 'completed'" in statement:
                if self.journal["lease_token"] != values[2]:
                    return []
                self.journal.update(
                    {
                        "status": "completed",
                        "lease_token": None,
                        "locked_at": None,
                        "updated_at": values[0],
                    }
                )
            return [{"operation_id": self.journal["operation_id"]}]
        if "WITH deleted AS (DELETE FROM" in statement:
            table_name = statement.split("DELETE FROM ", 1)[1].split(" WHERE ", 1)[0]
            self.events.append(f"sql-delete:{table_name}")
            if table_name != "rag_evidence_chunks":
                return [{"affected_count": 0}]
            original = len(self.evidence)
            if "tenant_id = %s" in statement:
                tenant_id = str(values[0])
                self.evidence = [
                    row for row in self.evidence if row["tenant_id"] != tenant_id
                ]
            else:
                cutoff = cast(datetime, values[0])
                self.evidence = [
                    row
                    for row in self.evidence
                    if cast(datetime, row["updated_at"]) >= cutoff
                ]
            return [{"affected_count": original - len(self.evidence)}]
        raise AssertionError(f"unexpected returning SQL: {statement}")


def _evidence(tenant_id: str, evidence_id: str, updated_at: datetime) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "evidence_id": evidence_id,
        "updated_at": updated_at,
    }


def _service(
    provider: StatefulLifecycleSqlProvider,
    backend: RecordingDeletionBackend,
) -> tuple[DataLifecycleService, AuditLedger]:
    audit = AuditLedger()
    return (
        DataLifecycleService(
            connection=provider,
            audit=audit,
            transactional_audit_factory=lambda _transaction: audit,
            policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
            rag_index_backend="hybrid",
            rag_deletion_backend=backend,
            clock=lambda: FIXED_NOW,
        ),
        audit,
    )


def test_hybrid_tenant_deletion_journals_locks_verifies_then_commits() -> None:
    provider = StatefulLifecycleSqlProvider(
        [
            _evidence("tenant-a", "ev-a", FIXED_NOW),
            _evidence("tenant-a", "ev-b", FIXED_NOW),
            _evidence("tenant-b", "ev-c", FIXED_NOW),
        ]
    )
    backend = RecordingDeletionBackend(provider.events)
    service, audit = _service(provider, backend)

    report = service.delete_tenant_data("tenant-a", actor_id="privacy-admin")

    assert backend.tenant_calls == ["tenant-a"]
    assert backend.calls == []
    assert [(row["tenant_id"], row["evidence_id"]) for row in provider.evidence] == [
        ("tenant-b", "ev-c")
    ]
    assert provider.journal is not None
    assert provider.journal["status"] == "completed"
    assert provider.journal["external_deleted_count"] == 2
    assert provider.tombstones == {"tenant-a": report.run_id}
    tenant_lock_index = next(
        index
        for index, event in enumerate(provider.events)
        if event.startswith('lock:hybrid_revision_v1:["tenant-a"')
    )
    assert tenant_lock_index < provider.events.index("external:tenant-a")
    assert provider.events.index("external:tenant-a") < provider.events.index(
        "tombstone:tenant-a"
    )
    assert provider.events.index("tombstone:tenant-a") < provider.events.index(
        "sql-delete:rag_evidence_chunks"
    )
    event = audit.export_events(tenant_id=SYSTEM_TENANT_ID)[0]
    assert event.metadata["rag_external_deleted_count"] == 2
    assert event.metadata["rag_external_parity_verified"] is True
    assert event.metadata["rag_tenant_deletion_fence_committed"] is True
    assert event.metadata["rag_lifecycle_operation_id"] == report.run_id


def test_hybrid_retention_deletes_only_expired_ids_from_both_stores() -> None:
    old = FIXED_NOW - timedelta(days=91)
    fresh = FIXED_NOW - timedelta(days=89)
    provider = StatefulLifecycleSqlProvider(
        [
            _evidence("tenant-a", "ev-old-a", old),
            _evidence("tenant-a", "ev-fresh", fresh),
            _evidence("tenant-b", "ev-old-b", old),
        ]
    )
    backend = RecordingDeletionBackend(provider.events)
    service, _audit = _service(provider, backend)

    service.execute_retention(actor_id="retention-operator")

    assert backend.calls == [
        ("tenant-a", ("ev-old-a",)),
        ("tenant-b", ("ev-old-b",)),
    ]
    assert [(row["tenant_id"], row["evidence_id"]) for row in provider.evidence] == [
        ("tenant-a", "ev-fresh")
    ]
    assert provider.journal is not None
    assert provider.journal["status"] == "completed"


def test_hybrid_external_failure_releases_journal_without_sql_or_success_audit() -> None:
    provider = StatefulLifecycleSqlProvider(
        [_evidence("tenant-a", "ev-a", FIXED_NOW)]
    )
    sentinel = "https://search.example/private?credential=secret"
    backend = RecordingDeletionBackend(provider.events, error=RuntimeError(sentinel))
    service, audit = _service(provider, backend)

    with pytest.raises(DataLifecycleError, match="without a success audit") as exc_info:
        service.delete_tenant_data("tenant-a")

    assert sentinel not in str(exc_info.value)
    assert provider.journal is not None
    assert provider.journal["status"] == "pending"
    assert provider.journal["last_error_code"] == "RagLifecycleCoordinatorError"
    assert not any(event.startswith("sql-delete:") for event in provider.events)
    assert provider.tombstones == {}
    assert audit.export_events(tenant_id=SYSTEM_TENANT_ID) == []
