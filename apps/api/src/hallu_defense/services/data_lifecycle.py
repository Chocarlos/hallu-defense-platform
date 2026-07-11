from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.postgres import SqlConnectionProvider
from hallu_defense.services.rag_index import PersistentRagDeletionBackend
from hallu_defense.services.rag_lifecycle import (
    RagLifecycleCoordinator,
    RagLifecycleCoordinatorError,
    RagLifecycleOperation,
)

ROOT = Path(__file__).resolve().parents[5]
DEFAULT_POLICY_PATH = ROOT / "infra" / "security" / "backup-retention-policy.json"

RETENTION_EXECUTION_EVENT = "retention_execution"
TENANT_DATA_DELETION_EVENT = "tenant_data_deletion"
SYSTEM_TENANT_ID = "system"


class DataLifecycleError(RuntimeError):
    pass


class DataLifecyclePolicyError(DataLifecycleError):
    pass


@dataclass(frozen=True)
class LifecycleTable:
    name: str
    retention_class: str
    timestamp_column: str
    retention_where_sql: str | None = None


@dataclass(frozen=True)
class TableDeletionResult:
    table: str
    retention_class: str | None
    cutoff: datetime | None
    affected_count: int
    dry_run: bool


@dataclass(frozen=True)
class RetentionExecutionReport:
    run_id: str
    dry_run: bool
    executed_at: datetime
    tables: tuple[TableDeletionResult, ...]
    audit_event_id: str

    @property
    def total_affected(self) -> int:
        return sum(table.affected_count for table in self.tables)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "dry_run": self.dry_run,
            "executed_at": self.executed_at.isoformat(),
            "total_affected": self.total_affected,
            "audit_event_id": self.audit_event_id,
            "tables": [_table_result_json(table) for table in self.tables],
        }


@dataclass(frozen=True)
class TenantDeletionReport:
    run_id: str
    tenant_id: str
    dry_run: bool
    executed_at: datetime
    tables: tuple[TableDeletionResult, ...]
    audit_event_id: str

    @property
    def total_affected(self) -> int:
        return sum(table.affected_count for table in self.tables)

    def to_json_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "dry_run": self.dry_run,
            "executed_at": self.executed_at.isoformat(),
            "total_affected": self.total_affected,
            "audit_event_id": self.audit_event_id,
            "tables": [_table_result_json(table) for table in self.tables],
        }


@dataclass(frozen=True)
class DataLifecyclePolicy:
    class_minimum_days: Mapping[str, int]
    postgres_retention_days: Mapping[str, int]

    @classmethod
    def from_path(cls, path: Path = DEFAULT_POLICY_PATH) -> DataLifecyclePolicy:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise DataLifecyclePolicyError("backup-retention-policy.json must contain an object.")
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> DataLifecyclePolicy:
        if payload.get("schema_version") != "backup-retention-policy.v1":
            raise DataLifecyclePolicyError(
                "backup-retention-policy.json schema_version must be backup-retention-policy.v1."
            )
        retention_classes = _mapping(payload.get("retention_classes"), "retention_classes")
        components = _mapping(payload.get("components"), "components")
        postgres = _mapping(components.get("postgres"), "components.postgres")
        retention = _mapping(postgres.get("retention"), "components.postgres.retention")
        configured_classes = _mapping(
            retention.get("classes"),
            "components.postgres.retention.classes",
        )

        class_minimum_days = {
            class_name: _positive_int(
                _mapping(class_config, f"retention_classes.{class_name}").get("minimum_days"),
                f"retention_classes.{class_name}.minimum_days",
            )
            for class_name, class_config in retention_classes.items()
            if isinstance(class_name, str)
        }
        postgres_retention_days: dict[str, int] = {}
        for class_name, class_policy in configured_classes.items():
            if not isinstance(class_name, str):
                raise DataLifecyclePolicyError("retention class names must be strings.")
            class_days = _positive_int(
                _mapping(class_policy, f"components.postgres.retention.classes.{class_name}").get(
                    "days"
                ),
                f"components.postgres.retention.classes.{class_name}.days",
            )
            minimum_days = class_minimum_days.get(class_name)
            if minimum_days is None:
                raise DataLifecyclePolicyError(
                    f"components.postgres.retention.classes.{class_name} is unknown."
                )
            if class_days < minimum_days:
                raise DataLifecyclePolicyError(
                    f"components.postgres.retention.classes.{class_name}.days "
                    f"must be at least retention_classes.{class_name}.minimum_days ({minimum_days})."
                )
            postgres_retention_days[class_name] = class_days

        missing_classes = sorted({
            table.retention_class
            for table in POSTGRES_LIFECYCLE_TABLES
            if table.retention_class not in postgres_retention_days
        })
        if missing_classes:
            raise DataLifecyclePolicyError(
                "components.postgres.retention.classes missing runtime classes: "
                + ", ".join(missing_classes)
            )

        return cls(
            class_minimum_days=class_minimum_days,
            postgres_retention_days=postgres_retention_days,
        )

    def days_for(self, retention_class: str) -> int:
        try:
            return self.postgres_retention_days[retention_class]
        except KeyError as exc:
            raise DataLifecyclePolicyError(
                f"No Postgres retention days configured for {retention_class!r}."
            ) from exc


# Literal table metadata only. These names come from committed migrations and
# are never derived from user input.
POSTGRES_LIFECYCLE_TABLES: tuple[LifecycleTable, ...] = (
    LifecycleTable("audit_events", "audit_ledger", "created_at"),
    LifecycleTable("audit_runs", "verification_runs", "created_at"),
    LifecycleTable("approval_execution_grants", "approval_records", "created_at"),
    LifecycleTable("approval_records", "approval_records", "created_at"),
    LifecycleTable(
        "rag_corpus_grants",
        "approval_records",
        "inserted_at",
        "EXISTS ("
        "SELECT 1 FROM rag_corpus_grants AS newer "
        "WHERE newer.tenant_id = rag_corpus_grants.tenant_id "
        "AND newer.corpus_id = rag_corpus_grants.corpus_id "
        "AND newer.version > rag_corpus_grants.version"
        ")",
    ),
    LifecycleTable("rag_evidence_chunks", "evidence_indexes", "updated_at"),
    LifecycleTable("eval_reports", "eval_reports", "published_at"),
    LifecycleTable(
        "rag_ingestion_jobs",
        "short_lived_cache",
        "updated_at",
        "status IN ('succeeded', 'dead')",
    ),
)


class DataLifecycleService:
    def __init__(
        self,
        *,
        connection: SqlConnectionProvider,
        audit: AuditLedger,
        transactional_audit_factory: Callable[[SqlConnectionProvider], AuditLedger],
        policy: DataLifecyclePolicy,
        rag_index_backend: str,
        rag_deletion_backend: PersistentRagDeletionBackend | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._audit = audit
        self._transactional_audit_factory = transactional_audit_factory
        self._policy = policy
        self._rag_index_backend = rag_index_backend.strip().lower()
        self._clock = clock
        self._rag_lifecycle = (
            RagLifecycleCoordinator(
                connection=connection,
                deletion_backend=rag_deletion_backend,
                clock=clock,
            )
            if rag_deletion_backend is not None
            else None
        )

    def execute_retention(
        self,
        *,
        dry_run: bool = False,
        actor_id: str = "system",
        trace_id: str | None = None,
    ) -> RetentionExecutionReport:
        executed_at = self._now()
        run_id = f"ret_{uuid4().hex}"
        if dry_run:
            return self._execute_retention(
                connection=self._connection,
                audit=self._audit,
                executed_at=executed_at,
                run_id=run_id,
                dry_run=True,
                actor_id=actor_id,
                trace_id=trace_id,
            )
        coordinator = self._coordinated_persistent_rag_deletion()
        if coordinator is None:
            with self._connection.transaction() as transaction:
                return self._execute_retention(
                    connection=transaction,
                    audit=self._transactional_audit_factory(transaction),
                    executed_at=executed_at,
                    run_id=run_id,
                    dry_run=False,
                    actor_id=actor_id,
                    trace_id=trace_id,
                )
        try:
            operation = coordinator.begin_retention(
                operation_id=run_id,
                executed_at=executed_at,
                evidence_cutoff=(
                    executed_at
                    - timedelta(days=self._policy.days_for("evidence_indexes"))
                ),
                actor_id=actor_id,
                trace_id=trace_id or run_id,
            )
        except RagLifecycleCoordinatorError:
            raise DataLifecycleError(
                "Coordinated persistent RAG retention could not acquire its journal lease."
            ) from None
        try:
            with self._connection.transaction() as transaction:
                coordinator.acquire_target_locks(transaction, operation)
                operation = coordinator.delete_external(transaction, operation)
                report = self._execute_retention(
                    connection=transaction,
                    audit=self._transactional_audit_factory(transaction),
                    executed_at=operation.executed_at,
                    run_id=operation.operation_id,
                    dry_run=False,
                    actor_id=operation.actor_id,
                    trace_id=operation.trace_id,
                    rag_operation=operation,
                )
                coordinator.mark_completed(transaction, operation)
            return report
        except Exception as exc:
            coordinator.release_after_failure(operation, exc)
            if isinstance(exc, DataLifecycleError):
                raise
            raise DataLifecycleError(
                "Coordinated persistent RAG retention failed without a success audit."
            ) from None

    def _execute_retention(
        self,
        *,
        connection: SqlConnectionProvider,
        audit: AuditLedger,
        executed_at: datetime,
        run_id: str,
        dry_run: bool,
        actor_id: str,
        trace_id: str | None,
        rag_operation: RagLifecycleOperation | None = None,
    ) -> RetentionExecutionReport:
        table_results: list[TableDeletionResult] = []
        for table in POSTGRES_LIFECYCLE_TABLES:
            retention_days = self._policy.days_for(table.retention_class)
            cutoff = executed_at - timedelta(days=retention_days)
            affected_count = self._count_or_delete_by_cutoff(
                connection,
                table,
                cutoff,
                dry_run=dry_run,
            )
            table_results.append(
                TableDeletionResult(
                    table=table.name,
                    retention_class=table.retention_class,
                    cutoff=cutoff,
                    affected_count=affected_count,
                    dry_run=dry_run,
                )
            )

        event = audit.append_event(
            trace_id=trace_id or run_id,
            tenant_id=SYSTEM_TENANT_ID,
            event_type=RETENTION_EXECUTION_EVENT,
            method="POST",
            path="/internal/data-lifecycle/retention",
            status_code=200,
            outcome="dry_run" if dry_run else "success",
            metadata={
                "actor_id": actor_id,
                "dry_run": dry_run,
                "run_id": run_id,
                "total_affected": sum(result.affected_count for result in table_results),
                "tables": [_table_result_json(result) for result in table_results],
                **_rag_operation_metadata(rag_operation),
            },
        )
        return RetentionExecutionReport(
            run_id=run_id,
            dry_run=dry_run,
            executed_at=executed_at,
            tables=tuple(table_results),
            audit_event_id=event.event_id,
        )

    def delete_tenant_data(
        self,
        tenant_id: str,
        *,
        dry_run: bool = False,
        actor_id: str = "system",
        trace_id: str | None = None,
    ) -> TenantDeletionReport:
        normalized_tenant = _validate_tenant_id(tenant_id)
        executed_at = self._now()
        run_id = f"tdel_{uuid4().hex}"
        if dry_run:
            return self._delete_tenant_data(
                connection=self._connection,
                audit=self._audit,
                normalized_tenant=normalized_tenant,
                executed_at=executed_at,
                run_id=run_id,
                dry_run=True,
                actor_id=actor_id,
                trace_id=trace_id,
            )
        coordinator = self._coordinated_persistent_rag_deletion()
        if coordinator is None:
            with self._connection.transaction() as transaction:
                return self._delete_tenant_data(
                    connection=transaction,
                    audit=self._transactional_audit_factory(transaction),
                    normalized_tenant=normalized_tenant,
                    executed_at=executed_at,
                    run_id=run_id,
                    dry_run=False,
                    actor_id=actor_id,
                    trace_id=trace_id,
                )
        try:
            operation = coordinator.begin_tenant_deletion(
                operation_id=run_id,
                tenant_id=normalized_tenant,
                executed_at=executed_at,
                actor_id=actor_id,
                trace_id=trace_id or run_id,
            )
        except RagLifecycleCoordinatorError:
            raise DataLifecycleError(
                "Coordinated persistent RAG tenant deletion could not acquire its journal lease."
            ) from None
        try:
            with self._connection.transaction() as transaction:
                coordinator.acquire_target_locks(transaction, operation)
                operation = coordinator.delete_external(transaction, operation)
                coordinator.record_tenant_deletion_fence(transaction, operation)
                report = self._delete_tenant_data(
                    connection=transaction,
                    audit=self._transactional_audit_factory(transaction),
                    normalized_tenant=normalized_tenant,
                    executed_at=operation.executed_at,
                    run_id=operation.operation_id,
                    dry_run=False,
                    actor_id=operation.actor_id,
                    trace_id=operation.trace_id,
                    rag_operation=operation,
                )
                coordinator.mark_completed(transaction, operation)
            return report
        except Exception as exc:
            coordinator.release_after_failure(operation, exc)
            if isinstance(exc, DataLifecycleError):
                raise
            raise DataLifecycleError(
                "Coordinated persistent RAG tenant deletion failed without a success audit."
            ) from None

    def _delete_tenant_data(
        self,
        *,
        connection: SqlConnectionProvider,
        audit: AuditLedger,
        normalized_tenant: str,
        executed_at: datetime,
        run_id: str,
        dry_run: bool,
        actor_id: str,
        trace_id: str | None,
        rag_operation: RagLifecycleOperation | None = None,
    ) -> TenantDeletionReport:
        table_results: list[TableDeletionResult] = []
        for table in POSTGRES_LIFECYCLE_TABLES:
            affected_count = self._count_or_delete_by_tenant(
                connection,
                table.name,
                normalized_tenant,
                dry_run=dry_run,
            )
            table_results.append(
                TableDeletionResult(
                    table=table.name,
                    retention_class=None,
                    cutoff=None,
                    affected_count=affected_count,
                    dry_run=dry_run,
                )
            )

        event = audit.append_event(
            trace_id=trace_id or run_id,
            tenant_id=SYSTEM_TENANT_ID,
            event_type=TENANT_DATA_DELETION_EVENT,
            method="POST",
            path="/internal/data-lifecycle/delete-tenant",
            status_code=200,
            outcome="dry_run" if dry_run else "success",
            metadata={
                "actor_id": actor_id,
                "dry_run": dry_run,
                "run_id": run_id,
                "deleted_tenant_id": normalized_tenant,
                "total_affected": sum(result.affected_count for result in table_results),
                "tables": [_table_result_json(result) for result in table_results],
                **_rag_operation_metadata(rag_operation),
            },
        )
        return TenantDeletionReport(
            run_id=run_id,
            tenant_id=normalized_tenant,
            dry_run=dry_run,
            executed_at=executed_at,
            tables=tuple(table_results),
            audit_event_id=event.event_id,
        )

    def _coordinated_persistent_rag_deletion(
        self,
    ) -> RagLifecycleCoordinator | None:
        if self._rag_index_backend == "opensearch":
            raise DataLifecycleError(
                "Non-dry lifecycle mutation is blocked for OpenSearch-only RAG because "
                "there is no authoritative PostgreSQL parity catalog from which to "
                "enumerate every external evidence ID. Use the hybrid backend."
            )
        if self._rag_index_backend != "hybrid":
            return None
        if self._rag_lifecycle is None:
            raise DataLifecycleError(
                "Non-dry lifecycle mutation is blocked for hybrid/OpenSearch RAG without "
                "the coordinated cross-store deletion journal and parity backend."
            )
        return self._rag_lifecycle

    def _count_or_delete_by_cutoff(
        self,
        connection: SqlConnectionProvider,
        table: LifecycleTable,
        cutoff: datetime,
        *,
        dry_run: bool,
    ) -> int:
        where = f"{table.timestamp_column} < %s"
        if table.retention_where_sql is not None:
            where = f"{where} AND {table.retention_where_sql}"
        if dry_run:
            rows = connection.fetch_all(
                f"SELECT count(*) AS affected_count FROM {table.name} WHERE {where}",
                (cutoff,),
            )
        else:
            rows = connection.execute_returning(
                f"WITH deleted AS (DELETE FROM {table.name} WHERE {where} RETURNING 1) "
                "SELECT count(*) AS affected_count FROM deleted",
                (cutoff,),
            )
        return _affected_count(rows, f"{table.name} retention")

    def _count_or_delete_by_tenant(
        self,
        connection: SqlConnectionProvider,
        table_name: str,
        tenant_id: str,
        *,
        dry_run: bool,
    ) -> int:
        if dry_run:
            rows = connection.fetch_all(
                f"SELECT count(*) AS affected_count FROM {table_name} WHERE tenant_id = %s",
                (tenant_id,),
            )
        else:
            rows = connection.execute_returning(
                f"WITH deleted AS (DELETE FROM {table_name} WHERE tenant_id = %s RETURNING 1) "
                "SELECT count(*) AS affected_count FROM deleted",
                (tenant_id,),
            )
        return _affected_count(rows, f"{table_name} tenant deletion")

    def _now(self) -> datetime:
        if self._clock is not None:
            current = self._clock()
            return _utc(current)
        return datetime.now(timezone.utc)


def load_data_lifecycle_policy(path: Path = DEFAULT_POLICY_PATH) -> DataLifecyclePolicy:
    return DataLifecyclePolicy.from_path(path)


def _table_result_json(result: TableDeletionResult) -> dict[str, object]:
    return {
        "table": result.table,
        "retention_class": result.retention_class,
        "cutoff": result.cutoff.isoformat() if result.cutoff is not None else None,
        "affected_count": result.affected_count,
        "dry_run": result.dry_run,
    }


def _rag_operation_metadata(
    operation: RagLifecycleOperation | None,
) -> dict[str, object]:
    if operation is None:
        return {}
    return {
        "rag_lifecycle_operation_id": operation.operation_id,
        "rag_external_deleted_count": operation.external_deleted_count,
        "rag_external_parity_verified": True,
        "rag_tenant_deletion_fence_committed": (
            operation.operation_kind == "tenant_deletion"
        ),
    }


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    raise DataLifecyclePolicyError(f"{path} must be an object.")


def _positive_int(value: object, path: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    raise DataLifecyclePolicyError(f"{path} must be a positive integer.")


def _affected_count(rows: Sequence[Mapping[str, object]], label: str) -> int:
    if len(rows) != 1:
        raise DataLifecycleError(f"{label} must return exactly one affected_count row.")
    value = rows[0].get("affected_count")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    raise DataLifecycleError(f"{label} returned invalid affected_count.")


def _validate_tenant_id(tenant_id: str) -> str:
    normalized = tenant_id.strip()
    if not normalized:
        raise DataLifecycleError("tenant_id must be non-empty.")
    if len(normalized) > 256:
        raise DataLifecycleError("tenant_id is too long.")
    if normalized == SYSTEM_TENANT_ID:
        raise DataLifecycleError("The reserved system tenant cannot be deleted.")
    return normalized


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
