from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.postgres import SqlConnectionProvider

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
    LifecycleTable("rag_corpus_grants", "approval_records", "inserted_at"),
    LifecycleTable("rag_evidence_chunks", "evidence_indexes", "updated_at"),
    LifecycleTable("eval_reports", "eval_reports", "published_at"),
    LifecycleTable(
        "rag_ingestion_jobs",
        "short_lived_cache",
        "updated_at",
        "status IN ('succeeded', 'failed', 'dead')",
    ),
)


class DataLifecycleService:
    def __init__(
        self,
        *,
        connection: SqlConnectionProvider,
        audit: AuditLedger,
        policy: DataLifecyclePolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._audit = audit
        self._policy = policy
        self._clock = clock

    def execute_retention(
        self,
        *,
        dry_run: bool = False,
        actor_id: str = "system",
        trace_id: str | None = None,
    ) -> RetentionExecutionReport:
        executed_at = self._now()
        run_id = f"ret_{uuid4().hex}"
        table_results: list[TableDeletionResult] = []
        for table in POSTGRES_LIFECYCLE_TABLES:
            retention_days = self._policy.days_for(table.retention_class)
            cutoff = executed_at - timedelta(days=retention_days)
            affected_count = self._count_or_delete_by_cutoff(table, cutoff, dry_run=dry_run)
            table_results.append(
                TableDeletionResult(
                    table=table.name,
                    retention_class=table.retention_class,
                    cutoff=cutoff,
                    affected_count=affected_count,
                    dry_run=dry_run,
                )
            )

        event = self._audit.append_event(
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
        table_results: list[TableDeletionResult] = []
        for table in POSTGRES_LIFECYCLE_TABLES:
            affected_count = self._count_or_delete_by_tenant(
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

        event = self._audit.append_event(
            trace_id=trace_id or run_id,
            tenant_id=normalized_tenant,
            event_type=TENANT_DATA_DELETION_EVENT,
            method="POST",
            path="/internal/data-lifecycle/delete-tenant",
            status_code=200,
            outcome="dry_run" if dry_run else "success",
            metadata={
                "actor_id": actor_id,
                "dry_run": dry_run,
                "run_id": run_id,
                "tenant_id": normalized_tenant,
                "total_affected": sum(result.affected_count for result in table_results),
                "tables": [_table_result_json(result) for result in table_results],
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

    def _count_or_delete_by_cutoff(
        self,
        table: LifecycleTable,
        cutoff: datetime,
        *,
        dry_run: bool,
    ) -> int:
        where = f"{table.timestamp_column} < %s"
        if table.retention_where_sql is not None:
            where = f"{where} AND {table.retention_where_sql}"
        if dry_run:
            rows = self._connection.fetch_all(
                f"SELECT count(*) AS affected_count FROM {table.name} WHERE {where}",
                (cutoff,),
            )
        else:
            rows = self._connection.execute_returning(
                f"WITH deleted AS (DELETE FROM {table.name} WHERE {where} RETURNING 1) "
                "SELECT count(*) AS affected_count FROM deleted",
                (cutoff,),
            )
        return _affected_count(rows, f"{table.name} retention")

    def _count_or_delete_by_tenant(
        self,
        table_name: str,
        tenant_id: str,
        *,
        dry_run: bool,
    ) -> int:
        if dry_run:
            rows = self._connection.fetch_all(
                f"SELECT count(*) AS affected_count FROM {table_name} WHERE tenant_id = %s",
                (tenant_id,),
            )
        else:
            rows = self._connection.execute_returning(
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
    return normalized


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
