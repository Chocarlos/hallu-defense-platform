from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from hallu_defense.services.postgres import SqlConnectionProvider
from hallu_defense.services.rag_index import (
    HYBRID_REVISION_LOCK_NAMESPACE,
    PersistentRagDeletionBackend,
    hybrid_tenant_lifecycle_lock_key,
)

RAG_LIFECYCLE_RETENTION = "retention"
RAG_LIFECYCLE_TENANT_DELETION = "tenant_deletion"
RAG_LIFECYCLE_ACTIVE_STATUSES = ("pending", "processing", "external_deleted")
DEFAULT_RAG_LIFECYCLE_BATCH_SIZE = 1000
DEFAULT_RAG_LIFECYCLE_LEASE_SECONDS = 15 * 60
MAX_RAG_LIFECYCLE_TENANT_LOCKS = 10_000


class RagLifecycleCoordinatorError(RuntimeError):
    pass


@dataclass(frozen=True)
class RagLifecycleOperation:
    operation_id: str
    operation_kind: str
    target_tenant_id: str | None
    executed_at: datetime
    evidence_cutoff: datetime | None
    actor_id: str
    trace_id: str
    status: str
    lease_token: str
    external_deleted_count: int = 0


class RagLifecycleCoordinator:
    """Durable coordinator for OpenSearch-first, PostgreSQL-final RAG deletion.

    The journal is committed before the external mutation. A retry reclaims the
    same incomplete operation and replays the idempotent delete/verification
    before PostgreSQL rows and the success audit are committed together.
    """

    def __init__(
        self,
        *,
        connection: SqlConnectionProvider,
        deletion_backend: PersistentRagDeletionBackend,
        clock: Callable[[], datetime] | None = None,
        batch_size: int = DEFAULT_RAG_LIFECYCLE_BATCH_SIZE,
        lease_seconds: int = DEFAULT_RAG_LIFECYCLE_LEASE_SECONDS,
    ) -> None:
        if not 1 <= batch_size <= DEFAULT_RAG_LIFECYCLE_BATCH_SIZE:
            raise RagLifecycleCoordinatorError("RAG lifecycle batch size must be 1..1000.")
        if lease_seconds <= 0:
            raise RagLifecycleCoordinatorError("RAG lifecycle lease must be positive.")
        self._connection = connection
        self._deletion_backend = deletion_backend
        self._clock = clock
        self._batch_size = batch_size
        self._lease_seconds = lease_seconds

    def begin_retention(
        self,
        *,
        operation_id: str,
        executed_at: datetime,
        evidence_cutoff: datetime,
        actor_id: str,
        trace_id: str,
    ) -> RagLifecycleOperation:
        return self._begin(
            operation_id=operation_id,
            operation_kind=RAG_LIFECYCLE_RETENTION,
            target_tenant_id=None,
            executed_at=executed_at,
            evidence_cutoff=evidence_cutoff,
            actor_id=actor_id,
            trace_id=trace_id,
        )

    def begin_tenant_deletion(
        self,
        *,
        operation_id: str,
        tenant_id: str,
        executed_at: datetime,
        actor_id: str,
        trace_id: str,
    ) -> RagLifecycleOperation:
        return self._begin(
            operation_id=operation_id,
            operation_kind=RAG_LIFECYCLE_TENANT_DELETION,
            target_tenant_id=tenant_id,
            executed_at=executed_at,
            evidence_cutoff=None,
            actor_id=actor_id,
            trace_id=trace_id,
        )

    def acquire_target_locks(
        self,
        transaction: SqlConnectionProvider,
        operation: RagLifecycleOperation,
    ) -> None:
        tenant_ids = self._target_tenant_ids(operation)
        for tenant_id in tenant_ids:
            transaction.fetch_all(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (
                    HYBRID_REVISION_LOCK_NAMESPACE
                    + hybrid_tenant_lifecycle_lock_key(tenant_id),
                ),
            )

    def delete_external(
        self,
        transaction: SqlConnectionProvider,
        operation: RagLifecycleOperation,
    ) -> RagLifecycleOperation:
        deleted_count = 0
        try:
            if operation.operation_kind == RAG_LIFECYCLE_TENANT_DELETION:
                tenant_id = operation.target_tenant_id
                if tenant_id is None:
                    raise RagLifecycleCoordinatorError(
                        "Tenant lifecycle operation is missing its target tenant."
                    )
                deleted_count = self._deletion_backend.delete_tenant(
                    tenant_id=tenant_id
                )
            else:
                for tenant_id, evidence_ids in self._target_batches(operation):
                    deleted_count += self._deletion_backend.delete_evidence_ids(
                        tenant_id=tenant_id,
                        evidence_ids=evidence_ids,
                    )
            rows = transaction.execute_returning(
                "UPDATE rag_lifecycle_operations "
                "SET status = 'external_deleted', external_deleted_count = %s, "
                "updated_at = %s "
                "WHERE operation_id = %s AND status = 'processing' "
                "AND lease_token = %s RETURNING operation_id",
                (
                    deleted_count,
                    self._now(),
                    operation.operation_id,
                    operation.lease_token,
                ),
            )
            _require_single_operation_row(rows, "mark external deletion")
        except Exception as exc:
            if isinstance(exc, RagLifecycleCoordinatorError):
                raise
            raise RagLifecycleCoordinatorError(
                "Persistent RAG external deletion failed; PostgreSQL mutation was not started."
            ) from None
        return replace(
            operation,
            status="external_deleted",
            external_deleted_count=deleted_count,
        )

    def record_tenant_deletion_fence(
        self,
        transaction: SqlConnectionProvider,
        operation: RagLifecycleOperation,
    ) -> None:
        """Persist the durable no-reingestion fence in the final SQL transaction."""
        if operation.operation_kind != RAG_LIFECYCLE_TENANT_DELETION:
            return
        tenant_id = operation.target_tenant_id
        if tenant_id is None:
            raise RagLifecycleCoordinatorError(
                "Tenant lifecycle operation is missing its target tenant."
            )
        transaction.execute(
            "INSERT INTO rag_tenant_deletion_tombstones "
            "(tenant_id, operation_id, deleted_at, actor_id, trace_id) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id) DO NOTHING",
            (
                tenant_id,
                operation.operation_id,
                operation.executed_at,
                operation.actor_id,
                operation.trace_id,
            ),
        )

    def mark_completed(
        self,
        transaction: SqlConnectionProvider,
        operation: RagLifecycleOperation,
    ) -> None:
        rows = transaction.execute_returning(
            "UPDATE rag_lifecycle_operations "
            "SET status = 'completed', lease_token = NULL, locked_at = NULL, "
            "last_error_code = NULL, updated_at = %s "
            "WHERE operation_id = %s AND status = 'external_deleted' "
            "AND lease_token = %s RETURNING operation_id",
            (self._now(), operation.operation_id, operation.lease_token),
        )
        _require_single_operation_row(rows, "complete lifecycle operation")

    def _begin(
        self,
        *,
        operation_id: str,
        operation_kind: str,
        target_tenant_id: str | None,
        executed_at: datetime,
        evidence_cutoff: datetime | None,
        actor_id: str,
        trace_id: str,
    ) -> RagLifecycleOperation:
        now = self._now()
        lease_token = f"raglease_{uuid4().hex}"
        lock_scope = f"rag-lifecycle:{operation_kind}:{target_tenant_id or '*'}"
        with self._connection.transaction() as transaction:
            transaction.fetch_all(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (lock_scope,),
            )
            rows = transaction.fetch_all(
                "SELECT operation_id, operation_kind, target_tenant_id, executed_at, "
                "evidence_cutoff, actor_id, trace_id, status, lease_token, locked_at, "
                "external_deleted_count FROM rag_lifecycle_operations "
                "WHERE operation_kind = %s AND target_tenant_id IS NOT DISTINCT FROM %s "
                "AND status IN ('pending', 'processing', 'external_deleted') "
                "ORDER BY created_at ASC, operation_id ASC FOR UPDATE LIMIT 1",
                (operation_kind, target_tenant_id),
            )
            if rows:
                operation, locked_at = _operation_from_row(rows[0])
                if operation.status == "processing" and locked_at is not None:
                    if locked_at > now - timedelta(seconds=self._lease_seconds):
                        raise RagLifecycleCoordinatorError(
                            "A matching persistent RAG lifecycle operation already holds a live lease."
                        )
            else:
                operation = RagLifecycleOperation(
                    operation_id=operation_id,
                    operation_kind=operation_kind,
                    target_tenant_id=target_tenant_id,
                    executed_at=_aware_utc(executed_at, "executed_at"),
                    evidence_cutoff=(
                        _aware_utc(evidence_cutoff, "evidence_cutoff")
                        if evidence_cutoff is not None
                        else None
                    ),
                    actor_id=_required_text(actor_id, "actor_id"),
                    trace_id=_required_text(trace_id, "trace_id"),
                    status="pending",
                    lease_token="",
                )
                transaction.execute(
                    "INSERT INTO rag_lifecycle_operations "
                    "(operation_id, operation_kind, target_tenant_id, executed_at, "
                    "evidence_cutoff, actor_id, trace_id, status, attempts, "
                    "external_deleted_count, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', 0, 0, %s, %s)",
                    (
                        operation.operation_id,
                        operation.operation_kind,
                        operation.target_tenant_id,
                        operation.executed_at,
                        operation.evidence_cutoff,
                        operation.actor_id,
                        operation.trace_id,
                        now,
                        now,
                    ),
                )
            claimed = transaction.execute_returning(
                "UPDATE rag_lifecycle_operations "
                "SET status = 'processing', lease_token = %s, locked_at = %s, "
                "attempts = attempts + 1, last_error_code = NULL, updated_at = %s "
                "WHERE operation_id = %s AND status IN ('pending', 'processing', 'external_deleted') "
                "RETURNING operation_id",
                (lease_token, now, now, operation.operation_id),
            )
            _require_single_operation_row(claimed, "claim lifecycle operation")
        return replace(operation, status="processing", lease_token=lease_token)

    def release_after_failure(self, operation: RagLifecycleOperation, exc: Exception) -> None:
        self._release_after_failure(operation, error_code=type(exc).__name__)

    def _target_tenant_ids(self, operation: RagLifecycleOperation) -> tuple[str, ...]:
        if operation.target_tenant_id is not None:
            return (operation.target_tenant_id,)
        cutoff = operation.evidence_cutoff
        if cutoff is None:
            raise RagLifecycleCoordinatorError(
                "Retention lifecycle operation is missing its evidence cutoff."
            )
        rows = self._connection.fetch_all(
            "SELECT DISTINCT tenant_id FROM rag_evidence_chunks "
            "WHERE updated_at < %s ORDER BY tenant_id ASC LIMIT %s",
            (cutoff, MAX_RAG_LIFECYCLE_TENANT_LOCKS + 1),
        )
        if len(rows) > MAX_RAG_LIFECYCLE_TENANT_LOCKS:
            raise RagLifecycleCoordinatorError(
                "Retention lifecycle operation exceeded its tenant-lock bound."
            )
        tenant_ids = tuple(
            _required_text(row.get("tenant_id"), "tenant_id") for row in rows
        )
        if tenant_ids != tuple(sorted(set(tenant_ids))):
            raise RagLifecycleCoordinatorError(
                "Retention lifecycle tenant lock query was not ordered and unique."
            )
        return tenant_ids

    def _target_batches(
        self,
        operation: RagLifecycleOperation,
    ) -> Iterator[tuple[str, tuple[str, ...]]]:
        last_tenant = ""
        last_evidence = ""
        while True:
            if operation.operation_kind == RAG_LIFECYCLE_RETENTION:
                cutoff = operation.evidence_cutoff
                if cutoff is None:
                    raise RagLifecycleCoordinatorError(
                        "Retention lifecycle operation is missing its evidence cutoff."
                    )
                rows = self._connection.fetch_all(
                    "SELECT tenant_id, evidence_id FROM rag_evidence_chunks "
                    "WHERE updated_at < %s AND (tenant_id, evidence_id) > (%s, %s) "
                    "ORDER BY tenant_id ASC, evidence_id ASC LIMIT %s",
                    (cutoff, last_tenant, last_evidence, self._batch_size),
                )
            elif operation.operation_kind == RAG_LIFECYCLE_TENANT_DELETION:
                tenant_id = operation.target_tenant_id
                if tenant_id is None:
                    raise RagLifecycleCoordinatorError(
                        "Tenant lifecycle operation is missing its target tenant."
                    )
                rows = self._connection.fetch_all(
                    "SELECT tenant_id, evidence_id FROM rag_evidence_chunks "
                    "WHERE tenant_id = %s AND evidence_id > %s "
                    "ORDER BY evidence_id ASC LIMIT %s",
                    (tenant_id, last_evidence, self._batch_size),
                )
            else:
                raise RagLifecycleCoordinatorError("Unsupported RAG lifecycle operation kind.")
            if len(rows) > self._batch_size:
                raise RagLifecycleCoordinatorError(
                    "RAG lifecycle target query exceeded its bounded batch size."
                )
            if not rows:
                return
            grouped: dict[str, list[str]] = defaultdict(list)
            previous = (last_tenant, last_evidence)
            for row in rows:
                tenant_id = _required_text(row.get("tenant_id"), "tenant_id")
                evidence_id = _required_text(row.get("evidence_id"), "evidence_id")
                if operation.target_tenant_id is not None and tenant_id != operation.target_tenant_id:
                    raise RagLifecycleCoordinatorError(
                        "RAG lifecycle target query crossed its tenant boundary."
                    )
                current = (tenant_id, evidence_id)
                if current <= previous:
                    raise RagLifecycleCoordinatorError(
                        "RAG lifecycle target query was not strictly ordered."
                    )
                previous = current
                grouped[tenant_id].append(evidence_id)
            for tenant_id, evidence_ids in grouped.items():
                yield tenant_id, tuple(evidence_ids)
            last_tenant, last_evidence = previous
            if len(rows) < self._batch_size:
                return

    def _release_after_failure(
        self,
        operation: RagLifecycleOperation,
        *,
        error_code: str,
    ) -> None:
        try:
            with self._connection.transaction() as transaction:
                transaction.execute(
                    "UPDATE rag_lifecycle_operations "
                    "SET status = 'pending', lease_token = NULL, locked_at = NULL, "
                    "last_error_code = %s, updated_at = %s "
                    "WHERE operation_id = %s AND lease_token = %s",
                    (
                        error_code[:128],
                        self._now(),
                        operation.operation_id,
                        operation.lease_token,
                    ),
                )
        except Exception:
            return

    def _now(self) -> datetime:
        value = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        return _aware_utc(value, "clock")


def _operation_from_row(
    row: Mapping[str, object],
) -> tuple[RagLifecycleOperation, datetime | None]:
    target = row.get("target_tenant_id")
    cutoff = row.get("evidence_cutoff")
    locked_at = row.get("locked_at")
    deleted = row.get("external_deleted_count", 0)
    if target is not None and not isinstance(target, str):
        raise RagLifecycleCoordinatorError("Lifecycle journal target tenant is invalid.")
    if cutoff is not None and not isinstance(cutoff, datetime):
        raise RagLifecycleCoordinatorError("Lifecycle journal evidence cutoff is invalid.")
    if locked_at is not None and not isinstance(locked_at, datetime):
        raise RagLifecycleCoordinatorError("Lifecycle journal lock timestamp is invalid.")
    if not isinstance(deleted, int) or isinstance(deleted, bool) or deleted < 0:
        raise RagLifecycleCoordinatorError("Lifecycle journal deleted count is invalid.")
    status = _required_text(row.get("status"), "status")
    raw_lease_token = row.get("lease_token")
    if status not in RAG_LIFECYCLE_ACTIVE_STATUSES:
        raise RagLifecycleCoordinatorError("Lifecycle journal status is invalid.")
    operation = RagLifecycleOperation(
        operation_id=_required_text(row.get("operation_id"), "operation_id"),
        operation_kind=_required_text(row.get("operation_kind"), "operation_kind"),
        target_tenant_id=target,
        executed_at=_aware_utc(row.get("executed_at"), "executed_at"),
        evidence_cutoff=(
            _aware_utc(cutoff, "evidence_cutoff") if cutoff is not None else None
        ),
        actor_id=_required_text(row.get("actor_id"), "actor_id"),
        trace_id=_required_text(row.get("trace_id"), "trace_id"),
        status=status,
        lease_token=raw_lease_token if isinstance(raw_lease_token, str) else "",
        external_deleted_count=deleted,
    )
    return operation, _aware_utc(locked_at, "locked_at") if locked_at is not None else None


def _require_single_operation_row(
    rows: Sequence[Mapping[str, object]],
    operation: str,
) -> None:
    if len(rows) != 1 or not isinstance(rows[0].get("operation_id"), str):
        raise RagLifecycleCoordinatorError(
            f"RAG lifecycle journal could not {operation}."
        )


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RagLifecycleCoordinatorError(f"RAG lifecycle {field} must be non-empty text.")
    return value.strip()


def _aware_utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RagLifecycleCoordinatorError(
            f"RAG lifecycle {field} must be timezone-aware."
        )
    return value.astimezone(timezone.utc)
