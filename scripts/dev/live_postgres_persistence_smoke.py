"""Live PostgreSQL persistence smoke for the durable audit ledger and approvals.

This mirrors ``scripts/dev/live_pgvector_rag_smoke.py``: skip-by-default, DSN
redacted in every output, self-cleaning, and driven end-to-end offline by an
injected fake connection so the module is exercised without a database. The
real (``ENABLED_ENV=true``) path is live-pending: it needs a Postgres reachable
at the DSN and is validated in an environment with Docker/pgvector.

What the enabled path proves against a real database:

1. Migrations apply cleanly (``apply_migrations`` over the pgvector schema).
2. Audit atomicity and idempotence: a sequential retry and concurrent callers
   persist exactly one run/completion pair and return the canonical event ID.
3. Audit multi-tenant isolation: completion pairs written for two smoke tenants
   are only ever returned to their own tenant on export (the storage WHERE
   clause, not the process, enforces the boundary).
4. Grant single-use under concurrency: one execution grant, two threads racing
   to consume it -- exactly one wins and the other is rejected with
   ``ApprovalExecutionGrantConsumedError`` (the ``UPDATE ... consumed_at IS NULL
   ... RETURNING`` guard is the invariant).

Connection strategy for the live path
-------------------------------------
Migrations run through :class:`PsycopgMigrationConnection` because
``apply_migrations`` hands whole (multi-statement) files to a *parameter-less*
``execute`` -- psycopg only runs every statement of a query when no parameters
are bound. Audit and approval storage run through a single shared
:class:`PooledPostgresProvider` so both racing threads contend on the same pool
and the database enforces the atomic guard.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.domain.models import (  # noqa: E402
    ApprovalDecision,
    ApprovalDecisionRequest,
    AuditEvent,
    Authority,
    Claim,
    ClaimVerdict,
    Evidence,
    EvidenceKind,
    FinalDecision,
    Freshness,
    RiskLevel,
    StalenessClass,
    ToolCallEnvelope,
    VerdictAction,
    VerdictStatus,
    VerificationRun,
)
from hallu_defense.services.approvals import (  # noqa: E402
    ApprovalExecutionGrantConsumedError,
    ApprovalQueue,
    PostgresApprovalQueueStorage,
)
from hallu_defense.services.audit import (  # noqa: E402
    AuditLedger,
    CompletedVerificationRecord,
    PostgresAuditLedgerStorage,
)
from hallu_defense.services.postgres import (  # noqa: E402
    PooledPostgresProvider,
    SqlConnectionProvider,
)
from hallu_defense.services.tool_definitions import (  # noqa: E402
    TrustedToolDefinition,
    TrustedToolRegistry,
)
from scripts.dev.apply_postgres_migrations import (  # noqa: E402
    MIGRATIONS_DIR,
    MigrationConnection,
    PsycopgMigrationConnection,
    apply_migrations,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_POSTGRES_PERSISTENCE_SMOKE_ENABLED"
DSN_ENV = "HALLU_DEFENSE_POSTGRES_DSN"

DEFAULT_DSN = "postgresql://hallu:hallu@localhost:5432/hallu_defense"
SMOKE_KIND = "live_postgres_persistence_smoke"
SMOKE_TENANT_PREFIX = "tenant-live-pg-persist-smoke"
SMOKE_TOOL_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {"scope": {"type": "string", "minLength": 1}},
    "required": ["scope"],
    "additionalProperties": False,
}
# Table names are frozen literal constants (never derived from input), so the
# scoped cleanup DELETEs below are safe to build without identifier validation.
CLEANUP_TABLES = (
    "audit_events",
    "audit_runs",
    "approval_execution_grants",
    "approval_records",
)
GRANT_RACE_WORKERS = 2
AUDIT_RACE_WORKERS = 4
RACE_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class LivePostgresPersistenceSmokeConfig:
    dsn: str


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    connection: SqlConnectionProvider | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env or os.environ
    dsn = effective_env.get(DSN_ENV, DEFAULT_DSN).strip() or DEFAULT_DSN

    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live postgres persistence smoke",
            "dsn": _redact_dsn(dsn),
            "schema_ready": False,
            "tenant_isolation": False,
            "audit_retry_exactly_once": False,
            "audit_race_exactly_once": False,
            "grant_race_single_success": False,
        }

    config = LivePostgresPersistenceSmokeConfig(dsn=dsn)
    return run_live_smoke(config, connection=connection, run_id=run_id)


def run_live_smoke(
    config: LivePostgresPersistenceSmokeConfig,
    *,
    connection: SqlConnectionProvider | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    smoke_run_id = run_id or uuid.uuid4().hex[:12]
    tenants = _smoke_tenants(smoke_run_id)

    sql_connection: SqlConnectionProvider
    migration_connection: MigrationConnection
    if connection is not None:
        sql_connection = connection
        migration_connection = connection
        should_close = False
    else:
        sql_connection = PooledPostgresProvider(dsn=config.dsn)
        migration_connection = PsycopgMigrationConnection(dsn=config.dsn)
        should_close = True

    schema_ready = False
    try:
        apply_migrations(migration_connection, migrations_dir=MIGRATIONS_DIR)
        schema_ready = True
        # Clear any leftover smoke rows from a prior aborted run before writing.
        _cleanup_smoke_rows(sql_connection, tenants)

        audit_result = _run_audit_isolation(sql_connection, tenants, smoke_run_id)
        grant_race_single_success = _run_grant_race(
            sql_connection, tenants[0], smoke_run_id
        )
        return {
            "status": "passed",
            "dsn": _redact_dsn(config.dsn),
            "schema_ready": True,
            **audit_result,
            "grant_race_single_success": grant_race_single_success,
        }
    finally:
        try:
            if schema_ready:
                _cleanup_smoke_rows(sql_connection, tenants)
        finally:
            if should_close:
                _close_if_possible(sql_connection)
                _close_if_possible(migration_connection)


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    connection: SqlConnectionProvider | None = None,
) -> int:
    del argv
    try:
        result = run_from_env(env, connection=connection)
    except Exception as exc:
        result = {
            "status": "failed",
            "error": str(exc),
            "schema_ready": False,
            "tenant_isolation": False,
            "audit_retry_exactly_once": False,
            "audit_race_exactly_once": False,
            "grant_race_single_success": False,
        }
        print(_json_result(result))
        return 1
    print(_json_result(result))
    return 0


def _run_audit_isolation(
    connection: SqlConnectionProvider,
    tenants: tuple[str, str],
    run_id: str,
) -> dict[str, bool]:
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=connection))
    tenant_a, tenant_b = tenants
    trace_a = f"tr_live_pg_persist_{run_id}_a"
    trace_b = f"tr_live_pg_persist_{run_id}_b"
    run_a = _smoke_run(tenant_id=tenant_a, trace_id=trace_a)
    run_b = _smoke_run(tenant_id=tenant_b, trace_id=trace_b)

    first_a = ledger.append_completed_run(run_a, path="/verification/run")
    retried_a = ledger.append_completed_run(run_a, path="/verification/run")
    retry_exactly_once = first_a.event.event_id == retried_a.event.event_id

    raced_b = _append_completion_concurrently(
        ledger,
        run=run_b,
        path="/verification/run",
        worker_count=AUDIT_RACE_WORKERS,
    )
    race_exactly_once = len({record.event.event_id for record in raced_b}) == 1

    runs_a = ledger.export(tenant_id=tenant_a)
    runs_b = ledger.export(tenant_id=tenant_b)
    events_a = ledger.export_events(tenant_id=tenant_a)
    events_b = ledger.export_events(tenant_id=tenant_b)

    isolation = (
        _runs_all_tenant(runs_a, tenant_a)
        and _runs_all_tenant(runs_b, tenant_b)
        and _has_run_trace(runs_a, trace_a)
        and _has_run_trace(runs_b, trace_b)
        and not _has_run_trace(runs_a, trace_b)
        and not _has_run_trace(runs_b, trace_a)
        and _events_all_tenant(events_a, tenant_a)
        and _events_all_tenant(events_b, tenant_b)
        and not _has_event_trace(events_a, trace_b)
        and not _has_event_trace(events_b, trace_a)
        and len([run for run in runs_a if run.trace_id == trace_a]) == 1
        and len([run for run in runs_b if run.trace_id == trace_b]) == 1
        and len([event for event in events_a if event.trace_id == trace_a]) == 1
        and len([event for event in events_b if event.trace_id == trace_b]) == 1
    )
    if not isolation:
        raise AssertionError(
            "live postgres audit tenant isolation failed: "
            f"tenant_a_traces={[run.trace_id for run in runs_a]}, "
            f"tenant_b_traces={[run.trace_id for run in runs_b]}"
        )
    if not retry_exactly_once:
        raise AssertionError(
            "live postgres audit sequential retry created a second completion"
        )
    if not race_exactly_once:
        raise AssertionError(
            "live postgres audit race returned multiple completion event IDs"
        )
    return {
        "tenant_isolation": True,
        "audit_retry_exactly_once": True,
        "audit_race_exactly_once": True,
    }


def _append_completion_concurrently(
    ledger: AuditLedger,
    *,
    run: VerificationRun,
    path: str,
    worker_count: int,
) -> list[CompletedVerificationRecord]:
    lock = threading.Lock()
    barrier = threading.Barrier(worker_count)
    records: list[CompletedVerificationRecord] = []
    errors: list[str] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=RACE_TIMEOUT_SECONDS)
            record = ledger.append_completed_run(run, path=path)
        except Exception as exc:  # noqa: BLE001 - any error fails the live race
            with lock:
                errors.append(type(exc).__name__)
            return
        with lock:
            records.append(record)

    threads = [
        threading.Thread(target=worker, name=f"audit-race-{index}")
        for index in range(worker_count)
    ]
    for thread in threads:
        thread.start()
    _join_race_threads(threads, label="audit completion")
    if errors or len(records) != worker_count:
        raise AssertionError(
            f"audit completion race failed: successful={len(records)}, errors={errors}"
        )
    return records


def _run_grant_race(
    connection: SqlConnectionProvider,
    tenant_id: str,
    run_id: str,
) -> bool:
    queue = ApprovalQueue(
        storage=PostgresApprovalQueueStorage(connection=connection),
        tool_registry=_smoke_tool_registry(),
        commitment_key=secrets.token_bytes(32),
        commitment_key_id="live-smoke-active",
        commitment_environment="test",
    )
    request_call = _smoke_tool_call(run_id)
    approval = queue.request_approval(
        tenant_id=tenant_id,
        trace_id=f"tr_live_pg_persist_{run_id}_grant",
        tool_call=request_call,
        reason="Live postgres persistence smoke grant race.",
        requested_by="live-smoke-agent",
    )
    result = queue.decide_with_grant(
        tenant_id,
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="live-smoke-reviewer",
        ),
    )
    grant = result.execution_grant
    if grant is None:
        raise AssertionError("approved decision did not issue an execution grant")

    consume_call = _smoke_tool_call(
        run_id,
        approval_id=approval.approval_id,
        execution_token=grant.execution_token,
    )
    counters = _consume_grant_concurrently(
        queue,
        tenant_id=tenant_id,
        tool_call=consume_call,
        worker_count=GRANT_RACE_WORKERS,
    )
    if counters["success"] != 1:
        raise AssertionError(
            f"grant race expected exactly one success, got {counters['success']}"
        )
    if counters["consumed"] != GRANT_RACE_WORKERS - 1:
        raise AssertionError(
            "grant race expected the losers rejected as already-consumed, got "
            f"{counters['consumed']}"
        )
    return counters["success"] == 1


def _consume_grant_concurrently(
    queue: ApprovalQueue,
    *,
    tenant_id: str,
    tool_call: ToolCallEnvelope,
    worker_count: int,
) -> dict[str, int]:
    lock = threading.Lock()
    barrier = threading.Barrier(worker_count)
    counters = {"success": 0, "consumed": 0, "other": 0}
    errors: list[str] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=RACE_TIMEOUT_SECONDS)
            queue.consume_execution_grant(
                tenant_id,
                tool_call,
                subject_id="live-smoke-agent",
            )
        except ApprovalExecutionGrantConsumedError:
            with lock:
                counters["consumed"] += 1
            return
        except Exception as exc:  # noqa: BLE001 - any other error fails the race
            with lock:
                counters["other"] += 1
                errors.append(str(exc))
            return
        with lock:
            counters["success"] += 1

    threads = [
        threading.Thread(target=worker, name=f"grant-race-{index}")
        for index in range(worker_count)
    ]
    for thread in threads:
        thread.start()
    _join_race_threads(threads, label="approval grant")

    if counters["other"]:
        raise AssertionError(f"unexpected grant race errors: {errors}")
    return counters


def _join_race_threads(threads: Sequence[threading.Thread], *, label: str) -> None:
    deadline = time.monotonic() + RACE_TIMEOUT_SECONDS
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        raise AssertionError(f"{label} race timed out: threads={alive}")


def _cleanup_smoke_rows(
    connection: SqlConnectionProvider,
    tenants: tuple[str, str],
) -> None:
    tenant_ids = list(tenants)
    for table in CLEANUP_TABLES:
        connection.execute(
            f"DELETE FROM {table} WHERE tenant_id = ANY(%s)",
            [tenant_ids],
        )


def _smoke_tenants(run_id: str) -> tuple[str, str]:
    return (
        f"{SMOKE_TENANT_PREFIX}-a-{run_id}",
        f"{SMOKE_TENANT_PREFIX}-b-{run_id}",
    )


def _smoke_run(*, tenant_id: str, trace_id: str) -> VerificationRun:
    return VerificationRun(
        trace_id=trace_id,
        tenant_id=tenant_id,
        input={"message_text": "Live postgres persistence smoke run."},
        claims=[
            Claim(claim_id=f"clm_{tenant_id}", text="Live smoke persistence claim.")
        ],
        evidence=[
            Evidence(
                evidence_id=f"ev_{tenant_id}",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="live-postgres-persistence-smoke",
                content="Live smoke evidence content.",
                structured_content={},
                authority=Authority.UNKNOWN,
                freshness=Freshness(
                    retrieved_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    staleness_class=StalenessClass.UNKNOWN,
                ),
            )
        ],
        verdicts=[
            ClaimVerdict(
                claim_id=f"clm_{tenant_id}",
                status=VerdictStatus.SUPPORTED,
                confidence=1.0,
                action=VerdictAction.ALLOW,
                reason="Supported by smoke evidence.",
            )
        ],
        final_decision=FinalDecision.ALLOW,
        final_text="Live postgres persistence smoke final text.",
        policy_version="live-smoke",
    )


def _smoke_tool_call(
    run_id: str,
    *,
    approval_id: str | None = None,
    execution_token: str | None = None,
) -> ToolCallEnvelope:
    # No sensitive keys, so the sanitized fingerprint is stable across the
    # request and the consume call.
    return ToolCallEnvelope(
        tool_name="live_smoke_persist_action",
        input={"scope": f"live-smoke-{run_id}"},
        schema=SMOKE_TOOL_SCHEMA,
        risk_level=RiskLevel.HIGH,
        approval_required=True,
        caller_context={"subject": "live-smoke-agent"},
        approval_id=approval_id,
        approval_execution_token=execution_token,
    )


def _smoke_tool_registry() -> TrustedToolRegistry:
    return TrustedToolRegistry(
        (
            TrustedToolDefinition(
                name="live_smoke_persist_action",
                version="1.0.0",
                policy_action="write_file",
                input_schema=SMOKE_TOOL_SCHEMA,
                output_schema={
                    "type": "object",
                    "properties": {"status": {"type": "string"}},
                    "required": ["status"],
                    "additionalProperties": False,
                },
                risk_level=RiskLevel.HIGH,
                approval_required=True,
                side_effects=("persistence_smoke",),
            ),
        )
    )


def _runs_all_tenant(runs: Sequence[VerificationRun], tenant_id: str) -> bool:
    return all(run.tenant_id == tenant_id for run in runs)


def _has_run_trace(runs: Sequence[VerificationRun], trace_id: str) -> bool:
    return any(run.trace_id == trace_id for run in runs)


def _events_all_tenant(events: Sequence[AuditEvent], tenant_id: str) -> bool:
    return all(event.tenant_id == tenant_id for event in events)


def _has_event_trace(events: Sequence[AuditEvent], trace_id: str) -> bool:
    return any(event.trace_id == trace_id for event in events)


def _close_if_possible(candidate: object) -> None:
    close = getattr(candidate, "close", None)
    if callable(close):
        close()


def _enabled(value: str) -> bool:
    return value.strip().lower() == "true"


def _redact_dsn(dsn: str) -> str:
    masked = re.sub(r"(?i)(password=)([^\s]+)", r"\1***", dsn)
    masked = re.sub(r"://([^:/\s]+):([^@\s]+)@", r"://\1:***@", masked)
    try:
        parsed = urlsplit(masked)
    except ValueError:
        return masked
    if parsed.password is None:
        return masked
    username = parsed.username or ""
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = ""
    try:
        if parsed.port is not None:
            port = f":{parsed.port}"
    except ValueError:
        return masked
    credentials = f"{username}:***@" if username else ""
    return urlunsplit(
        (
            parsed.scheme,
            f"{credentials}{hostname}{port}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
