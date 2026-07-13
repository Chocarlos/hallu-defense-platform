from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from scripts.dev import live_postgres_persistence_smoke as smoke


def test_live_workflow_waits_for_postgres_init_scripts_before_readiness() -> None:
    workflow = (smoke.ROOT / ".github" / "workflows" / "live.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("PostgreSQL init process complete; ready for start up") == 4

# A short placeholder password (never a real secret) proves DSN redaction: it
# must never survive into any emitted result. Kept < 16 chars so the secret
# scanner does not flag this test file.
_SMOKE_DSN = "postgresql://hallu:hunter2pw@localhost:5432/hallu_defense"
_REDACTED_DSN = "postgresql://hallu:***@localhost:5432/hallu_defense"


def test_skips_by_default_without_exposing_dsn_secret() -> None:
    result = smoke.run_from_env({smoke.DSN_ENV: _SMOKE_DSN})

    assert result["status"] == "skipped"
    assert result["schema_ready"] is False
    assert result["tenant_isolation"] is False
    assert result["grant_race_single_success"] is False
    assert result["dsn"] == _REDACTED_DSN
    assert "hunter2pw" not in json.dumps(result)


def test_enabled_path_runs_offline_with_injected_fake_connection() -> None:
    connection = RecordingPersistenceConnection()

    result = smoke.run_from_env(
        {smoke.ENABLED_ENV: "true", smoke.DSN_ENV: _SMOKE_DSN},
        connection=connection,
        run_id="unit",
    )

    assert result == {
        "status": "passed",
        "dsn": _REDACTED_DSN,
        "schema_ready": True,
        "tenant_isolation": True,
        "audit_retry_exactly_once": True,
        "audit_race_exactly_once": True,
        "grant_race_single_success": True,
    }
    assert "hunter2pw" not in json.dumps(result)


def test_enabled_path_enforces_tenant_scoped_audit_reads() -> None:
    connection = RecordingPersistenceConnection()

    smoke.run_from_env(
        {smoke.ENABLED_ENV: "true", smoke.DSN_ENV: _SMOKE_DSN},
        connection=connection,
        run_id="unit",
    )

    tenant_a, tenant_b = smoke._smoke_tenants("unit")
    run_selects = [
        parameters
        for method, statement, parameters in connection.calls
        if method == "fetch_all"
        and statement.startswith(
            "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
            "FROM audit_runs"
        )
    ]
    # Every audit-run read is scoped to a single tenant via WHERE tenant_id = %s,
    # and both smoke tenants are read back independently (isolation is enforced by
    # the query, not by the fake).
    selected_tenants = {parameters[0] for parameters in run_selects}
    assert selected_tenants == {tenant_a, tenant_b}
    assert all("WHERE tenant_id = %s" in statement for statement in connection.audit_run_selects)


def test_enabled_path_grant_race_uses_the_atomic_consume_guard() -> None:
    connection = RecordingPersistenceConnection()

    smoke.run_from_env(
        {smoke.ENABLED_ENV: "true", smoke.DSN_ENV: _SMOKE_DSN},
        connection=connection,
        run_id="unit",
    )

    consume_updates = [
        statement
        for method, statement, _parameters in connection.calls
        if method == "execute_returning"
        and statement.startswith("UPDATE approval_execution_grants SET consumed_at")
    ]
    # Both racing workers hit the guarded single-use UPDATE; the fake serialized
    # them so exactly one won (asserted via the passed result above).
    assert len(consume_updates) == smoke.GRANT_RACE_WORKERS
    assert all("consumed_at IS NULL" in statement for statement in consume_updates)
    assert connection.grant_consume_wins == 1


def test_main_prints_skip_json_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(env={smoke.DSN_ENV: _SMOKE_DSN})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
    assert payload["dsn"] == _REDACTED_DSN
    assert "hunter2pw" not in json.dumps(payload)


def test_main_reports_failure_when_migrations_cannot_apply(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = smoke.main(
        env={smoke.ENABLED_ENV: "true", smoke.DSN_ENV: _SMOKE_DSN},
        connection=_MigrationFailingConnection(),
    )

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert payload["schema_ready"] is False
    assert isinstance(payload["error"], str) and payload["error"]
    assert "hunter2pw" not in json.dumps(payload)


# --- Offline fakes ------------------------------------------------------------


@dataclass
class _GrantRow:
    tenant_id: str
    approval_id: str
    fingerprint: str
    expires_at: datetime
    consumed_at: datetime | None


class RecordingPersistenceConnection:
    """Stateful in-memory stand-in for the shared SqlConnectionProvider.

    It emulates just enough PostgreSQL semantics -- tenant-scoped audit reads,
    the pending-guarded decide UPDATE, and the single-use consume UPDATE -- to
    drive the smoke end-to-end without a database. It is thread-safe so the grant
    race exercises a genuine winner/loser split under a lock.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.audit_run_selects: list[str] = []
        self.grant_consume_wins = 0
        self._lock = threading.RLock()
        self._audit_runs: dict[tuple[str, str, str], dict[str, object]] = {}
        self._audit_events: dict[tuple[str, str, str, str], dict[str, object]] = {}
        self._next_audit_run_id = 1
        self._next_audit_event_id = 1
        self._records: dict[tuple[str, str], dict[str, object]] = {}
        self._grants: dict[str, _GrantRow] = {}
        self._migration_versions: dict[str, str] = {}

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        params = tuple(parameters)
        with self._lock:
            self.calls.append(("execute", statement, params))
            if statement.startswith("INSERT INTO audit_runs"):
                payload = _load_payload(params[2])
                run_key = (_as_str(params[0]), _as_str(params[1]), "")
                self._audit_runs[run_key] = {
                    "id": self._next_audit_run_id,
                    "tenant_id": run_key[0],
                    "trace_id": run_key[1],
                    "created_at": _as_datetime(params[3]),
                    "payload": payload,
                }
                self._next_audit_run_id += 1
            elif statement.startswith("INSERT INTO audit_events"):
                payload = _load_payload(params[3])
                event_key = (
                    _as_str(params[0]),
                    _as_str(params[1]),
                    _as_str(payload["event_type"]),
                    _as_str(payload["path"]),
                )
                self._audit_events[event_key] = {
                    "id": self._next_audit_event_id,
                    "tenant_id": event_key[0],
                    "trace_id": event_key[1],
                    "event_id": _as_str(params[2]),
                    "created_at": _as_datetime(params[4]),
                    "payload": payload,
                }
                self._next_audit_event_id += 1
            elif statement.startswith("INSERT INTO approval_records"):
                record_key = (_as_str(params[0]), _as_str(params[1]))
                self._records[record_key] = _load_payload(params[4])
            elif statement.startswith("INSERT INTO approval_execution_grants"):
                self._grants[_as_str(params[0])] = _GrantRow(
                    tenant_id=_as_str(params[2]),
                    approval_id=_as_str(params[1]),
                    fingerprint=_as_str(params[3]),
                    expires_at=_as_datetime(params[4]),
                    consumed_at=None,
                )
            elif statement.startswith("DELETE FROM"):
                self._delete_scoped(params)
            elif statement.startswith("INSERT INTO schema_migrations"):
                self._migration_versions[_as_str(params[0])] = _as_str(params[1])
            elif statement.startswith("UPDATE schema_migrations SET checksum_sha256"):
                self._migration_versions[_as_str(params[1])] = _as_str(params[0])
            # Anything else (advisory lock and migration DDL) is a no-op: the
            # fake simulates an atomic migration transaction.

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        params = tuple(parameters)
        with self._lock:
            self.calls.append(("fetch_all", statement, params))
            if statement.startswith("SELECT version, checksum_sha256 FROM schema_migrations"):
                return [
                    {"version": version, "checksum_sha256": checksum}
                    for version, checksum in sorted(self._migration_versions.items())
                ]
            if statement.startswith(
                "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
                "FROM audit_runs"
            ) and "AND completion_path = %s" in statement:
                key = (_as_str(params[0]), _as_str(params[1]), _as_str(params[2]))
                row = self._audit_runs.get(key)
                return [dict(row)] if row is not None else []
            if statement.startswith(
                "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
                "FROM audit_runs"
            ):
                self.audit_run_selects.append(statement)
                tenant = _as_str(params[0])
                trace = _as_str(params[1]) if "trace_id = %s" in statement else None
                rows = [
                    dict(row)
                    for (owner, _trace, _path), row in self._audit_runs.items()
                    if owner == tenant
                    and (trace is None or _trace == trace)
                    and (
                        "payload #>> '{input,replay_of}' IS NULL" not in statement
                        or not _is_replayed_run_row(row)
                    )
                ]
                return sorted(
                    rows,
                    key=lambda row: (
                        _as_datetime(row["created_at"]),
                        _as_int(row["id"]),
                    ),
                    reverse=True,
                )
            if statement.startswith(
                "SELECT id, tenant_id, trace_id, event_id, created_at, payload FROM audit_events"
            ):
                tenant = _as_str(params[0])
                if "payload ->> 'event_type'" in statement:
                    event_key = (
                        tenant,
                        _as_str(params[1]),
                        _as_str(params[2]),
                        _as_str(params[3]),
                    )
                    row = self._audit_events.get(event_key)
                    return [dict(row)] if row is not None else []
                rows = [
                    dict(row)
                    for (owner, _trace, _event_type, _path), row in self._audit_events.items()
                    if owner == tenant
                ]
                return sorted(
                    rows,
                    key=lambda row: (
                        _as_datetime(row["created_at"]),
                        _as_int(row["id"]),
                    ),
                    reverse=True,
                )
            if statement.startswith("SELECT payload FROM approval_records"):
                record = self._records.get((_as_str(params[0]), _as_str(params[1])))
                return [{"payload": record}] if record is not None else []
            if statement.startswith(
                "SELECT consumed_at, expires_at FROM approval_execution_grants"
            ):
                grant = self._grants.get(_as_str(params[0]))
                if (
                    grant is None
                    or grant.approval_id != _as_str(params[1])
                    or grant.tenant_id != _as_str(params[2])
                    or grant.fingerprint != _as_str(params[3])
                ):
                    return []
                return [{"consumed_at": grant.consumed_at, "expires_at": grant.expires_at}]
        raise AssertionError(f"Unexpected fetch_all statement: {statement}")

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        params = tuple(parameters)
        with self._lock:
            self.calls.append(("execute_returning", statement, params))
            if statement.startswith("INSERT INTO audit_runs"):
                run_key = (
                    _as_str(params[0]),
                    _as_str(params[1]),
                    _as_str(params[2]),
                )
                if run_key in self._audit_runs:
                    return []
                row = {
                    "id": self._next_audit_run_id,
                    "tenant_id": run_key[0],
                    "trace_id": run_key[1],
                    "completion_path": run_key[2],
                    "created_at": _as_datetime(params[4]),
                    "payload": _load_payload(params[3]),
                }
                self._audit_runs[run_key] = row
                self._next_audit_run_id += 1
                return [dict(row)]
            if statement.startswith("INSERT INTO audit_events"):
                payload = _load_payload(params[3])
                event_key = (
                    _as_str(params[0]),
                    _as_str(params[1]),
                    _as_str(payload["event_type"]),
                    _as_str(payload["path"]),
                )
                if event_key in self._audit_events:
                    return []
                row = {
                    "id": self._next_audit_event_id,
                    "tenant_id": event_key[0],
                    "trace_id": event_key[1],
                    "event_id": _as_str(params[2]),
                    "created_at": _as_datetime(params[4]),
                    "payload": payload,
                }
                self._audit_events[event_key] = row
                self._next_audit_event_id += 1
                return [dict(row)]
            if statement.startswith("UPDATE approval_records SET status"):
                record_key = (_as_str(params[3]), _as_str(params[4]))
                record = self._records.get(record_key)
                if record is None or record.get("status") != "pending":
                    return []
                self._records[record_key] = _load_payload(params[2])
                return [{"approval_id": params[3]}]
            if statement.startswith("UPDATE approval_execution_grants SET consumed_at"):
                grant = self._grants.get(_as_str(params[0]))
                now = datetime.now(timezone.utc)
                if (
                    grant is not None
                    and grant.approval_id == _as_str(params[1])
                    and grant.tenant_id == _as_str(params[2])
                    and grant.consumed_at is None
                    and grant.expires_at > now
                    and grant.fingerprint == _as_str(params[3])
                ):
                    grant.consumed_at = now
                    self.grant_consume_wins += 1
                    return [{"approval_id": grant.approval_id}]
                return []
        raise AssertionError(f"Unexpected execute_returning statement: {statement}")

    @contextmanager
    def transaction(self) -> Iterator[smoke.MigrationConnection]:
        with self._lock:
            audit_runs_snapshot = dict(self._audit_runs)
            audit_events_snapshot = dict(self._audit_events)
            next_run_id_snapshot = self._next_audit_run_id
            next_event_id_snapshot = self._next_audit_event_id
            try:
                yield self
            except BaseException:
                self._audit_runs = audit_runs_snapshot
                self._audit_events = audit_events_snapshot
                self._next_audit_run_id = next_run_id_snapshot
                self._next_audit_event_id = next_event_id_snapshot
                raise

    def _delete_scoped(self, parameters: tuple[object, ...]) -> None:
        tenants = set(_as_str_list(parameters[0]))
        self._audit_runs = {
            key: row for key, row in self._audit_runs.items() if key[0] not in tenants
        }
        self._audit_events = {
            key: row for key, row in self._audit_events.items() if key[0] not in tenants
        }
        self._records = {
            key: value for key, value in self._records.items() if key[1] not in tenants
        }
        self._grants = {
            token: grant for token, grant in self._grants.items() if grant.tenant_id not in tenants
        }


class _MigrationFailingConnection:
    """Connection whose migration DDL always fails, to exercise main()'s failure."""

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        raise RuntimeError("simulated migration failure")

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        return []

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        return []

    @contextmanager
    def transaction(self) -> Iterator[smoke.MigrationConnection]:
        yield self


def _load_payload(value: object) -> dict[str, object]:
    decoded = json.loads(_as_str(value))
    assert isinstance(decoded, dict)
    return decoded


def _is_replayed_run_row(row: Mapping[str, object]) -> bool:
    payload = row.get("payload")
    if not isinstance(payload, Mapping):
        return False
    run_input = payload.get("input")
    return isinstance(run_input, Mapping) and isinstance(run_input.get("replay_of"), str)


def _as_str(value: object) -> str:
    assert isinstance(value, str)
    return value


def _as_datetime(value: object) -> datetime:
    assert isinstance(value, datetime)
    return value


def _as_int(value: object) -> int:
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def _as_str_list(value: object) -> Sequence[str]:
    assert isinstance(value, Sequence) and not isinstance(value, str)
    assert all(isinstance(item, str) for item in value)
    return [item for item in value if isinstance(item, str)]
