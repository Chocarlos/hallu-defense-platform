from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from threading import Lock
from uuid import uuid4

from hallu_defense.config import Settings
from hallu_defense.domain.models import AuditEvent, VerificationRun

SENSITIVE_KEYWORDS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
REDACTED = "[REDACTED]"


class AuditLedgerError(RuntimeError):
    pass


class AuditLedgerConfigurationError(AuditLedgerError):
    pass


class AuditLedgerStorageError(AuditLedgerError):
    pass


class AuditLedger:
    def __init__(self, storage_path: Path | None = None) -> None:
        self._storage_path = storage_path
        self._runs: list[VerificationRun] = []
        self._events: list[AuditEvent] = []
        self._lock = Lock()
        if self._storage_path is not None:
            self._load_from_storage()

    def append(self, run: VerificationRun) -> None:
        stored_run = _redact_verification_run(run)
        with self._lock:
            self._runs.append(stored_run)
            self._append_record_locked("verification_run", stored_run)

    def append_event(
        self,
        *,
        trace_id: str,
        tenant_id: str,
        event_type: str,
        method: str,
        path: str,
        status_code: int,
        outcome: str,
        metadata: dict[str, object] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            trace_id=trace_id,
            tenant_id=tenant_id,
            event_type=event_type,
            method=method,
            path=path,
            status_code=status_code,
            outcome=outcome,
            metadata=metadata or {},
        )
        stored_event = _redact_audit_event(event)
        with self._lock:
            self._events.append(stored_event)
            self._append_record_locked("audit_event", stored_event)
        return stored_event

    def export(self, tenant_id: str | None = None, trace_id: str | None = None) -> list[VerificationRun]:
        with self._lock:
            runs = list(self._runs)
        if tenant_id is not None:
            runs = [run for run in runs if run.tenant_id == tenant_id]
        if trace_id is not None:
            runs = [run for run in runs if run.trace_id == trace_id]
        return runs

    def export_events(
        self,
        tenant_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[AuditEvent]:
        with self._lock:
            events = list(self._events)
        if tenant_id is not None:
            events = [event for event in events if event.tenant_id == tenant_id]
        if trace_id is not None:
            events = [event for event in events if event.trace_id == trace_id]
        return events

    def _load_from_storage(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        runs: list[VerificationRun] = []
        events: list[AuditEvent] = []
        with self._storage_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(record, Mapping):
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} must be a JSON object"
                    )
                record_type = record.get("record_type")
                payload = record.get("payload")
                if not isinstance(payload, Mapping):
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} payload must be an object"
                    )
                if record_type == "verification_run":
                    runs.append(VerificationRun.model_validate(payload))
                elif record_type == "audit_event":
                    events.append(AuditEvent.model_validate(payload))
                else:
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} has unsupported record_type"
                    )
        self._runs = runs
        self._events = events

    def _append_record_locked(
        self,
        record_type: str,
        payload: VerificationRun | AuditEvent,
    ) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "record_type": record_type,
            "payload": payload.model_dump(mode="json"),
        }
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def create_audit_ledger(settings: Settings) -> AuditLedger:
    backend = settings.audit_ledger_backend.strip().lower()
    if backend == "memory":
        if settings.environment.lower() in {"production", "staging"}:
            raise AuditLedgerConfigurationError(
                "Production and staging must configure a persistent audit ledger backend."
            )
        return AuditLedger()
    if backend == "jsonl":
        return AuditLedger(storage_path=settings.audit_ledger_path)
    raise AuditLedgerConfigurationError(
        f"Unsupported audit ledger backend: {settings.audit_ledger_backend}"
    )


def _redact_verification_run(run: VerificationRun) -> VerificationRun:
    return run.model_copy(
        update={
            "input": _redact_value(run.input),
            "claims": [
                claim.model_copy(update={"text": _redact_text(claim.text)})
                for claim in run.claims
            ],
            "evidence": [
                evidence.model_copy(update={"content": _redact_text(evidence.content)})
                for evidence in run.evidence
            ],
            "final_text": _redact_text(run.final_text),
        },
        deep=True,
    )


def _redact_audit_event(event: AuditEvent) -> AuditEvent:
    return event.model_copy(update={"metadata": _redact_value(event.metadata)}, deep=True)


def _redact_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(value: str) -> str:
    lowered = value.lower()
    if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
        return REDACTED
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)
