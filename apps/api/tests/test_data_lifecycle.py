from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone

import pytest

from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.data_lifecycle import (
    POSTGRES_LIFECYCLE_TABLES,
    SYSTEM_TENANT_ID,
    TENANT_DATA_DELETION_EVENT,
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


def _service(provider: CountingSqlProvider) -> tuple[DataLifecycleService, AuditLedger]:
    audit = AuditLedger()
    service = DataLifecycleService(
        connection=provider,
        audit=audit,
        policy=DataLifecyclePolicy.from_mapping(load_policy(POLICY_PATH)),
        clock=lambda: FIXED_NOW,
    )
    return service, audit


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
    assert "status IN ('succeeded', 'failed', 'dead')" in calls_by_table["rag_ingestion_jobs"][1]

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

    events = audit.export_events(tenant_id="tenant-a")
    assert len(events) == 1
    assert events[0].event_type == TENANT_DATA_DELETION_EVENT
    assert events[0].metadata["actor_id"] == "privacy-admin"


def test_delete_tenant_data_dry_run_counts_without_deleting() -> None:
    provider = CountingSqlProvider(affected_count=4)
    service, _ = _service(provider)

    report = service.delete_tenant_data("tenant-a", dry_run=True)

    assert report.total_affected == 4 * len(POSTGRES_LIFECYCLE_TABLES)
    assert {call[0] for call in provider.calls} == {"fetch_all"}
    assert all("SELECT count(*)" in call[1] and "DELETE FROM" not in call[1] for call in provider.calls)


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
