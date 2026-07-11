"""Skip-safe CLI for Postgres retention execution and tenant data deletion."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import load_settings  # noqa: E402
from hallu_defense.services.audit import AuditLedger, PostgresAuditLedgerStorage  # noqa: E402
from hallu_defense.services.data_lifecycle import (  # noqa: E402
    DEFAULT_POLICY_PATH,
    DataLifecycleService,
    load_data_lifecycle_policy,
)
from hallu_defense.services.postgres import (  # noqa: E402
    SqlConnectionProvider,
    build_postgres_provider,
)
from hallu_defense.services.rag_index import (  # noqa: E402
    PersistentRagDeletionBackend,
    create_rag_index_backend,
)

ENABLED_ENV = "HALLU_DEFENSE_RETENTION_EXECUTION_ENABLED"
TENANT_DELETE_ENABLED_ENV = "HALLU_DEFENSE_TENANT_DATA_DELETION_ENABLED"
DRY_RUN_ENV = "HALLU_DEFENSE_RETENTION_EXECUTION_DRY_RUN"
POLICY_PATH_ENV = "HALLU_DEFENSE_RETENTION_POLICY_PATH"


@dataclass(frozen=True)
class RetentionCliConfig:
    enabled: bool
    tenant_delete_enabled: bool
    dry_run: bool
    policy_path: Path


def run_from_env(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    connection: SqlConnectionProvider | None = None,
    audit: AuditLedger | None = None,
    rag_deletion_backend: PersistentRagDeletionBackend | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    args = _parse_args(argv)
    config = _config_from_env(effective_env)

    if not config.enabled:
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run lifecycle operations",
            "operation": args.operation,
        }

    if args.operation == "delete-tenant":
        if not config.tenant_delete_enabled:
            return {
                "status": "skipped",
                "reason": f"set {TENANT_DELETE_ENABLED_ENV}=true to delete tenant data",
                "operation": args.operation,
                "tenant_id": args.tenant_id,
            }
        _validate_tenant_confirmation(args.tenant_id, args.confirm_tenant_id)

    service = _build_service(
        policy_path=config.policy_path,
        connection=connection,
        audit=audit,
        rag_index_backend=effective_env.get("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid"),
        rag_deletion_backend=rag_deletion_backend,
    )
    dry_run = bool(args.dry_run or (config.dry_run and not args.no_dry_run))
    if args.operation == "delete-tenant":
        tenant_report = service.delete_tenant_data(
            args.tenant_id,
            dry_run=dry_run,
            actor_id=args.actor_id,
        )
        return {
            "status": "passed",
            "operation": args.operation,
            **tenant_report.to_json_dict(),
        }

    retention_report = service.execute_retention(dry_run=dry_run, actor_id=args.actor_id)
    return {
        "status": "passed",
        "operation": args.operation,
        **retention_report.to_json_dict(),
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    connection: SqlConnectionProvider | None = None,
    audit: AuditLedger | None = None,
    rag_deletion_backend: PersistentRagDeletionBackend | None = None,
) -> int:
    try:
        result = run_from_env(
            argv,
            env=env,
            connection=connection,
            audit=audit,
            rag_deletion_backend=rag_deletion_backend,
        )
    except Exception as exc:
        print(_json_result({"status": "failed", "error": str(exc)}))
        return 1
    print(_json_result(result))
    return 0


def _build_service(
    *,
    policy_path: Path,
    connection: SqlConnectionProvider | None,
    audit: AuditLedger | None,
    rag_index_backend: str,
    rag_deletion_backend: PersistentRagDeletionBackend | None,
) -> DataLifecycleService:
    normalized_backend = rag_index_backend.strip().lower()
    settings = None
    if connection is None or (
        normalized_backend in {"hybrid", "opensearch"}
        and rag_deletion_backend is None
    ):
        settings = load_settings()
    sql_provider = connection or build_postgres_provider(settings or load_settings())
    deletion_backend = rag_deletion_backend
    if normalized_backend in {"hybrid", "opensearch"} and deletion_backend is None:
        assert settings is not None
        created_backend = create_rag_index_backend(settings)
        if created_backend is None or not callable(
            getattr(created_backend, "delete_evidence_ids", None)
        ):
            raise RuntimeError(
                "Persistent RAG lifecycle deletion backend is unavailable."
            )
        deletion_backend = cast(PersistentRagDeletionBackend, created_backend)
    if audit is None:
        # Dry-runs remain SQL read-only. Mutating executions replace this
        # process-local ledger with a transaction-bound Postgres ledger below.
        audit_ledger = AuditLedger()

        def transactional_audit_factory(
            transaction: SqlConnectionProvider,
        ) -> AuditLedger:
            return AuditLedger(
                storage=PostgresAuditLedgerStorage(connection=transaction)
            )

    else:
        audit_ledger = audit

        def transactional_audit_factory(
            transaction: SqlConnectionProvider,
        ) -> AuditLedger:
            del transaction
            return audit_ledger

    return DataLifecycleService(
        connection=sql_provider,
        audit=audit_ledger,
        transactional_audit_factory=transactional_audit_factory,
        policy=load_data_lifecycle_policy(policy_path),
        rag_index_backend=rag_index_backend,
        rag_deletion_backend=deletion_backend,
    )


def _config_from_env(env: Mapping[str, str]) -> RetentionCliConfig:
    return RetentionCliConfig(
        enabled=_enabled(env.get(ENABLED_ENV, "")),
        tenant_delete_enabled=_enabled(env.get(TENANT_DELETE_ENABLED_ENV, "")),
        dry_run=_enabled(env.get(DRY_RUN_ENV, "")),
        policy_path=Path(env.get(POLICY_PATH_ENV, str(DEFAULT_POLICY_PATH))).resolve(),
    )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        nargs="?",
        choices=("execute-retention", "delete-tenant"),
        default="execute-retention",
    )
    parser.add_argument("--tenant-id", default="", help="tenant to delete for delete-tenant")
    parser.add_argument(
        "--confirm-tenant-id",
        default="",
        help="must match --tenant-id for delete-tenant",
    )
    parser.add_argument("--actor-id", default="lifecycle-cli")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-dry-run", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.operation == "delete-tenant" and not args.tenant_id.strip():
        parser.error("delete-tenant requires --tenant-id")
    if args.dry_run and args.no_dry_run:
        parser.error("--dry-run and --no-dry-run are mutually exclusive")
    return args


def _validate_tenant_confirmation(tenant_id: str, confirmed_tenant_id: str) -> None:
    if tenant_id.strip() != confirmed_tenant_id.strip():
        raise ValueError("--confirm-tenant-id must exactly match --tenant-id")


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    sys.exit(main())
