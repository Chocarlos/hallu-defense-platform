from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
AUDIT_DOC = ROOT / "docs" / "security" / "audit-ledger.md"
AUDIT_SERVICE = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "audit.py"
)
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


class AuditLedgerConfigError(ValueError):
    pass


def validate_audit_ledger_config(
    *,
    env_example_text: str,
    audit_doc_text: str,
    audit_service_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _require(
        env_example_text,
        {
            "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=memory",
            "HALLU_DEFENSE_AUDIT_LEDGER_PATH=var/audit/audit-ledger.jsonl",
        },
        ".env.example",
        errors,
    )
    _require(
        audit_doc_text,
        {
            "jsonl",
            "append-only",
            "Production and staging require `postgres`",
            "atomically",
            "exactly once",
            "REPEATABLE READ, READ ONLY",
            "[REDACTED]",
        },
        "docs/security/audit-ledger.md",
        errors,
    )
    _require(
        audit_service_text,
        {
            "storage_path=settings.audit_ledger_path",
            "Production and staging require the PostgreSQL persistent audit ledger backend.",
            "append_completed_run",
            "append_replayed_run",
            "append_run_with_event",
            "export_snapshot",
            "limit=limit + 1",
            "find_replay_source",
            "load_replay_source_candidates",
            "ORDER BY created_at DESC, id DESC LIMIT 2",
            "ReplaySourceConflictError",
            "payload #>> '{input,replay_of}' IS NULL",
            "verification_completed and verification_replay must be persisted",
            "related_events",
            "ON CONFLICT DO NOTHING",
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "REDACTED",
            'model_dump(mode="json")',
            "model_copy(deep=True)",
        },
        "audit service",
        errors,
    )
    script = "scripts/ci/check_audit_ledger_config.py"
    if "audit-ledger-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the audit-ledger-config gate")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_audit_ledger_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_audit_ledger_config.py")
    if errors:
        raise AuditLedgerConfigError("\n".join(errors))


def load_current_config() -> tuple[str, str, str, str, str, str]:
    return (
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        AUDIT_DOC.read_text(encoding="utf-8"),
        AUDIT_SERVICE.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def main() -> None:
    (
        env_example_text,
        audit_doc_text,
        audit_service_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()
    validate_audit_ledger_config(
        env_example_text=env_example_text,
        audit_doc_text=audit_doc_text,
        audit_service_text=audit_service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )
    print("Validated audit ledger configuration.")


if __name__ == "__main__":
    main()
