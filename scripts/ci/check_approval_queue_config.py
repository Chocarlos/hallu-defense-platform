from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
APPROVAL_DOC = ROOT / "docs" / "security" / "approvals.md"
APPROVAL_SERVICE = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "approvals.py"
API_DEPENDENCIES = ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


class ApprovalQueueConfigError(ValueError):
    pass


def validate_approval_queue_config(
    *,
    env_example_text: str,
    approval_doc_text: str,
    approval_service_text: str,
    api_dependencies_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _require(
        env_example_text,
        {
            "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND=memory",
            "HALLU_DEFENSE_APPROVAL_QUEUE_PATH=var/approvals/approval-queue.jsonl",
            "HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS=900",
            "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME=",
            "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID=",
            "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_SECRET_NAME=",
            "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_KEY_ID=",
            "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_VALID_UNTIL=",
        },
        ".env.example",
        errors,
    )
    _require(
        approval_doc_text,
        {
            "jsonl",
            "append-only",
            "Production and staging require PostgreSQL",
            "[REDACTED]",
            "execution grant",
            "atomic decision and grant",
            "original unredacted",
            "Production and staging require",
            "Vault",
            "api_key`, `secret`, `token`, or `password",
            "review does not create a quota bypass",
            "explicit opaque",
            "cannot exceed seven",
            "archive the old",
            "wrong-environment",
            "HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS",
        },
        "docs/security/approvals.md",
        errors,
    )
    _require(
        approval_service_text,
        {
            "storage_path=settings.approval_queue_path",
            "Production and staging require the PostgreSQL approval queue backend",
            "REDACTED",
            "model_dump(mode=\"json\")",
            "ApprovalExecutionGrant",
            "approval_execution_grant",
            "TOOL_CALL_COMMITMENT_DOMAIN",
            "APPROVAL_BINDING_VERSION",
            "_hallu_approval_commitment_v3",
            "Legacy or provisional approval commitment storage is unsupported",
            "MAX_COMMITMENT_ROTATION_OVERLAP",
            "_verification_key",
            "decide_with_grant_once",
            "with self._connection.transaction() as transaction",
            "hmac.new",
            "A keyed approval queue cannot approve a legacy unkeyed commitment",
            "_resolve_commitment_keys",
            "Production and staging require an approval commitment SecretManager name",
            "explicit opaque approval commitment key identifier",
        },
        "approval service",
        errors,
    )
    _require(
        api_dependencies_text,
        {
            "create_approval_queue(",
            "secret_manager=secret_manager",
            "environment=settings.environment",
        },
        "API dependencies",
        errors,
    )
    script = "scripts/ci/check_approval_queue_config.py"
    if "approval-queue-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the approval-queue-config gate")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_approval_queue_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_approval_queue_config.py")
    if errors:
        raise ApprovalQueueConfigError("\n".join(errors))


def load_current_config() -> tuple[str, str, str, str, str, str, str]:
    return (
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        APPROVAL_DOC.read_text(encoding="utf-8"),
        APPROVAL_SERVICE.read_text(encoding="utf-8"),
        API_DEPENDENCIES.read_text(encoding="utf-8"),
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
        approval_doc_text,
        approval_service_text,
        api_dependencies_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()
    validate_approval_queue_config(
        env_example_text=env_example_text,
        approval_doc_text=approval_doc_text,
        approval_service_text=approval_service_text,
        api_dependencies_text=api_dependencies_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )
    print("Validated approval queue configuration.")


if __name__ == "__main__":
    main()
