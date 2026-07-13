from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "minio_backup_drill.py"
CLI_PATH = ROOT / "scripts" / "dev" / "minio_backup_restore_drill.py"
S3_CLIENT_PATH = ROOT / "scripts" / "dev" / "s3_sigv4.py"
POLICY_PATH = ROOT / "infra" / "security" / "backup-retention-policy.json"
DOC_PATH = ROOT / "docs" / "security" / "backup-restore-retention.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"
LIVE_TEST_PATH = ROOT / "apps" / "api" / "tests" / "test_live_minio_backup_restore_drill.py"

EXPECTED_MANIFEST_FIELDS = {
    "source_ref",
    "replica_key",
    "plaintext_size",
    "plaintext_sha256",
    "encrypted_size",
}
class MinioBackupDrillConfigError(ValueError):
    pass


def validate_repository() -> None:
    validate_sources(
        core_text=CORE_PATH.read_text(encoding="utf-8"),
        cli_text=CLI_PATH.read_text(encoding="utf-8"),
        s3_client_text=S3_CLIENT_PATH.read_text(encoding="utf-8"),
        policy=json.loads(POLICY_PATH.read_text(encoding="utf-8")),
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_text=CI_PATH.read_text(encoding="utf-8"),
        security_text=SECURITY_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_test_text=LIVE_TEST_PATH.read_text(encoding="utf-8"),
    )


def validate_sources(
    *,
    core_text: str,
    cli_text: str,
    s3_client_text: str,
    policy: Mapping[str, object],
    docs_text: str,
    makefile_text: str,
    ci_text: str,
    security_text: str,
    live_workflow_text: str,
    live_test_text: str,
) -> None:
    errors: list[str] = []
    _require_markers(
        core_text,
        (
            "SecretManager",
            'DEFAULT_SECRET_NAME = "backup/encryption-key"',
            "Cipher(algorithms.AES(key), modes.GCM",
            "authenticate_additional_data",
            "InvalidTag",
            "while remaining",
            "read(min(chunk_bytes, remaining))",
            "max_total_bytes",
            "_private_temporary_directory",
            "_cleanup_synthetic_prefixes",
            "source_prefix",
            '"restored_from_replica": True',
            '"parity_passed": True',
        ),
        "core",
        errors,
    )
    _validate_manifest_fields(core_text, errors)
    _require_markers(
        cli_text,
        (
            "HALLU_DEFENSE_MINIO_BACKUP_RESTORE_DRILL_ENABLED",
            "S3SigV4Client",
            "S3ObjectStore",
            "max_response_bytes",
            "download_file",
            "upload_file",
            "delete_prefix",
            "PRODUCTION_LIKE_ENVIRONMENTS",
            'field="access_key"',
            'field="secret_key"',
            "require_https",
            "allowed_origins",
            "allow_private_endpoint",
            "create_secret_manager",
            'field(repr=False)',
        ),
        "CLI",
        errors,
    )
    _validate_cli_ast(cli_text, errors)
    _require_markers(
        s3_client_text,
        (
            'ALGORITHM = "AWS4-HMAC-SHA256"',
            'SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date"',
            "MAX_LIST_PAGES",
            "MAX_LIST_OBJECTS",
            "_read_bounded",
            "os.O_EXCL",
            "ssl.create_default_context",
            "ElementTree.fromstring",
            "hmac.new",
            "x-amz-content-sha256",
            "require_https",
            "allowed_origins",
            "_resolve_connect_host",
            "address.is_global",
            "_PinnedHTTPSConnection",
            "time.monotonic",
            "prefix boundary",
            "CreateFileW",
            "D:P(A;;FA;;;",
            "destination.unlink(missing_ok=True)",
        ),
        "SigV4 client",
        errors,
    )
    _validate_s3_client_ast(s3_client_text, errors)
    if "str(exc)" in cli_text or "traceback" in cli_text:
        errors.append("CLI failure output must not render exceptions or tracebacks")

    _validate_policy(policy, errors)
    _require_markers(
        docs_text,
        (
            "minio_backup_restore_drill.py",
            "AES-256-GCM",
            "cross-bucket-encrypted-replica",
            "tenant",
            "corruption",
            "not a scheduler",
            "not an autonomous restore",
            "monotonic wall-clock",
            "protected DACL",
        ),
        "backup documentation",
        errors,
    )

    gate = "scripts/ci/check_minio_backup_drill.py"
    if "minio-backup-drill-config:" not in makefile_text or gate not in makefile_text:
        errors.append("Makefile must expose minio-backup-drill-config")
    if (
        "minio-backup-restore-drill:" not in makefile_text
        or "scripts/dev/minio_backup_restore_drill.py" not in makefile_text
    ):
        errors.append("Makefile must expose minio-backup-restore-drill")
    if gate not in ci_text:
        errors.append("CI workflow must run the MinIO backup drill gate")
    if gate not in security_text:
        errors.append("security workflow must run the MinIO backup drill gate")
    _require_markers(
        live_test_text,
        (
            "@pytest.mark.live",
            "test_live_minio_replica_restore_is_tenant_scoped_and_rejects_corruption",
            "hallu-drill-src-",
            "hallu-drill-rep-",
            "_assert_synthetic_prefixes_empty",
        ),
        "MinIO live test",
        errors,
    )
    _require_markers(
        live_workflow_text,
        (
            "minio-backup-restore-live:",
            "hallu-minio-${{ github.run_id }}-${{ github.run_attempt }}",
            "docker compose up -d minio",
            "HALLU_DEFENSE_MINIO_BACKUP_ENDPOINT: http://127.0.0.1:9000",
            'HALLU_DEFENSE_SECRET_BACKUP_ENCRYPTION_KEY="$(python -c',
            "secrets.token_bytes(32)",
            "export HALLU_DEFENSE_SECRET_BACKUP_ENCRYPTION_KEY",
            "test_live_minio_backup_restore_drill.py --suite-lane=live",
            "docker compose stop minio",
            "docker compose rm -f minio",
            'docker volume rm "${COMPOSE_PROJECT_NAME}_seaweedfs-data"',
        ),
        "live workflow",
        errors,
    )
    if errors:
        raise MinioBackupDrillConfigError("\n".join(errors))


def _validate_manifest_fields(core_text: str, errors: list[str]) -> None:
    try:
        tree = ast.parse(core_text)
    except SyntaxError:
        errors.append("core MinIO backup drill must parse as Python")
        return
    manifest_class = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ManifestEntry"
        ),
        None,
    )
    if manifest_class is None:
        errors.append("core must define ManifestEntry")
        return
    method = next(
        (
            node
            for node in manifest_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "to_mapping"
        ),
        None,
    )
    if method is None:
        errors.append("ManifestEntry must define to_mapping")
        return
    returned = next(
        (node.value for node in ast.walk(method) if isinstance(node, ast.Return)),
        None,
    )
    if not isinstance(returned, ast.Dict):
        errors.append("ManifestEntry.to_mapping must return an explicit dictionary")
        return
    keys = {
        key.value
        for key in returned.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if keys != EXPECTED_MANIFEST_FIELDS or len(returned.keys) != len(EXPECTED_MANIFEST_FIELDS):
        errors.append("manifest fields must be limited to opaque refs, sizes, and SHA-256")


def _validate_cli_ast(cli_text: str, errors: list[str]) -> None:
    try:
        tree = ast.parse(cli_text)
    except SyntaxError:
        errors.append("MinIO backup drill CLI must parse as Python")
        return
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    if any("minio/" + "mc" in value for value in constants):
        errors.append("MinIO tool images must not be used by the drill")
    if any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and (
            any(alias.name == "subprocess" for alias in node.names)
            if isinstance(node, ast.Import)
            else node.module == "subprocess"
        )
        for node in ast.walk(tree)
    ):
        errors.append("MinIO backup drill must use the in-process SigV4 client")


def _validate_s3_client_ast(client_text: str, errors: list[str]) -> None:
    try:
        tree = ast.parse(client_text)
    except SyntaxError:
        errors.append("SigV4 client must parse as Python")
        return
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    if "subprocess" in imports or "boto3" in imports or "botocore" in imports:
        errors.append("SigV4 client must remain dependency-free and in-process")
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    if any("minio/" + "mc" in value for value in constants):
        errors.append("SigV4 client must not reference MinIO tool images")


def _validate_policy(policy: Mapping[str, object], errors: list[str]) -> None:
    components = policy.get("components")
    minio = components.get("minio") if isinstance(components, Mapping) else None
    backup = minio.get("backup") if isinstance(minio, Mapping) else None
    if not isinstance(backup, Mapping):
        errors.append("policy must define components.minio.backup")
        return
    if backup.get("source") != "primary-data-bucket":
        errors.append("MinIO backup source must be primary-data-bucket")
    if backup.get("target") != "cross-bucket-encrypted-replica":
        errors.append("MinIO backup target must be cross-bucket-encrypted-replica")
    if backup.get("encrypted") is not True:
        errors.append("MinIO backup policy must require encryption")
    if backup.get("source") == backup.get("target"):
        errors.append("MinIO backup source and target must be distinct")


def _require_markers(
    text: str,
    markers: tuple[str, ...],
    label: str,
    errors: list[str],
) -> None:
    for marker in markers:
        if marker not in text:
            errors.append(f"{label} missing required marker {marker!r}")


def main() -> None:
    validate_repository()
    print("Validated the tenant-scoped encrypted MinIO replica/restore drill.")


if __name__ == "__main__":
    main()
