from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infra" / "security" / "backup-retention-policy.json"
DOC_PATH = ROOT / "docs" / "security" / "backup-restore-retention.md"
SECURITY_PATH = ROOT / "SECURITY.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"

REQUIRED_COMPONENTS = {
    "eval-reports",
    "grafana",
    "minio",
    "opensearch",
    "otel-collector",
    "postgres",
    "prometheus",
    "redis",
    "sandbox-artifacts",
}
ALLOWED_PROFILES = {"active", "future-required"}
ALLOWED_FREQUENCIES = {"continuous", "hourly", "daily", "weekly", "not_applicable"}


class BackupRetentionConfigError(ValueError):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise BackupRetentionConfigError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return payload


def validate_policy(policy: Mapping[str, object]) -> None:
    errors: list[str] = []
    if policy.get("schema_version") != "backup-retention-policy.v1":
        errors.append("schema_version must be backup-retention-policy.v1")

    defaults = _mapping(policy.get("defaults"), "defaults", errors)
    if defaults.get("backup_encryption_required") is not True:
        errors.append("defaults.backup_encryption_required must be true")
    if defaults.get("restore_drill_required") is not True:
        errors.append("defaults.restore_drill_required must be true")
    if defaults.get("tenant_scoped_deletion_required") is not True:
        errors.append("defaults.tenant_scoped_deletion_required must be true")
    if defaults.get("deletion_audit_event_required") is not True:
        errors.append("defaults.deletion_audit_event_required must be true")
    maximum_restore_drill_days = _positive_int(
        defaults.get("maximum_restore_drill_interval_days"),
        "defaults.maximum_restore_drill_interval_days",
        errors,
    )

    retention_classes = _mapping(policy.get("retention_classes"), "retention_classes", errors)
    if not retention_classes:
        errors.append("retention_classes must not be empty")
    class_minimums = _retention_class_minimums(retention_classes, errors)

    components = _mapping(policy.get("components"), "components", errors)
    missing_components = REQUIRED_COMPONENTS - set(components)
    if missing_components:
        errors.append(f"components missing required entries: {', '.join(sorted(missing_components))}")

    for component_name in sorted(components):
        component = _mapping(components.get(component_name), f"components.{component_name}", errors)
        _validate_component(
            component_name=component_name,
            component=component,
            class_minimums=class_minimums,
            maximum_restore_drill_days=maximum_restore_drill_days,
            errors=errors,
        )

    if errors:
        raise BackupRetentionConfigError("\n".join(errors))


def validate_supporting_files(
    *,
    docs_text: str,
    security_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    required_script = "scripts/ci/check_backup_retention_config.py"
    if "backup-retention-policy.json" not in docs_text or "restore drill" not in docs_text:
        errors.append("docs/security/backup-restore-retention.md must document policy and restore drill expectations")
    if "backup/restore and retention policy" not in security_text.lower():
        errors.append("SECURITY.md must mention the backup/restore and retention policy")
    if "backup-retention-config:" not in makefile_text or required_script not in makefile_text:
        errors.append("Makefile must expose backup-retention-config")
    if required_script not in ci_workflow_text:
        errors.append("CI workflow must run check_backup_retention_config.py")
    if required_script not in security_workflow_text:
        errors.append("security workflow must run check_backup_retention_config.py")

    if errors:
        raise BackupRetentionConfigError("\n".join(errors))


def _validate_component(
    *,
    component_name: str,
    component: Mapping[str, object],
    class_minimums: Mapping[str, int],
    maximum_restore_drill_days: int,
    errors: list[str],
) -> None:
    path = f"components.{component_name}"
    if component.get("profile") not in ALLOWED_PROFILES:
        errors.append(f"{path}.profile must be one of {sorted(ALLOWED_PROFILES)}")

    persistent = component.get("persistent")
    if not isinstance(persistent, bool):
        errors.append(f"{path}.persistent must be a boolean")
        persistent = False

    data_classes = component.get("data_classes")
    if not isinstance(data_classes, list) or not data_classes:
        errors.append(f"{path}.data_classes must be a non-empty list")
    elif not all(isinstance(item, str) and item in class_minimums for item in data_classes):
        errors.append(f"{path}.data_classes must reference known retention classes")

    backup = _mapping(component.get("backup"), f"{path}.backup", errors)
    _validate_backup(
        path=f"{path}.backup",
        backup=backup,
        persistent=persistent,
        maximum_restore_drill_days=maximum_restore_drill_days,
        errors=errors,
    )

    retention = _mapping(component.get("retention"), f"{path}.retention", errors)
    _validate_retention(
        path=f"{path}.retention",
        retention=retention,
        data_classes=data_classes if isinstance(data_classes, list) else [],
        class_minimums=class_minimums,
        errors=errors,
    )


def _validate_backup(
    *,
    path: str,
    backup: Mapping[str, object],
    persistent: bool,
    maximum_restore_drill_days: int,
    errors: list[str],
) -> None:
    enabled = backup.get("enabled")
    if not isinstance(enabled, bool):
        errors.append(f"{path}.enabled must be a boolean")
        enabled = False
    if persistent and enabled is not True:
        errors.append(f"{path}.enabled must be true for persistent components")

    frequency = backup.get("frequency")
    if frequency not in ALLOWED_FREQUENCIES:
        errors.append(f"{path}.frequency must be one of {sorted(ALLOWED_FREQUENCIES)}")
    if enabled and frequency == "not_applicable":
        errors.append(f"{path}.frequency must not be not_applicable when backups are enabled")

    if backup.get("encrypted") is not True:
        errors.append(f"{path}.encrypted must be true")

    target = backup.get("target")
    if not _nonempty_string(target):
        errors.append(f"{path}.target must be a non-empty string")
    elif enabled and str(target) == "not_applicable":
        errors.append(f"{path}.target must name a backup target when backups are enabled")

    rpo_minutes = _non_negative_int(backup.get("rpo_minutes"), f"{path}.rpo_minutes", errors)
    rto_minutes = _non_negative_int(backup.get("rto_minutes"), f"{path}.rto_minutes", errors)
    if persistent and rpo_minutes <= 0:
        errors.append(f"{path}.rpo_minutes must be greater than zero for persistent components")
    if rto_minutes <= 0:
        errors.append(f"{path}.rto_minutes must be greater than zero")

    restore_drill_days = _non_negative_int(
        backup.get("restore_drill_interval_days"),
        f"{path}.restore_drill_interval_days",
        errors,
    )
    if persistent and restore_drill_days <= 0:
        errors.append(f"{path}.restore_drill_interval_days must be greater than zero for persistent components")
    if restore_drill_days > maximum_restore_drill_days:
        errors.append(
            f"{path}.restore_drill_interval_days must be no more than "
            f"{maximum_restore_drill_days}"
        )


def _validate_retention(
    *,
    path: str,
    retention: Mapping[str, object],
    data_classes: Sequence[object],
    class_minimums: Mapping[str, int],
    errors: list[str],
) -> None:
    if retention.get("tenant_scoped_deletion") is not True:
        errors.append(f"{path}.tenant_scoped_deletion must be true")
    if retention.get("audit_event_required") is not True:
        errors.append(f"{path}.audit_event_required must be true")

    classes = _mapping(retention.get("classes"), f"{path}.classes", errors)
    if not classes:
        errors.append(f"{path}.classes must not be empty")

    missing_data_classes = sorted(
        str(item) for item in data_classes if isinstance(item, str) and item not in classes
    )
    if missing_data_classes:
        errors.append(f"{path}.classes missing data classes: {', '.join(missing_data_classes)}")

    for class_name in sorted(classes):
        if class_name not in class_minimums:
            errors.append(f"{path}.classes.{class_name} must reference a known retention class")
            continue
        class_policy = _mapping(classes.get(class_name), f"{path}.classes.{class_name}", errors)
        days = _positive_int(class_policy.get("days"), f"{path}.classes.{class_name}.days", errors)
        minimum_days = class_minimums[class_name]
        if days < minimum_days:
            errors.append(f"{path}.classes.{class_name}.days must be at least {minimum_days}")


def _retention_class_minimums(
    retention_classes: Mapping[str, object],
    errors: list[str],
) -> dict[str, int]:
    minimums: dict[str, int] = {}
    for class_name in sorted(retention_classes):
        class_config = _mapping(
            retention_classes.get(class_name),
            f"retention_classes.{class_name}",
            errors,
        )
        minimums[class_name] = _positive_int(
            class_config.get("minimum_days"),
            f"retention_classes.{class_name}.minimum_days",
            errors,
        )
    return minimums


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _positive_int(value: object, path: str, errors: list[str]) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    errors.append(f"{path} must be a positive integer")
    return 0


def _non_negative_int(value: object, path: str, errors: list[str]) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    errors.append(f"{path} must be a non-negative integer")
    return 0


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _component_count(policy: Mapping[str, object]) -> int:
    components = policy.get("components")
    if isinstance(components, Mapping):
        return len(components)
    return 0


def main() -> None:
    policy = load_policy()
    validate_policy(policy)
    validate_supporting_files(
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        security_text=SECURITY_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(f"Validated backup/restore and retention policy with {_component_count(policy)} component(s).")


if __name__ == "__main__":
    main()
