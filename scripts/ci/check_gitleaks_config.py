from __future__ import annotations

import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.ci.run_gitleaks import (  # noqa: E402
    CONFIG_PATH,
    FIXTURE_MANIFEST_PATH,
    GITLEAKS_IMAGE,
    GitleaksExecutionError,
    GITLEAKS_LINUX_X64_SHA256,
    GITLEAKS_VERSION,
    ROOT,
    load_fixture_fingerprints,
)

MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
RUNNER_PATH = ROOT / "scripts" / "ci" / "run_gitleaks.py"
TEST_PATH = ROOT / "apps" / "api" / "tests" / "test_gitleaks_gate.py"
IGNORE_PATH = ROOT / ".gitleaksignore"


class GitleaksConfigError(ValueError):
    pass


def _has_allowlist_config(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in {"allowlist", "allowlists"} or _has_allowlist_config(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_has_allowlist_config(child) for child in value)
    return False


def validate_gitleaks_config(
    *,
    config_text: str,
    runner_text: str,
    test_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    try:
        parsed_config = tomllib.loads(config_text)
    except tomllib.TOMLDecodeError as exc:
        errors.append(f".gitleaks.toml is invalid TOML: {exc}")
        parsed_config = {}
    if _has_allowlist_config(parsed_config):
        errors.append(
            ".gitleaks.toml must not contain path, regex, rule, or global allowlists"
        )
    if "--max-target-megabytes" in runner_text:
        errors.append("run_gitleaks.py must not skip large files by size")
    for marker in (
        "[extend]",
        "useDefault = true",
        "database-uri-with-credentials",
        "credential-assignment",
    ):
        if marker not in config_text:
            errors.append(f".gitleaks.toml missing `{marker}`")
    for marker in (
        f'GITLEAKS_VERSION = "{GITLEAKS_VERSION}"',
        GITLEAKS_IMAGE.split("@", 1)[1],
        GITLEAKS_LINUX_X64_SHA256,
        "FIXTURE_MANIFEST_PATH",
        "load_fixture_fingerprints",
        "_finding_fingerprint",
        '"--report-format"',
        '"--report-path"',
        '"--ignore-gitleaks-allow"',
        "hashlib.sha256(match.encode",
        '"--network",',
        '"none",',
        '"no-new-privileges:true"',
        '"git",',
        '"dir",',
        '"--log-opts=--all"',
    ):
        if marker not in runner_text:
            errors.append(f"run_gitleaks.py missing `{marker}`")
    for marker in (
        "test_real_gitleaks_detects_high_risk_fixture",
        "aws-access-token",
        "database-dsn",
        "signed-jwt",
        "credential-synonym",
        "encrypted-private-key",
        "test_real_gitleaks_accepts_clean_placeholders",
        "test_gitleaks_runner_scans_worktree_and_complete_git_history",
        "test_gitleaks_runner_suppresses_only_exact_synthetic_fingerprint",
        "test_gitleaks_runner_rejects_any_fingerprint_dimension_drift",
        "test_fixture_manifest_rejects_path_patterns",
    ):
        if marker not in test_text:
            errors.append(f"Gitleaks tests missing `{marker}`")
    for marker in (
        "gitleaks-config:",
        "scripts/ci/check_gitleaks_config.py",
        "gitleaks-scan:",
        "scripts/ci/run_gitleaks.py",
    ):
        if marker not in makefile_text:
            errors.append(f"Makefile missing `{marker}`")
    for workflow_name, workflow_text in (
        ("ci", ci_workflow_text),
        ("security", security_workflow_text),
    ):
        if "scripts/ci/check_gitleaks_config.py" not in workflow_text:
            errors.append(f"{workflow_name} workflow must run the Gitleaks config gate")
    for marker in (
        f'GITLEAKS_VERSION: "{GITLEAKS_VERSION}"',
        GITLEAKS_LINUX_X64_SHA256,
        "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz",
        "sha256sum --check",
        "scripts/ci/run_gitleaks.py",
        'HALLU_DEFENSE_GITLEAKS_LIVE_TEST: "true"',
        "apps/api/tests/test_gitleaks_gate.py",
        "fetch-depth: 0",
        'version)" = "${GITLEAKS_VERSION}"',
    ):
        if marker not in security_workflow_text:
            errors.append(f"security workflow missing `{marker}`")
    if errors:
        raise GitleaksConfigError("\n".join(errors))


def main() -> None:
    if IGNORE_PATH.exists():
        raise GitleaksConfigError(
            ".gitleaksignore is forbidden; use only exact synthetic fingerprints."
        )
    try:
        load_fixture_fingerprints("fixtures")
        load_fixture_fingerprints("secret_scan_fixtures")
    except GitleaksExecutionError as exc:
        raise GitleaksConfigError(str(exc)) from None
    validate_gitleaks_config(
        config_text=CONFIG_PATH.read_text(encoding="utf-8"),
        runner_text=RUNNER_PATH.read_text(encoding="utf-8"),
        test_text=TEST_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    fixture_count = len(load_fixture_fingerprints("fixtures")) + len(
        load_fixture_fingerprints("secret_scan_fixtures")
    )
    print(
        "Validated pinned Gitleaks policy, installer, workflows, and "
        f"{fixture_count} exact synthetic fixture fingerprint(s) from "
        f"{FIXTURE_MANIFEST_PATH.relative_to(ROOT)}."
    )


if __name__ == "__main__":
    main()
