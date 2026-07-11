from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.ci.run_gitleaks import (  # noqa: E402
    CONFIG_PATH,
    GITLEAKS_IMAGE,
    GITLEAKS_LINUX_X64_SHA256,
    GITLEAKS_VERSION,
    ROOT,
)

MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
RUNNER_PATH = ROOT / "scripts" / "ci" / "run_gitleaks.py"
TEST_PATH = ROOT / "apps" / "api" / "tests" / "test_gitleaks_gate.py"


class GitleaksConfigError(ValueError):
    pass


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
        '"--redact=100"',
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
        f"GITLEAKS_VERSION: \"{GITLEAKS_VERSION}\"",
        GITLEAKS_LINUX_X64_SHA256,
        "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz",
        "sha256sum --check",
        "scripts/ci/run_gitleaks.py",
        "HALLU_DEFENSE_GITLEAKS_LIVE_TEST: \"true\"",
        "apps/api/tests/test_gitleaks_gate.py",
        "fetch-depth: 0",
    ):
        if marker not in security_workflow_text:
            errors.append(f"security workflow missing `{marker}`")
    if errors:
        raise GitleaksConfigError("\n".join(errors))


def main() -> None:
    validate_gitleaks_config(
        config_text=CONFIG_PATH.read_text(encoding="utf-8"),
        runner_text=RUNNER_PATH.read_text(encoding="utf-8"),
        test_text=TEST_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print("Validated pinned Gitleaks policy, installer, workflows, and fixtures.")


if __name__ == "__main__":
    main()
