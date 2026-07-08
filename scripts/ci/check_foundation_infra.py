from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE_PATH = ROOT / "Makefile"
PACKAGE_JSON_PATH = ROOT / "package.json"
API_PYPROJECT_PATH = ROOT / "apps" / "api" / "pyproject.toml"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOWS_DIR = ROOT / ".github" / "workflows"

REQUIRED_PATHS = (
    "apps",
    "apps/api",
    "apps/api/pyproject.toml",
    "apps/console",
    "apps/console/package.json",
    "packages",
    "packages/contracts",
    "packages/contracts/package.json",
    "packages/sdk",
    "packages/sdk/package.json",
    "packages/agent-adapters",
    "packages/agent-adapters/package.json",
    "packages/mcp-server",
    "packages/mcp-server/package.json",
    "infra",
    "infra/docker",
    "infra/grafana",
    "infra/opa",
    "infra/otel",
    "infra/prometheus",
    "infra/rag",
    "infra/security",
    "evals",
    "evals/golden_sets",
    "evals/reports",
    "evals/runners",
    "scripts",
    "scripts/ci",
    "scripts/dev",
)
REQUIRED_WORKSPACES = (
    "packages/contracts",
    "packages/sdk",
    "packages/agent-adapters",
    "packages/mcp-server",
    "apps/console",
)
REQUIRED_ROOT_NPM_SCRIPTS = {
    "build": "npm run build --workspaces --if-present",
    "test": "npm run test --workspaces --if-present",
    "typecheck": "npm run typecheck --workspaces --if-present",
}
REQUIRED_MAKE_TARGETS = (
    "lint",
    "typecheck",
    "test",
    "build",
    "contracts",
    "openapi",
    "openapi-check",
    "foundation-docs-check",
    "foundation-infra-check",
    "traceability-check",
    "worklog-check",
    "policy-test",
    "sandbox-test",
    "evals-smoke",
    "evals-scenarios",
    "security-check",
)
TARGET_BODY_MARKERS = {
    "lint": ("ruff check",),
    "typecheck": ("mypy apps/api/src", "npm run typecheck"),
    "test": ("pytest apps/api/tests", "npm run test"),
    "build": ("npm run build",),
    "contracts": ("check_json_schemas.py", "test_contracts.py"),
    "openapi": ("export_openapi.py",),
    "openapi-check": ("check_openapi.py",),
    "foundation-docs-check": ("check_foundation_docs.py",),
    "foundation-infra-check": ("check_foundation_infra.py",),
    "traceability-check": ("check_traceability_matrix.py",),
    "worklog-check": ("check_worklog.py",),
    "policy-test": ("run_policy_tests.py",),
    "sandbox-test": ("pytest apps/api/tests -k sandbox",),
    "evals-smoke": ("evals/runners/smoke.py",),
    "evals-scenarios": ("evals/runners/scenarios.py",),
    "security-check": ("secret_scan.py", "npm audit --omit dev"),
}
REQUIRED_WORKFLOW_FILES = (
    "ci.yml",
    "security.yml",
    "evals.yml",
)
CI_REQUIRED_MARKERS = (
    "backend:",
    "typescript:",
    "actions/setup-python",
    "actions/setup-node",
    "python -m pytest apps/api/tests",
    "python scripts/ci/check_openapi.py",
    "python scripts/ci/check_foundation_docs.py",
    "python scripts/ci/check_foundation_infra.py",
    "python scripts/ci/check_traceability_matrix.py",
    "python scripts/ci/check_worklog.py",
    "python scripts/ci/run_policy_tests.py",
    "python scripts/ci/check_auth_config.py",
    "python scripts/ci/check_rag_persistence_config.py",
    "python scripts/ci/python_dependency_audit.py",
    "python scripts/ci/check_grafana_dashboards.py",
    "npm run typecheck",
    "npm run test",
    "npm run build",
)
TARGET_RE = re.compile(r"^(?P<target>[A-Za-z0-9_.-]+):(?:\s|$)")


class FoundationInfraError(ValueError):
    pass


def collect_existing_paths(root: Path = ROOT) -> set[str]:
    return {
        relative_path.as_posix()
        for relative_path in (Path(required_path) for required_path in REQUIRED_PATHS)
        if (root / relative_path).exists()
    }


def collect_workflow_files(path: Path = WORKFLOWS_DIR) -> set[str]:
    if not path.exists():
        return set()
    return {workflow_path.name for workflow_path in path.glob("*.yml")}


def validate_foundation_infra(
    *,
    existing_paths: set[str],
    package_json_text: str,
    api_pyproject_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    workflow_files: set[str],
) -> None:
    errors: list[str] = []
    _validate_monorepo_layout(existing_paths, package_json_text, api_pyproject_text, errors)
    _validate_makefile(makefile_text, errors)
    _validate_ci(ci_workflow_text, workflow_files, errors)
    if errors:
        raise FoundationInfraError("\n".join(errors))


def _validate_monorepo_layout(
    existing_paths: set[str],
    package_json_text: str,
    api_pyproject_text: str,
    errors: list[str],
) -> None:
    missing_paths = sorted(set(REQUIRED_PATHS) - existing_paths)
    for missing_path in missing_paths:
        errors.append(f"missing required repository path: {missing_path}")

    try:
        package_json = json.loads(package_json_text)
    except json.JSONDecodeError as exc:
        errors.append(f"package.json must be valid JSON: {exc}")
        package_json = {}

    workspaces = package_json.get("workspaces", [])
    if not isinstance(workspaces, list):
        errors.append("package.json workspaces must be a list")
        workspaces = []
    for workspace in REQUIRED_WORKSPACES:
        if workspace not in workspaces:
            errors.append(f"package.json missing workspace: {workspace}")

    scripts = package_json.get("scripts", {})
    if not isinstance(scripts, dict):
        errors.append("package.json scripts must be an object")
        scripts = {}
    for script_name, expected_command in REQUIRED_ROOT_NPM_SCRIPTS.items():
        if scripts.get(script_name) != expected_command:
            errors.append(
                f"package.json script `{script_name}` must be `{expected_command}`"
            )

    try:
        api_project = tomllib.loads(api_pyproject_text)
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"apps/api/pyproject.toml must be valid TOML: {exc}")
        return

    project = api_project.get("project", {})
    if project.get("name") != "hallu-defense-api":
        errors.append("apps/api/pyproject.toml must define project name hallu-defense-api")
    if project.get("requires-python") != ">=3.12":
        errors.append("apps/api/pyproject.toml must require Python >=3.12")
    optional_dependencies = project.get("optional-dependencies", {})
    dev_dependencies = optional_dependencies.get("dev", [])
    for dependency in ("pytest", "ruff", "mypy", "jsonschema"):
        if not any(str(candidate).startswith(dependency) for candidate in dev_dependencies):
            errors.append(f"apps/api dev dependencies must include {dependency}")


def _validate_makefile(makefile_text: str, errors: list[str]) -> None:
    targets = _parse_make_targets(makefile_text)
    phony_targets = _parse_phony_targets(makefile_text)
    target_bodies = _parse_target_bodies(makefile_text)

    if "VENV_PY" not in makefile_text or "PY :=" not in makefile_text:
        errors.append("Makefile must prefer the repository virtualenv Python when present")

    for target in REQUIRED_MAKE_TARGETS:
        if target not in targets:
            errors.append(f"Makefile missing target: {target}")
        if target not in phony_targets:
            errors.append(f".PHONY missing target: {target}")
        body = "\n".join(target_bodies.get(target, ()))
        for marker in TARGET_BODY_MARKERS[target]:
            if marker not in body:
                errors.append(f"Makefile target `{target}` missing command marker: {marker}")


def _validate_ci(
    ci_workflow_text: str,
    workflow_files: set[str],
    errors: list[str],
) -> None:
    for workflow_file in REQUIRED_WORKFLOW_FILES:
        if workflow_file not in workflow_files:
            errors.append(f".github/workflows missing workflow file: {workflow_file}")
    for marker in CI_REQUIRED_MARKERS:
        if marker not in ci_workflow_text:
            errors.append(f".github/workflows/ci.yml missing marker: {marker}")


def _parse_make_targets(makefile_text: str) -> set[str]:
    targets: set[str] = set()
    for line in makefile_text.splitlines():
        match = TARGET_RE.match(line)
        if match is not None:
            targets.add(match.group("target"))
    return targets


def _parse_phony_targets(makefile_text: str) -> set[str]:
    phony_targets: set[str] = set()
    for line in makefile_text.splitlines():
        if line.startswith(".PHONY:"):
            phony_targets.update(line.removeprefix(".PHONY:").strip().split())
    return phony_targets


def _parse_target_bodies(makefile_text: str) -> dict[str, tuple[str, ...]]:
    bodies: dict[str, list[str]] = {}
    current_target: str | None = None
    for line in makefile_text.splitlines():
        match = TARGET_RE.match(line)
        if match is not None:
            current_target = match.group("target")
            bodies.setdefault(current_target, [])
            continue
        if current_target is not None and line.startswith("\t"):
            bodies[current_target].append(line.strip())
    return {target: tuple(lines) for target, lines in bodies.items()}


def main() -> None:
    validate_foundation_infra(
        existing_paths=collect_existing_paths(),
        package_json_text=PACKAGE_JSON_PATH.read_text(encoding="utf-8"),
        api_pyproject_text=API_PYPROJECT_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        workflow_files=collect_workflow_files(),
    )
    print(
        "Validated foundation infrastructure with "
        f"{len(REQUIRED_PATHS)} paths, {len(REQUIRED_MAKE_TARGETS)} Makefile targets, "
        f"and {len(REQUIRED_WORKFLOW_FILES)} workflow files."
    )


if __name__ == "__main__":
    main()
