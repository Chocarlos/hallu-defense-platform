from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE_PATH = ROOT / "Makefile"
PACKAGE_JSON_PATH = ROOT / "package.json"
PACKAGE_LOCK_PATH = ROOT / "package-lock.json"
ESLINT_CONFIG_PATH = ROOT / "eslint.config.mjs"
API_PYPROJECT_PATH = ROOT / "apps" / "api" / "pyproject.toml"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOWS_DIR = ROOT / ".github" / "workflows"

REQUIRED_PATHS = (
    "apps",
    "package-lock.json",
    "eslint.config.mjs",
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
    "lint": "eslint . --max-warnings=0",
    "test": "npm run test --workspaces --if-present",
    "typecheck": "npm run typecheck --workspaces --if-present",
}
REQUIRED_ROOT_DEV_DEPENDENCIES = {
    "eslint": "9.39.4",
    "eslint-config-next": "16.2.10",
    "next": "16.2.10",
}
REQUIRED_OVERRIDES = {"next": {"postcss": "8.5.10"}}
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
    "lint": ("ruff check", "npm run lint"),
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
    "security-check": (
        "secret_scan.py",
        "npm audit --audit-level=high",
        "npm audit --omit=dev --audit-level=high",
    ),
}
REQUIRED_WORKFLOW_FILES = (
    "ci.yml",
    "security.yml",
    "evals.yml",
)
CI_REQUIRED_MARKERS = (
    "backend:",
    "typescript:",
    "runs-on: ubuntu-24.04",
    "permissions:\n  contents: read",
    "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
    "persist-credentials: false",
    "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0",
    "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0",
    "open-policy-agent/setup-opa@b2b258e089860efaadaaf71bf6e3aecb4a3eeff1 # v2.4.0",
    'node-version: "24.18.0"',
    'python-version: "3.12.13"',
    'pip-version: "26.1.2"',
    "python scripts/ci/install_python_lock.py build-tools",
    "python scripts/ci/compile_python_locks.py --check",
    "python scripts/ci/install_python_lock.py dev",
    "python scripts/ci/check_python_reproducibility.py",
    "python -m ruff check apps/api/src apps/api/tests scripts evals",
    "python -m mypy apps/api/src",
    "python scripts/ci/check_json_schemas.py",
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
    "npm ci",
    "npm audit --audit-level=high",
    "npm audit --omit=dev --audit-level=high",
    "npm run lint",
    "npm run test",
    "npm run build",
)
TARGET_RE = re.compile(r"^(?P<target>[A-Za-z0-9_.-]+):(?:\s|$)")
ACTION_USE_RE = re.compile(
    r"^\s*-\s+uses:\s+(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)"
    r"(?:\s+#\s*(?P<version>v[^\s]+))?\s*$",
    re.MULTILINE,
)


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
    package_lock_text: str,
    eslint_config_text: str,
    api_pyproject_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    workflow_files: set[str],
) -> None:
    errors: list[str] = []
    _validate_monorepo_layout(
        existing_paths,
        package_json_text,
        package_lock_text,
        eslint_config_text,
        api_pyproject_text,
        errors,
    )
    _validate_makefile(makefile_text, errors)
    _validate_ci(ci_workflow_text, workflow_files, errors)
    if errors:
        raise FoundationInfraError("\n".join(errors))


def _validate_monorepo_layout(
    existing_paths: set[str],
    package_json_text: str,
    package_lock_text: str,
    eslint_config_text: str,
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
    dev_dependencies = package_json.get("devDependencies", {})
    if not isinstance(dev_dependencies, dict):
        errors.append("package.json devDependencies must be an object")
        dev_dependencies = {}
    for dependency, expected_version in REQUIRED_ROOT_DEV_DEPENDENCIES.items():
        if dev_dependencies.get(dependency) != expected_version:
            errors.append(
                f"package.json devDependency `{dependency}` must be `{expected_version}`"
            )
    if package_json.get("overrides") != REQUIRED_OVERRIDES:
        errors.append("package.json must contain only the approved next -> postcss 8.5.10 override")
    if package_json.get("resolutions") not in (None, {}):
        errors.append("package.json must not contain dependency resolutions")
    if package_json.get("engines") != {"node": "24.18.0", "npm": "11.16.0"}:
        errors.append("package.json must pin engines.node 24.18.0 and engines.npm 11.16.0")

    try:
        package_lock = json.loads(package_lock_text)
    except json.JSONDecodeError as exc:
        errors.append(f"package-lock.json must be valid JSON: {exc}")
        package_lock = {}
    lock_packages = package_lock.get("packages", {})
    lock_root = lock_packages.get("", {}) if isinstance(lock_packages, dict) else {}
    lock_dev_dependencies = (
        lock_root.get("devDependencies", {}) if isinstance(lock_root, dict) else {}
    )
    for dependency, expected_version in REQUIRED_ROOT_DEV_DEPENDENCIES.items():
        if not isinstance(lock_dev_dependencies, dict) or lock_dev_dependencies.get(
            dependency
        ) != expected_version:
            errors.append(
                f"package-lock.json root devDependency `{dependency}` must match package.json"
            )
    if package_lock.get("overrides") not in (None, REQUIRED_OVERRIDES):
        errors.append("package-lock.json overrides must match the approved PostCSS correction")
    next_package = lock_packages.get("node_modules/next", {}) if isinstance(lock_packages, dict) else {}
    nested_postcss = (
        lock_packages.get("node_modules/next/node_modules/postcss", {})
        if isinstance(lock_packages, dict)
        else {}
    )
    if not isinstance(next_package, dict) or next_package.get("version") != "16.2.10":
        errors.append("package-lock.json must resolve Next 16.2.10 exactly")
    if not isinstance(nested_postcss, dict) or nested_postcss.get("version") != "8.5.10":
        errors.append("package-lock.json must resolve Next's PostCSS to 8.5.10")

    for marker in (
        'from "eslint/config"',
        'from "eslint-config-next/core-web-vitals"',
        'from "eslint-config-next/typescript"',
        'rootDir: "apps/console/"',
        '"@typescript-eslint/no-unused-vars"',
        'argsIgnorePattern: "^_"',
        '"@next/next/no-html-link-for-pages": "off"',
        '".claude/worktrees/**"',
        '".claude/settings.local.json"',
        '".codex-leader-worktrees/**"',
        '".codex-leader-worktrees/**"',
        '"**/.next/**"',
        '"**/dist/**"',
        '"**/next-env.d.ts"',
    ):
        if marker not in eslint_config_text:
            errors.append(f"eslint.config.mjs missing production lint marker: {marker}")

    try:
        api_project = tomllib.loads(api_pyproject_text)
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"apps/api/pyproject.toml must be valid TOML: {exc}")
        return

    project = api_project.get("project", {})
    if project.get("name") != "hallu-defense-api":
        errors.append("apps/api/pyproject.toml must define project name hallu-defense-api")
    if project.get("requires-python") != ">=3.12,<3.13":
        errors.append("apps/api/pyproject.toml must pin Python >=3.12,<3.13")
    optional_dependencies = project.get("optional-dependencies", {})
    dev_dependencies = optional_dependencies.get("dev", [])
    for dependency in ("pytest", "ruff", "mypy"):
        if not any(str(candidate).startswith(dependency) for candidate in dev_dependencies):
            errors.append(f"apps/api dev dependencies must include {dependency}")
    runtime_dependencies = project.get("dependencies", [])
    if not any(str(candidate).startswith("jsonschema") for candidate in runtime_dependencies):
        errors.append("apps/api runtime dependencies must include jsonschema")


def _validate_makefile(makefile_text: str, errors: list[str]) -> None:
    targets = _parse_make_targets(makefile_text)
    phony_targets = _parse_phony_targets(makefile_text)
    target_bodies = _parse_target_bodies(makefile_text)

    if "VENV_PY" not in makefile_text or "PY :=" not in makefile_text:
        errors.append("Makefile must prefer the repository virtualenv Python when present")
    if "VENV_PY := .venv/Scripts/python.exe" not in makefile_text:
        errors.append("Makefile must use the executable Windows virtualenv Python path")

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
    if ci_workflow_text.count("runs-on: ubuntu-24.04") != 2:
        errors.append("ci.yml must pin both jobs to ubuntu-24.04")
    if "ubuntu-latest" in ci_workflow_text:
        errors.append("ci.yml must not use the floating ubuntu-latest runner")
    if "npm install" in ci_workflow_text:
        errors.append("ci.yml must use npm ci instead of mutating dependency resolution")
    if ci_workflow_text.count("timeout-minutes:") != 2:
        errors.append("ci.yml must bound every job with timeout-minutes")
    if "pip install --upgrade" in ci_workflow_text or "pip install -e" in ci_workflow_text:
        errors.append("ci.yml must install Python only from the exact hashed locks")
    if ci_workflow_text.count("--omit") != 1 or "npm audit --omit=dev --audit-level=high" not in ci_workflow_text:
        errors.append("ci.yml may use only the exact runtime npm audit omit command")
    action_uses = list(ACTION_USE_RE.finditer(ci_workflow_text))
    if not action_uses:
        errors.append("ci.yml must declare pinned third-party actions")
    for match in action_uses:
        action = match.group("action")
        reference = match.group("ref")
        version = match.group("version")
        if re.fullmatch(r"[0-9a-f]{40}", reference) is None:
            errors.append(f"ci.yml action {action} must be pinned to a full commit SHA")
        if version is None:
            errors.append(f"ci.yml action {action} SHA must retain a version comment")


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
        package_lock_text=PACKAGE_LOCK_PATH.read_text(encoding="utf-8"),
        eslint_config_text=ESLINT_CONFIG_PATH.read_text(encoding="utf-8"),
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
