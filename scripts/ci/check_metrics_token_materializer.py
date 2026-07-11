from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CORE_PATH = (
    ROOT
    / "apps"
    / "api"
    / "src"
    / "hallu_defense"
    / "services"
    / "metrics_token_materializer.py"
)
CLI_PATH = ROOT / "scripts" / "dev" / "materialize_metrics_bearer_token.py"
PROMETHEUS_PATH = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
DOC_PATH = ROOT / "docs" / "deployment" / "metrics-bearer-token-materializer.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"

EXPECTED_CREDENTIALS_FILE = "/run/secrets/hallu_defense_metrics_bearer_token"
MAKE_TARGET = "metrics-token-materializer-config"
GATE_SCRIPT = "scripts/ci/check_metrics_token_materializer.py"


class MetricsTokenMaterializerConfigError(ValueError):
    pass


def validate_metrics_token_materializer_config(
    *,
    core_text: str,
    cli_text: str,
    prometheus: Mapping[str, object],
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_core(core_text, errors)
    _validate_cli(cli_text, errors)
    _validate_single_secret_source(core_text, cli_text, errors)
    _validate_prometheus(prometheus, errors)
    _validate_docs(docs_text, errors)
    _validate_makefile(makefile_text, errors)
    _validate_workflows(ci_workflow_text, security_workflow_text, errors)
    if errors:
        raise MetricsTokenMaterializerConfigError("\n".join(errors))


def _validate_core(core_text: str, errors: list[str]) -> None:
    _require(
        core_text,
        {
            "class PosixAtomicFileOperations",
            "class AtomicSecretFileWriter",
            "class MetricsBearerTokenMaterializer",
            "secret_manager.get_secret(self._secret_name)",
            "os.replace(",
            "os.fsync(",
            'getattr(os, "fchmod")',
            "SECURE_FILE_MODE = 0o600",
            "O_NOFOLLOW",
            "follow_symlinks=False",
            "INSECURE_DIRECTORY_BITS = 0o022",
            "self._operations.fsync(directory_fd)",
            "MIN_REFRESH_INTERVAL_SECONDS",
            "MAX_REFRESH_INTERVAL_SECONDS",
            "from None",
        },
        "metrics token materializer core",
        errors,
    )


def _validate_cli(cli_text: str, errors: list[str]) -> None:
    _require(
        cli_text,
        {
            "settings.metrics_bearer_token_secret_name",
            "create_secret_manager(settings)",
            "AtomicSecretFileWriter(args.output)",
            '"--watch"',
            '"--interval-seconds"',
            "signal.SIGINT",
            "signal.SIGTERM",
            "previous file retained",
        },
        "metrics token materializer CLI",
        errors,
    )


def _validate_single_secret_source(
    core_text: str,
    cli_text: str,
    errors: list[str],
) -> None:
    runtime_text = f"{core_text}\n{cli_text}"
    for forbidden in (
        "os.getenv(",
        "os.environ[",
        '"--token"',
        '"--secret-value"',
        "observability/metrics-scrape-token",
        "observability/metrics-bearer-token",
    ):
        if forbidden in runtime_text:
            errors.append(
                "Metrics token runtime must use only the configured SecretManager source; "
                f"found forbidden `{forbidden}`"
            )

    try:
        trees = (ast.parse(core_text), ast.parse(cli_text))
    except SyntaxError:
        errors.append("Metrics token runtime sources must be valid Python")
        return
    get_secret_calls = 0
    create_manager_calls = 0
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "get_secret":
                    get_secret_calls += 1
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "create_secret_manager":
                    create_manager_calls += 1
            assignment = _string_assignment(node)
            if assignment is not None:
                name, _value = assignment
                if "TOKEN" in name.upper():
                    errors.append(
                        "Metrics token runtime must not assign a hardcoded token value "
                        f"to {name}"
                    )
    if get_secret_calls != 1:
        errors.append("Metrics token runtime must have exactly one SecretManager.get_secret call")
    if create_manager_calls != 1:
        errors.append("Metrics token CLI must construct exactly one real SecretManager")


def _string_assignment(node: ast.AST) -> tuple[str, str] | None:
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
        if not isinstance(node.value.value, str) or len(node.targets) != 1:
            return None
        target = node.targets[0]
        if isinstance(target, ast.Name):
            return target.id, node.value.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant):
        if isinstance(node.target, ast.Name) and isinstance(node.value.value, str):
            return node.target.id, node.value.value
    return None


def _validate_prometheus(prometheus: Mapping[str, object], errors: list[str]) -> None:
    scrape_configs = prometheus.get("scrape_configs")
    if not isinstance(scrape_configs, list):
        errors.append("prometheus.prod.yml scrape_configs must be a list")
        return
    scrape = next(
        (
            item
            for item in scrape_configs
            if isinstance(item, Mapping) and item.get("job_name") == "hallu-defense-api"
        ),
        None,
    )
    if not isinstance(scrape, Mapping):
        errors.append("prometheus.prod.yml must contain the hallu-defense-api scrape job")
        return
    authorization = scrape.get("authorization")
    if not isinstance(authorization, Mapping):
        errors.append("prometheus.prod.yml scrape authorization must be an object")
        return
    if authorization.get("credentials_file") != EXPECTED_CREDENTIALS_FILE:
        errors.append(
            "Prometheus credentials_file must match the materializer destination "
            f"{EXPECTED_CREDENTIALS_FILE}"
        )
    if "credentials" in authorization:
        errors.append("Prometheus authorization must not contain inline credentials")


def _validate_docs(docs_text: str, errors: list[str]) -> None:
    _require(
        docs_text,
        {
            "sidecar",
            "systemd",
            "tmpfiles.d",
            "emptyDir",
            "same numeric UID",
            "0600",
            "--watch",
            "SIGTERM",
            "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
            EXPECTED_CREDENTIALS_FILE,
        },
        "metrics token materializer deployment documentation",
        errors,
    )


def _validate_makefile(makefile_text: str, errors: list[str]) -> None:
    phony_line = next(
        (line for line in makefile_text.splitlines() if line.startswith(".PHONY:")),
        "",
    )
    if f"{MAKE_TARGET}:" not in makefile_text:
        errors.append(f"Makefile must expose {MAKE_TARGET}")
    if MAKE_TARGET not in phony_line:
        errors.append(f".PHONY must include {MAKE_TARGET}")
    if GATE_SCRIPT not in makefile_text:
        errors.append(f"Makefile must wire {GATE_SCRIPT}")
    security_section = makefile_text.partition("security-check:")[2]
    if GATE_SCRIPT not in security_section:
        errors.append(f"security-check must run {GATE_SCRIPT}")


def _validate_workflows(
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    if GATE_SCRIPT not in ci_workflow_text:
        errors.append(f"CI workflow must run {GATE_SCRIPT}")
    if GATE_SCRIPT not in security_workflow_text:
        errors.append(f"security workflow must run {GATE_SCRIPT}")


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in sorted(snippets):
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def load_current_config() -> dict[str, object]:
    prometheus = yaml.safe_load(PROMETHEUS_PATH.read_text(encoding="utf-8"))
    if not isinstance(prometheus, Mapping):
        raise MetricsTokenMaterializerConfigError(
            "infra/prometheus/prometheus.prod.yml must contain a YAML object"
        )
    return {
        "core_text": CORE_PATH.read_text(encoding="utf-8"),
        "cli_text": CLI_PATH.read_text(encoding="utf-8"),
        "prometheus": prometheus,
        "docs_text": DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def main() -> None:
    validate_metrics_token_materializer_config(**load_current_config())
    print("Validated metrics bearer token materializer configuration.")


if __name__ == "__main__":
    main()
