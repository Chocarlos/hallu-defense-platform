from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "infra" / "k8s" / "helm" / "hallu-defense"
CHART_PATH = CHART_DIR / "Chart.yaml"
VALUES_PATH = CHART_DIR / "values.yaml"
TEMPLATES_DIR = CHART_DIR / "templates"
DEPLOYMENT_DOC_PATH = ROOT / "docs" / "deployment" / "kubernetes-helm.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"

HELM_TEMPLATE_COMMAND = "helm template hallu-defense infra/k8s/helm/hallu-defense"
REQUIRED_TEMPLATE_FILES = {
    "_helpers.tpl",
    "api-deployment.yaml",
    "console-deployment.yaml",
    "worker-deployment.yaml",
    "migration-job.yaml",
    "pgvector-statefulset.yaml",
    "opensearch-statefulset.yaml",
    "secrets.yaml",
}
DEFAULT_SECRET_MARKERS = {
    "change-me",
    "minioadmin",
    "local-dev-only",
    "dev-root",
    "hallu:hallu",
}


class HelmChartConfigError(ValueError):
    pass


def load_yaml_file(path: Path) -> Mapping[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise HelmChartConfigError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return loaded


def load_template_texts(path: Path = TEMPLATES_DIR) -> dict[str, str]:
    if not path.exists():
        return {}
    return {
        template_path.name: template_path.read_text(encoding="utf-8")
        for template_path in sorted(path.glob("*.yaml"))
    } | {
        template_path.name: template_path.read_text(encoding="utf-8")
        for template_path in sorted(path.glob("*.tpl"))
    }


def validate_helm_chart(
    *,
    chart: Mapping[str, object],
    values: Mapping[str, object],
    templates: Mapping[str, str],
    deployment_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_chart_metadata(chart, errors)
    _validate_values(values, errors)
    _validate_templates(templates, errors)
    _validate_no_default_secrets(values, errors)
    _validate_supporting_files(
        deployment_doc_text=deployment_doc_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        live_workflow_text=live_workflow_text,
        errors=errors,
    )
    if errors:
        raise HelmChartConfigError("\n".join(errors))


def run_helm_template_if_available(
    *,
    helm_binary: str = "helm",
) -> dict[str, object]:
    executable = shutil.which(helm_binary)
    if executable is None:
        return {
            "status": "skipped",
            "reason": f"{helm_binary} executable is unavailable",
            "command": HELM_TEMPLATE_COMMAND,
        }
    result = subprocess.run(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            "--set",
            "worker.enabled=true",
            "--set-string",
            "secrets.keycloakJwks=jwks-placeholder",
            "--set-string",
            "secrets.vaultToken=prod-vault-token",
            "--set-string",
            "secrets.postgresDsn=postgresql://prod_user:prod_pass@postgres:5432/prod_db",
            "--set-string",
            "secrets.postgresUser=prod_user",
            "--set-string",
            "secrets.postgresPassword=prod_pass",
            "--set-string",
            "secrets.postgresDatabase=prod_db",
            "--set-string",
            "secrets.metricsBearerToken=prod-metrics-token",
            "--set-string",
            "secrets.opensearchInitialAdminPassword=prod-opensearch-pass",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise HelmChartConfigError(
            "helm template failed: "
            + (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
        )
    _validate_rendered_manifest(result.stdout)
    return {"status": "passed", "command": HELM_TEMPLATE_COMMAND}


def _validate_chart_metadata(chart: Mapping[str, object], errors: list[str]) -> None:
    if chart.get("apiVersion") != "v2":
        errors.append("Chart.yaml apiVersion must be v2")
    if chart.get("name") != "hallu-defense":
        errors.append("Chart.yaml name must be hallu-defense")
    if chart.get("type") != "application":
        errors.append("Chart.yaml type must be application")


def _validate_values(values: Mapping[str, object], errors: list[str]) -> None:
    kind_dependencies = _mapping(values.get("kindDependencies"), "values.kindDependencies", errors)
    if kind_dependencies.get("enabled") is not True:
        errors.append("values.kindDependencies.enabled must default true for kind")
    pgvector = _mapping(kind_dependencies.get("pgvector"), "values.kindDependencies.pgvector", errors)
    if pgvector.get("image") != "pgvector/pgvector:pg16":
        errors.append("values must pin pgvector/pgvector:pg16")
    opensearch = _mapping(kind_dependencies.get("opensearch"), "values.kindDependencies.opensearch", errors)
    if opensearch.get("image") != "opensearchproject/opensearch:2.15.0":
        errors.append("values must pin opensearchproject/opensearch:2.15.0")
    worker = _mapping(values.get("worker"), "values.worker", errors)
    if worker.get("enabled") is not True:
        errors.append("worker.enabled must default true now that the Batch 6 runtime exists")
    for section_name in ("api", "console", "worker"):
        section = _mapping(values.get(section_name), f"values.{section_name}", errors)
        resources = _mapping(section.get("resources"), f"values.{section_name}.resources", errors)
        _mapping(resources.get("requests"), f"values.{section_name}.resources.requests", errors)
        _mapping(resources.get("limits"), f"values.{section_name}.resources.limits", errors)
    secrets = _mapping(values.get("secrets"), "values.secrets", errors)
    for secret_key in (
        "keycloakJwks",
        "vaultToken",
        "postgresDsn",
        "postgresPassword",
        "metricsBearerToken",
        "opensearchInitialAdminPassword",
    ):
        if secrets.get(secret_key) not in {"", None}:
            errors.append(f"values.secrets.{secret_key} must default empty")


def _validate_templates(templates: Mapping[str, str], errors: list[str]) -> None:
    missing = REQUIRED_TEMPLATE_FILES - set(templates)
    if missing:
        errors.append("Helm chart missing template files: " + ", ".join(sorted(missing)))
        return
    combined = "\n".join(templates.values())
    for marker in (
        "runAsNonRoot: true",
        "allowPrivilegeEscalation: false",
        "drop:",
        "readOnlyRootFilesystem: true",
        "resources:",
        "limits:",
        "requests:",
        "livenessProbe:",
        "readinessProbe:",
        "secretKeyRef:",
        "stringData:",
        "required \"secrets.",
        "prometheus.io/scrape",
        "HALLU_DEFENSE_ENV",
        "value: production",
        "HALLU_DEFENSE_AUTH_REQUIRED",
        "HALLU_DEFENSE_AUTH_CLAIMS_MODE",
        "value: oidc_jwt",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "value: vault",
        "HALLU_DEFENSE_SANDBOX_BACKEND",
        "value: docker",
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "value: postgres",
        "HALLU_DEFENSE_INGESTION_MODE",
        "value: async",
        "kind: Job",
        "apply_postgres_migrations.py",
        "kind: StatefulSet",
        "pgvector",
        "opensearch",
    ):
        if marker not in combined:
            errors.append(f"Helm templates missing `{marker}`")
    if "unsigned_headers" in combined:
        errors.append("Helm templates must not configure unsigned auth headers")
    if "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND\n  value: memory" in combined:
        errors.append("Helm templates must not configure memory audit backend")
    if templates["_helpers.tpl"].count("runAsNonRoot: true") < 2:
        errors.append("Helm helper security contexts must set runAsNonRoot: true")
    if "{{- if .Values.worker.enabled }}" not in templates["worker-deployment.yaml"]:
        errors.append("worker deployment must be explicitly gated by worker.enabled")


def _validate_no_default_secrets(value: object, errors: list[str], path: str = "values") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            _validate_no_default_secrets(nested, errors, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, str):
        for index, nested in enumerate(value):
            _validate_no_default_secrets(nested, errors, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for marker in DEFAULT_SECRET_MARKERS:
        if marker in lowered:
            errors.append(f"{path} contains default secret marker {marker!r}")


def _validate_supporting_files(
    *,
    deployment_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_helm_chart.py"
    for marker in (
        "infra/k8s/helm/hallu-defense",
        "api, console, and worker deployment templates",
        "worker.enabled=true",
        "Batch 6 ingestion worker runtime",
        "pgvector and OpenSearch kind defaults",
        "helm template",
        "scripts/dev/live_kind_helm_smoke.py",
    ):
        if marker not in deployment_doc_text:
            errors.append(f"Kubernetes deployment docs missing `{marker}`")
    for target, marker in (
        ("helm-chart-check", script),
        ("kind-helm-live-smoke", "scripts/dev/live_kind_helm_smoke.py"),
    ):
        if f"{target}:" not in makefile_text or marker not in makefile_text:
            errors.append(f"Makefile must expose {target}")
        if not _makefile_phony_includes(makefile_text, target):
            errors.append(f"Makefile .PHONY must include {target}")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_helm_chart.py")
    security_section = makefile_text.partition("security-check:")[2]
    if script not in security_section:
        errors.append("security-check must include check_helm_chart.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_helm_chart.py")
    if "kind-helm-live:" not in live_workflow_text:
        errors.append("live workflow must include kind-helm-live job")
    if "HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED" not in live_workflow_text:
        errors.append("kind-helm-live job must wire the kind/Helm smoke env gate")


def _validate_rendered_manifest(rendered: str) -> None:
    docs = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, Mapping)]
    errors: list[str] = []
    kinds_by_component: set[tuple[str, str]] = set()
    for doc in docs:
        metadata = _mapping(doc.get("metadata"), "rendered.metadata", errors)
        labels = _mapping(metadata.get("labels"), "rendered.metadata.labels", errors)
        component = labels.get("app.kubernetes.io/component")
        if isinstance(component, str):
            kinds_by_component.add((str(doc.get("kind")), component))
    for expected in (
        ("Deployment", "api"),
        ("Deployment", "console"),
        ("Deployment", "worker"),
        ("Job", "migrations"),
        ("StatefulSet", "pgvector"),
        ("StatefulSet", "opensearch"),
    ):
        if expected not in kinds_by_component:
            errors.append(f"rendered chart missing {expected[0]} for {expected[1]}")
    if "unsigned_headers" in rendered or "value: memory" in rendered:
        errors.append("rendered chart contains fail-open auth or memory backend markers")
    if errors:
        raise HelmChartConfigError("\n".join(errors))


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    return target in phony_line.split()


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def main() -> None:
    validate_helm_chart(
        chart=load_yaml_file(CHART_PATH),
        values=load_yaml_file(VALUES_PATH),
        templates=load_template_texts(),
        deployment_doc_text=DEPLOYMENT_DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    template_result = run_helm_template_if_available()
    suffix = (
        "Helm template skipped because helm is unavailable."
        if template_result["status"] == "skipped"
        else "Helm template passed."
    )
    print("Validated Helm chart scaffold and static deployment invariants. " + suffix)


if __name__ == "__main__":
    main()
