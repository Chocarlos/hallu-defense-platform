from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OTEL_CONFIG_PATH = ROOT / "infra" / "otel" / "otel-collector-config.yaml"
COMPOSE_PATH = ROOT / "docker-compose.yml"
PROMETHEUS_PROD_PATH = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
OTEL_EXPORT_CHECK_PATH = ROOT / "scripts" / "dev" / "live_otel_export_check.py"
OBSERVABILITY_SMOKE_PATH = ROOT / "scripts" / "dev" / "live_observability_smoke.py"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"

OTEL_FILE_EXPORTER_PATH = "/otel-output/spans.jsonl"
PROMETHEUS_METRICS_CREDENTIALS_FILE = "/run/secrets/hallu_defense_metrics_bearer_token"
REQUIRED_MAKE_TARGETS = (
    "observability-config",
    "otel-export-live-smoke",
    "observability-live-smoke",
)


class ObservabilityConfigError(ValueError):
    pass


def validate_observability_config(
    *,
    otel: Mapping[str, object],
    compose_text: str,
    prometheus_prod: Mapping[str, object],
    otel_export_check_text: str,
    observability_smoke_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_otel_file_exporter(otel, errors)
    _validate_compose_mount(compose_text, errors)
    _validate_prod_prometheus_scrape_auth(prometheus_prod, errors)
    _validate_live_scripts(
        otel_export_check_text=otel_export_check_text,
        observability_smoke_text=observability_smoke_text,
        errors=errors,
    )
    _validate_makefile(makefile_text, errors)
    _validate_default_ci(ci_workflow_text, security_workflow_text, errors)
    _validate_live_workflow(live_workflow_text, errors)
    if errors:
        raise ObservabilityConfigError("\n".join(errors))


def _validate_otel_file_exporter(otel: Mapping[str, object], errors: list[str]) -> None:
    exporters = _mapping(otel.get("exporters"), "otel exporters", errors)
    file_exporter = _mapping(exporters.get("file"), "otel exporters.file", errors)
    if file_exporter.get("path") != OTEL_FILE_EXPORTER_PATH:
        errors.append(f"OTel file exporter path must be {OTEL_FILE_EXPORTER_PATH}")
    if file_exporter.get("format") != "json":
        errors.append("OTel file exporter format must be json")
    rotation = _mapping(file_exporter.get("rotation"), "otel exporters.file.rotation", errors)
    for key in ("max_megabytes", "max_days", "max_backups"):
        value = rotation.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"OTel file exporter rotation.{key} must be a positive integer")

    service = _mapping(otel.get("service"), "otel service", errors)
    pipelines = _mapping(service.get("pipelines"), "otel service.pipelines", errors)
    traces = _mapping(pipelines.get("traces"), "otel service.pipelines.traces", errors)
    traces_exporters = _string_sequence(traces.get("exporters"), "otel traces exporters", errors)
    if "debug" not in traces_exporters or "file" not in traces_exporters:
        errors.append("OTel traces pipeline must export to both debug and file")


def _validate_compose_mount(compose_text: str, errors: list[str]) -> None:
    if "otel-collector:" not in compose_text:
        errors.append("docker-compose.yml must define otel-collector")
    if "./var/otel:/otel-output" not in compose_text:
        errors.append("docker-compose.yml otel-collector must mount ./var/otel:/otel-output")


def _validate_prod_prometheus_scrape_auth(
    prometheus_prod: Mapping[str, object],
    errors: list[str],
) -> None:
    scrape = _prometheus_api_scrape(prometheus_prod, errors)
    if scrape is None:
        return
    authorization = _mapping(scrape.get("authorization"), "prometheus.prod authorization", errors)
    if authorization.get("type") != "Bearer":
        errors.append("prometheus.prod.yml authorization.type must be Bearer")
    if authorization.get("credentials_file") != PROMETHEUS_METRICS_CREDENTIALS_FILE:
        errors.append(
            "prometheus.prod.yml authorization.credentials_file must be "
            f"{PROMETHEUS_METRICS_CREDENTIALS_FILE}"
        )
    if "credentials" in authorization:
        errors.append("prometheus.prod.yml must use credentials_file, not inline credentials")


def _prometheus_api_scrape(
    prometheus_prod: Mapping[str, object],
    errors: list[str],
) -> Mapping[str, object] | None:
    scrape_configs = _sequence(prometheus_prod.get("scrape_configs"), "prometheus scrape_configs", errors)
    for candidate in scrape_configs:
        scrape = _mapping(candidate, "prometheus scrape_config", errors)
        if scrape.get("job_name") == "hallu-defense-api":
            if scrape.get("metrics_path") != "/metrics":
                errors.append("prometheus.prod.yml hallu-defense-api job must scrape /metrics")
            return scrape
    errors.append("prometheus.prod.yml missing hallu-defense-api scrape job")
    return None


def _validate_live_scripts(
    *,
    otel_export_check_text: str,
    observability_smoke_text: str,
    errors: list[str],
) -> None:
    _require(
        otel_export_check_text,
        {
            "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_ENABLED",
            "spans.jsonl",
            "SENSITIVE_ATTRIBUTE_KEY_FRAGMENTS",
            "tenant_id",
            "payload",
            "source_ref",
            "repo_ref",
            "message_text",
            "secret",
            "HTTP ",
            "verification.",
            "policy.evaluate",
            "sandbox.run",
        },
        "scripts/dev/live_otel_export_check.py",
        errors,
    )
    _require(
        observability_smoke_text,
        {
            "HALLU_DEFENSE_LIVE_OBSERVABILITY_SMOKE_ENABLED",
            "/api/v1/targets",
            "hallu_http_requests_total",
            "hallu_verification_",
            "/api/health",
            "/api/datasources/name/",
            "OK.",
        },
        "scripts/dev/live_observability_smoke.py",
        errors,
    )


def _validate_makefile(makefile_text: str, errors: list[str]) -> None:
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    for target in REQUIRED_MAKE_TARGETS:
        if f"{target}:" not in makefile_text:
            errors.append(f"Makefile must expose {target}")
        if target not in phony_line:
            errors.append(f".PHONY must include {target}")
    if "scripts/ci/check_observability_config.py" not in makefile_text:
        errors.append("Makefile must wire check_observability_config.py")
    if "scripts/dev/live_otel_export_check.py" not in makefile_text:
        errors.append("Makefile must wire live_otel_export_check.py")
    if "scripts/dev/live_observability_smoke.py" not in makefile_text:
        errors.append("Makefile must wire live_observability_smoke.py")
    security_section = makefile_text.partition("security-check:")[2]
    if "scripts/ci/check_observability_config.py" not in security_section:
        errors.append("security-check must run check_observability_config.py")


def _validate_default_ci(
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_observability_config.py"
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_observability_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_observability_config.py")
    for workflow_name, text in {
        "CI workflow": ci_workflow_text,
        "security workflow": security_workflow_text,
    }.items():
        for live_script in (
            "scripts/dev/live_otel_export_check.py",
            "scripts/dev/live_observability_smoke.py",
        ):
            if live_script in text:
                errors.append(f"{workflow_name} must not run live observability script {live_script}")


def _validate_live_workflow(live_workflow_text: str, errors: list[str]) -> None:
    _require(
        live_workflow_text,
        {
            "observability-live:",
            "docker compose up -d",
            "scripts/dev/live_otel_export_check.py",
            "scripts/dev/live_observability_smoke.py",
            'HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_ENABLED: "true"',
            'HALLU_DEFENSE_LIVE_OBSERVABILITY_SMOKE_ENABLED: "true"',
            "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_API_BASE_URL",
            "HALLU_DEFENSE_LIVE_OBSERVABILITY_PROMETHEUS_URL",
            "HALLU_DEFENSE_LIVE_OBSERVABILITY_GRAFANA_URL",
            "docker compose down -v",
        },
        ".github/workflows/live.yml",
        errors,
    )


def load_yaml_file(path: Path) -> Mapping[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ObservabilityConfigError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return payload


def load_current_config() -> dict[str, object]:
    return {
        "otel": load_yaml_file(OTEL_CONFIG_PATH),
        "compose_text": COMPOSE_PATH.read_text(encoding="utf-8"),
        "prometheus_prod": load_yaml_file(PROMETHEUS_PROD_PATH),
        "otel_export_check_text": OTEL_EXPORT_CHECK_PATH.read_text(encoding="utf-8"),
        "observability_smoke_text": OBSERVABILITY_SMOKE_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _sequence(value: object, path: str, errors: list[str]) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return value
    errors.append(f"{path} must be a list")
    return ()


def _string_sequence(value: object, path: str, errors: list[str]) -> tuple[str, ...]:
    sequence = _sequence(value, path, errors)
    strings: list[str] = []
    for item in sequence:
        if isinstance(item, str):
            strings.append(item)
        else:
            errors.append(f"{path} must contain only strings")
    return tuple(strings)


def _require(text: str, snippets: set[str], label: str, errors: list[str]) -> None:
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{label} missing `{snippet}`")


def main() -> None:
    validate_observability_config(**load_current_config())
    print("Validated live observability config.")


if __name__ == "__main__":
    main()
