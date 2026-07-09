from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE_PATH = ROOT / "docker-compose.yml"
PROD_COMPOSE_PATH = ROOT / "docker-compose.prod.yml"
PROMETHEUS_PROD_PATH = ROOT / "infra" / "prometheus" / "prometheus.prod.yml"
PROD_DOC_PATH = ROOT / "docs" / "deployment" / "production-profile.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"

PROMETHEUS_METRICS_CREDENTIALS_FILE = "/run/secrets/hallu_defense_metrics_bearer_token"
COMPOSE_CONFIG_COMMAND = "docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet"

REQUIRED_API_ENV = {
    "HALLU_DEFENSE_ENV": "production",
    "HALLU_DEFENSE_AUTH_REQUIRED": "true",
    "HALLU_DEFENSE_AUTH_CLAIMS_MODE": "oidc_jwt",
    "HALLU_DEFENSE_OIDC_ISSUER": "https://auth.example.invalid/realms/hallu-defense",
    "HALLU_DEFENSE_OIDC_AUDIENCE": "hallu-defense-api",
    "HALLU_DEFENSE_OIDC_JWKS_PATH": "/run/hallu-defense/keycloak-jwks.json",
    "HALLU_DEFENSE_CORS_ALLOW_ORIGINS": "https://console.example.invalid",
    "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
    "HALLU_DEFENSE_VAULT_ADDR": "http://vault:8200",
    "HALLU_DEFENSE_VAULT_MOUNT": "secret",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV": "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN",
    "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME": "observability/metrics-scrape-token",
    "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
    "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND": "postgres",
    "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "pgvector",
    "HALLU_DEFENSE_INGESTION_MODE": "async",
    "HALLU_DEFENSE_OTEL_ENABLED": "true",
    "HALLU_DEFENSE_OTEL_EXPORTER": "otlp",
    "HALLU_DEFENSE_OTEL_ENDPOINT": "http://otel-collector:4318/v1/traces",
    "HALLU_DEFENSE_SANDBOX_BACKEND": "docker",
    "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE": "hallu-defense-sandbox:ci",
    "HALLU_DEFENSE_SANDBOX_DOCKER_PATH": "docker",
}
REQUIRED_API_DEPENDS_ON = {"otel-collector", "postgres", "redis", "vault"}
REQUIRED_API_VOLUMES = {
    "./var/keycloak/jwks.json:/run/hallu-defense/keycloak-jwks.json:ro",
    "/var/run/docker.sock:/var/run/docker.sock",
}
REQUIRED_PROMETHEUS_VOLUMES = {
    "./infra/prometheus/prometheus.prod.yml:/etc/prometheus/prometheus.yml:ro",
    f"./var/prometheus/api-metrics.jwt:{PROMETHEUS_METRICS_CREDENTIALS_FILE}:ro",
}
DEFAULT_CREDENTIAL_MARKERS = {
    "hallu:hallu",
    "minioadmin",
    "change-me",
    "local-dev-only",
    "admin:admin",
    "dev-root",
}


class ProdProfileConfigError(ValueError):
    pass


def load_yaml_file(path: Path) -> Mapping[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ProdProfileConfigError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return loaded


def validate_prod_profile_config(
    *,
    base_compose: Mapping[str, object],
    prod_compose: Mapping[str, object],
    prometheus_prod: Mapping[str, object],
    prod_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_base_and_overlay_parse(base_compose, prod_compose, errors)
    _validate_api_overlay(prod_compose, errors)
    _validate_prometheus_overlay(prod_compose, prometheus_prod, errors)
    _validate_no_default_credentials(prod_compose, errors)
    _validate_supporting_files(
        prod_doc_text=prod_doc_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        live_workflow_text=live_workflow_text,
        errors=errors,
    )
    if errors:
        raise ProdProfileConfigError("\n".join(errors))


def run_compose_config_if_available(
    *,
    runner: Sequence[str] = ("docker", "compose"),
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    executable = shutil.which(runner[0])
    if executable is None:
        return {
            "status": "skipped",
            "reason": f"{runner[0]} executable is unavailable",
            "command": COMPOSE_CONFIG_COMMAND,
        }

    compose_env = dict(os.environ)
    if env is not None:
        compose_env.update(env)
    compose_env.update(
        {
            "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN": "prod-profile-compose-token",
            "HALLU_DEFENSE_POSTGRES_DSN": "postgresql://prod_user:prod_pass@postgres:5432/prod_db",
            "GRAFANA_ADMIN_USER": "prod-grafana-user",
            "GRAFANA_ADMIN_PASSWORD": "prod-grafana-pass",
            "POSTGRES_USER": "prod_user",
            "POSTGRES_PASSWORD": "prod_pass",
            "POSTGRES_DB": "prod_db",
            "MINIO_ROOT_USER": "prod_minio_user",
            "MINIO_ROOT_PASSWORD": "prod_minio_pass",
        }
    )
    result = subprocess.run(
        [
            executable,
            *runner[1:],
            "-f",
            str(BASE_COMPOSE_PATH),
            "-f",
            str(PROD_COMPOSE_PATH),
            "config",
            "--quiet",
        ],
        cwd=ROOT,
        env=compose_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ProdProfileConfigError(
            "docker compose base+prod config failed: "
            + (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
        )
    return {"status": "passed", "command": COMPOSE_CONFIG_COMMAND}


def _validate_base_and_overlay_parse(
    base_compose: Mapping[str, object],
    prod_compose: Mapping[str, object],
    errors: list[str],
) -> None:
    base_services = _mapping(base_compose.get("services"), "docker-compose.yml services", errors)
    prod_services = _mapping(prod_compose.get("services"), "docker-compose.prod.yml services", errors)
    for service_name in ("api", "postgres", "prometheus", "vault"):
        if service_name not in base_services:
            errors.append(f"base compose missing service {service_name}")
    for service_name in ("api", "console", "postgres", "prometheus", "grafana", "minio"):
        if service_name not in prod_services:
            errors.append(f"prod compose overlay missing service {service_name}")


def _validate_api_overlay(prod_compose: Mapping[str, object], errors: list[str]) -> None:
    services = _mapping(prod_compose.get("services"), "docker-compose.prod.yml services", errors)
    api = _mapping(services.get("api"), "prod api service", errors)
    env = _mapping(api.get("environment"), "prod api environment", errors)
    for key, expected in REQUIRED_API_ENV.items():
        if env.get(key) != expected:
            errors.append(f"prod api environment {key} must be {expected}")

    if str(env.get("HALLU_DEFENSE_AUTH_CLAIMS_MODE", "")).lower() != "oidc_jwt":
        errors.append("production profile must use oidc_jwt and never unsigned headers")
    for backend_key in (
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND",
        "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
    ):
        if str(env.get(backend_key, "")).lower() in {"memory", "local", "jsonl"}:
            errors.append(f"production profile must not use memory/local backend for {backend_key}")
    if str(env.get("HALLU_DEFENSE_SANDBOX_BACKEND", "")).lower() == "host":
        errors.append("production profile must not use host sandbox backend")

    runtime_token = env.get("HALLU_DEFENSE_RUNTIME_VAULT_TOKEN")
    if not isinstance(runtime_token, str) or ":?" not in runtime_token:
        errors.append("prod api must require HALLU_DEFENSE_RUNTIME_VAULT_TOKEN from runtime env")
    postgres_dsn = env.get("HALLU_DEFENSE_POSTGRES_DSN")
    if not isinstance(postgres_dsn, str) or ":?" not in postgres_dsn:
        errors.append("prod api must require HALLU_DEFENSE_POSTGRES_DSN from runtime env")

    origins = str(env.get("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", ""))
    if "http://" in origins or "*" in origins:
        errors.append("production CORS origins must be https-only and non-wildcard")

    issuer = str(env.get("HALLU_DEFENSE_OIDC_ISSUER", ""))
    if not issuer.startswith("https://") or ("keycloak" not in issuer and "auth." not in issuer):
        errors.append("production profile must set an HTTPS Keycloak/OIDC issuer placeholder")
    jwks_path = str(env.get("HALLU_DEFENSE_OIDC_JWKS_PATH", ""))
    if not jwks_path.startswith("/run/") or "jwks" not in jwks_path:
        errors.append("production profile must use a mounted JWKS path")

    depends_on = set(_string_sequence(api.get("depends_on"), "prod api depends_on", errors))
    missing_deps = REQUIRED_API_DEPENDS_ON - depends_on
    if missing_deps:
        errors.append("prod api depends_on missing: " + ", ".join(sorted(missing_deps)))

    volumes = set(_string_sequence(api.get("volumes"), "prod api volumes", errors))
    missing_volumes = REQUIRED_API_VOLUMES - volumes
    if missing_volumes:
        errors.append("prod api volumes missing: " + ", ".join(sorted(missing_volumes)))


def _validate_prometheus_overlay(
    prod_compose: Mapping[str, object],
    prometheus_prod: Mapping[str, object],
    errors: list[str],
) -> None:
    services = _mapping(prod_compose.get("services"), "docker-compose.prod.yml services", errors)
    prometheus_service = _mapping(services.get("prometheus"), "prod prometheus service", errors)
    volumes = set(_string_sequence(prometheus_service.get("volumes"), "prod prometheus volumes", errors))
    missing_volumes = REQUIRED_PROMETHEUS_VOLUMES - volumes
    if missing_volumes:
        errors.append("prod prometheus volumes missing: " + ", ".join(sorted(missing_volumes)))

    scrape_configs = _sequence(prometheus_prod.get("scrape_configs"), "prometheus prod scrape_configs", errors)
    api_scrape = None
    for scrape in scrape_configs:
        candidate = _mapping(scrape, "prometheus prod scrape_config", errors)
        if candidate.get("job_name") == "hallu-defense-api":
            api_scrape = candidate
            break
    if api_scrape is None:
        errors.append("prometheus.prod.yml missing hallu-defense-api scrape job")
        return
    auth = _mapping(api_scrape.get("authorization"), "prometheus prod authorization", errors)
    if auth.get("type") != "Bearer":
        errors.append("prometheus prod scrape must use Bearer authorization")
    if auth.get("credentials_file") != PROMETHEUS_METRICS_CREDENTIALS_FILE:
        errors.append("prometheus prod scrape must read JWT from credentials_file")
    if "credentials" in auth:
        errors.append("prometheus prod scrape must not inline credentials")


def _validate_no_default_credentials(value: object, errors: list[str], path: str = "prod compose") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            _validate_no_default_credentials(nested, errors, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, str):
        for index, nested in enumerate(value):
            _validate_no_default_credentials(nested, errors, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for marker in DEFAULT_CREDENTIAL_MARKERS:
        if marker in lowered:
            errors.append(f"{path} contains default credential marker {marker!r}")


def _validate_supporting_files(
    *,
    prod_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_prod_profile_config.py"
    for marker in (
        "docker-compose.prod.yml",
        COMPOSE_CONFIG_COMMAND,
        "skips when Docker is unavailable",
        "root-equivalent Docker socket",
        "scripts/dev/export_keycloak_jwks.py",
        "HALLU_DEFENSE_INGESTION_MODE=async",
        "Batch 5 eval report APIs",
        "Batch 6 ingestion worker runtime",
    ):
        if marker not in prod_doc_text:
            errors.append(f"production profile docs missing `{marker}`")
    for target, marker in (
        ("prod-profile-config", script),
        ("prod-profile-e2e", "scripts/dev/live_prod_profile_e2e.py"),
        ("keycloak-jwks-export", "scripts/dev/export_keycloak_jwks.py"),
    ):
        if f"{target}:" not in makefile_text or marker not in makefile_text:
            errors.append(f"Makefile must expose {target}")
        if not _makefile_phony_includes(makefile_text, target):
            errors.append(f"Makefile .PHONY must include {target}")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_prod_profile_config.py")
    security_section = makefile_text.partition("security-check:")[2]
    if script not in security_section:
        errors.append("security-check must include check_prod_profile_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_prod_profile_config.py")
    if "prod-profile-e2e:" not in live_workflow_text:
        errors.append("live workflow must include prod-profile-e2e job")
    if "HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_ENABLED" not in live_workflow_text:
        errors.append("prod-profile-e2e job must wire the prod profile smoke env gate")


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    return target in phony_line.split()


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


def main() -> None:
    validate_prod_profile_config(
        base_compose=load_yaml_file(BASE_COMPOSE_PATH),
        prod_compose=load_yaml_file(PROD_COMPOSE_PATH),
        prometheus_prod=load_yaml_file(PROMETHEUS_PROD_PATH),
        prod_doc_text=PROD_DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    compose_result = run_compose_config_if_available()
    suffix = (
        "Docker compose config skipped because Docker is unavailable."
        if compose_result["status"] == "skipped"
        else "Docker compose base+prod config passed."
    )
    print("Validated production profile Compose overlay and runtime gate configuration. " + suffix)


if __name__ == "__main__":
    main()
