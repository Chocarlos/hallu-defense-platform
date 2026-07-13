from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
KEYCLOAK_REALM_PATH = ROOT / "infra" / "security" / "keycloak" / "realm-hallu-defense.json"
PROMETHEUS_CONFIG_PATH = ROOT / "infra" / "prometheus" / "prometheus.yml"
OTEL_CONFIG_PATH = ROOT / "infra" / "otel" / "otel-collector-config.yaml"
GRAFANA_DATASOURCE_PATH = (
    ROOT / "infra" / "grafana" / "provisioning" / "datasources" / "prometheus.yml"
)
GRAFANA_DASHBOARD_PROVIDER_PATH = (
    ROOT / "infra" / "grafana" / "provisioning" / "dashboards" / "hallu-defense.yml"
)
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_SERVICES = {
    "api",
    "ingestion-worker",
    "opensearch-bootstrap",
    "postgres-migrations",
    "console",
    "prometheus",
    "grafana",
    "otel-collector",
    "postgres",
    "opensearch",
    "redis",
    "minio",
    "keycloak",
    "vault",
}
REQUIRED_VOLUMES = {"postgres-data", "grafana-data", "opensearch-data", "seaweedfs-data"}
REQUIRED_PORTS = {
    "api": "127.0.0.1:8000:8000",
    "ingestion-worker": (),
    "opensearch-bootstrap": (),
    "postgres-migrations": (),
    "console": "127.0.0.1:3000:3000",
    "prometheus": "127.0.0.1:9090:9090",
    "grafana": "127.0.0.1:3001:3000",
    "otel-collector": ("127.0.0.1:4317:4317", "127.0.0.1:4318:4318"),
    "postgres": "127.0.0.1:5432:5432",
    "opensearch": "127.0.0.1:9200:9200",
    "redis": "127.0.0.1:6379:6379",
    "minio": "127.0.0.1:9000:9000",
    "keycloak": "127.0.0.1:8081:8080",
    "vault": "127.0.0.1:8200:8200",
}
PINNED_IMAGES = {
    "prometheus": "prom/prometheus:v3.13.0-distroless@sha256:f3b6aae627d96e7ad8256cdf6de5953247735117c6f577383fadb42efeeea7bc",
    "otel-collector": "otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108",
    "redis": "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
    "vault": "hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
}
REQUIRED_KEYCLOAK_REALM_ROLES = {
    "verifier",
    "auditor",
    "approval_reviewer",
    "rag_writer",
    "metrics_reader",
    "eval_publisher",
    "tool_operator",
    "sandbox_runner",
    "policy_evaluator",
}
KEYCLOAK_REALM_NAME = "hallu-defense"
KEYCLOAK_API_CLIENT_ID = "hallu-defense-api"
KEYCLOAK_CONSOLE_CLIENT_ID = "hallu-defense-console"
KEYCLOAK_CONSOLE_USER = "console-reviewer"
REQUIRED_CONSOLE_ROLES = {
    "verifier",
    "approval_reviewer",
    "policy_evaluator",
    "sandbox_runner",
    "tool_operator",
}
REQUIRED_CONSOLE_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_CONSOLE_AUTH_MODE": "unsigned-local",
    "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN": "http://localhost:3000",
    "HALLU_DEFENSE_CONSOLE_API_ORIGIN": "http://localhost:8000",
    "HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP": "true",
    "HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL": "true",
    "HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID": "tenant-a",
    "HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID": KEYCLOAK_CONSOLE_USER,
    "HALLU_DEFENSE_CONSOLE_LOCAL_ROLES": ",".join(sorted(REQUIRED_CONSOLE_ROLES)),
}
OTEL_FILE_EXPORTER_PATH = "/otel-output/spans.jsonl"
REQUIRED_API_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_AUTH_REQUIRED": "false",
    "HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES": "1048576",
    "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS": "15",
    "HALLU_DEFENSE_ALLOWED_WORKSPACE": "/workspace",
    "HALLU_DEFENSE_OTEL_ENABLED": "true",
    "HALLU_DEFENSE_OTEL_EXPORTER": "otlp",
    "HALLU_DEFENSE_OTEL_ENDPOINT": "http://otel-collector:4318/v1/traces",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "hybrid",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://opensearch:9200",
    "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
    "HALLU_DEFENSE_POSTGRES_DSN": "postgresql://hallu:hallu@postgres:5432/hallu_defense",
    "HALLU_DEFENSE_INGESTION_MODE": "sync",
}
REQUIRED_API_DEPENDS_ON = {
    "otel-collector",
    "postgres",
    "redis",
    "opensearch-bootstrap",
    "postgres-migrations",
}
REQUIRED_WORKER_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_RUNTIME_ROLE": "worker",
    "HALLU_DEFENSE_AUTH_REQUIRED": "false",
    "HALLU_DEFENSE_ALLOWED_WORKSPACE": "/workspace",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "hybrid",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://opensearch:9200",
    "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
    "HALLU_DEFENSE_POSTGRES_DSN": "postgresql://hallu:hallu@postgres:5432/hallu_defense",
    "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
    "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
    "HALLU_DEFENSE_INGESTION_MODE": "async",
    "HALLU_DEFENSE_INGESTION_WORKER_ID": "compose-ingestion-worker",
}
REQUIRED_WORKER_DEPENDS_ON = {
    "postgres",
    "opensearch-bootstrap",
    "postgres-migrations",
}
REQUIRED_OPENSEARCH_BOOTSTRAP_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_RUNTIME_ROLE": "opensearch-bootstrap",
    "HALLU_DEFENSE_AUTH_REQUIRED": "false",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://opensearch:9200",
    "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
}
REQUIRED_GRAFANA_ENV = {
    "GF_USERS_ALLOW_SIGN_UP": "false",
    "GF_AUTH_ANONYMOUS_ENABLED": "false",
    "GF_ANALYTICS_REPORTING_ENABLED": "false",
}
REQUIRED_COMPOSE_VOLUME_MOUNTS = {
    "api": ".:/workspace:ro",
    "ingestion-worker": ".:/workspace:ro",
    "prometheus": "./infra/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
    "grafana": (
        "./infra/grafana/provisioning:/etc/grafana/provisioning:ro",
        "./infra/grafana/dashboards:/var/lib/grafana/dashboards:ro",
        "grafana-data:/var/lib/grafana",
    ),
    "otel-collector": (
        "./infra/otel/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro",
        "./var/otel:/otel-output",
    ),
    "postgres": "./infra/rag/pgvector:/docker-entrypoint-initdb.d:ro",
    "opensearch": "opensearch-data:/usr/share/opensearch/data",
    "minio": "seaweedfs-data:/data",
    "keycloak": "./infra/security/keycloak:/opt/keycloak/data/import:ro",
}


class LocalRuntimeConfigError(ValueError):
    pass


def load_yaml_file(path: Path) -> Mapping[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise LocalRuntimeConfigError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return loaded


def validate_local_runtime_config(
    *,
    compose: Mapping[str, object],
    prometheus: Mapping[str, object],
    otel: Mapping[str, object],
    grafana_datasource_text: str,
    grafana_dashboard_provider_text: str,
    makefile_text: str,
    ci_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_compose(compose, errors)
    _validate_prometheus(prometheus, errors)
    _validate_otel(otel, errors)
    _validate_grafana_provisioning(
        grafana_datasource_text=grafana_datasource_text,
        grafana_dashboard_provider_text=grafana_dashboard_provider_text,
        errors=errors,
    )
    _validate_supporting_files(
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        errors=errors,
    )
    if errors:
        raise LocalRuntimeConfigError("\n".join(errors))


def _validate_compose(compose: Mapping[str, object], errors: list[str]) -> None:
    services = _mapping(compose.get("services"), "docker-compose.yml services", errors)
    missing_services = REQUIRED_SERVICES - set(services)
    if missing_services:
        errors.append("docker-compose.yml missing services: " + ", ".join(sorted(missing_services)))

    volumes = _mapping(compose.get("volumes"), "docker-compose.yml volumes", errors)
    missing_volumes = REQUIRED_VOLUMES - set(volumes)
    if missing_volumes:
        errors.append("docker-compose.yml missing volumes: " + ", ".join(sorted(missing_volumes)))

    for service_name in sorted(REQUIRED_SERVICES & set(services)):
        service = _mapping(services[service_name], f"service {service_name}", errors)
        _validate_service_port(service_name, service, errors)
        _validate_service_image_or_build(service_name, service, errors)
        _validate_service_volume(service_name, service, errors)

    _validate_environment("api", services, REQUIRED_API_ENV, errors)
    _validate_environment("grafana", services, REQUIRED_GRAFANA_ENV, errors)
    _validate_api_dependencies(services, errors)
    _validate_ingestion_worker(services, errors)
    _validate_opensearch_bootstrap(services, errors)
    _validate_postgres_migrations(services, errors)
    _validate_console_dependencies(services, errors)
    _validate_observability_dependencies(services, errors)
    _validate_postgres(services, errors)
    _validate_opensearch(services, errors)
    _validate_minio(services, errors)
    _validate_keycloak(compose, errors)
    _validate_vault(services, errors)


def _validate_service_port(
    service_name: str,
    service: Mapping[str, object],
    errors: list[str],
) -> None:
    required_ports = REQUIRED_PORTS[service_name]
    if required_ports == ():
        return
    ports = _string_sequence(service.get("ports"), f"{service_name}.ports", errors)
    if isinstance(required_ports, str):
        required_ports = (required_ports,)
    for required_port in required_ports:
        if required_port not in ports:
            errors.append(f"service {service_name} missing port mapping {required_port}")
    for published_port in ports:
        if not published_port.startswith("127.0.0.1:"):
            errors.append(
                f"service {service_name} port must bind only to 127.0.0.1: {published_port}"
            )


def _validate_service_image_or_build(
    service_name: str,
    service: Mapping[str, object],
    errors: list[str],
) -> None:
    if service_name in {
        "api",
        "console",
        "grafana",
        "ingestion-worker",
        "opensearch-bootstrap",
        "opensearch",
        "postgres-migrations",
        "postgres",
        "keycloak",
        "minio",
    }:
        build = _mapping(service.get("build"), f"{service_name}.build", errors)
        dockerfile = build.get("dockerfile")
        if not isinstance(dockerfile, str) or not (ROOT / dockerfile).exists():
            errors.append(f"service {service_name} build.dockerfile must exist")
        if build.get("context") != ".":
            errors.append(f"service {service_name} build.context must be repo root")
        if (
            service_name in {
                "ingestion-worker",
                "opensearch-bootstrap",
                "postgres-migrations",
            }
            and dockerfile != "infra/docker/api.Dockerfile"
        ):
            errors.append(f"service {service_name} must use the API Dockerfile")
        if service_name == "postgres":
            if dockerfile != "infra/docker/pgvector.Dockerfile":
                errors.append("service postgres must use the pgvector Dockerfile")
            if service.get("image") != "hallu-defense-pgvector:ci":
                errors.append("service postgres must tag the first-party pgvector image")
        if service_name == "keycloak":
            if dockerfile != "infra/docker/keycloak.Dockerfile":
                errors.append("service keycloak must use the hardened Keycloak Dockerfile")
            if service.get("image") != "hallu-defense-keycloak:ci":
                errors.append("service keycloak must tag the first-party Keycloak image")
        if service_name == "grafana":
            if dockerfile != "infra/docker/grafana.Dockerfile":
                errors.append("service grafana must use the hardened Grafana Dockerfile")
            if service.get("image") != "hallu-defense-grafana:ci":
                errors.append("service grafana must tag the first-party Grafana image")
        if service_name == "opensearch":
            if dockerfile != "infra/docker/opensearch.Dockerfile":
                errors.append("service opensearch must use the hardened OpenSearch Dockerfile")
            if service.get("image") != "hallu-defense-opensearch:ci":
                errors.append("service opensearch must tag the first-party OpenSearch image")
        if service_name == "minio":
            if dockerfile != "infra/docker/seaweedfs.Dockerfile":
                errors.append("service minio must use the hardened SeaweedFS Dockerfile")
            if service.get("image") != "hallu-defense-seaweedfs:ci":
                errors.append("service minio must tag the first-party SeaweedFS image")
        return

    image = service.get("image")
    expected_image = PINNED_IMAGES[service_name]
    if image != expected_image:
        errors.append(f"service {service_name} image must equal {expected_image}")


def _validate_service_volume(
    service_name: str,
    service: Mapping[str, object],
    errors: list[str],
) -> None:
    required_mounts = REQUIRED_COMPOSE_VOLUME_MOUNTS.get(service_name)
    if required_mounts is None:
        return
    if isinstance(required_mounts, str):
        required_mounts = (required_mounts,)
    volumes = _string_sequence(service.get("volumes"), f"{service_name}.volumes", errors)
    for required_mount in required_mounts:
        if required_mount not in volumes:
            errors.append(f"service {service_name} missing volume mount {required_mount}")


def _validate_environment(
    service_name: str,
    services: Mapping[str, object],
    required_env: Mapping[str, str],
    errors: list[str],
) -> None:
    service = _mapping(services.get(service_name), f"service {service_name}", errors)
    env = _mapping(service.get("environment"), f"{service_name}.environment", errors)
    for key, expected_value in required_env.items():
        if env.get(key) != expected_value:
            errors.append(f"service {service_name} environment {key} must be {expected_value}")


def _validate_api_dependencies(services: Mapping[str, object], errors: list[str]) -> None:
    api = _mapping(services.get("api"), "service api", errors)
    depends_on = set(_dependency_names(api.get("depends_on"), "api.depends_on", errors))
    missing = REQUIRED_API_DEPENDS_ON - depends_on
    if missing:
        errors.append("service api depends_on missing: " + ", ".join(sorted(missing)))


def _validate_ingestion_worker(services: Mapping[str, object], errors: list[str]) -> None:
    worker = _mapping(services.get("ingestion-worker"), "service ingestion-worker", errors)
    command = _string_sequence(worker.get("command"), "ingestion-worker.command", errors)
    if command != ("python", "-m", "hallu_defense.worker"):
        errors.append("service ingestion-worker command must be python -m hallu_defense.worker")
    depends_on = set(
        _dependency_names(worker.get("depends_on"), "ingestion-worker.depends_on", errors)
    )
    missing = REQUIRED_WORKER_DEPENDS_ON - depends_on
    if missing:
        errors.append(
            "service ingestion-worker depends_on missing: " + ", ".join(sorted(missing))
        )
    _validate_environment("ingestion-worker", services, REQUIRED_WORKER_ENV, errors)


def _validate_opensearch_bootstrap(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    bootstrap = _mapping(
        services.get("opensearch-bootstrap"),
        "service opensearch-bootstrap",
        errors,
    )
    command = _string_sequence(
        bootstrap.get("command"),
        "opensearch-bootstrap.command",
        errors,
    )
    if command != ("python", "/app/scripts/dev/bootstrap_opensearch_template.py"):
        errors.append("service opensearch-bootstrap must run the schema v2 bootstrap")
    _validate_environment(
        "opensearch-bootstrap",
        services,
        REQUIRED_OPENSEARCH_BOOTSTRAP_ENV,
        errors,
    )
    dependencies = _mapping(
        bootstrap.get("depends_on"),
        "opensearch-bootstrap.depends_on",
        errors,
    )
    opensearch_dependency = _mapping(
        dependencies.get("opensearch"),
        "opensearch-bootstrap.depends_on.opensearch",
        errors,
    )
    if opensearch_dependency.get("condition") != "service_healthy":
        errors.append("service opensearch-bootstrap must wait for healthy OpenSearch")
    for workload_name in ("api", "ingestion-worker"):
        workload = _mapping(services.get(workload_name), f"service {workload_name}", errors)
        workload_dependencies = _mapping(
            workload.get("depends_on"),
            f"{workload_name}.depends_on",
            errors,
        )
        bootstrap_dependency = _mapping(
            workload_dependencies.get("opensearch-bootstrap"),
            f"{workload_name}.depends_on.opensearch-bootstrap",
            errors,
        )
        if bootstrap_dependency.get("condition") != "service_completed_successfully":
            errors.append(
                f"service {workload_name} must block on successful OpenSearch bootstrap"
            )


def _validate_postgres_migrations(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    migrations = _mapping(
        services.get("postgres-migrations"),
        "service postgres-migrations",
        errors,
    )
    command = _string_sequence(
        migrations.get("command"),
        "postgres-migrations.command",
        errors,
    )
    if command != ("python", "/app/scripts/dev/apply_postgres_migrations.py"):
        errors.append("service postgres-migrations must run the packaged migration CLI")
    env = _mapping(
        migrations.get("environment"),
        "postgres-migrations.environment",
        errors,
    )
    if env != {
        "HALLU_DEFENSE_POSTGRES_DSN": (
            "postgresql://hallu:hallu@postgres:5432/hallu_defense"
        )
    }:
        errors.append("service postgres-migrations must receive only the local migration DSN")
    dependencies = _mapping(
        migrations.get("depends_on"),
        "postgres-migrations.depends_on",
        errors,
    )
    expected_conditions = {
        "postgres": "service_healthy",
        "opensearch-bootstrap": "service_completed_successfully",
    }
    for dependency, condition in expected_conditions.items():
        config = _mapping(
            dependencies.get(dependency),
            f"postgres-migrations.depends_on.{dependency}",
            errors,
        )
        if config.get("condition") != condition:
            errors.append(
                f"service postgres-migrations must wait for {dependency} {condition}"
            )
    if migrations.get("restart") != "no":
        errors.append("service postgres-migrations must be a restart:no one-shot")
    for workload_name in ("api", "ingestion-worker"):
        workload = _mapping(services.get(workload_name), f"service {workload_name}", errors)
        workload_dependencies = _mapping(
            workload.get("depends_on"),
            f"{workload_name}.depends_on",
            errors,
        )
        migration_dependency = _mapping(
            workload_dependencies.get("postgres-migrations"),
            f"{workload_name}.depends_on.postgres-migrations",
            errors,
        )
        if migration_dependency.get("condition") != "service_completed_successfully":
            errors.append(
                f"service {workload_name} must block on successful PostgreSQL migrations"
            )


def _validate_console_dependencies(services: Mapping[str, object], errors: list[str]) -> None:
    console = _mapping(services.get("console"), "service console", errors)
    depends_on = set(_dependency_names(console.get("depends_on"), "console.depends_on", errors))
    if "api" not in depends_on:
        errors.append("service console must depend on api")
    env = _mapping(console.get("environment"), "console.environment", errors)
    if "NEXT_PUBLIC_API_BASE_URL" in env:
        errors.append("service console must not bake NEXT_PUBLIC runtime configuration")
    for key, expected in REQUIRED_CONSOLE_ENV.items():
        actual = env.get(key)
        if key == "HALLU_DEFENSE_CONSOLE_LOCAL_ROLES" and isinstance(actual, str):
            if set(actual.split(",")) != REQUIRED_CONSOLE_ROLES:
                errors.append("service console must grant the complete local Console role fixture")
        elif actual != expected:
            errors.append(f"service console environment {key} must equal {expected}")


def _validate_observability_dependencies(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    prometheus = _mapping(services.get("prometheus"), "service prometheus", errors)
    prometheus_depends_on = set(
        _dependency_names(prometheus.get("depends_on"), "prometheus.depends_on", errors)
    )
    if "api" not in prometheus_depends_on:
        errors.append("service prometheus must depend on api")

    grafana = _mapping(services.get("grafana"), "service grafana", errors)
    grafana_depends_on = set(
        _dependency_names(grafana.get("depends_on"), "grafana.depends_on", errors)
    )
    if "prometheus" not in grafana_depends_on:
        errors.append("service grafana must depend on prometheus")
    _validate_hardened_local_service(
        "grafana",
        grafana,
        required_tmpfs=(
            "/tmp:rw,noexec,nosuid,nodev,size=32m",
            "/var/log/grafana:rw,noexec,nosuid,nodev,size=32m",
        ),
        expected_user="472:472",
        allowed_volumes=(
            "./infra/grafana/provisioning:/etc/grafana/provisioning:ro",
            "./infra/grafana/dashboards:/var/lib/grafana/dashboards:ro",
            "grafana-data:/var/lib/grafana",
        ),
        errors=errors,
    )


def _validate_hardened_local_service(
    service_name: str,
    service: Mapping[str, object],
    *,
    required_tmpfs: tuple[str, ...],
    expected_user: str,
    allowed_volumes: tuple[str, ...],
    errors: list[str],
) -> None:
    if service.get("read_only") is not True:
        errors.append(f"service {service_name} must use a read-only root filesystem")
    if _string_sequence(service.get("cap_drop"), f"{service_name}.cap_drop", errors) != (
        "ALL",
    ):
        errors.append(f"service {service_name} must drop all Linux capabilities")
    security_options = _string_sequence(
        service.get("security_opt"),
        f"{service_name}.security_opt",
        errors,
    )
    if security_options != ("no-new-privileges:true",):
        errors.append(
            f"service {service_name} must set only no-new-privileges security_opt"
        )
    user_override = service.get("user")
    if user_override is not None and str(user_override) != expected_user:
        errors.append(
            f"service {service_name} user override must be absent or {expected_user}"
        )
    if service.get("entrypoint") is not None:
        errors.append(f"service {service_name} must not override the image entrypoint")
    if service.get("privileged") is True:
        errors.append(f"service {service_name} must not be privileged")
    for key in (
        "cap_add",
        "devices",
        "device_cgroup_rules",
        "volumes_from",
        "group_add",
        "sysctls",
    ):
        if service.get(key) not in (None, (), [], {}):
            errors.append(f"service {service_name} must not set {key}")
    for key in ("pid", "ipc", "network_mode", "uts", "cgroup"):
        if service.get(key) not in (None, ""):
            errors.append(f"service {service_name} must not override {key}")
    volumes = _string_sequence(service.get("volumes"), f"{service_name}.volumes", errors)
    if len(volumes) != len(allowed_volumes) or set(volumes) != set(allowed_volumes):
        errors.append(f"service {service_name} volumes must equal the hardened allowlist")
    tmpfs = _string_sequence(service.get("tmpfs"), f"{service_name}.tmpfs", errors)
    for mount in required_tmpfs:
        if mount not in tmpfs:
            mount_path = mount.split(":", 1)[0]
            errors.append(
                f"service {service_name} must mount exact hardened tmpfs {mount_path}"
            )


def _validate_postgres(services: Mapping[str, object], errors: list[str]) -> None:
    postgres = _mapping(services.get("postgres"), "service postgres", errors)
    env = _mapping(postgres.get("environment"), "postgres.environment", errors)
    for key in ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"):
        if not isinstance(env.get(key), str) or not str(env[key]).strip():
            errors.append(f"service postgres environment {key} must be non-empty")
    healthcheck = _mapping(postgres.get("healthcheck"), "postgres.healthcheck", errors)
    if "pg_isready -U hallu -d hallu_defense" not in str(healthcheck.get("test")):
        errors.append("service postgres healthcheck must use pg_isready for hallu_defense")


def _validate_opensearch(services: Mapping[str, object], errors: list[str]) -> None:
    opensearch = _mapping(services.get("opensearch"), "service opensearch", errors)
    env = _mapping(opensearch.get("environment"), "opensearch.environment", errors)
    if env.get("discovery.type") != "single-node":
        errors.append("service opensearch must use single-node discovery locally")
    if env.get("DISABLE_SECURITY_PLUGIN") != "true":
        errors.append("service opensearch must declare its core-only security posture")
    if env.get("DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI") != "true":
        errors.append("service opensearch must disable the removed performance analyzer")
    if env.get("transport.host") != "127.0.0.1":
        errors.append(
            "service opensearch must bind its unauthenticated single-node transport "
            "listener to loopback"
        )
    for legacy_key in ("plugins.security.disabled", "OPENSEARCH_INITIAL_ADMIN_PASSWORD"):
        if legacy_key in env:
            errors.append(
                f"service opensearch must not configure removed plugin setting {legacy_key}"
            )
    java_opts = env.get("OPENSEARCH_JAVA_OPTS")
    if not isinstance(java_opts, str) or "-Xms" not in java_opts or "-Xmx" not in java_opts:
        errors.append("service opensearch must set bounded Java heap options")
    required_java_opts = (
        "-Xms512m -Xmx512m -Dorg.bouncycastle.native.cpu_variant=java"
    )
    if java_opts != required_java_opts:
        errors.append(
            "service opensearch must use the exact bounded heap and force the "
            "Bouncy Castle Java implementation so the hardened noexec /tmp remains usable"
        )
    healthcheck = _mapping(opensearch.get("healthcheck"), "opensearch.healthcheck", errors)
    health_command = healthcheck.get("test")
    if "_cluster/health" not in str(health_command):
        errors.append("service opensearch healthcheck must query cluster health")
    _validate_hardened_local_service(
        "opensearch",
        opensearch,
        required_tmpfs=(
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "/usr/share/opensearch/config:rw,noexec,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700",
            "/usr/share/opensearch/logs:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700",
        ),
        expected_user="1000:1000",
        allowed_volumes=("opensearch-data:/usr/share/opensearch/data",),
        errors=errors,
    )


def _validate_minio(services: Mapping[str, object], errors: list[str]) -> None:
    minio = _mapping(services.get("minio"), "service minio", errors)
    command = _string_sequence(minio.get("command"), "minio.command", errors)
    expected_command = (
        "mini",
        "-dir=/data",
        "-s3.port=9000",
        "-bucket=hallu-backups,hallu-primary,hallu-backup-replica",
    )
    if command != expected_command:
        errors.append("service minio must run SeaweedFS mini with the approved S3 contract")
    env = _mapping(minio.get("environment"), "minio.environment", errors)
    expected_env = {
        "AWS_ACCESS_KEY_ID": "${HALLU_DEFENSE_MINIO_ACCESS_KEY:-minioadmin}",
        "AWS_SECRET_ACCESS_KEY": "${HALLU_DEFENSE_MINIO_SECRET_KEY:-minioadmin}",
    }
    if env != expected_env:
        errors.append("service minio must map the stable credential contract to SeaweedFS")
    if "MINIO_ROOT_USER" in env or "MINIO_ROOT_PASSWORD" in env:
        errors.append("service minio must not pass ignored legacy server credentials")
    _validate_hardened_local_service(
        "minio",
        minio,
        required_tmpfs=(
            "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700",
        ),
        expected_user="10001:10001",
        allowed_volumes=("seaweedfs-data:/data",),
        errors=errors,
    )


def _validate_keycloak(compose: Mapping[str, object], errors: list[str]) -> None:
    services = _mapping(compose.get("services"), "docker-compose.yml services", errors)
    keycloak = _mapping(services.get("keycloak"), "service keycloak", errors)
    command = keycloak.get("command")
    if isinstance(command, str):
        tokens: tuple[str, ...] = tuple(command.split())
    else:
        tokens = _string_sequence(command, "keycloak.command", errors)
    for token in (
        "start",
        "--optimized",
        "--import-realm",
        "--http-enabled=true",
        "--hostname-strict=false",
    ):
        if token not in tokens:
            errors.append(f"service keycloak command must include {token}")
    if "start-dev" in tokens:
        errors.append("service keycloak must not use the H2-backed development mode")
    env = _mapping(keycloak.get("environment"), "keycloak.environment", errors)
    required_env = {
        "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
        "KC_DB": "postgres",
        "KC_DB_URL": "jdbc:postgresql://postgres:5432/hallu_defense",
        "KC_DB_USERNAME": "hallu",
        "KC_DB_PASSWORD": "hallu",
    }
    for key, expected in required_env.items():
        if env.get(key) != expected:
            errors.append(f"service keycloak environment {key} must equal {expected}")
    dependencies = _mapping(keycloak.get("depends_on"), "keycloak.depends_on", errors)
    postgres = _mapping(dependencies.get("postgres"), "keycloak.depends_on.postgres", errors)
    if postgres.get("condition") != "service_healthy":
        errors.append("service keycloak must wait for healthy PostgreSQL")
    _validate_hardened_local_service(
        "keycloak",
        keycloak,
        required_tmpfs=(
            "/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700",
            "/opt/keycloak/data:rw,noexec,nosuid,nodev,size=128m,uid=10001,gid=10001,mode=0700",
        ),
        expected_user="10001:10001",
        allowed_volumes=(
            "./infra/security/keycloak:/opt/keycloak/data/import:ro",
        ),
        errors=errors,
    )
    _validate_keycloak_realm(errors)


def _validate_vault(services: Mapping[str, object], errors: list[str]) -> None:
    vault = _mapping(services.get("vault"), "service vault", errors)
    command = vault.get("command")
    if isinstance(command, str):
        tokens: tuple[str, ...] = tuple(command.split())
    else:
        tokens = _string_sequence(command, "vault.command", errors)
    if "-dev" not in tokens:
        errors.append("service vault command must run Vault in dev mode locally")
    if "-dev-listen-address=0.0.0.0:8200" not in tokens:
        errors.append("service vault command must listen on 0.0.0.0:8200")
    if not any(token.startswith("-dev-root-token-id=") for token in tokens):
        errors.append("service vault command must set a deterministic local dev root token id")


def _validate_keycloak_realm(errors: list[str]) -> None:
    try:
        text = KEYCLOAK_REALM_PATH.read_text(encoding="utf-8")
    except OSError:
        errors.append(f"Keycloak realm export {KEYCLOAK_REALM_PATH.name} must exist")
        return
    if "-----BEGIN" in text:
        errors.append("Keycloak realm export must not embed a PEM private key")
    try:
        realm = json.loads(text)
    except json.JSONDecodeError:
        errors.append("Keycloak realm export must be valid JSON")
        return
    if not isinstance(realm, Mapping):
        errors.append("Keycloak realm export must be a JSON object")
        return
    if realm.get("realm") != KEYCLOAK_REALM_NAME:
        errors.append(f"Keycloak realm export must define realm {KEYCLOAK_REALM_NAME}")
    _validate_keycloak_realm_roles(realm, errors)
    _validate_keycloak_realm_client(realm, errors)


def _validate_keycloak_realm_roles(realm: Mapping[str, object], errors: list[str]) -> None:
    roles_section = realm.get("roles")
    realm_roles: Sequence[object] = ()
    if isinstance(roles_section, Mapping):
        candidate = roles_section.get("realm")
        if isinstance(candidate, Sequence) and not isinstance(candidate, str):
            realm_roles = candidate
    role_names: set[str] = set()
    for role in realm_roles:
        if isinstance(role, Mapping):
            name = role.get("name")
            if isinstance(name, str):
                role_names.add(name)
    missing = REQUIRED_KEYCLOAK_REALM_ROLES - role_names
    if missing:
        errors.append(
            "Keycloak realm export missing realm roles: " + ", ".join(sorted(missing))
        )


def _validate_keycloak_realm_client(realm: Mapping[str, object], errors: list[str]) -> None:
    clients = realm.get("clients")
    client_list: Sequence[object] = ()
    if isinstance(clients, Sequence) and not isinstance(clients, str):
        client_list = clients
    api_client: Mapping[str, object] | None = None
    for client in client_list:
        if isinstance(client, Mapping) and client.get("clientId") == KEYCLOAK_API_CLIENT_ID:
            api_client = client
            break
    if api_client is None:
        errors.append(f"Keycloak realm export missing client {KEYCLOAK_API_CLIENT_ID}")
        return
    if api_client.get("serviceAccountsEnabled") is not True:
        errors.append(f"Keycloak client {KEYCLOAK_API_CLIENT_ID} must enable service accounts")
    if api_client.get("publicClient") is not False:
        errors.append(f"Keycloak client {KEYCLOAK_API_CLIENT_ID} must be a confidential client")

    console_client = next(
        (
            client
            for client in client_list
            if isinstance(client, Mapping)
            and client.get("clientId") == KEYCLOAK_CONSOLE_CLIENT_ID
        ),
        None,
    )
    if not isinstance(console_client, Mapping):
        errors.append(f"Keycloak realm export missing client {KEYCLOAK_CONSOLE_CLIENT_ID}")
        return
    expected_flags = {
        "publicClient": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
    }
    for key, expected in expected_flags.items():
        if console_client.get(key) is not expected:
            errors.append(
                f"Keycloak client {KEYCLOAK_CONSOLE_CLIENT_ID} {key} must be {expected}"
            )
    if "secret" in console_client:
        errors.append(f"Keycloak public client {KEYCLOAK_CONSOLE_CLIENT_ID} must not have a secret")
    attributes = console_client.get("attributes")
    if not isinstance(attributes, Mapping) or attributes.get("pkce.code.challenge.method") != "S256":
        errors.append(f"Keycloak client {KEYCLOAK_CONSOLE_CLIENT_ID} must require PKCE S256")
    expected_redirects = {
        f"http://localhost:{port}/auth/callback"
        for port in (3000, 3100)
    } | {
        f"http://127.0.0.1:{port}/auth/callback"
        for port in (3000, 3100)
    }
    redirects = console_client.get("redirectUris")
    redirect_values = (
        {redirect for redirect in redirects if isinstance(redirect, str)}
        if isinstance(redirects, Sequence) and not isinstance(redirects, str)
        else set()
    )
    if (
        not isinstance(redirects, Sequence)
        or isinstance(redirects, str)
        or len(redirect_values) != len(redirects)
        or redirect_values != expected_redirects
    ):
        errors.append(
            f"Keycloak client {KEYCLOAK_CONSOLE_CLIENT_ID} must use only exact local callback URIs"
        )
    mappers = console_client.get("protocolMappers")
    mapper_list = (
        mappers
        if isinstance(mappers, Sequence) and not isinstance(mappers, str)
        else ()
    )
    mapper_names = {
        name
        for mapper in mapper_list
        if isinstance(mapper, Mapping)
        and isinstance((name := mapper.get("name")), str)
    }
    if not {"audience-hallu-defense-api", "tenant-id", "realm-roles"}.issubset(
        mapper_names
    ):
        errors.append(
            f"Keycloak client {KEYCLOAK_CONSOLE_CLIENT_ID} must emit API audience, tenant, and roles"
        )

    users = realm.get("users")
    user_list = users if isinstance(users, Sequence) and not isinstance(users, str) else ()
    console_user = next(
        (
            user
            for user in user_list
            if isinstance(user, Mapping) and user.get("username") == KEYCLOAK_CONSOLE_USER
        ),
        None,
    )
    if not isinstance(console_user, Mapping) or console_user.get("enabled") is not True:
        errors.append(f"Keycloak realm must define enabled test user {KEYCLOAK_CONSOLE_USER}")
        return
    user_roles = console_user.get("realmRoles")
    user_role_values = (
        {role for role in user_roles if isinstance(role, str)}
        if isinstance(user_roles, Sequence) and not isinstance(user_roles, str)
        else set()
    )
    if (
        not isinstance(user_roles, Sequence)
        or isinstance(user_roles, str)
        or len(user_role_values) != len(user_roles)
        or not REQUIRED_CONSOLE_ROLES.issubset(user_role_values)
    ):
        errors.append(f"Keycloak test user {KEYCLOAK_CONSOLE_USER} is missing Console roles")
    user_attributes = console_user.get("attributes")
    if not isinstance(user_attributes, Mapping) or user_attributes.get("tenant_id") != ["tenant-a"]:
        errors.append(f"Keycloak test user {KEYCLOAK_CONSOLE_USER} must be bound to tenant-a")
    credentials = console_user.get("credentials")
    credential_list = (
        credentials
        if isinstance(credentials, Sequence) and not isinstance(credentials, str)
        else ()
    )
    if not any(
        isinstance(credential, Mapping)
        and credential.get("type") == "password"
        and isinstance(credential.get("value"), str)
        and bool(credential.get("value"))
        and credential.get("temporary") is False
        for credential in credential_list
    ):
        errors.append(
            f"Keycloak test user {KEYCLOAK_CONSOLE_USER} must have a non-temporary local password"
        )


def _validate_prometheus(prometheus: Mapping[str, object], errors: list[str]) -> None:
    scrape_configs = _sequence(prometheus.get("scrape_configs"), "scrape_configs", errors)
    for scrape_config in scrape_configs:
        scrape = _mapping(scrape_config, "scrape_config", errors)
        if scrape.get("job_name") != "hallu-defense-api":
            continue
        if scrape.get("metrics_path") != "/metrics":
            errors.append("Prometheus hallu-defense-api job must scrape /metrics")
        static_configs = _sequence(scrape.get("static_configs"), "static_configs", errors)
        targets = _targets_from_static_configs(static_configs, errors)
        if "api:8000" not in targets:
            errors.append("Prometheus hallu-defense-api job must target api:8000")
        return
    errors.append("Prometheus config missing hallu-defense-api scrape job")


def _targets_from_static_configs(
    static_configs: Sequence[object],
    errors: list[str],
) -> set[str]:
    targets: set[str] = set()
    for static_config in static_configs:
        config = _mapping(static_config, "static_config", errors)
        targets.update(_string_sequence(config.get("targets"), "static_config.targets", errors))
    return targets


def _validate_otel(otel: Mapping[str, object], errors: list[str]) -> None:
    receivers = _mapping(otel.get("receivers"), "otel receivers", errors)
    otlp = _mapping(receivers.get("otlp"), "otel receivers.otlp", errors)
    protocols = _mapping(otlp.get("protocols"), "otel receivers.otlp.protocols", errors)
    grpc = _mapping(protocols.get("grpc"), "otel grpc protocol", errors)
    http = _mapping(protocols.get("http"), "otel http protocol", errors)
    if grpc.get("endpoint") != "0.0.0.0:4317":
        errors.append("OTel gRPC receiver must listen on 0.0.0.0:4317")
    if http.get("endpoint") != "0.0.0.0:4318":
        errors.append("OTel HTTP receiver must listen on 0.0.0.0:4318")

    processors = _mapping(otel.get("processors"), "otel processors", errors)
    if "batch" not in processors:
        errors.append("OTel config must include batch processor")
    exporters = _mapping(otel.get("exporters"), "otel exporters", errors)
    if "debug" not in exporters:
        errors.append("OTel config must include debug exporter for local runtime")
    _validate_otel_file_exporter(exporters, errors)
    service = _mapping(otel.get("service"), "otel service", errors)
    pipelines = _mapping(service.get("pipelines"), "otel service.pipelines", errors)
    traces = _mapping(pipelines.get("traces"), "otel traces pipeline", errors)
    if "otlp" not in _string_sequence(traces.get("receivers"), "otel traces receivers", errors):
        errors.append("OTel traces pipeline must receive otlp")
    if "batch" not in _string_sequence(traces.get("processors"), "otel traces processors", errors):
        errors.append("OTel traces pipeline must use batch processor")
    traces_exporters = _string_sequence(traces.get("exporters"), "otel traces exporters", errors)
    if "debug" not in traces_exporters:
        errors.append("OTel traces pipeline must export debug locally")
    if "file" not in traces_exporters:
        errors.append("OTel traces pipeline must export to the file sink")


def _validate_otel_file_exporter(exporters: Mapping[str, object], errors: list[str]) -> None:
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


def _validate_grafana_provisioning(
    *,
    grafana_datasource_text: str,
    grafana_dashboard_provider_text: str,
    errors: list[str],
) -> None:
    for expected in ("uid: prometheus", "type: prometheus", "url: http://prometheus:9090"):
        if expected not in grafana_datasource_text:
            errors.append(f"Grafana datasource missing {expected}")
    for expected in ("folder: Hallu Defense", "path: /var/lib/grafana/dashboards"):
        if expected not in grafana_dashboard_provider_text:
            errors.append(f"Grafana dashboard provider missing {expected}")


def _validate_supporting_files(
    *,
    makefile_text: str,
    ci_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_local_runtime_config.py"
    if "local-runtime-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose local-runtime-config")
    phony_line = next((line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), "")
    if "local-runtime-config" not in phony_line:
        errors.append(".PHONY must include local-runtime-config")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_local_runtime_config.py")


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


def _dependency_names(value: object, path: str, errors: list[str]) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        names = tuple(name for name in value if isinstance(name, str))
        if len(names) != len(value):
            errors.append(f"{path} keys must be strings")
        return names
    return _string_sequence(value, path, errors)


def main() -> None:
    validate_local_runtime_config(
        compose=load_yaml_file(DOCKER_COMPOSE_PATH),
        prometheus=load_yaml_file(PROMETHEUS_CONFIG_PATH),
        otel=load_yaml_file(OTEL_CONFIG_PATH),
        grafana_datasource_text=GRAFANA_DATASOURCE_PATH.read_text(encoding="utf-8"),
        grafana_dashboard_provider_text=GRAFANA_DASHBOARD_PROVIDER_PATH.read_text(
            encoding="utf-8"
        ),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(
        "Validated local runtime Compose configuration for "
        f"{len(REQUIRED_SERVICES)} services and {len(REQUIRED_VOLUMES)} volumes."
    )


if __name__ == "__main__":
    main()
