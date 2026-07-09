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
REQUIRED_VOLUMES = {"postgres-data", "opensearch-data", "minio-data"}
REQUIRED_PORTS = {
    "api": "8000:8000",
    "ingestion-worker": (),
    "console": "3000:3000",
    "prometheus": "9090:9090",
    "grafana": "3001:3000",
    "otel-collector": ("4317:4317", "4318:4318"),
    "postgres": "5432:5432",
    "opensearch": ("9200:9200", "9600:9600"),
    "redis": "6379:6379",
    "minio": ("9000:9000", "9001:9001"),
    "keycloak": "8081:8080",
    "vault": "8200:8200",
}
PINNED_IMAGE_PREFIXES = {
    "prometheus": "prom/prometheus:v",
    "grafana": "grafana/grafana:",
    "otel-collector": "otel/opentelemetry-collector-contrib:",
    "postgres": "pgvector/pgvector:pg",
    "opensearch": "opensearchproject/opensearch:",
    "redis": "redis:",
    "minio": "minio/minio:RELEASE.",
    "keycloak": "quay.io/keycloak/keycloak:",
    "vault": "hashicorp/vault:1.17",
}
REQUIRED_KEYCLOAK_REALM_ROLES = {
    "verifier",
    "auditor",
    "approval_reviewer",
    "rag_writer",
    "metrics_reader",
    "eval_publisher",
}
KEYCLOAK_REALM_NAME = "hallu-defense"
KEYCLOAK_API_CLIENT_ID = "hallu-defense-api"
OTEL_FILE_EXPORTER_PATH = "/otel-output/spans.jsonl"
REQUIRED_API_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_AUTH_REQUIRED": "false",
    "HALLU_DEFENSE_ALLOWED_WORKSPACE": "/workspace",
    "HALLU_DEFENSE_OTEL_ENABLED": "true",
    "HALLU_DEFENSE_OTEL_EXPORTER": "otlp",
    "HALLU_DEFENSE_OTEL_ENDPOINT": "http://otel-collector:4318/v1/traces",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://opensearch:9200",
    "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
    "HALLU_DEFENSE_POSTGRES_DSN": "postgresql://hallu:hallu@postgres:5432/hallu_defense",
    "HALLU_DEFENSE_INGESTION_MODE": "sync",
}
REQUIRED_API_DEPENDS_ON = {"otel-collector", "postgres", "redis", "opensearch"}
REQUIRED_WORKER_ENV = {
    "HALLU_DEFENSE_ENV": "local",
    "HALLU_DEFENSE_AUTH_REQUIRED": "false",
    "HALLU_DEFENSE_ALLOWED_WORKSPACE": "/workspace",
    "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://opensearch:9200",
    "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
    "HALLU_DEFENSE_POSTGRES_DSN": "postgresql://hallu:hallu@postgres:5432/hallu_defense",
    "HALLU_DEFENSE_INGESTION_MODE": "async",
    "HALLU_DEFENSE_INGESTION_WORKER_ID": "compose-ingestion-worker",
}
REQUIRED_WORKER_DEPENDS_ON = {"postgres", "opensearch"}
REQUIRED_GRAFANA_ENV = {
    "GF_USERS_ALLOW_SIGN_UP": "false",
    "GF_AUTH_ANONYMOUS_ENABLED": "false",
    "GF_ANALYTICS_REPORTING_ENABLED": "false",
}
REQUIRED_COMPOSE_VOLUME_MOUNTS = {
    "api": ".:/workspace:ro",
    "ingestion-worker": ".:/workspace:ro",
    "prometheus": "./infra/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
    "grafana": "./infra/grafana/provisioning:/etc/grafana/provisioning:ro",
    "otel-collector": (
        "./infra/otel/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro",
        "./var/otel:/otel-output",
    ),
    "postgres": "./infra/rag/pgvector:/docker-entrypoint-initdb.d:ro",
    "opensearch": "opensearch-data:/usr/share/opensearch/data",
    "minio": "minio-data:/data",
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


def _validate_service_image_or_build(
    service_name: str,
    service: Mapping[str, object],
    errors: list[str],
) -> None:
    if service_name in {"api", "console", "ingestion-worker"}:
        build = _mapping(service.get("build"), f"{service_name}.build", errors)
        dockerfile = build.get("dockerfile")
        if not isinstance(dockerfile, str) or not (ROOT / dockerfile).exists():
            errors.append(f"service {service_name} build.dockerfile must exist")
        if build.get("context") != ".":
            errors.append(f"service {service_name} build.context must be repo root")
        if service_name == "ingestion-worker" and dockerfile != "infra/docker/api.Dockerfile":
            errors.append("service ingestion-worker must use the API Dockerfile")
        return

    image = service.get("image")
    expected_prefix = PINNED_IMAGE_PREFIXES[service_name]
    if not isinstance(image, str) or not image.startswith(expected_prefix):
        errors.append(f"service {service_name} image must start with {expected_prefix}")
    if isinstance(image, str) and (image.endswith(":latest") or ":latest" in image):
        errors.append(f"service {service_name} image must not use latest")


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
    depends_on = set(_string_sequence(api.get("depends_on"), "api.depends_on", errors))
    missing = REQUIRED_API_DEPENDS_ON - depends_on
    if missing:
        errors.append("service api depends_on missing: " + ", ".join(sorted(missing)))


def _validate_ingestion_worker(services: Mapping[str, object], errors: list[str]) -> None:
    worker = _mapping(services.get("ingestion-worker"), "service ingestion-worker", errors)
    command = _string_sequence(worker.get("command"), "ingestion-worker.command", errors)
    if command != ("python", "-m", "hallu_defense.worker"):
        errors.append("service ingestion-worker command must be python -m hallu_defense.worker")
    depends_on = set(
        _string_sequence(worker.get("depends_on"), "ingestion-worker.depends_on", errors)
    )
    missing = REQUIRED_WORKER_DEPENDS_ON - depends_on
    if missing:
        errors.append(
            "service ingestion-worker depends_on missing: " + ", ".join(sorted(missing))
        )
    _validate_environment("ingestion-worker", services, REQUIRED_WORKER_ENV, errors)


def _validate_console_dependencies(services: Mapping[str, object], errors: list[str]) -> None:
    console = _mapping(services.get("console"), "service console", errors)
    depends_on = set(_string_sequence(console.get("depends_on"), "console.depends_on", errors))
    if "api" not in depends_on:
        errors.append("service console must depend on api")
    env = _mapping(console.get("environment"), "console.environment", errors)
    if env.get("NEXT_PUBLIC_API_BASE_URL") != "http://localhost:8000":
        errors.append("service console must target local API base URL")


def _validate_observability_dependencies(
    services: Mapping[str, object],
    errors: list[str],
) -> None:
    prometheus = _mapping(services.get("prometheus"), "service prometheus", errors)
    prometheus_depends_on = set(
        _string_sequence(prometheus.get("depends_on"), "prometheus.depends_on", errors)
    )
    if "api" not in prometheus_depends_on:
        errors.append("service prometheus must depend on api")

    grafana = _mapping(services.get("grafana"), "service grafana", errors)
    grafana_depends_on = set(_string_sequence(grafana.get("depends_on"), "grafana.depends_on", errors))
    if "prometheus" not in grafana_depends_on:
        errors.append("service grafana must depend on prometheus")


def _validate_postgres(services: Mapping[str, object], errors: list[str]) -> None:
    postgres = _mapping(services.get("postgres"), "service postgres", errors)
    env = _mapping(postgres.get("environment"), "postgres.environment", errors)
    for key in ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"):
        if not isinstance(env.get(key), str) or not str(env[key]).strip():
            errors.append(f"service postgres environment {key} must be non-empty")


def _validate_opensearch(services: Mapping[str, object], errors: list[str]) -> None:
    opensearch = _mapping(services.get("opensearch"), "service opensearch", errors)
    env = _mapping(opensearch.get("environment"), "opensearch.environment", errors)
    if env.get("discovery.type") != "single-node":
        errors.append("service opensearch must use single-node discovery locally")
    if env.get("plugins.security.disabled") != "true":
        errors.append("service opensearch must disable bundled security only in local compose")
    admin_password = env.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD")
    if not isinstance(admin_password, str) or len(admin_password) < 12:
        errors.append("service opensearch must set a local-only initial admin password")
    java_opts = env.get("OPENSEARCH_JAVA_OPTS")
    if not isinstance(java_opts, str) or "-Xms" not in java_opts or "-Xmx" not in java_opts:
        errors.append("service opensearch must set bounded Java heap options")


def _validate_minio(services: Mapping[str, object], errors: list[str]) -> None:
    minio = _mapping(services.get("minio"), "service minio", errors)
    command = minio.get("command")
    if not isinstance(command, str) or "--console-address \":9001\"" not in command:
        errors.append("service minio must expose the console on port 9001")
    env = _mapping(minio.get("environment"), "minio.environment", errors)
    for key in ("MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"):
        if not isinstance(env.get(key), str) or not str(env[key]).strip():
            errors.append(f"service minio environment {key} must be non-empty")


def _validate_keycloak(compose: Mapping[str, object], errors: list[str]) -> None:
    services = _mapping(compose.get("services"), "docker-compose.yml services", errors)
    keycloak = _mapping(services.get("keycloak"), "service keycloak", errors)
    command = keycloak.get("command")
    if isinstance(command, str):
        tokens: tuple[str, ...] = tuple(command.split())
    else:
        tokens = _string_sequence(command, "keycloak.command", errors)
    if "--import-realm" not in tokens:
        errors.append("service keycloak command must include --import-realm")
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
