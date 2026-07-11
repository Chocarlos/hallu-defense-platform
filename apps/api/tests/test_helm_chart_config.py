from __future__ import annotations

import copy
import importlib
import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Makefile").exists() and (parent / ".github").exists():
            return parent
    raise AssertionError("Repository root not found from Helm chart test.")


ROOT = _repo_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

check_helm_chart = importlib.import_module("scripts.ci.check_helm_chart")
API_DOCKERFILE_PATH = check_helm_chart.API_DOCKERFILE_PATH
API_DEPENDENCIES_PATH = check_helm_chart.API_DEPENDENCIES_PATH
CHART_PATH = check_helm_chart.CHART_PATH
CI_WORKFLOW_PATH = check_helm_chart.CI_WORKFLOW_PATH
CONFIG_PATH = check_helm_chart.CONFIG_PATH
DEPLOYMENT_DOC_PATH = check_helm_chart.DEPLOYMENT_DOC_PATH
HelmChartConfigError = check_helm_chart.HelmChartConfigError
LIVE_WORKFLOW_PATH = check_helm_chart.LIVE_WORKFLOW_PATH
LIVE_SMOKE_PATH = check_helm_chart.LIVE_SMOKE_PATH
MAKEFILE_PATH = check_helm_chart.MAKEFILE_PATH
PROD_COMPOSE_PATH = check_helm_chart.PROD_COMPOSE_PATH
READINESS_PATH = check_helm_chart.READINESS_PATH
SECURITY_WORKFLOW_PATH = check_helm_chart.SECURITY_WORKFLOW_PATH
KIND_VALUES_PATH = check_helm_chart.KIND_VALUES_PATH
KIND_VAULT_BOOTSTRAP_PATH = check_helm_chart.KIND_VAULT_BOOTSTRAP_PATH
VALUES_PATH = check_helm_chart.VALUES_PATH
VALUES_SCHEMA_PATH = check_helm_chart.VALUES_SCHEMA_PATH
WORKER_RUNTIME_PATH = check_helm_chart.WORKER_RUNTIME_PATH
load_template_texts = check_helm_chart.load_template_texts
load_yaml_file = check_helm_chart.load_yaml_file
run_helm_template_if_available = check_helm_chart.run_helm_template_if_available
validate_helm_chart = check_helm_chart.validate_helm_chart


def _current_inputs() -> dict[str, object]:
    return {
        "chart": load_yaml_file(CHART_PATH),
        "values": load_yaml_file(VALUES_PATH),
        "kind_values": load_yaml_file(KIND_VALUES_PATH),
        "templates": load_template_texts(),
        "api_dockerfile_text": API_DOCKERFILE_PATH.read_text(encoding="utf-8"),
        "deployment_doc_text": DEPLOYMENT_DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_workflow_text": LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "live_smoke_text": LIVE_SMOKE_PATH.read_text(encoding="utf-8"),
        "prod_compose_text": PROD_COMPOSE_PATH.read_text(encoding="utf-8"),
        "config_text": CONFIG_PATH.read_text(encoding="utf-8"),
        "api_dependencies_text": API_DEPENDENCIES_PATH.read_text(encoding="utf-8"),
        "worker_runtime_text": WORKER_RUNTIME_PATH.read_text(encoding="utf-8"),
        "readiness_text": READINESS_PATH.read_text(encoding="utf-8"),
        "kind_vault_bootstrap_text": KIND_VAULT_BOOTSTRAP_PATH.read_text(encoding="utf-8"),
    }


def _values_schema() -> dict[str, object]:
    payload = json.loads(VALUES_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _merged_kind_values() -> dict[str, object]:
    merged = copy.deepcopy(load_yaml_file(VALUES_PATH))

    def merge(target: dict[str, object], override: dict[str, object]) -> None:
        for key, value in override.items():
            current = target.get(key)
            if isinstance(current, dict) and isinstance(value, dict):
                merge(current, value)
            else:
                target[key] = copy.deepcopy(value)

    merge(merged, load_yaml_file(KIND_VALUES_PATH))
    return merged


def test_helm_chart_validates_current_repository() -> None:
    validate_helm_chart(**_current_inputs())


def test_values_schema_is_draft7_and_closes_every_object_shape() -> None:
    schema = _values_schema()

    assert schema["$schema"] in {
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft-07/schema#",
    }
    Draft7Validator.check_schema(schema)
    pending: list[tuple[str, object]] = [("$", schema)]
    object_paths: list[str] = []
    while pending:
        path, node = pending.pop()
        if isinstance(node, dict):
            if node.get("type") == "object" or isinstance(node.get("properties"), dict):
                object_paths.append(path)
                assert node.get("additionalProperties") is False, path
            for key, child in node.items():
                pending.append((f"{path}/{key}", child))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                pending.append((f"{path}/{index}", child))
    assert len(object_paths) >= 40


@pytest.mark.parametrize(
    ("profile", "values_factory"),
    [
        ("base", lambda: load_yaml_file(VALUES_PATH)),
        ("kind", _merged_kind_values),
    ],
)
def test_values_schema_accepts_complete_baseline_profiles(
    profile: str,
    values_factory: Callable[[], dict[str, object]],
) -> None:
    errors = sorted(
        Draft7Validator(_values_schema()).iter_errors(values_factory()),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )

    assert not errors, (
        f"{profile} values failed Draft 7 validation: "
        + "; ".join(
            f"/{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
            for error in errors
        )
    )


def test_values_schema_rejects_unknown_top_level_and_nested_keys() -> None:
    validator = Draft7Validator(_values_schema())
    values = _merged_kind_values()
    values["workre"] = {"enabled": True}
    values["worker"]["metricPort"] = 9090
    values["sandbox"]["cleanupGraceSecond"] = 10

    locations = {
        "/" + "/".join(str(part) for part in error.absolute_path)
        for error in validator.iter_errors(values)
    }
    assert "/" in locations
    assert "/worker" in locations
    assert "/sandbox" in locations


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("worker", "enabled"), False),
        (("worker", "replicas"), -1),
        (("worker", "metricsPort"), 0),
        (("worker", "metricsPort"), 65_536),
        (("worker", "command"), "python -m hallu_defense.worker"),
        (("worker", "setupGraceSeconds"), 0),
        (("api", "service", "port"), 0),
        (("api", "replicas"), -1),
        (("migrations", "expectedCount"), 13),
        (("sandbox", "setupGraceSeconds"), 4),
        (("sandbox", "setupGraceSeconds"), 61),
        (("sandbox", "cleanupGraceSeconds"), 0),
        (("sandbox", "cleanupGraceSeconds"), 121),
        (("sandbox", "cleanupGraceSeconds"), "10"),
        (("provider", "apiKeySecretName"), "a/../b"),
        (("vault", "mount"), "secret/../root"),
        (("rateLimit", "redis", "urlSecretName"), "a//b"),
        (("vault", "address"), "https://vault.example:65536"),
        (("provider", "openaiCompatibleBaseUrl"), "https://a..b/v1"),
        (("provider", "openaiCompatibleBaseUrl"), "https://a-.b/v1"),
        (("provider", "openaiCompatibleBaseUrl"), f"https://{'a' * 64}.b/v1"),
        (("networkPolicy", "kubernetesApi", 0, "cidr"), "::::/128"),
        (("kindDependencies", "vault", "image"), "busybox:latest"),
        (("kindDependencies", "redis", "image"), "busybox:latest"),
        (("networkPolicy", "ingress", "api", "callers", 0, "podLabelKey"), "a//b"),
        (("networkPolicy", "ingress", "api", "callers", 0, "podLabelKey"), "a/b/c"),
        (
            ("networkPolicy", "ingress", "api", "callers", 0, "podLabelKey"),
            "A.example/key",
        ),
    ],
)
def test_values_schema_rejects_invalid_types_ports_and_ranges(
    path: tuple[str | int, ...],
    invalid: object,
) -> None:
    values = _merged_kind_values()
    target = values
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = invalid

    errors = list(Draft7Validator(_values_schema()).iter_errors(values))
    assert errors
    assert any(tuple(error.absolute_path) == path for error in errors)


def test_values_schema_pins_exact_migration_checksum_inventory() -> None:
    values = load_yaml_file(VALUES_PATH)
    checksums = values["migrations"]["expectedChecksums"]
    checksums["000_schema_migrations.sql"] = "0" * 64
    checksums["999_typo.sql"] = "1" * 64

    errors = list(Draft7Validator(_values_schema()).iter_errors(values))
    assert errors
    rendered = "\n".join(error.message for error in errors)
    assert "999_typo.sql" in rendered
    assert "1b95184e" in rendered


@pytest.mark.parametrize(
    ("release", "overrides", "expected_marker"),
    [
        (
            "hallu-defense",
            ("--set", "worker.enabeld=true"),
            "worker",
        ),
        (
            "hallu-defense",
            ("--set", "worker.metricsPort=0"),
            "metricsport",
        ),
        (
            "hallu-defense",
            ("--set", "worker.enabled=false"),
            "enabled",
        ),
        (
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSeconds=0"),
            "cleanupgraceseconds",
        ),
        (
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSeconds=121"),
            "cleanupgraceseconds",
        ),
        (
            "hallu-defense",
            ("--set-string", "sandbox.cleanupGraceSeconds=oops"),
            "cleanupgraceseconds",
        ),
        (
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSecond=10"),
            "sandbox",
        ),
        (
            "hallu-defense",
            ("--set-string", "kindDependencies.pgvector.image=postgres:latest"),
            "exact local repository",
        ),
        (
            "hallu-defense",
            ("--set", "kindDependencies.redis.enabled=false"),
            "requires vault, pgvector, opensearch, and redis fixtures",
        ),
        (
            "hallu-defense",
            ("--set", "global.imagePullPolicy=Always"),
            "imagepullpolicy=ifnotpresent",
        ),
        (
            "hallu-defense",
            ("--set", "sandbox.image.pullPolicy=Always"),
            "pullpolicy=ifnotpresent",
        ),
        (
            "hallu-defense",
            ("--set-string", "kindDependencies.vault.image=busybox:latest"),
            "vault/image",
        ),
        (
            "hallu-defense",
            ("--set-string", "kindDependencies.redis.image=busybox:latest"),
            "redis/image",
        ),
        (
            "hallu-defense",
            (
                "--set-string",
                "console.publicOrigin=https://console.kind.invalid:65536",
                "--set-string",
                "cors.allowOrigins[0]=https://console.kind.invalid:65536",
            ),
            "publicorigin",
        ),
        (
            "hallu-defense",
            ("--set-string", "networkPolicy.kubernetesApi[0].cidr=::::/128"),
            "cidr",
        ),
        (
            "hallu-defense",
            ("--set-string", "provider.apiKeySecretName=a/../b"),
            "apikeysecretname",
        ),
        (
            "hallu-defense",
            (
                "--set-string",
                "networkPolicy.ingress.api.callers[0].podLabelKey=a//b",
            ),
            "podlabelkey",
        ),
        (
            "hallu-defense-release-name-deliberate-long",
            (),
            "at most 38",
        ),
    ],
)
def test_helm_template_fails_closed_for_typos_and_dangerous_values(
    release: str,
    overrides: tuple[str, ...],
    expected_marker: str,
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("Helm is unavailable")

    result = subprocess.run(
        [
            helm,
            "template",
            release,
            str(CHART_PATH.parent),
            "--namespace",
            "hallu-defense",
            "--values",
            str(KIND_VALUES_PATH),
            *overrides,
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=120,
    )
    detail = f"{result.stdout}\n{result.stderr}".lower()
    assert result.returncode != 0
    assert expected_marker.lower() in detail


@pytest.mark.parametrize(
    "component",
    ["migrations", "vault-bootstrap", "sandbox-fixture"],
)
def test_rendered_revision_jobs_reject_semantic_ttl_drift(component: str) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("Helm is unavailable")
    result = subprocess.run(
        [
            helm,
            "template",
            "hallu-defense",
            str(CHART_PATH.parent),
            "--namespace",
            "hallu-defense",
            "--values",
            str(KIND_VALUES_PATH),
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=True,
        timeout=120,
    )
    documents = list(yaml.safe_load_all(result.stdout))
    target = next(
        document
        for document in documents
        if isinstance(document, dict)
        and document.get("kind") == "Job"
        and document.get("metadata", {})
        .get("labels", {})
        .get("app.kubernetes.io/component")
        == component
    )
    target["spec"]["ttlSecondsAfterFinished"] = 601
    target.setdefault("metadata", {}).setdefault("annotations", {})[
        "test-only-original-ttl"
    ] = "ttlSecondsAfterFinished: 600"

    with pytest.raises(
        HelmChartConfigError,
        match=rf"rendered {component} Job must set ttlSecondsAfterFinished=600",
    ):
        check_helm_chart._validate_rendered_manifest(yaml.safe_dump_all(documents))


def test_helm_chart_rejects_missing_worker_template() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates.pop("worker-deployment.yaml")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker-deployment"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    ("template_name", "error_marker"),
    [
        ("migration-job.yaml", "migration Job"),
        ("vault-bootstrap-job.yaml", "Vault bootstrap Job"),
        ("sandbox-fixture-job.yaml", "sandbox fixture Job"),
    ],
)
def test_helm_chart_rejects_revision_job_ttl_drift(
    template_name: str,
    error_marker: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    original = templates[template_name]
    templates[template_name] = original.replace(
        "ttlSecondsAfterFinished: 600",
        "ttlSecondsAfterFinished: 601",
        1,
    )
    assert templates[template_name] != original
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match=error_marker):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_api_cleanup_grace_mapping() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    cleanup_block = (
        "- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS\n"
        "  value: {{ .Values.sandbox.cleanupGraceSeconds | quote }}\n"
    )
    assert cleanup_block in helpers
    templates["_helpers.tpl"] = helpers.replace(cleanup_block, "", 1)
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="cleanup grace environment"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_non_root_security_context() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace("runAsNonRoot: true", "runAsNonRoot: false")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="runAsNonRoot"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_plaintext_secret_defaults() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    secrets = values["secrets"]
    assert isinstance(secrets, dict)
    secrets["postgresPassword"] = "change-me"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="default secret marker"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    "secret_key",
    ["metricsBearerToken", "kindProviderApiKey", "kindMetricsBearerToken"],
)
def test_helm_chart_rejects_duplicate_kubernetes_credential_source(secret_key: str) -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    secrets = values["secrets"]
    assert isinstance(secrets, dict)
    secrets[secret_key] = "duplicate-kubernetes-secret-value"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="forbidden duplicate value source"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_nonrandom_kind_vault_bootstrap_credentials() -> None:
    inputs = _current_inputs()
    inputs["kind_vault_bootstrap_text"] = str(inputs["kind_vault_bootstrap_text"]).replace(
        "secret_generator.token_urlsafe(32)",
        '"fixed-bootstrap-credential-value"',
    )

    with pytest.raises(HelmChartConfigError, match="bootstrap script.*token_urlsafe"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_kind_approval_commitment_secret_seed() -> None:
    inputs = _current_inputs()
    inputs["kind_vault_bootstrap_text"] = str(inputs["kind_vault_bootstrap_text"]).replace(
        "APPROVAL_COMMITMENT_SECRET_NAME_ENV",
        "REMOVED_KIND_SECRET_MARKER",
    )

    with pytest.raises(HelmChartConfigError, match="bootstrap script.*APPROVAL"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_api_approval_commitment_secret_name() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["_helpers.tpl"] = templates["_helpers.tpl"].replace(
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
        "REMOVED_COMMITMENT_NAME",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="APPROVAL_TOOL_CALL_COMMITMENT"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_postgres_kind_tls_exception_in_base_values() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    values["postgres"]["kindInsecureTlsEnabled"] = True
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="managed verify-full TLS"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_exact_kind_postgres_tls_exception() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["postgres"]["kindInsecureTlsEnabled"] = False
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="PostgreSQL TLS exception"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_worker_authenticated_metrics_port() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        "containerPort: {{ .Values.worker.metricsPort }}",
        "containerPort: 9191",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="metrics integration"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_worker_setup_grace_on_both_probes() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        "initialDelaySeconds: {{ .Values.worker.setupGraceSeconds }}",
        "initialDelaySeconds: 1",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker authenticated metrics"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_fixture_pod_readiness_evidence() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-fixture-job.yaml"] = templates[
        "sandbox-fixture-job.yaml"
    ].replace("readinessProbe:", "removedReadinessProbe:")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="sandbox fixture Job"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_worker_metrics_cluster_ip_service() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-service.yaml"] = templates["worker-service.yaml"].replace(
        "targetPort: metrics",
        "targetPort: 9191",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker metrics Service"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_bypassable_sandbox_identity_match_condition() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-validating-admission-policy.yaml"] = templates[
        "sandbox-validating-admission-policy.yaml"
    ].replace(
        "spec:\n  failurePolicy: Fail",
        "spec:\n  matchConditions:\n    - name: bypass\n      expression: request.userInfo.username == 'ignored'\n  failurePolicy: Fail",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="bypassable matchCondition"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_worker_metrics_scraper_allowlist() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["ingress"]["worker"]["metricsScrapers"] = []
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="worker_metrics|worker.metricsScrapers"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_mock_provider_backend() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    assert isinstance(kind_values, dict)
    provider = kind_values["provider"]
    assert isinstance(provider, dict)
    provider["backend"] = "mock"
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="provider.backend"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_deployment_endpoint_placeholder_defaults() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    vault = values["vault"]
    assert isinstance(vault, dict)
    vault["address"] = "https://vault.example.invalid"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="vault.address.*default empty"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_console_process_local_multi_replica() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    console = values["console"]
    assert isinstance(console, dict)
    console["replicas"] = 2
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="console.replicas must equal 1"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_console_local_or_unsigned_value_contract() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    console = values["console"]
    assert isinstance(console, dict)
    console["allowUnsignedLocal"] = True
    inputs["values"] = values

    with pytest.raises(
        HelmChartConfigError,
        match="only the production OIDC runtime contract",
    ):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_console_next_public_environment() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    console = templates["console-deployment.yaml"]
    templates["console-deployment.yaml"] = console.replace(
        "HALLU_DEFENSE_CONSOLE_API_ORIGIN",
        "NEXT_PUBLIC_API_ORIGIN",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="NEXT_PUBLIC_"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_process_local_console_restart_warning() -> None:
    inputs = _current_inputs()
    inputs["deployment_doc_text"] = str(inputs["deployment_doc_text"]).replace(
        "Restarting the Console invalidates active",
        "Console restart behavior is unspecified",
    )

    with pytest.raises(
        HelmChartConfigError,
        match="Restarting the Console invalidates active",
    ):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_dependencies_enabled_in_production_defaults() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    dependencies = values["kindDependencies"]
    assert isinstance(dependencies, dict)
    dependencies["enabled"] = True
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="default false"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_overlay_without_dependencies() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    assert isinstance(kind_values, dict)
    dependencies = kind_values["kindDependencies"]
    assert isinstance(dependencies, dict)
    dependencies["enabled"] = False
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="values-kind.yaml"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_eval_reports_backend() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace(
        "- name: HALLU_DEFENSE_EVAL_REPORTS_BACKEND\n  value: postgres\n",
        "",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="eval reports|EVAL_REPORTS_BACKEND"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_api_image_without_migration_assets() -> None:
    inputs = _current_inputs()
    inputs["api_dockerfile_text"] = str(inputs["api_dockerfile_text"]).replace(
        "COPY infra/rag/pgvector /app/infra/rag/pgvector",
        "",
    )

    with pytest.raises(HelmChartConfigError, match="migration runtime asset"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_placeholder_worker_probe() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    worker = templates["worker-deployment.yaml"]
    templates["worker-deployment.yaml"] = worker.replace(
        "from pathlib import Path",
        'print("worker probe placeholder")',
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="placeholder"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_migration_count_drift() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    migrations = values["migrations"]
    assert isinstance(migrations, dict)
    migrations["expectedCount"] = check_helm_chart.EXPECTED_MIGRATION_COUNT - 1
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="expectedCount"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_non_sensitive_migration_secret_reference_schema() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    secrets = values["secrets"]
    assert isinstance(secrets, dict)
    migrations = secrets["migrations"]
    assert isinstance(migrations, dict)
    migrations.pop("postgresDsnKey")
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="precreated Secret references|postgresDsnKey"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_migration_job_using_runtime_dsn() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["migration-job.yaml"] = templates["migration-job.yaml"].replace(
        'include "hallu-defense.migrationsSecretName"',
        'include "hallu-defense.runtimeSecretName"',
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="migration Job"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_precreated_secret_identity_guard() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["secrets.yaml"] = templates["secrets.yaml"].replace(
        "hasKey $seenNames $name",
        "false",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="precreated-Secret boundary"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_count_only_migration_wait() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["_helpers.tpl"] = templates["_helpers.tpl"].replace(
        "migration_check.run()",
        'cursor.execute("SELECT count(*) FROM schema_migrations")',
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="exact versions|count-only"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_runtime_migration_checksum_subset() -> None:
    inputs = _current_inputs()
    inputs["readiness_text"] = str(inputs["readiness_text"]).replace(
        "if applied != self._expected:",
        "if not set(self._expected).issubset(applied):",
    )

    with pytest.raises(HelmChartConfigError, match="exact canonical checksum"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_pgdata_at_local_path_mount_root() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    pgvector = templates["pgvector-statefulset.yaml"]
    templates["pgvector-statefulset.yaml"] = pgvector.replace(
        "value: /var/lib/postgresql/data/pgdata",
        "value: /var/lib/postgresql/data",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="PGDATA"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_api_readiness_probe_using_liveness_endpoint() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        "path: /ready",
        "path: /health",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="readinessProbe.*ready"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        ("timeoutSeconds: 5", "timeoutSeconds: 1"),
        ("            timeoutSeconds: 5\n", ""),
    ),
)
def test_helm_chart_requires_bounded_api_probe_timeouts(
    old: str,
    new: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        old,
        new,
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="API.*timeoutSeconds: 5"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_worker_inheriting_api_environment() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        'include "hallu-defense.workerEnv"',
        'include "hallu-defense.apiEnv"',
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker.*apiEnv"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_bounded_api_request_body_deadline() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["_helpers.tpl"] = templates["_helpers.tpl"].replace(
        "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS",
        "REMOVED_REQUEST_BODY_TIMEOUT_SECONDS",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="template marker|Helm templates missing"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_api_only_oidc_in_worker_environment() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace(
        "- name: HALLU_DEFENSE_RUNTIME_ROLE\n  value: worker\n",
        "- name: HALLU_DEFENSE_RUNTIME_ROLE\n  value: worker\n"
        "- name: HALLU_DEFENSE_OIDC_ISSUER\n  value: https://auth.invalid\n",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="workerEnv.*OIDC"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_hybrid_worker_readiness_cli() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        "- --check-ready",
        "- --once",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="readiness"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        ("timeoutSeconds: 5", "timeoutSeconds: 1"),
        ("            timeoutSeconds: 5\n", ""),
    ),
)
def test_helm_chart_requires_bounded_worker_probe_timeouts(
    old: str,
    new: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        old,
        new,
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker.*timeoutSeconds: 5"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_core_only_opensearch_derivative() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    values["kindDependencies"]["opensearch"]["image"] = "opensearchproject/opensearch:3.7.0"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="core-only OpenSearch derivative"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_core_only_opensearch_runtime_flags() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        "DISABLE_SECURITY_PLUGIN", "REMOVED_SECURITY_FLAG", 1
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="core-only OpenSearch StatefulSet"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_duplicate_last_bouncycastle_cpu_variant() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        "-Dorg.bouncycastle.native.cpu_variant=java",
        "-Dorg.bouncycastle.native.cpu_variant=java -Dorg.bouncycastle.native.cpu_variant=native",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="OPENSEARCH_JAVA_OPTS.*exact"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_loopback_only_opensearch_transport() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        "value: 127.0.0.1", "value: 0.0.0.0", 1
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="transport.host.*127.0.0.1"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_java_only_bouncycastle_fips_runtime() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        "-Dorg.bouncycastle.native.cpu_variant=java",
        "-Dorg.bouncycastle.native.cpu_variant=native",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="OPENSEARCH_JAVA_OPTS.*exact"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    "marker",
    (
        "readOnlyRootFilesystem: true",
        "mountPath: /tmp",
        "mountPath: /usr/share/opensearch/logs",
        "mountPath: /usr/share/opensearch/config",
    ),
)
def test_helm_chart_requires_opensearch_read_only_root_and_scratch_mounts(
    marker: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        marker, "removed-hardening-marker", 1
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="hardened OpenSearch StatefulSet"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize("marker", ("medium: Memory", "sizeLimit: 16Mi"))
def test_helm_chart_requires_bounded_in_memory_opensearch_config(
    marker: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["opensearch-statefulset.yaml"] = templates["opensearch-statefulset.yaml"].replace(
        marker, "removed-config-volume-marker", 1
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="exact 16Mi.*writable config"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_removed_opensearch_password_material() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    values["secrets"]["opensearchInitialAdminPassword"] = "forbidden"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="forbidden duplicate value source"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_minimal_api_bootstrap_ca_mount() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    api_template = templates["api-deployment.yaml"]
    prefix, marker, bootstrap = api_template.partition("- name: bootstrap-opensearch-schema")
    templates["api-deployment.yaml"] = (
        prefix
        + marker
        + bootstrap.replace(
            "- name: vault-ca\n              mountPath:",
            "- name: missing-vault-ca\n              mountPath:",
            1,
        )
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="bootstrap init missing.*vault-ca"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_dedicated_opensearch_bootstrap_backend() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["_helpers.tpl"] = templates["_helpers.tpl"].replace(
        "HALLU_DEFENSE_RAG_INDEX_BACKEND\n  value: opensearch",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND\n  value: hybrid",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="opensearchBootstrapEnv missing"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_noncanonical_kubernetes_api_cidr() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["kubernetesApi"][0]["cidr"] = "10.96.0.1/24"
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="canonical network notation"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_address_family_wildcard_egress() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["kubernetesApi"][0]["cidr"] = "0.0.0.0/0"
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="exactly one host"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize("cidr", ["0.0.0.0/1", "128.0.0.0/1", "2001:db8::/64"])
def test_helm_chart_rejects_broad_prefix_egress(cidr: str) -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["kubernetesApi"][0]["cidr"] = cidr
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="exactly one host"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_invalid_precreated_secret_name() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["secrets"]["runtime"]["name"] = "Invalid_Secret"
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="DNS subdomain"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_invalid_secret_key_selector() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    values["secrets"]["runtime"]["postgresDsnKey"] = "invalid/key"
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="Secret data key"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_duplicate_external_network_peers() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["api"]["external"] = [
        {"name": "provider-a", "cidr": "192.0.2.1/32", "port": 443},
        {"name": "provider-b", "cidr": "192.0.2.1/32", "port": 443},
    ]
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="duplicate destination"):
        validate_helm_chart(**inputs)


def test_helm_chart_never_grants_kubernetes_api_egress_to_worker() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    policy = templates["application-egress-network-policies.yaml"]
    templates["application-egress-network-policies.yaml"] = policy.replace(
        "range $peer := .Values.networkPolicy.worker.external",
        "range $peer := .Values.networkPolicy.kubernetesApi",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="Kubernetes API CIDRs"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    "marker",
    [
        "-console-egress",
        "-migrations-egress",
        "-vault-bootstrap-egress",
        'range $component := list "pgvector" "opensearch" "vault"',
        '$sources = list "api" "worker" "migrations"',
        '$sources = list "api" "worker"',
        '$sources = list "api" "worker" "vault-bootstrap" "redis"',
    ],
)
def test_helm_chart_requires_egress_policy_for_every_workload(marker: str) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    policy = templates["application-egress-network-policies.yaml"]
    assert marker in policy
    templates["application-egress-network-policies.yaml"] = policy.replace(
        marker,
        "missing-egress-policy-marker",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="application egress NetworkPolicies"):
        validate_helm_chart(**inputs)


def test_helm_chart_requires_redis_vault_only_egress_policy() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["redis-deployment.yaml"] = templates["redis-deployment.yaml"].replace(
        "          port: 8200",
        "          port: 443",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="Redis least-privilege egress"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_migrations_external_egress() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    kind_values["networkPolicy"]["migrations"]["external"] = [
        {"name": "forbidden", "cidr": "203.0.113.20/32", "port": 5432}
    ]
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="migrations external egress"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_api_without_pinned_runtime_role() -> None:
    inputs = _current_inputs()
    inputs["api_dependencies_text"] = str(inputs["api_dependencies_text"]).replace(
        "load_settings(expected_runtime_role=RUNTIME_ROLE_API)",
        "load_settings()",
    )

    with pytest.raises(HelmChartConfigError, match="API executable.*runtime role"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_overlay_without_tls_vault() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    assert isinstance(kind_values, dict)
    dependencies = kind_values["kindDependencies"]
    assert isinstance(dependencies, dict)
    vault = dependencies["vault"]
    assert isinstance(vault, dict)
    vault["enabled"] = False
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="enable vault"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_otlp_without_collector() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    assert isinstance(kind_values, dict)
    otel = kind_values["otel"]
    assert isinstance(otel, dict)
    otel["enabled"] = True
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="disable OTLP"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_hardcoded_undeployed_otel_collector() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace(
        '{{ required "otel.endpoint is required when otel.enabled=true" .Values.otel.endpoint | quote }}',
        "http://otel-collector:4318/v1/traces",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="undeployed OpenTelemetry Collector"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_vault_dev_listener_conflicting_with_tls_listener() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["vault-deployment.yaml"] = templates["vault-deployment.yaml"].replace(
        "- -dev-listen-address=127.0.0.1:18200\n",
        "",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="dev-listen-address"):
        validate_helm_chart(**inputs)


def test_helm_chart_template_skips_when_helm_missing() -> None:
    result = run_helm_template_if_available(helm_binary="definitely-missing-helm")

    assert result["status"] == "skipped"
    assert "helm template" in result["command"]


def test_helm_chart_rejects_kind_latest_sandbox_image() -> None:
    inputs = _current_inputs()
    kind_values = copy.deepcopy(inputs["kind_values"])
    assert isinstance(kind_values, dict)
    sandbox = kind_values["sandbox"]
    assert isinstance(sandbox, dict)
    image = sandbox["image"]
    assert isinstance(image, dict)
    image["reference"] = "hallu-defense-sandbox:latest"
    inputs["kind_values"] = kind_values

    with pytest.raises(HelmChartConfigError, match="locally built pinned sandbox image"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_production_created_sandbox_claim() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    sandbox = values["sandbox"]
    assert isinstance(sandbox, dict)
    workspace = sandbox["workspace"]
    assert isinstance(workspace, dict)
    workspace["createClaim"] = True
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="must not create"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_sandbox_rbac_permission_expansion() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-rbac.yaml"] = templates["sandbox-rbac.yaml"].replace(
        "      - delete\n",
        "      - delete\n      - update\n",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="forbidden permission|least-privilege"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_permissive_sandbox_network_policy() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-network-policy.yaml"] = templates["sandbox-network-policy.yaml"].replace(
        "egress: []", "egress:\n  - {}"
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="egress"):
        validate_helm_chart(**inputs)


@pytest.mark.parametrize(
    ("marker", "replacement"),
    [
        ("!has(e.valueFrom)", "true"),
        ("volumeMounts.size() == 4", "volumeMounts.size() >= 4"),
        ("m.readOnly == true", "m.readOnly == false"),
        (
            "quantity(v.emptyDir.sizeLimit).compareTo(quantity('512Mi')) == 0",
            "quantity(v.emptyDir.sizeLimit).compareTo(quantity('1Gi')) == 0",
        ),
        ("c.args[1] == '50000'", "c.args[1] == '500000'"),
        ("c.args[2] == '536870912'", "c.args[2] == '5368709120'"),
        (
            "quantity(c.resources.limits['cpu']).compareTo(",
            "quantity(c.resources.limits['cpu']).isGreaterThan(",
        ),
        ("c.securityContext.procMount == 'Default'", "true"),
        ("object.spec.manualSelector == false", "true"),
        ("object.metadata.finalizers.size() == 0", "true"),
        (
            "!has(object.metadata.generateName) || object.metadata.generateName == ''",
            "true",
        ),
        (
            "!has(object.spec.template.spec.hostIPC) ||",
            "true ||",
        ),
        ("!has(c.stdin) || c.stdin == false", "true"),
        ("quantity('15Mi'), quantity('16Mi')", "quantity('15Mi')"),
    ],
)
def test_helm_chart_rejects_weakened_sandbox_admission_barriers(
    marker: str,
    replacement: str,
) -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    admission = templates["sandbox-validating-admission-policy.yaml"]
    assert marker in admission
    templates["sandbox-validating-admission-policy.yaml"] = admission.replace(
        marker,
        replacement,
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="admission policy"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_worker_service_account_token_mount() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["worker-deployment.yaml"] = templates["worker-deployment.yaml"].replace(
        "      automountServiceAccountToken: false\n",
        "",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="worker-deployment.*automount"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_namespace_agnostic_cluster_scoped_admission_name() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["_helpers.tpl"] = templates["_helpers.tpl"].replace(
        '{{- $namespaceHash := sha256sum (printf "%s/%s" .Release.Namespace (include "hallu-defense.sandboxNamespace" .)) | trunc 8 -}}',
        '{{- $namespaceHash := "fixedhash" -}}',
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="sha256sum"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_opa_environment_on_worker() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace(
        "- name: HALLU_DEFENSE_INGESTION_WORKER_ID\n",
        "- name: HALLU_DEFENSE_OPA_ENABLED\n"
        '  value: "true"\n'
        "- name: HALLU_DEFENSE_INGESTION_WORKER_ID\n",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="workerEnv.*OPA"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_unbounded_global_tmp_default() -> None:
    inputs = _current_inputs()
    values = copy.deepcopy(inputs["values"])
    assert isinstance(values, dict)
    global_values = values["global"]
    assert isinstance(global_values, dict)
    global_values["tmpSizeLimit"] = ""
    inputs["values"] = values

    with pytest.raises(HelmChartConfigError, match="tmpSizeLimit.*64Mi"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_unbounded_workload_tmp_emptydir() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["migration-job.yaml"] = templates["migration-job.yaml"].replace(
        "emptyDir:\n            sizeLimit: {{ .Values.global.tmpSizeLimit | quote }}",
        "emptyDir: {}",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="migration-job.*tmp emptyDir"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_world_readable_api_token_regression() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        "defaultMode: 0440\n            sources:",
        "defaultMode: 0644\n            sources:",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="defaultMode: 0440"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_nonrotating_api_token_projection() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        "expirationSeconds: 3600",
        "expirationSeconds: 86400",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="expirationSeconds: 3600"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_api_token_mount_in_init_container() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    bootstrap_mount = (
        "          volumeMounts:\n"
        "            - name: bootstrap-secrets\n"
        "              mountPath: /run/secrets\n"
        "              readOnly: true"
    )
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        bootstrap_mount,
        bootstrap_mount
        + "\n            - name: kube-api-access\n"
        + "              mountPath: /var/run/secrets/kubernetes.io/serviceaccount",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="init containers.*projected Kubernetes token"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_writable_api_workspace_mount() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["api-deployment.yaml"] = templates["api-deployment.yaml"].replace(
        "            - name: workspace\n"
        "              mountPath: {{ .Values.sandbox.workspace.mountPath | quote }}\n"
        "              readOnly: true",
        "            - name: workspace\n"
        "              mountPath: {{ .Values.sandbox.workspace.mountPath | quote }}\n"
        "              readOnly: false",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="workspace PVC mount.*read-only"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_sandbox_role_in_application_namespace() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-rbac.yaml"] = templates["sandbox-rbac.yaml"].replace(
        'namespace: {{ include "hallu-defense.sandboxNamespace" . }}',
        "namespace: {{ .Release.Namespace }}",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="sandbox RBAC"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_missing_application_default_deny_ingress() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["application-egress-network-policies.yaml"] = templates[
        "application-egress-network-policies.yaml"
    ].replace("-default-deny-ingress", "-missing-ingress-boundary")
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="default-deny-ingress"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_vap_match_policy_at_invalid_spec_root() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["sandbox-validating-admission-policy.yaml"] = templates[
        "sandbox-validating-admission-policy.yaml"
    ].replace(
        "  matchConstraints:\n    matchPolicy: Equivalent",
        "  matchPolicy: Equivalent\n  matchConstraints:",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="matchConstraints"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_unsupported_redis_cli_probe_flags() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    templates["redis-deployment.yaml"] = templates["redis-deployment.yaml"].replace(
        "-h 127.0.0.1 -p 6379",
        "--host 127.0.0.1 --port 6379",
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="redis-cli"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_kind_local_image_exception_in_prod_compose() -> None:
    inputs = _current_inputs()
    inputs["prod_compose_text"] = (
        str(inputs["prod_compose_text"])
        + "\nHALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE: true\n"
    )

    with pytest.raises(HelmChartConfigError, match="docker-compose.prod.yml"):
        validate_helm_chart(**inputs)


def test_helm_chart_rejects_unscoped_kind_local_image_exception() -> None:
    inputs = _current_inputs()
    templates = dict(inputs["templates"])
    helpers = templates["_helpers.tpl"]
    templates["_helpers.tpl"] = helpers.replace(
        "{{- if .Values.kindDependencies.enabled }}\n"
        "- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE",
        "- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE",
        1,
    )
    inputs["templates"] = templates

    with pytest.raises(HelmChartConfigError, match="only for kind"):
        validate_helm_chart(**inputs)
