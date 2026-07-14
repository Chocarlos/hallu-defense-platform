from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml
from jsonschema import Draft7Validator, SchemaError

ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "infra" / "k8s" / "helm" / "hallu-defense"
CHART_PATH = CHART_DIR / "Chart.yaml"
VALUES_PATH = CHART_DIR / "values.yaml"
VALUES_SCHEMA_PATH = CHART_DIR / "values.schema.json"
KIND_VALUES_PATH = CHART_DIR / "values-kind.yaml"
TEMPLATES_DIR = CHART_DIR / "templates"
DEPLOYMENT_DOC_PATH = ROOT / "docs" / "deployment" / "kubernetes-helm.md"
MARKETING_DOC_PATH = ROOT / "docs" / "deployment" / "marketing-launch.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"
LIVE_SMOKE_PATH = ROOT / "scripts" / "dev" / "live_kind_helm_smoke.py"
PROD_COMPOSE_PATH = ROOT / "docker-compose.prod.yml"
KIND_VAULT_BOOTSTRAP_PATH = ROOT / "scripts" / "dev" / "bootstrap_kind_vault.py"
API_DOCKERFILE_PATH = ROOT / "infra" / "docker" / "api.Dockerfile"
CONFIG_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
API_DEPENDENCIES_PATH = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "api" / "dependencies.py"
)
WORKER_RUNTIME_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "worker.py"
READINESS_PATH = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "readiness.py"
)
MIGRATIONS_DIR = ROOT / "infra" / "rag" / "pgvector"

HELM_TEMPLATE_COMMAND = (
    "helm lint infra/k8s/helm/hallu-defense --namespace hallu-defense && "
    "helm template hallu-defense "
    "infra/k8s/helm/hallu-defense -f infra/k8s/helm/hallu-defense/values-kind.yaml"
    " --namespace hallu-defense"
)
HELM_RELEASE_NAMESPACE = "hallu-defense"
EXPECTED_MIGRATION_VERSIONS = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"))
)
EXPECTED_MIGRATION_COUNT = len(EXPECTED_MIGRATION_VERSIONS)
EXPECTED_MIGRATION_CHECKSUMS = {
    path.name: hashlib.sha256(
        path.read_text(encoding="utf-8").encode("utf-8")
    ).hexdigest()
    for path in sorted(MIGRATIONS_DIR.glob("*.sql"))
}
REQUIRED_TEMPLATE_FILES = {
    "_helpers.tpl",
    "application-egress-network-policies.yaml",
    "api-deployment.yaml",
    "console-deployment.yaml",
    "worker-deployment.yaml",
    "worker-service.yaml",
    "migration-job.yaml",
    "pgvector-statefulset.yaml",
    "opensearch-statefulset.yaml",
    "vault-deployment.yaml",
    "vault-bootstrap-job.yaml",
    "secrets.yaml",
    "sandbox-rbac.yaml",
    "sandbox-fixture-job.yaml",
    "sandbox-network-policy.yaml",
    "sandbox-validating-admission-policy.yaml",
    "sandbox-workspace-pvc.yaml",
    "redis-deployment.yaml",
}
DEFAULT_SECRET_MARKERS = {
    "change-me",
    "minioadmin",
    "local-dev-only",
    "dev-root",
    "hallu:hallu",
}
KUBERNETES_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
KUBERNETES_SECRET_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PRODUCTION_SANDBOX_DIGEST = (
    "registry.example/hallu-defense-sandbox@sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
PRODUCTION_WORKLOAD_DIGESTS = {
    "api": (
        "registry.example/hallu-defense-api@sha256:"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ),
    "console": (
        "registry.example/hallu-defense-console@sha256:"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    ),
    "worker": (
        "registry.example/hallu-defense-api@sha256:"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ),
    "migrations": (
        "registry.example/hallu-defense-api@sha256:"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ),
}
DEMO_PRIVACY_EMAIL_254 = (
    "a" * 64 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
)
DEMO_PRIVACY_EMAIL_255 = DEMO_PRIVACY_EMAIL_254 + "d"


class HelmChartConfigError(ValueError):
    pass


def load_yaml_file(path: Path) -> Mapping[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise HelmChartConfigError(
            f"{path.relative_to(ROOT)} must contain a YAML object"
        )
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
    kind_values: Mapping[str, object],
    templates: Mapping[str, str],
    api_dockerfile_text: str,
    deployment_doc_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    live_workflow_text: str,
    live_smoke_text: str,
    prod_compose_text: str,
    config_text: str,
    api_dependencies_text: str,
    worker_runtime_text: str,
    readiness_text: str,
    kind_vault_bootstrap_text: str,
    marketing_doc_text: str | None = None,
) -> None:
    errors: list[str] = []
    if marketing_doc_text is None:
        try:
            marketing_doc_text = MARKETING_DOC_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"marketing deployment runbook could not be read: {exc}")
            marketing_doc_text = ""
    _validate_chart_metadata(chart, errors)
    _validate_values_schema(values, kind_values, errors)
    _validate_values(values, kind_values, errors)
    _validate_templates(templates, errors)
    _validate_migration_readiness_contract(
        templates=templates,
        readiness_text=readiness_text,
        errors=errors,
    )
    _validate_api_image_contents(api_dockerfile_text, errors)
    _validate_runtime_role_boundaries(
        config_text=config_text,
        api_dependencies_text=api_dependencies_text,
        worker_runtime_text=worker_runtime_text,
        errors=errors,
    )
    _validate_kind_vault_bootstrap_script(kind_vault_bootstrap_text, errors)
    _validate_no_default_secrets(values, errors)
    _validate_no_default_secrets(kind_values, errors, "kind_values")
    _validate_supporting_files(
        deployment_doc_text=deployment_doc_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        live_workflow_text=live_workflow_text,
        live_smoke_text=live_smoke_text,
        prod_compose_text=prod_compose_text,
        marketing_doc_text=marketing_doc_text,
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
    value_args = [
        "--namespace",
        HELM_RELEASE_NAMESPACE,
        "--kube-version",
        "1.36.1",
        "--values",
        str(KIND_VALUES_PATH),
    ]
    lint_result = _run_helm_command(
        [executable, "lint", str(CHART_DIR), *value_args],
        label="helm lint",
    )
    del lint_result
    template_result = _run_helm_command(
        [executable, "template", "hallu-defense", str(CHART_DIR), *value_args],
        label="helm template",
    )
    _validate_rendered_manifest(template_result.stdout)
    demo_args = _demo_helm_value_args()
    _run_helm_command(
        [executable, "lint", str(CHART_DIR), *value_args, *demo_args],
        label="enabled demo helm lint",
    )
    enabled_demo_result = _run_helm_command(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *value_args,
            *demo_args,
        ],
        label="enabled demo helm template",
    )
    _validate_rendered_demo_intake_manifest(
        enabled_demo_result.stdout,
        profile="enabled kind demo",
        webhook_cidr="192.0.2.30/32",
        webhook_port=443,
        redis_cidr="192.0.2.31/32",
        redis_port=6380,
    )
    _run_helm_command(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *value_args,
            *_demo_helm_value_args(privacy_contact=DEMO_PRIVACY_EMAIL_254),
        ],
        label="enabled demo 254-character privacy contact",
    )
    for label, overrides, expected_error in (
        (
            "enabled demo missing privacy contact",
            ("--set-string", "demoRequests.privacyContactEmail="),
            "/demoRequests/privacyContactEmail",
        ),
        (
            "enabled demo missing webhook origin",
            ("--set-string", "demoRequests.webhookAllowedOrigin="),
            "/demoRequests/webhookAllowedOrigin",
        ),
        (
            "enabled demo missing Secret name",
            ("--set-string", "secrets.demo.name="),
            "/secrets/demo/name",
        ),
        (
            "enabled demo wrong Redis CA path",
            (
                "--set-string",
                "demoRequests.redisCaPath=/run/hallu-defense/demo/redis-url",
            ),
            "/demoRequests/redisCaPath",
        ),
        (
            "enabled demo excessive privacy contact",
            (
                "--set-string",
                f"demoRequests.privacyContactEmail={DEMO_PRIVACY_EMAIL_255}",
            ),
            "/demoRequests/privacyContactEmail",
        ),
        (
            "enabled demo duplicate Secret key",
            ("--set-string", "secrets.demo.metricsBearerKey=redis-ca.pem"),
            "secrets.demo data keys must be distinct",
        ),
    ):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *value_args,
                *demo_args,
                *overrides,
            ],
            label=label,
            expected_error=expected_error,
        )
    for label, args, expected_error in (
        (
            "enabled demo missing webhook egress",
            _demo_helm_value_args(include_webhook_egress=False),
            "/networkPolicy/console/demoWebhook",
        ),
        (
            "enabled demo missing Redis egress",
            _demo_helm_value_args(include_redis_egress=False),
            "/networkPolicy/console/demoRedis",
        ),
    ):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *value_args,
                *args,
            ],
            label=label,
            expected_error=expected_error,
        )
    for cleanup_grace_seconds in (15, 20, 30):
        _run_helm_command(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *value_args,
                "--set",
                f"sandbox.cleanupGraceSeconds={cleanup_grace_seconds}",
            ],
            label=f"helm template cleanup grace {cleanup_grace_seconds}",
        )
    for label, release, overrides, expected_error in (
        (
            "kind unknown worker typo",
            "hallu-defense",
            ("--set", "worker.enabeld=true"),
            "/worker",
        ),
        (
            "kind invalid worker metrics port",
            "hallu-defense",
            ("--set", "worker.metricsPort=0"),
            "/worker/metricsPort",
        ),
        (
            "kind invalid worker metrics port type",
            "hallu-defense",
            ("--set-string", "worker.metricsPort=oops"),
            "/worker/metricsPort",
        ),
        (
            "kind excessive worker replicas",
            "hallu-defense",
            ("--set", "worker.replicas=65"),
            "/worker/replicas",
        ),
        (
            "kind excessive sandbox setup grace",
            "hallu-defense",
            ("--set", "sandbox.setupGraceSeconds=61"),
            "/sandbox/setupGraceSeconds",
        ),
        (
            "kind below-minimum sandbox cleanup grace",
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSeconds=14"),
            "/sandbox/cleanupGraceSeconds",
        ),
        (
            "kind excessive sandbox cleanup grace",
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSeconds=31"),
            "/sandbox/cleanupGraceSeconds",
        ),
        (
            "kind invalid sandbox cleanup grace type",
            "hallu-defense",
            ("--set-string", "sandbox.cleanupGraceSeconds=oops"),
            "/sandbox/cleanupGraceSeconds",
        ),
        (
            "kind unknown sandbox cleanup typo",
            "hallu-defense",
            ("--set", "sandbox.cleanupGraceSecond=20"),
            "/sandbox",
        ),
        (
            "kind disabled required worker",
            "hallu-defense",
            ("--set", "worker.enabled=false"),
            "/worker/enabled",
        ),
        (
            "kind disabled required Redis fixture",
            "hallu-defense",
            ("--set", "kindDependencies.redis.enabled=false"),
            "requires vault, pgvector, opensearch, and redis fixtures",
        ),
        (
            "kind arbitrary Vault image",
            "hallu-defense",
            ("--set-string", "kindDependencies.vault.image=busybox:latest"),
            "/kindDependencies/vault/image",
        ),
        (
            "kind arbitrary Redis image",
            "hallu-defense",
            ("--set-string", "kindDependencies.redis.image=busybox:latest"),
            "/kindDependencies/redis/image",
        ),
        (
            "kind remote pull policy",
            "hallu-defense",
            ("--set", "global.imagePullPolicy=Always"),
            "global.imagePullPolicy=IfNotPresent",
        ),
        (
            "kind invalid HTTPS origin port",
            "hallu-defense",
            (
                "--set-string",
                "console.publicOrigin=https://console.kind.invalid:65536",
                "--set-string",
                "cors.allowOrigins[0]=https://console.kind.invalid:65536",
            ),
            "/console/publicOrigin",
        ),
        (
            "kind invalid IPv6 host CIDR",
            "hallu-defense",
            ("--set-string", "networkPolicy.kubernetesApi[0].cidr=::::/128"),
            "/networkPolicy/kubernetesApi/0/cidr",
        ),
        (
            "kind traversing logical Secret path",
            "hallu-defense",
            ("--set-string", "provider.apiKeySecretName=a/../b"),
            "/provider/apiKeySecretName",
        ),
        (
            "kind invalid qualified Pod label key",
            "hallu-defense",
            (
                "--set-string",
                "networkPolicy.ingress.api.callers[0].podLabelKey=a//b",
            ),
            "/networkPolicy/ingress/api/callers/0/podLabelKey",
        ),
        (
            "kind overlong release-derived name",
            "hallu-defense-release-name-deliberate-long",
            (),
            "release-derived fullname must be at most 38 characters",
        ),
    ):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                release,
                str(CHART_DIR),
                *value_args,
                *overrides,
            ],
            label=label,
            expected_error=expected_error,
        )
    production_args = _production_helm_value_args()
    production_result = _run_helm_command(
        [executable, "template", "hallu-defense", str(CHART_DIR), *production_args],
        label="production helm template",
    )
    _validate_rendered_production_sandbox(production_result.stdout)
    production_demo_result = _run_helm_command(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *production_args,
            *demo_args,
        ],
        label="enabled production demo helm template",
    )
    _validate_rendered_demo_intake_manifest(
        production_demo_result.stdout,
        profile="enabled production demo",
        webhook_cidr="192.0.2.30/32",
        webhook_port=443,
        redis_cidr="192.0.2.31/32",
        redis_port=6380,
    )
    for label, args, expected_error in (
        (
            "production sandbox missing existing claim",
            _production_helm_value_args(existing_claim=""),
            "sandbox.workspace.existingClaim is required",
        ),
        (
            "production sandbox missing API reader claim",
            _production_helm_value_args(api_existing_claim=""),
            "sandbox.workspace.apiExistingClaim is required",
        ),
        (
            "production sandbox reuses application namespace",
            _production_helm_value_args(
                sandbox_namespace=HELM_RELEASE_NAMESPACE
            ),
            "sandbox.namespace must differ from the Helm release namespace",
        ),
        (
            "production sandbox mutable tag",
            _production_helm_value_args(
                image_reference="registry.example/sandbox:2026-07-09"
            ),
            "repository@sha256",
        ),
        (
            "production sandbox latest tag",
            _production_helm_value_args(
                image_reference="registry.example/sandbox:latest"
            ),
            "repository@sha256",
        ),
        (
            "production sandbox chart-created claim",
            _production_helm_value_args(existing_claim="", create_claim=True),
            "production requires existing namespaced RWX claims",
        ),
        (
            "production sandbox fixture",
            _production_helm_value_args(fixture_enabled=True),
            "sandbox.fixture.enabled=true is allowed only",
        ),
    ):
        _run_helm_command_expect_failure(
            [executable, "template", "hallu-defense", str(CHART_DIR), *args],
            label=label,
            expected_error=expected_error,
        )
    for workload in ("api", "console", "worker", "migrations"):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *_production_helm_value_args(
                    workload_images={workload: f"registry.example/{workload}:mutable"}
                ),
            ],
            label=f"production mutable {workload} image",
            expected_error="repository@sha256",
        )
    _run_helm_command_expect_failure(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *_production_helm_value_args(include_migrations_egress=False),
        ],
        label="production migrations without dedicated egress",
        expected_error=(
            "networkPolicy.migrations.external requires explicit production CIDRs"
        ),
    )
    _run_helm_command_expect_failure(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *_production_helm_value_args(include_console_egress=False),
        ],
        label="production Console without dedicated OIDC egress",
        expected_error=(
            "networkPolicy.console.external requires explicit production OIDC CIDRs"
        ),
    )
    _run_helm_command_expect_failure(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *_production_helm_value_args(migrations_secret_name=""),
        ],
        label="production missing migration-owner DSN",
        expected_error=(
            "secrets.migrations.name is required when migrations.enabled=true"
        ),
    )
    _run_helm_command_expect_failure(
        [
            executable,
            "template",
            "hallu-defense",
            str(CHART_DIR),
            *_production_helm_value_args(
                migrations_secret_name="prod-runtime-secret",
            ),
        ],
        label="production reused runtime Secret for migrations",
        expected_error=(
            "secrets.migrations.name must reference a distinct precreated Secret"
        ),
    )
    for label, overrides, expected_error in (
        (
            "production invalid runtime Secret name",
            ("--set-string", "secrets.runtime.name=Invalid_Secret"),
            "/secrets/runtime/name",
        ),
        (
            "production invalid runtime Secret key",
            ("--set-string", "secrets.runtime.postgresDsnKey=invalid/key"),
            "/secrets/runtime/postgresDsnKey",
        ),
        (
            "production reused runtime Secret for bootstrap",
            ("--set-string", "secrets.bootstrap.name=prod-runtime-secret"),
            "secrets.bootstrap.name must reference a distinct precreated Secret",
        ),
        (
            "production missing API ingress callers",
            (),
            "networkPolicy.ingress.api.callers requires at least one explicit",
        ),
    ):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *_production_helm_value_args(
                    include_api_ingress_callers=(
                        label != "production missing API ingress callers"
                    )
                ),
                *overrides,
            ],
            label=label,
            expected_error=expected_error,
        )
    for label, overrides, expected_error in (
        (
            "production wildcard API egress",
            ("--set-string", "networkPolicy.api.external[0].cidr=203.0.113.1/0"),
            "/networkPolicy/api/external/0/cidr",
        ),
        (
            "production split-default API egress",
            ("--set-string", "networkPolicy.api.external[0].cidr=0.0.0.0/1"),
            "/networkPolicy/api/external/0/cidr",
        ),
        (
            "production broad IPv6 API egress",
            ("--set-string", "networkPolicy.api.external[0].cidr=2001:db8::/64"),
            "/networkPolicy/api/external/0/cidr",
        ),
        (
            "production insecure OpenSearch",
            ("--set-string", "opensearch.endpoint=http://opensearch.prod.invalid:9200"),
            "/opensearch/endpoint",
        ),
        (
            "production insecure Console public origin",
            ("--set-string", "console.publicOrigin=http://console.prod.invalid"),
            "/console/publicOrigin",
        ),
        (
            "production noncanonical Console API origin",
            ("--set-string", "console.apiOrigin=https://api.prod.invalid/"),
            "/console/apiOrigin",
        ),
        (
            "production mismatched Console issuer",
            (
                "--set-string",
                "console.oidc.issuer=https://other-auth.prod.invalid/realms/hallu-defense",
            ),
            "console.oidc.issuer must exactly match oidc.issuer",
        ),
        (
            "production mismatched Console API audience",
            ("--set-string", "console.oidc.apiAudience=other-api"),
            "console.oidc.apiAudience must exactly match oidc.audience",
        ),
        (
            "production multiple Console replicas",
            ("--set", "console.replicas=2"),
            "/console/replicas",
        ),
    ):
        _run_helm_command_expect_failure(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                *_production_helm_value_args(),
                *overrides,
            ],
            label=label,
            expected_error=expected_error,
        )

    admission_names: list[str] = []
    for namespace in ("tenant-a", "tenant-b"):
        namespaced = _run_helm_command(
            [
                executable,
                "template",
                "hallu-defense",
                str(CHART_DIR),
                "--namespace",
                namespace,
                *value_args[2:],
            ],
            label=f"namespaced Helm template {namespace}",
        )
        admission_names.append(
            _rendered_name_for_kind(namespaced.stdout, "ValidatingAdmissionPolicy")
        )
    if len(set(admission_names)) != 2:
        raise HelmChartConfigError(
            "sandbox admission policy names must differ across release namespaces"
        )
    return {
        "status": "passed",
        "command": HELM_TEMPLATE_COMMAND,
        "checks": [
            "helm lint",
            "disabled Helm templates",
            "enabled demo Helm templates",
            "negative values",
        ],
    }


def _production_helm_value_args(
    *,
    image_reference: str = PRODUCTION_SANDBOX_DIGEST,
    existing_claim: str = "prod-sandbox-rwx",
    api_existing_claim: str = "prod-sandbox-rwx-reader",
    sandbox_namespace: str = "prod-sandbox",
    create_claim: bool = False,
    fixture_enabled: bool = False,
    workload_images: Mapping[str, str] | None = None,
    include_migrations_egress: bool = True,
    include_console_egress: bool = True,
    include_api_ingress_callers: bool = True,
    migrations_secret_name: str = "prod-migrations-secret",
) -> list[str]:
    effective_workload_images = dict(PRODUCTION_WORKLOAD_DIGESTS)
    if workload_images is not None:
        effective_workload_images.update(workload_images)
    values = {
        "oidc.issuer": "https://auth.prod.invalid/realms/hallu-defense",
        "oidc.audience": "hallu-defense-api",
        "cors.allowOrigins[0]": "https://console.prod.invalid",
        "outboundHttps.allowedOrigins[0]": "https://vault.prod.invalid",
        "outboundHttps.allowedOrigins[1]": "https://auth.prod.invalid",
        "outboundHttps.allowedOrigins[2]": "https://llm.prod.invalid",
        "outboundHttps.allowedOrigins[3]": "https://opensearch.prod.invalid",
        "vault.address": "https://vault.prod.invalid",
        "vault.caSecretName": "managed-vault-ca",
        "postgres.caSecretName": "managed-postgres-ca",
        "provider.backend": "openai-compatible",
        "provider.model": "production-model",
        "provider.openaiCompatibleBaseUrl": "https://llm.prod.invalid/v1",
        "provider.apiKeySecretName": "providers/openai/api-key",
        "otel.endpoint": "https://otel.prod.invalid/v1/traces",
        "console.publicOrigin": "https://console.prod.invalid",
        "console.apiOrigin": "https://api.prod.invalid",
        "console.oidc.issuer": "https://auth.prod.invalid/realms/hallu-defense",
        "console.oidc.clientId": "hallu-defense-console",
        "console.oidc.apiAudience": "hallu-defense-api",
        "sandbox.tenantId": "prod-tenant",
        "sandbox.namespace": sandbox_namespace,
        "rateLimit.redis.caSecretName": "managed-redis-ca",
        "ragIndex.backend": "hybrid",
        "opensearch.endpoint": "https://opensearch.prod.invalid",
        "opensearch.indexName": "hallu_evidence",
        "opensearch.authorizationSecretName": "rag/opensearch/authorization",
        "opensearch.caSecretName": "managed-opensearch-ca",
        "networkPolicy.kubernetesApi[0].cidr": "192.0.2.10/32",
        "networkPolicy.ingress.api.metricsScrapers[0].name": "prometheus",
        "networkPolicy.ingress.api.metricsScrapers[0].namespace": "observability",
        "networkPolicy.ingress.api.metricsScrapers[0].podLabelKey": "app.kubernetes.io/name",
        "networkPolicy.ingress.api.metricsScrapers[0].podLabelValue": "prometheus",
        "networkPolicy.ingress.worker.metricsScrapers[0].name": "prometheus-worker",
        "networkPolicy.ingress.worker.metricsScrapers[0].namespace": "observability",
        "networkPolicy.ingress.worker.metricsScrapers[0].podLabelKey": "app.kubernetes.io/name",
        "networkPolicy.ingress.worker.metricsScrapers[0].podLabelValue": "prometheus",
        "networkPolicy.ingress.console.callers[0].name": "ingress-controller",
        "networkPolicy.ingress.console.callers[0].namespace": "ingress-system",
        "networkPolicy.ingress.console.callers[0].podLabelKey": "app.kubernetes.io/name",
        "networkPolicy.ingress.console.callers[0].podLabelValue": "ingress-nginx",
        "networkPolicy.api.external[0].name": "api-https-egress-gateway",
        "networkPolicy.api.external[0].cidr": "198.51.100.10/32",
        "networkPolicy.api.external[1].name": "api-postgres",
        "networkPolicy.api.external[1].cidr": "198.51.100.11/32",
        "networkPolicy.api.external[2].name": "api-redis",
        "networkPolicy.api.external[2].cidr": "198.51.100.12/32",
        "networkPolicy.worker.external[0].name": "worker-https-egress-gateway",
        "networkPolicy.worker.external[0].cidr": "203.0.113.10/32",
        "networkPolicy.worker.external[1].name": "worker-postgres",
        "networkPolicy.worker.external[1].cidr": "203.0.113.11/32",
        "sandbox.image.reference": image_reference,
        "api.image.reference": effective_workload_images["api"],
        "console.image.reference": effective_workload_images["console"],
        "worker.image.reference": effective_workload_images["worker"],
        "migrations.image.reference": effective_workload_images["migrations"],
        "sandbox.workspace.existingClaim": existing_claim,
        "sandbox.workspace.apiExistingClaim": api_existing_claim,
        "secrets.runtime.name": "prod-runtime-secret",
        "secrets.bootstrap.name": "prod-bootstrap-secret",
        "secrets.migrations.name": migrations_secret_name,
    }
    if include_migrations_egress:
        values.update(
            {
                "networkPolicy.migrations.external[0].name": "migrations-postgres",
                "networkPolicy.migrations.external[0].cidr": "203.0.113.20/32",
            }
        )
    if include_console_egress:
        values.update(
            {
                "networkPolicy.console.external[0].name": "console-oidc-egress-gateway",
                "networkPolicy.console.external[0].cidr": "198.51.100.20/32",
            }
        )
    if include_api_ingress_callers:
        values.update(
            {
                "networkPolicy.ingress.api.callers[0].name": "ingress-controller",
                "networkPolicy.ingress.api.callers[0].namespace": "ingress-system",
                "networkPolicy.ingress.api.callers[0].podLabelKey": "app.kubernetes.io/name",
                "networkPolicy.ingress.api.callers[0].podLabelValue": "ingress-nginx",
            }
        )
    args = ["--namespace", HELM_RELEASE_NAMESPACE, "--kube-version", "1.36.1"]
    for name, value in values.items():
        args.extend(("--set-string", f"{name}={value}"))
    args.extend(
        (
            "--set",
            f"sandbox.workspace.createClaim={str(create_claim).lower()}",
            "--set",
            f"sandbox.fixture.enabled={str(fixture_enabled).lower()}",
            "--set",
            "networkPolicy.kubernetesApi[0].port=443",
            "--set",
            "networkPolicy.api.external[0].port=443",
            "--set",
            "networkPolicy.api.external[1].port=5432",
            "--set",
            "networkPolicy.api.external[2].port=6379",
            "--set",
            "networkPolicy.worker.external[0].port=443",
            "--set",
            "networkPolicy.worker.external[1].port=5432",
        )
    )
    if include_migrations_egress:
        args.extend(("--set", "networkPolicy.migrations.external[0].port=5432"))
    if include_console_egress:
        args.extend(("--set", "networkPolicy.console.external[0].port=443"))
    return args


def _demo_helm_value_args(
    *,
    include_webhook_egress: bool = True,
    include_redis_egress: bool = True,
    privacy_contact: str = "privacy@example.invalid",
) -> list[str]:
    args = [
        "--set",
        "demoRequests.enabled=true",
        "--set-string",
        f"demoRequests.privacyContactEmail={privacy_contact}",
        "--set-string",
        "demoRequests.webhookAllowedOrigin=https://crm.kind.invalid",
        "--set-string",
        "secrets.demo.name=hallu-defense-demo-v1",
    ]
    if include_webhook_egress:
        args.extend(
            [
                "--set-string",
                "networkPolicy.console.demoWebhook[0].name=demo-webhook",
                "--set-string",
                "networkPolicy.console.demoWebhook[0].cidr=192.0.2.30/32",
                "--set",
                "networkPolicy.console.demoWebhook[0].port=443",
            ]
        )
    if include_redis_egress:
        args.extend(
            [
                "--set-string",
                "networkPolicy.console.demoRedis[0].name=demo-redis",
                "--set-string",
                "networkPolicy.console.demoRedis[0].cidr=192.0.2.31/32",
                "--set",
                "networkPolicy.console.demoRedis[0].port=6380",
            ]
        )
    return args


def _run_helm_command_expect_failure(
    command: Sequence[str],
    *,
    label: str,
    expected_error: str,
) -> None:
    try:
        result = subprocess.run(
            list(command),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise HelmChartConfigError(f"{label} timed out after 120 seconds") from exc
    if result.returncode == 0:
        raise HelmChartConfigError(f"{label} unexpectedly rendered successfully")
    detail = result.stderr.strip() or result.stdout.strip()
    if expected_error not in detail:
        raise HelmChartConfigError(
            f"{label} failed without expected marker {expected_error!r}: {detail[:1000]}"
        )


def _run_helm_command(
    command: Sequence[str], *, label: str
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise HelmChartConfigError(f"{label} timed out after 120 seconds") from exc
    if result.returncode != 0:
        raise HelmChartConfigError(
            f"{label} failed: "
            + (
                result.stderr.strip()
                or result.stdout.strip()
                or f"exit {result.returncode}"
            )
        )
    return result


def _validate_chart_metadata(chart: Mapping[str, object], errors: list[str]) -> None:
    if chart.get("apiVersion") != "v2":
        errors.append("Chart.yaml apiVersion must be v2")
    if chart.get("name") != "hallu-defense":
        errors.append("Chart.yaml name must be hallu-defense")
    if chart.get("type") != "application":
        errors.append("Chart.yaml type must be application")
    if chart.get("kubeVersion") != ">=1.34.0-0":
        errors.append(
            "Chart.yaml kubeVersion must require Kubernetes >=1.34 for stable native sidecars and NetworkPolicy enforcement"
        )


def _validate_values_schema(
    values: Mapping[str, object],
    kind_values: Mapping[str, object],
    errors: list[str],
) -> None:
    try:
        payload = json.loads(VALUES_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(
            f"values.schema.json must be present and valid JSON ({type(exc).__name__})"
        )
        return
    if not isinstance(payload, Mapping):
        errors.append("values.schema.json must contain an object")
        return
    if payload.get("$schema") != "https://json-schema.org/draft-07/schema#":
        errors.append("values.schema.json must declare JSON Schema Draft 7")
    try:
        Draft7Validator.check_schema(payload)
    except SchemaError as exc:
        errors.append(f"values.schema.json is not valid Draft 7: {exc.message}")
        return

    properties = _mapping(payload.get("properties"), "values.schema.properties", errors)
    actual_top_level = set(values)
    if set(properties) != actual_top_level:
        errors.append(
            "values.schema.json must declare every and only top-level values key"
        )
    sandbox_schema = _mapping(
        properties.get("sandbox"),
        "values.schema.properties.sandbox",
        errors,
    )
    sandbox_properties = _mapping(
        sandbox_schema.get("properties"),
        "values.schema.properties.sandbox.properties",
        errors,
    )
    cleanup_grace_schema = _mapping(
        sandbox_properties.get("cleanupGraceSeconds"),
        "values.schema.properties.sandbox.properties.cleanupGraceSeconds",
        errors,
    )
    if dict(cleanup_grace_schema) != {
        "type": "integer",
        "minimum": 15,
        "maximum": 30,
    }:
        errors.append(
            "values.schema.json sandbox.cleanupGraceSeconds must accept exactly "
            "the integer range 15..30"
        )
    required = payload.get("required")
    if not isinstance(required, Sequence) or isinstance(required, (str, bytes)):
        errors.append("values.schema.json root required must be an array")
    elif set(required) != actual_top_level:
        errors.append("values.schema.json must require every top-level values key")

    for path, schema_node in _iter_schema_nodes(payload):
        if schema_node.get("type") == "object" and schema_node.get(
            "additionalProperties"
        ) is not False:
            errors.append(
                "values.schema.json object schemas must reject unknown properties: "
                + path
            )

    validator = Draft7Validator(payload)
    merged_kind_values = _deep_merge(values, kind_values)
    for profile, document in (
        ("base values", values),
        ("kind merged values", merged_kind_values),
    ):
        for validation_error in sorted(
            validator.iter_errors(document), key=lambda item: list(item.absolute_path)
        ):
            path = ".".join(str(part) for part in validation_error.absolute_path)
            location = f" at {path}" if path else ""
            errors.append(
                f"values.schema.json rejected {profile}{location}: "
                f"{validation_error.message}"
            )
    for cleanup_grace_seconds in (15, 20, 30):
        candidate = copy.deepcopy(merged_kind_values)
        candidate_sandbox = candidate.get("sandbox")
        if isinstance(candidate_sandbox, dict):
            candidate_sandbox["cleanupGraceSeconds"] = cleanup_grace_seconds
        if list(validator.iter_errors(candidate)):
            errors.append(
                "values.schema.json must accept sandbox.cleanupGraceSeconds="
                f"{cleanup_grace_seconds}"
            )
    for cleanup_grace_seconds in (14, 31):
        candidate = copy.deepcopy(merged_kind_values)
        candidate_sandbox = candidate.get("sandbox")
        if isinstance(candidate_sandbox, dict):
            candidate_sandbox["cleanupGraceSeconds"] = cleanup_grace_seconds
        if not list(validator.iter_errors(candidate)):
            errors.append(
                "values.schema.json must reject sandbox.cleanupGraceSeconds="
                f"{cleanup_grace_seconds}"
            )

    demo_schema = _mapping(
        properties.get("demoRequests"),
        "values.schema.properties.demoRequests",
        errors,
    )
    demo_properties = _mapping(
        demo_schema.get("properties"),
        "values.schema.properties.demoRequests.properties",
        errors,
    )
    if demo_properties.get("enabled") != {
        "type": "boolean",
        "default": False,
    }:
        errors.append(
            "values.schema.json demoRequests.enabled must be boolean and default false"
        )

    enabled_candidate = copy.deepcopy(merged_kind_values)
    enabled_candidate["demoRequests"].update(
        {
            "enabled": True,
            "privacyContactEmail": "privacy@example.invalid",
            "webhookAllowedOrigin": "https://crm.kind.invalid",
        }
    )
    enabled_candidate["networkPolicy"]["console"].update(
        {
            "demoWebhook": [
                {"name": "demo-webhook", "cidr": "192.0.2.30/32", "port": 443}
            ],
            "demoRedis": [
                {"name": "demo-redis", "cidr": "192.0.2.31/32", "port": 6380}
            ],
        }
    )
    enabled_candidate["secrets"]["demo"]["name"] = "hallu-defense-demo-v1"
    enabled_errors = list(validator.iter_errors(enabled_candidate))
    if enabled_errors:
        errors.append(
            "values.schema.json must accept the complete enabled demo profile: "
            + "; ".join(item.message for item in enabled_errors[:3])
        )
    else:
        for length, email, should_accept in (
            (254, DEMO_PRIVACY_EMAIL_254, True),
            (255, DEMO_PRIVACY_EMAIL_255, False),
        ):
            boundary_candidate = copy.deepcopy(enabled_candidate)
            boundary_candidate["demoRequests"]["privacyContactEmail"] = email
            boundary_errors = list(validator.iter_errors(boundary_candidate))
            if len(email) != length:
                errors.append(
                    f"internal demo privacy email fixture must contain {length} characters"
                )
            elif should_accept and boundary_errors:
                errors.append(
                    "values.schema.json must accept enabled demo privacy email length 254"
                )
            elif not should_accept and not boundary_errors:
                errors.append(
                    "values.schema.json must reject enabled demo privacy email length 255"
                )
        invalid_enabled_cases = {
            "privacy contact": ("demoRequests", "privacyContactEmail"),
            "webhook origin": ("demoRequests", "webhookAllowedOrigin"),
            "webhook egress": ("networkPolicy", "console", "demoWebhook"),
            "Redis egress": ("networkPolicy", "console", "demoRedis"),
            "demo Secret name": ("secrets", "demo", "name"),
        }
        for label, path in invalid_enabled_cases.items():
            invalid_candidate = copy.deepcopy(enabled_candidate)
            target: dict[str, object] = invalid_candidate
            for segment in path[:-1]:
                nested = target.get(segment)
                if not isinstance(nested, dict):
                    nested = {}
                    target[segment] = nested
                target = nested
            target[path[-1]] = [] if path[-1].startswith("demo") else ""
            if not list(validator.iter_errors(invalid_candidate)):
                errors.append(
                    "values.schema.json must reject enabled demo without " + label
                )


def _iter_schema_nodes(
    value: object,
    *,
    path: str = "$",
) -> Sequence[tuple[str, Mapping[str, object]]]:
    nodes: list[tuple[str, Mapping[str, object]]] = []
    if isinstance(value, Mapping):
        nodes.append((path, value))
        for key, child in value.items():
            nodes.extend(_iter_schema_nodes(child, path=f"{path}.{key}"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            nodes.extend(_iter_schema_nodes(child, path=f"{path}[{index}]"))
    return nodes


def _deep_merge(
    base: Mapping[str, object],
    override: Mapping[str, object],
) -> dict[str, object]:
    merged = copy.deepcopy(dict(base))
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _validate_values(
    values: Mapping[str, object],
    kind_values: Mapping[str, object],
    errors: list[str],
) -> None:
    global_values = _mapping(values.get("global"), "values.global", errors)
    if global_values.get("tmpSizeLimit") != "64Mi":
        errors.append("values.global.tmpSizeLimit must default to the bounded 64Mi")
    demo_requests = _mapping(
        values.get("demoRequests"), "values.demoRequests", errors
    )
    if dict(demo_requests) != {
        "enabled": False,
        "privacyContactEmail": "",
        "webhookAllowedOrigin": "",
        "redisCaPath": "/run/hallu-defense/demo/redis-ca.pem",
    }:
        errors.append(
            "values.demoRequests must default disabled with empty public metadata and the exact Redis CA path"
        )
    demo_secrets = _mapping(
        _mapping(values.get("secrets"), "values.secrets", errors).get("demo"),
        "values.secrets.demo",
        errors,
    )
    expected_demo_secrets = {
        "name": "",
        "webhookUrlKey": "webhook-url",
        "webhookHmacSecretKey": "webhook-hmac-secret",
        "redisUrlKey": "redis-url",
        "redisCaKey": "redis-ca.pem",
        "metricsBearerKey": "metrics-bearer",
    }
    if dict(demo_secrets) != expected_demo_secrets:
        errors.append(
            "values.secrets.demo must expose an empty name and exactly five distinct key selectors"
        )
    elif len(set(str(value) for key, value in demo_secrets.items() if key != "name")) != 5:
        errors.append("values.secrets.demo data key selectors must be distinct")
    base_network = _mapping(
        values.get("networkPolicy"), "values.networkPolicy", errors
    )
    base_console_network = _mapping(
        base_network.get("console"), "values.networkPolicy.console", errors
    )
    for path in ("demoWebhook", "demoRedis"):
        if base_console_network.get(path) != []:
            errors.append(
                f"values.networkPolicy.console.{path} must default to an empty allowlist"
            )
    merged_kind_demo = _mapping(
        _deep_merge(values, kind_values).get("demoRequests"),
        "kind merged demoRequests",
        errors,
    )
    if merged_kind_demo.get("enabled") is not False:
        errors.append("values-kind.yaml must keep demoRequests.enabled=false by default")
    kind_dependencies = _mapping(
        values.get("kindDependencies"), "values.kindDependencies", errors
    )
    if kind_dependencies.get("enabled") is not False:
        errors.append(
            "values.kindDependencies.enabled must default false for production safety"
        )
    vault = _mapping(
        kind_dependencies.get("vault"), "values.kindDependencies.vault", errors
    )
    if vault.get("image") != "hallu-defense-vault:ci":
        errors.append("values must select the locally rebuilt hardened Vault image")
    pgvector = _mapping(
        kind_dependencies.get("pgvector"), "values.kindDependencies.pgvector", errors
    )
    if pgvector.get("image") != "hallu-defense-pgvector:ci":
        errors.append(
            "values must select the locally built hardened pgvector derivative"
        )
    opensearch = _mapping(
        kind_dependencies.get("opensearch"),
        "values.kindDependencies.opensearch",
        errors,
    )
    if opensearch.get("image") != "hallu-defense-opensearch:ci":
        errors.append(
            "values must select the locally built core-only OpenSearch derivative"
        )
    redis = _mapping(
        kind_dependencies.get("redis"), "values.kindDependencies.redis", errors
    )
    if redis.get("image") != (
        "redis:7-alpine@sha256:"
        "6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    ):
        errors.append("values must pin the verified Redis 7.4.9 image digest")
    kind_override = _mapping(
        kind_values.get("kindDependencies"),
        "kind_values.kindDependencies",
        errors,
    )
    if kind_override.get("enabled") is not True:
        errors.append("values-kind.yaml must explicitly enable kindDependencies")
    for dependency in ("vault", "pgvector", "opensearch", "redis"):
        section = _mapping(
            kind_override.get(dependency),
            f"kind_values.kindDependencies.{dependency}",
            errors,
        )
        if section.get("enabled") is not True:
            errors.append(f"values-kind.yaml must explicitly enable {dependency}")
    kind_opensearch_dependency = _mapping(
        kind_override.get("opensearch"),
        "kind_values.kindDependencies.opensearch",
        errors,
    )
    if kind_opensearch_dependency.get("image") != "hallu-defense-opensearch:ci":
        errors.append(
            "values-kind.yaml must select the locally built core-only OpenSearch derivative"
        )
    worker = _mapping(values.get("worker"), "values.worker", errors)
    if worker.get("enabled") is not True:
        errors.append(
            "worker.enabled must default true now that the Batch 6 runtime exists"
        )
    expected_worker_command = [
        "python",
        "-m",
        "hallu_defense.worker",
        "--metrics-host",
        "0.0.0.0",
        "--metrics-port",
        "9090",
    ]
    if worker.get("replicas") != 1:
        errors.append("values.worker.replicas must default to one active consumer")
    if worker.get("command") != expected_worker_command:
        errors.append("values.worker.command must use the exact ingestion worker CLI")
    if worker.get("metricsPort") != 9090:
        errors.append("values.worker.metricsPort must be the authenticated port 9090")
    setup_grace = worker.get("setupGraceSeconds")
    if (
        not isinstance(setup_grace, int)
        or isinstance(setup_grace, bool)
        or not 1 <= setup_grace <= 300
    ):
        errors.append("values.worker.setupGraceSeconds must be between 1 and 300")
    if worker.get("podAnnotations") != {
        "prometheus.io/scrape": "true",
        "prometheus.io/path": "/metrics",
        "prometheus.io/port": "9090",
    }:
        errors.append("values.worker.podAnnotations must pin the Prometheus 9090 scrape")
    for component in ("api", "console", "worker", "migrations"):
        component_values = _mapping(
            values.get(component), f"values.{component}", errors
        )
        component_image = _mapping(
            component_values.get("image"),
            f"values.{component}.image",
            errors,
        )
        if component_image.get("reference") not in {"", None}:
            errors.append(
                f"values.{component}.image.reference must default empty for deployment-supplied digest"
            )
        kind_component = _mapping(
            kind_values.get(component),
            f"kind_values.{component}",
            errors,
        )
        kind_image = _mapping(
            kind_component.get("image"),
            f"kind_values.{component}.image",
            errors,
        )
        expected_kind_image = (
            "hallu-defense-console:ci"
            if component == "console"
            else "hallu-defense-api:ci"
        )
        if kind_image.get("reference") != expected_kind_image:
            errors.append(
                f"values-kind.yaml must pin {component}.image.reference={expected_kind_image}"
            )
    provider_defaults = _mapping(values.get("provider"), "values.provider", errors)
    otel_defaults = _mapping(values.get("otel"), "values.otel", errors)
    oidc_defaults = _mapping(values.get("oidc"), "values.oidc", errors)
    vault_defaults = _mapping(values.get("vault"), "values.vault", errors)
    cors_defaults = _mapping(values.get("cors"), "values.cors", errors)
    outbound_defaults = _mapping(
        values.get("outboundHttps"),
        "values.outboundHttps",
        errors,
    )
    console_defaults = _mapping(values.get("console"), "values.console", errors)
    if console_defaults.get("replicas") != 1:
        errors.append(
            "values.console.replicas must equal 1 while OIDC state is process-local"
        )
    rag_defaults = _mapping(values.get("ragIndex"), "values.ragIndex", errors)
    if rag_defaults != {"backend": "hybrid", "timeoutSeconds": 5}:
        errors.append("values.ragIndex must default to the bounded hybrid backend")
    opensearch_defaults = _mapping(
        values.get("opensearch"), "values.opensearch", errors
    )
    if opensearch_defaults.get("endpoint") not in {"", None}:
        errors.append("values.opensearch.endpoint must default empty")
    if opensearch_defaults.get("indexName") != "hallu_evidence":
        errors.append("values.opensearch.indexName must default to hallu_evidence")
    if opensearch_defaults.get("authorizationSecretName") not in {"", None}:
        errors.append("values.opensearch.authorizationSecretName must default empty")
    if opensearch_defaults.get("caPath") != "/run/hallu-defense/opensearch-ca.pem":
        errors.append("values.opensearch.caPath must use the managed mount path")
    if opensearch_defaults.get("caSecretName") not in {"", None}:
        errors.append("values.opensearch.caSecretName must default empty")
    if opensearch_defaults.get("caSecretKey") != "ca.crt":
        errors.append("values.opensearch.caSecretKey must default to ca.crt")
    postgres_defaults = _mapping(values.get("postgres"), "values.postgres", errors)
    if postgres_defaults != {
        "caPath": "/run/hallu-defense/postgres-ca.pem",
        "caSecretName": "",
        "caSecretKey": "ca.crt",
        "kindInsecureTlsEnabled": False,
    }:
        errors.append("values.postgres must default to managed verify-full TLS")
    kind_rag = _mapping(kind_values.get("ragIndex"), "kind_values.ragIndex", errors)
    if kind_rag.get("backend") != "hybrid":
        errors.append("values-kind.yaml must select the hybrid RAG backend")
    kind_opensearch = _mapping(
        kind_values.get("opensearch"),
        "kind_values.opensearch",
        errors,
    )
    if kind_opensearch.get("endpoint") != "http://hallu-defense-opensearch:9200":
        errors.append(
            "values-kind.yaml must pin the exact internal OpenSearch endpoint"
        )
    if kind_opensearch.get("authorizationSecretName") not in {"", None}:
        errors.append("values-kind.yaml OpenSearch must not receive credentials")
    if kind_opensearch.get("caSecretName") not in {"", None}:
        errors.append("values-kind.yaml OpenSearch must not mount a managed CA")
    kind_postgres = _mapping(
        kind_values.get("postgres"), "kind_values.postgres", errors
    )
    if kind_postgres != {"caSecretName": "", "kindInsecureTlsEnabled": True}:
        errors.append(
            "values-kind.yaml must scope the explicit insecure PostgreSQL TLS exception to Kind"
        )
    network_policy = _mapping(
        values.get("networkPolicy"), "values.networkPolicy", errors
    )
    if network_policy.get("kubernetesApi") != []:
        errors.append("values.networkPolicy.kubernetesApi must default empty")
    ingress_defaults = _mapping(
        network_policy.get("ingress"), "values.networkPolicy.ingress", errors
    )
    api_ingress_defaults = _mapping(
        ingress_defaults.get("api"), "values.networkPolicy.ingress.api", errors
    )
    console_ingress_defaults = _mapping(
        ingress_defaults.get("console"), "values.networkPolicy.ingress.console", errors
    )
    worker_ingress_defaults = _mapping(
        ingress_defaults.get("worker"), "values.networkPolicy.ingress.worker", errors
    )
    if api_ingress_defaults != {"callers": [], "metricsScrapers": []}:
        errors.append(
            "values.networkPolicy.ingress.api must default to empty allowlists"
        )
    if console_ingress_defaults != {"callers": []}:
        errors.append(
            "values.networkPolicy.ingress.console must default to an empty allowlist"
        )
    if worker_ingress_defaults != {"metricsScrapers": []}:
        errors.append(
            "values.networkPolicy.ingress.worker must default to an empty metrics allowlist"
        )
    for role in ("api", "console", "worker", "migrations"):
        role_policy = _mapping(
            network_policy.get(role),
            f"values.networkPolicy.{role}",
            errors,
        )
        if role_policy.get("external") != []:
            errors.append(f"values.networkPolicy.{role}.external must default empty")
    kind_network_policy = _mapping(
        kind_values.get("networkPolicy"),
        "kind_values.networkPolicy",
        errors,
    )
    _validate_network_policy_peers(
        kind_network_policy.get("kubernetesApi"),
        "kind_values.networkPolicy.kubernetesApi",
        errors,
        require_names=False,
    )
    if kind_network_policy.get("kubernetesApi") != [
        {"cidr": "10.96.0.1/32", "port": 443}
    ]:
        errors.append("values-kind.yaml must pin Kind's exact Kubernetes Service VIP")
    kind_ingress = _mapping(
        kind_network_policy.get("ingress"), "kind_values.networkPolicy.ingress", errors
    )
    kind_api_ingress = _mapping(
        kind_ingress.get("api"), "kind_values.networkPolicy.ingress.api", errors
    )
    kind_console_ingress = _mapping(
        kind_ingress.get("console"), "kind_values.networkPolicy.ingress.console", errors
    )
    kind_worker_ingress = _mapping(
        kind_ingress.get("worker"), "kind_values.networkPolicy.ingress.worker", errors
    )
    expected_kind_ingress = {
        "api_callers": [
            {
                "name": "kind-api-caller",
                "namespace": "$release",
                "podLabelKey": "hallu-defense.openai.com/network-client",
                "podLabelValue": "api",
            }
        ],
        "metrics": [
            {
                "name": "kind-metrics-scraper",
                "namespace": "$release",
                "podLabelKey": "hallu-defense.openai.com/network-client",
                "podLabelValue": "metrics",
            }
        ],
        "console_callers": [
            {
                "name": "kind-console-caller",
                "namespace": "$release",
                "podLabelKey": "hallu-defense.openai.com/network-client",
                "podLabelValue": "console",
            }
        ],
        "worker_metrics": [
            {
                "name": "kind-worker-metrics-scraper",
                "namespace": "$release",
                "podLabelKey": "hallu-defense.openai.com/network-client",
                "podLabelValue": "metrics",
            }
        ],
    }
    actual_kind_ingress = {
        "api_callers": kind_api_ingress.get("callers"),
        "metrics": kind_api_ingress.get("metricsScrapers"),
        "console_callers": kind_console_ingress.get("callers"),
        "worker_metrics": kind_worker_ingress.get("metricsScrapers"),
    }
    if actual_kind_ingress != expected_kind_ingress:
        errors.append(
            "values-kind.yaml must pin exact API, console, and metrics ingress peers"
        )
    for path, peers in (
        (
            "kind_values.networkPolicy.ingress.api.callers",
            kind_api_ingress.get("callers"),
        ),
        (
            "kind_values.networkPolicy.ingress.api.metricsScrapers",
            kind_api_ingress.get("metricsScrapers"),
        ),
        (
            "kind_values.networkPolicy.ingress.console.callers",
            kind_console_ingress.get("callers"),
        ),
        (
            "kind_values.networkPolicy.ingress.worker.metricsScrapers",
            kind_worker_ingress.get("metricsScrapers"),
        ),
    ):
        _validate_ingress_peers(peers, path, errors)
    for role in ("api", "console", "worker", "migrations"):
        role_policy = _mapping(
            kind_network_policy.get(role),
            f"kind_values.networkPolicy.{role}",
            errors,
        )
        _validate_network_policy_peers(
            role_policy.get("external"),
            f"kind_values.networkPolicy.{role}.external",
            errors,
            require_names=True,
        )
        if role_policy.get("external") != []:
            errors.append(f"values-kind.yaml {role} external egress must default deny")
    for path, value in (
        ("values.oidc.issuer", oidc_defaults.get("issuer")),
        ("values.oidc.audience", oidc_defaults.get("audience")),
        ("values.vault.address", vault_defaults.get("address")),
        ("values.provider.backend", provider_defaults.get("backend")),
        ("values.provider.model", provider_defaults.get("model")),
        (
            "values.provider.openaiCompatibleBaseUrl",
            provider_defaults.get("openaiCompatibleBaseUrl"),
        ),
        ("values.provider.apiKeySecretName", provider_defaults.get("apiKeySecretName")),
        ("values.otel.endpoint", otel_defaults.get("endpoint")),
    ):
        if value not in {"", None}:
            errors.append(
                f"{path} must default empty and be supplied by the deployment"
            )
    expected_console_keys = {
        "replicas",
        "image",
        "publicOrigin",
        "apiOrigin",
        "oidc",
        "service",
        "resources",
    }
    if set(console_defaults) != expected_console_keys:
        errors.append(
            "values.console must expose only the production OIDC runtime contract"
        )
    console_oidc_defaults = _mapping(
        console_defaults.get("oidc"), "values.console.oidc", errors
    )
    if set(console_oidc_defaults) != {"issuer", "clientId", "apiAudience"}:
        errors.append(
            "values.console.oidc must expose only issuer, clientId, and apiAudience"
        )
    for path, value in (
        ("values.console.publicOrigin", console_defaults.get("publicOrigin")),
        ("values.console.apiOrigin", console_defaults.get("apiOrigin")),
        ("values.console.oidc.issuer", console_oidc_defaults.get("issuer")),
        ("values.console.oidc.clientId", console_oidc_defaults.get("clientId")),
        (
            "values.console.oidc.apiAudience",
            console_oidc_defaults.get("apiAudience"),
        ),
    ):
        if value not in {"", None}:
            errors.append(
                f"{path} must default empty and be supplied by the deployment"
            )
    if cors_defaults.get("allowOrigins") != []:
        errors.append(
            "values.cors.allowOrigins must default empty and be supplied by the deployment"
        )
    if outbound_defaults.get("allowedOrigins") != []:
        errors.append(
            "values.outboundHttps.allowedOrigins must default empty and be supplied by the deployment"
        )
    if vault_defaults.get("caSecretName") not in {"", None}:
        errors.append("values.vault.caSecretName must default empty")
    if "tokenEnv" in vault_defaults:
        errors.append("values.vault must not expose a raw-token environment contract")
    if vault_defaults.get("caSecretKey") != "ca.crt":
        errors.append("values.vault.caSecretKey must default to ca.crt")
    if (
        otel_defaults.get("enabled") is not True
        or otel_defaults.get("exporter") != "otlp"
    ):
        errors.append(
            "values.otel must default to enabled OTLP with a deployment-supplied endpoint"
        )

    sandbox_defaults = _mapping(values.get("sandbox"), "values.sandbox", errors)
    if sandbox_defaults.get("backend") != "kubernetes":
        errors.append("values.sandbox.backend must default to kubernetes")
    if sandbox_defaults.get("namespace") not in {"", None}:
        errors.append(
            "values.sandbox.namespace must default empty and be deployment-supplied"
        )
    if sandbox_defaults.get("tenantId") not in {"", None}:
        errors.append(
            "values.sandbox.tenantId must default empty and be deployment-supplied"
        )
    if sandbox_defaults.get("setupGraceSeconds") != 15:
        errors.append(
            "values.sandbox.setupGraceSeconds must default to the bounded 15-second fixture grace"
        )
    if sandbox_defaults.get("cleanupGraceSeconds") != 20:
        errors.append(
            "values.sandbox.cleanupGraceSeconds must default to the bounded 20-second cleanup grace"
        )
    sandbox_image = _mapping(
        sandbox_defaults.get("image"), "values.sandbox.image", errors
    )
    if sandbox_image.get("reference") not in {"", None}:
        errors.append(
            "values.sandbox.image.reference must default empty and require a deployment-supplied digest"
        )
    sandbox_workspace = _mapping(
        sandbox_defaults.get("workspace"),
        "values.sandbox.workspace",
        errors,
    )
    if sandbox_workspace.get("existingClaim") not in {"", None}:
        errors.append("values.sandbox.workspace.existingClaim must default empty")
    if sandbox_workspace.get("apiExistingClaim") not in {"", None}:
        errors.append("values.sandbox.workspace.apiExistingClaim must default empty")
    if sandbox_workspace.get("createClaim") is not False:
        errors.append("production defaults must not create the sandbox workspace claim")
    if sandbox_workspace.get("accessModes") != ["ReadWriteMany"]:
        errors.append("production sandbox workspace must require ReadWriteMany")
    sandbox_fixture = _mapping(
        sandbox_defaults.get("fixture"),
        "values.sandbox.fixture",
        errors,
    )
    if sandbox_fixture.get("enabled") is not False:
        errors.append("production defaults must not enable the kind sandbox fixture")
    sandbox_resources = _mapping(
        sandbox_defaults.get("resources"),
        "values.sandbox.resources",
        errors,
    )
    if sandbox_resources != {"cpu": "1", "memoryMb": 512, "pidsLimit": 256}:
        errors.append("sandbox resources must remain aligned with the admission policy")

    kind_sandbox = _mapping(kind_values.get("sandbox"), "kind_values.sandbox", errors)
    if kind_sandbox.get("backend") != "kubernetes":
        errors.append("values-kind.yaml must select the kubernetes sandbox backend")
    if kind_sandbox.get("namespace") != "hallu-defense-sandbox":
        errors.append(
            "values-kind.yaml must use the dedicated hallu-defense-sandbox namespace"
        )
    if kind_sandbox.get("tenantId") != "kind-smoke-tenant":
        errors.append("values-kind.yaml must bind the sandbox PVC to kind-smoke-tenant")
    kind_sandbox_image = _mapping(
        kind_sandbox.get("image"),
        "kind_values.sandbox.image",
        errors,
    )
    if kind_sandbox_image.get("reference") != "hallu-defense-sandbox:ci":
        errors.append(
            "values-kind.yaml must use the locally built pinned sandbox image tag"
        )
    kind_sandbox_workspace = _mapping(
        kind_sandbox.get("workspace"),
        "kind_values.sandbox.workspace",
        errors,
    )
    if kind_sandbox_workspace.get("createClaim") is not True:
        errors.append(
            "values-kind.yaml must create its isolated sandbox workspace claim"
        )
    if kind_sandbox_workspace.get("existingClaim") not in {"", None}:
        errors.append("values-kind.yaml must not expose an external workspace claim")
    if kind_sandbox_workspace.get("apiExistingClaim") not in {"", None}:
        errors.append("values-kind.yaml must generate its application reader claim")
    if kind_sandbox_workspace.get("accessModes") != ["ReadWriteOnce"]:
        errors.append("values-kind.yaml sandbox workspace must use ReadWriteOnce")
    kind_sandbox_fixture = _mapping(
        kind_sandbox.get("fixture"),
        "kind_values.sandbox.fixture",
        errors,
    )
    if kind_sandbox_fixture.get("enabled") is not True:
        errors.append("values-kind.yaml must prepare the isolated sandbox fixture")

    rate_limit = _mapping(values.get("rateLimit"), "values.rateLimit", errors)
    if rate_limit.get("backend") != "redis":
        errors.append("Helm production must use the Redis rate limit backend")
    rate_limit_redis = _mapping(
        rate_limit.get("redis"),
        "values.rateLimit.redis",
        errors,
    )
    if rate_limit_redis.get("urlSecretName") != "quotas/tool-validation/redis-url":
        errors.append(
            "Helm must resolve the Redis URL from its fixed Vault logical name"
        )
    if rate_limit_redis.get("caSecretName") not in {"", None}:
        errors.append("managed Redis CA Secret name must default empty")
    if rate_limit_redis.get("caPath") != "/run/hallu-defense/redis-ca.pem":
        errors.append("Helm must mount the Redis CA at the validated runtime path")

    provider = _mapping(kind_values.get("provider"), "kind_values.provider", errors)
    if provider.get("backend") not in {"openai", "openai-compatible"}:
        errors.append("kind_values.provider.backend must select a non-mock adapter")
    if (
        not isinstance(provider.get("model"), str)
        or not str(provider.get("model")).strip()
    ):
        errors.append("kind_values.provider.model must be a non-empty string")
    if provider.get("backend") in {"openai", "openai-compatible"}:
        base_url = str(provider.get("openaiCompatibleBaseUrl", ""))
        if not base_url.startswith("https://"):
            errors.append("kind_values.provider.openaiCompatibleBaseUrl must use HTTPS")
        if (
            not isinstance(provider.get("apiKeySecretName"), str)
            or not str(provider.get("apiKeySecretName")).strip()
        ):
            errors.append("kind_values.provider.apiKeySecretName must be configured")
    kind_oidc = _mapping(kind_values.get("oidc"), "kind_values.oidc", errors)
    if not str(kind_oidc.get("issuer", "")).startswith("https://"):
        errors.append("kind_values.oidc.issuer must use HTTPS")
    if not str(kind_oidc.get("audience", "")).strip():
        errors.append("kind_values.oidc.audience must be configured")
    kind_vault = _mapping(kind_values.get("vault"), "kind_values.vault", errors)
    if kind_vault.get("address") != "https://hallu-defense-vault:8200":
        errors.append(
            "kind_values.vault.address must use the in-cluster TLS Vault service"
        )
    kind_cors = _mapping(kind_values.get("cors"), "kind_values.cors", errors)
    kind_origins = kind_cors.get("allowOrigins")
    if (
        not isinstance(kind_origins, Sequence)
        or isinstance(kind_origins, str)
        or not kind_origins
    ):
        errors.append("kind_values.cors.allowOrigins must contain HTTPS origins")
    elif any(
        not isinstance(origin, str) or not origin.startswith("https://")
        for origin in kind_origins
    ):
        errors.append("kind_values.cors.allowOrigins must contain only HTTPS origins")
    kind_outbound = _mapping(
        kind_values.get("outboundHttps"),
        "kind_values.outboundHttps",
        errors,
    )
    if kind_outbound.get("allowedOrigins") != [
        "https://hallu-defense-vault:8200",
        "https://auth.kind.invalid",
        "https://llm-gateway.kind.invalid",
    ]:
        errors.append(
            "values-kind.yaml must pin the exact outbound HTTPS origin allowlist"
        )
    kind_console = _mapping(kind_values.get("console"), "kind_values.console", errors)
    kind_console_oidc = _mapping(
        kind_console.get("oidc"), "kind_values.console.oidc", errors
    )
    expected_kind_console_runtime = {
        "publicOrigin": "https://console.kind.invalid",
        "apiOrigin": "https://api.kind.invalid",
        "issuer": "https://auth.kind.invalid/realms/hallu-defense",
        "clientId": "hallu-defense-console",
        "apiAudience": "hallu-defense-api",
    }
    actual_kind_console_runtime = {
        "publicOrigin": kind_console.get("publicOrigin"),
        "apiOrigin": kind_console.get("apiOrigin"),
        "issuer": kind_console_oidc.get("issuer"),
        "clientId": kind_console_oidc.get("clientId"),
        "apiAudience": kind_console_oidc.get("apiAudience"),
    }
    if actual_kind_console_runtime != expected_kind_console_runtime:
        errors.append(
            "values-kind.yaml must pin the exact Console OIDC runtime contract"
        )
    if (
        not isinstance(kind_origins, Sequence)
        or isinstance(kind_origins, str)
        or kind_console.get("publicOrigin") not in kind_origins
    ):
        errors.append(
            "values-kind.yaml Console public origin must appear in CORS origins"
        )
    if kind_console_oidc.get("issuer") != kind_oidc.get("issuer"):
        errors.append("values-kind.yaml Console and API OIDC issuers must match")
    if kind_console_oidc.get("apiAudience") != kind_oidc.get("audience"):
        errors.append(
            "values-kind.yaml Console audience must match the API OIDC audience"
        )
    kind_otel = _mapping(kind_values.get("otel"), "kind_values.otel", errors)
    if kind_otel.get("enabled") is not False:
        errors.append(
            "values-kind.yaml must disable OTLP because the chart has no collector"
        )
    migrations = _mapping(values.get("migrations"), "values.migrations", errors)
    if migrations.get("expectedCount") != EXPECTED_MIGRATION_COUNT:
        errors.append(
            f"values.migrations.expectedCount must be {EXPECTED_MIGRATION_COUNT}"
        )
    expected_checksums = _mapping(
        migrations.get("expectedChecksums"),
        "values.migrations.expectedChecksums",
        errors,
    )
    if expected_checksums != EXPECTED_MIGRATION_CHECKSUMS:
        errors.append(
            "values.migrations.expectedChecksums must equal the exact canonical "
            "SHA-256 inventory derived from infra/rag/pgvector"
        )
    wait_timeout = migrations.get("waitTimeoutSeconds")
    if (
        not isinstance(wait_timeout, int)
        or isinstance(wait_timeout, bool)
        or wait_timeout <= 0
    ):
        errors.append("values.migrations.waitTimeoutSeconds must be a positive integer")
    for section_name in ("api", "console", "worker"):
        section = _mapping(values.get(section_name), f"values.{section_name}", errors)
        resources = _mapping(
            section.get("resources"), f"values.{section_name}.resources", errors
        )
        _mapping(
            resources.get("requests"),
            f"values.{section_name}.resources.requests",
            errors,
        )
        _mapping(
            resources.get("limits"), f"values.{section_name}.resources.limits", errors
        )
    secrets = _mapping(values.get("secrets"), "values.secrets", errors)
    runtime_secret = _mapping(secrets.get("runtime"), "values.secrets.runtime", errors)
    bootstrap_secret = _mapping(
        secrets.get("bootstrap"), "values.secrets.bootstrap", errors
    )
    migrations_secret = _mapping(
        secrets.get("migrations"), "values.secrets.migrations", errors
    )
    expected_secret_sections = {
        "runtime": {
            "name": "",
            "keycloakJwksKey": "keycloak-jwks.json",
            "vaultTokenKey": "vault-token",
            "postgresDsnKey": "postgres-dsn",
        },
        "bootstrap": {"name": "", "vaultTokenKey": "vault-token"},
        "migrations": {
            "name": "",
            "postgresDsnKey": "migrations-postgres-dsn",
        },
        "kindPostgres": {"name": ""},
        "kindVault": {"name": ""},
        "kindRedisTls": {"name": ""},
    }
    for section_name, expected in expected_secret_sections.items():
        section = _mapping(
            secrets.get(section_name), f"values.secrets.{section_name}", errors
        )
        if section != expected:
            errors.append(
                f"values.secrets.{section_name} must contain only non-sensitive "
                "precreated Secret references"
            )
    for path, key in (
        (
            "values.secrets.runtime.keycloakJwksKey",
            runtime_secret.get("keycloakJwksKey"),
        ),
        ("values.secrets.runtime.vaultTokenKey", runtime_secret.get("vaultTokenKey")),
        ("values.secrets.runtime.postgresDsnKey", runtime_secret.get("postgresDsnKey")),
        (
            "values.secrets.bootstrap.vaultTokenKey",
            bootstrap_secret.get("vaultTokenKey"),
        ),
        (
            "values.secrets.migrations.postgresDsnKey",
            migrations_secret.get("postgresDsnKey"),
        ),
    ):
        _validate_kubernetes_secret_key(key, path, errors)
    for forbidden_key in (
        "keycloakJwks",
        "vaultToken",
        "postgresDsn",
        "migrationsPostgresDsn",
        "postgresUser",
        "postgresPassword",
        "postgresDatabase",
        "kindVaultCaCertificate",
        "kindVaultTlsCertificate",
        "kindVaultTlsPrivateKey",
        "kindRedisCaCertificate",
        "kindRedisTlsCertificate",
        "kindRedisTlsPrivateKey",
        "metricsBearerToken",
        "kindProviderApiKey",
        "kindMetricsBearerToken",
        "opensearchInitialAdminPassword",
    ):
        if forbidden_key in secrets:
            errors.append(
                f"values.secrets.{forbidden_key} is a forbidden duplicate value source"
            )
    kind_secrets = _mapping(kind_values.get("secrets"), "kind_values.secrets", errors)
    expected_kind_names = {
        "runtime": "hallu-defense-runtime",
        "bootstrap": "hallu-defense-bootstrap",
        "migrations": "hallu-defense-migrations",
        "kindPostgres": "hallu-defense-postgres",
        "kindVault": "hallu-defense-kind-vault",
        "kindRedisTls": "hallu-defense-kind-redis-tls",
    }
    actual_kind_names: list[str] = []
    for section_name, expected_name in expected_kind_names.items():
        section = _mapping(
            kind_secrets.get(section_name),
            f"kind_values.secrets.{section_name}",
            errors,
        )
        name = section.get("name")
        if name != expected_name:
            errors.append(
                f"kind_values.secrets.{section_name}.name must be {expected_name!r}"
            )
        _validate_kubernetes_secret_name(
            name, f"kind_values.secrets.{section_name}.name", errors
        )
        if isinstance(name, str):
            actual_kind_names.append(name)
    if len(actual_kind_names) != len(set(actual_kind_names)):
        errors.append("kind_values Secret references must all use distinct names")


def _validate_kubernetes_secret_name(
    value: object,
    path: str,
    errors: list[str],
) -> None:
    if not isinstance(value, str) or not value or len(value) > 253:
        errors.append(f"{path} must be a non-empty Kubernetes DNS subdomain")
        return
    labels = value.split(".")
    if any(
        not label or len(label) > 63 or KUBERNETES_DNS_LABEL_RE.fullmatch(label) is None
        for label in labels
    ):
        errors.append(f"{path} must be a valid Kubernetes DNS subdomain")


def _validate_kubernetes_secret_key(
    value: object,
    path: str,
    errors: list[str],
) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or KUBERNETES_SECRET_KEY_RE.fullmatch(value) is None
    ):
        errors.append(f"{path} must be a valid Kubernetes Secret data key")


def _validate_ingress_peers(
    value: object,
    path: str,
    errors: list[str],
) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        errors.append(f"{path} must contain explicit namespace and pod-label peers")
        return
    seen_names: set[str] = set()
    for index, raw_peer in enumerate(value):
        peer = _mapping(raw_peer, f"{path}[{index}]", errors)
        if set(peer) != {"name", "namespace", "podLabelKey", "podLabelValue"}:
            errors.append(
                f"{path}[{index}] must contain only the exact peer selector fields"
            )
        name = peer.get("name")
        if not isinstance(name, str) or not name or name in seen_names:
            errors.append(f"{path}[{index}].name must be non-empty and unique")
        else:
            seen_names.add(name)
        namespace = peer.get("namespace")
        if namespace != "$release":
            if (
                not isinstance(namespace, str)
                or not namespace
                or len(namespace) > 63
                or KUBERNETES_DNS_LABEL_RE.fullmatch(namespace) is None
            ):
                errors.append(
                    f"{path}[{index}].namespace must be $release or a DNS label"
                )
        label_key = peer.get("podLabelKey")
        if (
            not isinstance(label_key, str)
            or not label_key
            or len(label_key) > 253
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_-]*", label_key) is None
        ):
            errors.append(f"{path}[{index}].podLabelKey is invalid")
        label_value = peer.get("podLabelValue")
        if (
            not isinstance(label_value, str)
            or not 1 <= len(label_value) <= 63
            or re.fullmatch(r"[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?", label_value)
            is None
        ):
            errors.append(f"{path}[{index}].podLabelValue is invalid")


def _validate_network_policy_peers(
    value: object,
    path: str,
    errors: list[str],
    *,
    require_names: bool,
) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        errors.append(f"{path} must be a list of explicit CIDR/port peers")
        return
    seen_destinations: set[tuple[str, int]] = set()
    seen_names: set[str] = set()
    for index, raw_peer in enumerate(value):
        peer = _mapping(raw_peer, f"{path}[{index}]", errors)
        name = peer.get("name")
        if require_names:
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{path}[{index}].name must be non-empty")
            elif name in seen_names:
                errors.append(f"{path} contains duplicate peer name {name!r}")
            else:
                seen_names.add(name)
        cidr = peer.get("cidr")
        if not isinstance(cidr, str) or not cidr.strip():
            errors.append(f"{path}[{index}].cidr must be non-empty")
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"{path}[{index}].cidr must be a valid CIDR")
            continue
        if str(network) != cidr:
            errors.append(f"{path}[{index}].cidr must use canonical network notation")
        expected_prefix = 32 if network.version == 4 else 128
        if network.prefixlen != expected_prefix:
            errors.append(
                f"{path}[{index}].cidr must identify exactly one host "
                f"(/{expected_prefix})"
            )
        port = peer.get("port")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            errors.append(f"{path}[{index}].port must be an integer from 1 to 65535")
            continue
        destination = (cidr, port)
        if destination in seen_destinations:
            errors.append(f"{path} contains duplicate destination {cidr}:{port}")
        seen_destinations.add(destination)


def _validate_templates(templates: Mapping[str, str], errors: list[str]) -> None:
    missing = REQUIRED_TEMPLATE_FILES - set(templates)
    if missing:
        errors.append(
            "Helm chart missing template files: " + ", ".join(sorted(missing))
        )
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
        'required "secrets.',
        'required "oidc.issuer',
        'required "vault.address',
        'required "provider.backend',
        'required "console.publicOrigin',
        'required "console.apiOrigin',
        'required "console.oidc.issuer',
        'required "console.oidc.clientId',
        'required "console.oidc.apiAudience',
        'required "outboundHttps.allowedOrigins',
        "prometheus.io/scrape",
        "HALLU_DEFENSE_ENV",
        "value: production",
        "HALLU_DEFENSE_AUTH_REQUIRED",
        "HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_AUTH_CLAIMS_MODE",
        "value: oidc_jwt",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "value: vault",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "/run/secrets/hallu_defense_vault_token",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE",
        "/run/secrets/hallu_defense_postgres_dsn",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
        ".Values.postgres.caPath",
        "HALLU_DEFENSE_SANDBOX_BACKEND",
        ".Values.sandbox.backend",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "value: postgres",
        "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID",
        ".Values.approvalCommitment.activeSecretName",
        ".Values.approvalCommitment.activeKeyId",
        "HALLU_DEFENSE_EVAL_REPORTS_BACKEND",
        "HALLU_DEFENSE_PROVIDER_BACKEND",
        ".Values.provider.backend",
        "HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL",
        "HALLU_DEFENSE_INGESTION_MODE",
        "value: async",
        "kind: Job",
        "apply_postgres_migrations.py",
        "wait-for-postgres",
        "wait-for-migrations",
        "secrets.migrations.name is required when migrations.enabled=true",
        "must reference a distinct precreated Secret",
        "discover_expected_migrations",
        "validate_postgres_tls",
        "activeDeadlineSeconds:",
        "ttlSecondsAfterFinished:",
        "kind: StatefulSet",
        "pgvector",
        "opensearch",
        "bootstrap-opensearch-schema",
        "bootstrap_opensearch_template.py",
        "vault-bootstrap",
        "bootstrap_kind_vault.py",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "kind: ValidatingAdmissionPolicy",
        "failurePolicy: Fail",
        "validationActions:",
        "kind: NetworkPolicy",
        "networkPolicy.kubernetesApi requires at least one explicit API-only CIDR and port",
        "networkPolicy.ingress.api.callers requires at least one explicit namespace and pod-label peer",
        "networkPolicy.ingress.api.metricsScrapers requires at least one explicit namespace and pod-label peer",
        "networkPolicy.ingress.worker.metricsScrapers requires at least one explicit namespace and pod-label peer",
        "networkPolicy.ingress.console.callers requires at least one explicit namespace and pod-label peer",
        "networkPolicy.console.external requires explicit production OIDC CIDRs and ports",
        "-default-deny-ingress",
        "kubernetes.io/metadata.name: kube-system",
        "k8s-app: kube-dns",
        "must identify exactly one host (/32 IPv4 or /128 IPv6)",
        "hallu-defense.openai.com/network-policy: deny-egress",
        "egress: []",
        "kind: Role",
        "sandbox.namespace must differ from the Helm release namespace",
        'include "hallu-defense.sandboxApiWorkspaceClaimName"',
        "kind: PersistentVolume",
        "automountServiceAccountToken: false",
        "release-derived fullname must be at most 38 characters",
        ":kind-<run-id> scratch tag",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS",
        ".Values.sandbox.cleanupGraceSeconds",
    ):
        if marker not in combined:
            errors.append(f"Helm templates missing `{marker}`")
    if "unsigned_headers" in combined:
        errors.append("Helm templates must not configure unsigned auth headers")
    if "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND\n  value: memory" in combined:
        errors.append("Helm templates must not configure memory audit backend")
    if (
        "HALLU_DEFENSE_EVAL_REPORTS_BACKEND\n  value: postgres"
        not in templates["_helpers.tpl"]
    ):
        errors.append("Helm API env must configure PostgreSQL eval reports")
    if "/var/run/docker.sock" in combined:
        errors.append("Helm chart must never mount the Docker socket")
    if templates["_helpers.tpl"].count("runAsNonRoot: true") < 2:
        errors.append("Helm helper security contexts must set runAsNonRoot: true")
    if "{{- if .Values.worker.enabled }}" not in templates["worker-deployment.yaml"]:
        errors.append("worker deployment must be explicitly gated by worker.enabled")
    if "worker probe placeholder" in templates["worker-deployment.yaml"]:
        errors.append("worker probes must not use placeholder commands")
    api_template = templates["api-deployment.yaml"]
    if (
        "readinessProbe:\n            httpGet:\n              path: /ready"
        not in api_template
    ):
        errors.append("API readinessProbe must use /ready")
    if api_template.count("timeoutSeconds: 5") != 2:
        errors.append("API liveness/readiness probes must each set timeoutSeconds: 5")
    worker_template = templates["worker-deployment.yaml"]
    if "hallu_defense.worker\n                - --check-ready" not in worker_template:
        errors.append("worker readinessProbe must invoke the bounded --check-ready CLI")
    if worker_template.count("timeoutSeconds: 5") != 2:
        errors.append(
            "worker liveness/readiness probes must each set timeoutSeconds: 5"
        )
    if 'include "hallu-defense.workerEnv"' not in worker_template:
        errors.append("worker deployment must use the dedicated workerEnv helper")
    if 'include "hallu-defense.apiEnv"' in worker_template:
        errors.append("worker deployment must not inherit apiEnv")
    for marker in (
        ".Values.worker.podAnnotations",
        "containerPort: {{ .Values.worker.metricsPort }}",
        "name: metrics",
        "progressDeadlineSeconds: {{ add (int .Values.migrations.waitTimeoutSeconds) (int .Values.worker.setupGraceSeconds) }}",
        "initialDelaySeconds: {{ .Values.worker.setupGraceSeconds }}",
    ):
        if marker not in worker_template:
            errors.append(
                f"worker authenticated metrics integration missing `{marker}`"
            )
    worker_service = templates["worker-service.yaml"]
    for marker in (
        "{{- if .Values.worker.enabled }}",
        "kind: Service",
        'name: {{ include "hallu-defense.fullname" . }}-worker',
        "type: ClusterIP",
        "app.kubernetes.io/component: worker",
        "port: {{ .Values.worker.metricsPort }}",
        "targetPort: metrics",
    ):
        if marker not in worker_service:
            errors.append(f"worker metrics Service missing `{marker}`")
    console_template = templates["console-deployment.yaml"]
    for marker in (
        "HALLU_DEFENSE_ENV",
        "value: production",
        "HALLU_DEFENSE_CONSOLE_AUTH_MODE",
        "value: oidc",
        "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN",
        "HALLU_DEFENSE_CONSOLE_API_ORIGIN",
        "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER",
        "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID",
        "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE",
        "HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM",
        "value: tenant_id",
        "HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM",
        "value: roles",
        "HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES",
        "value: verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator",
        "console.replicas must equal 1",
        "console.publicOrigin must appear exactly in cors.allowOrigins",
        "console.oidc.issuer must exactly match oidc.issuer",
        "console.oidc.apiAudience must exactly match oidc.audience",
    ):
        if marker not in console_template:
            errors.append(f"Console production OIDC template missing `{marker}`")
    for marker in (
        "strategy:\n    type: Recreate",
        'required "demoRequests.privacyContactEmail is required when intake is enabled"',
        'required "demoRequests.webhookAllowedOrigin is required when intake is enabled"',
        "(gt (len $privacyContact) 254)",
        "valid email address of at most 254 characters",
        "HALLU_DEFENSE_DEMO_REQUESTS_ENABLED",
        "HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL",
        "HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE",
        "/run/hallu-defense/demo/webhook-url",
        "HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE",
        "/run/hallu-defense/demo/webhook-hmac-secret",
        "HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN",
        "HALLU_DEFENSE_DEMO_REDIS_URL_FILE",
        "/run/hallu-defense/demo/redis-url",
        "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
        ".Values.demoRequests.redisCaPath",
        "HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE",
        "/run/hallu-defense/demo/metrics-bearer",
        "mountPath: /run/hallu-defense/demo",
        "readOnly: true",
        "secretName: {{ .Values.secrets.demo.name | quote }}",
        "defaultMode: 0440",
        "path: webhook-url",
        "path: webhook-hmac-secret",
        "path: redis-url",
        "path: redis-ca.pem",
        "path: metrics-bearer",
    ):
        if marker not in console_template:
            errors.append(f"Console demo intake template missing `{marker}`")
    if console_template.count("path: /console") != 2:
        errors.append("Console liveness/readiness probes must both target /console")
    if "path: /\n" in console_template:
        errors.append("Console probes must never target the public root route")
    if console_template.count("timeoutSeconds: 5") != 2:
        errors.append("Console liveness/readiness probes must each time out in 5 seconds")
    expected_demo_key_markers = (
        "- key: {{ .Values.secrets.demo.webhookUrlKey | quote }}",
        "- key: {{ .Values.secrets.demo.webhookHmacSecretKey | quote }}",
        "- key: {{ .Values.secrets.demo.redisUrlKey | quote }}",
        "- key: {{ .Values.secrets.demo.redisCaKey | quote }}",
        "- key: {{ .Values.secrets.demo.metricsBearerKey | quote }}",
    )
    for marker in expected_demo_key_markers:
        if console_template.count(marker) != 1:
            errors.append(
                f"Console demo Secret projection must reference `{marker}` exactly once"
            )
    helpers_template = templates["_helpers.tpl"]
    for marker in ("runAsUser: 10001", "runAsGroup: 10001", "fsGroup: 10001"):
        if marker not in helpers_template:
            errors.append(
                f"Helm POSIX reader contract for 0440 Secret projections missing `{marker}`"
            )
    network_template = templates["application-egress-network-policies.yaml"]
    for marker in (
        "networkPolicy.console.demoWebhook requires explicit webhook /32 or /128 peers",
        "networkPolicy.console.demoRedis requires explicit Redis /32 or /128 peers",
        '(dict "path" "networkPolicy.console.demoWebhook" "peers" .Values.networkPolicy.console.demoWebhook)',
        '(dict "path" "networkPolicy.console.demoRedis" "peers" .Values.networkPolicy.console.demoRedis)',
        "concat .Values.networkPolicy.console.demoWebhook .Values.networkPolicy.console.demoRedis",
    ):
        if marker not in network_template:
            errors.append(f"Console demo egress template missing `{marker}`")
    for forbidden_marker in (
        "NEXT_PUBLIC_",
        "HALLU_DEFENSE_CONSOLE_ALLOW_",
        "HALLU_DEFENSE_CONSOLE_LOCAL_",
    ):
        if forbidden_marker in console_template:
            errors.append(
                "Console production template must not expose weakening/client env "
                f"`{forbidden_marker}`"
            )
    migration_template = templates["migration-job.yaml"]
    for marker in (
        'include "hallu-defense.migrationsSecretName"',
        ".Values.secrets.migrations.postgresDsnKey",
        "path: hallu_defense_postgres_dsn",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE",
        "HALLU_DEFENSE_ENV",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
        "hallu-defense.openai.com/release-revision: {{ .Release.Revision | quote }}",
        "ttlSecondsAfterFinished: 600",
    ):
        if marker not in migration_template:
            errors.append(
                f"migration Job must consume its dedicated file-mounted Secret (`{marker}`)"
            )
    if 'include "hallu-defense.runtimeSecretName"' in migration_template:
        errors.append("migration Job must not reference the runtime Secret")
    helpers = templates["_helpers.tpl"]
    if ".Values.secrets.migrations.postgresDsnKey" in helpers:
        errors.append(
            "API/worker/readiness helpers must never consume the DDL migration DSN"
        )
    secrets_template = templates["secrets.yaml"]
    for marker in (
        "Helm intentionally renders no Secret objects",
        "secrets.runtime.name",
        "secrets.bootstrap.name",
        "secrets.migrations.name",
        "valid Kubernetes DNS subdomain",
        "valid Kubernetes Secret data key",
        "distinct precreated Secret",
        "hasKey $seenNames $name",
        "secrets.demo.name is required when demoRequests.enabled=true",
        "secrets.demo.webhookUrlKey",
        "secrets.demo.webhookHmacSecretKey",
        "secrets.demo.redisUrlKey",
        "secrets.demo.redisCaKey",
        "secrets.demo.metricsBearerKey",
    ):
        if marker not in secrets_template:
            errors.append(f"Helm precreated-Secret boundary missing `{marker}`")
    for forbidden_marker in (
        "kind: Secret",
        "stringData:",
        ".Values.secrets.postgresDsn",
        ".Values.secrets.migrationsPostgresDsn",
        ".Values.secrets.vaultToken",
        ".Values.secrets.keycloakJwks",
    ):
        if forbidden_marker in secrets_template:
            errors.append(
                f"Helm must not render sensitive Secret material (`{forbidden_marker}`)"
            )
    for workload_template in (api_template, worker_template):
        for marker in (
            "runtime-secrets",
            "runtime-postgres-secret",
            "bootstrap-secrets",
            "mountPath: /run/secrets",
            "readOnly: true",
        ):
            if marker not in workload_template:
                errors.append(
                    f"runtime workload Secret mounts missing hardened marker `{marker}`"
                )
    for raw_secret_env in (
        "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN",
        "- name: HALLU_DEFENSE_POSTGRES_DSN\n",
    ):
        if raw_secret_env in combined:
            errors.append(
                f"Helm workloads must not expose raw credentials via env (`{raw_secret_env}`)"
            )
    opensearch_template = templates["opensearch-statefulset.yaml"]
    for marker in (
        "DISABLE_INSTALL_DEMO_CONFIG",
        "DISABLE_SECURITY_PLUGIN",
        "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI",
    ):
        if opensearch_template.count(marker) != 1:
            errors.append(
                f"core-only OpenSearch StatefulSet must set exactly one `{marker}`"
            )
    expected_opensearch_java_opts = (
        'value: "-Xms512m -Xmx512m -Dorg.bouncycastle.native.cpu_variant=java"'
    )
    if (
        opensearch_template.count(expected_opensearch_java_opts) != 1
        or opensearch_template.count("org.bouncycastle.native.cpu_variant") != 1
    ):
        errors.append(
            "OpenSearch OPENSEARCH_JAVA_OPTS must be exact with one Java-only "
            "Bouncy Castle cpu_variant"
        )
    expected_transport_binding = (
        "- name: transport.host\n              value: 127.0.0.1"
    )
    if (
        opensearch_template.count(expected_transport_binding) != 1
        or opensearch_template.count("transport.host") != 1
    ):
        errors.append("OpenSearch transport.host must bind exactly once to 127.0.0.1")
    for marker in (
        "readOnlyRootFilesystem: true",
        "mountPath: /tmp",
        "mountPath: /usr/share/opensearch/logs",
        "mountPath: /usr/share/opensearch/config",
    ):
        if opensearch_template.count(marker) != 1:
            errors.append(
                f"hardened OpenSearch StatefulSet must set exactly one `{marker}`"
            )
    if (
        opensearch_template.count(
            "sizeLimit: {{ .Values.global.tmpSizeLimit | quote }}"
        )
        != 2
    ):
        errors.append(
            "hardened OpenSearch StatefulSet must bound both tmp and logs emptyDirs"
        )
    for marker in ("medium: Memory", "sizeLimit: 16Mi"):
        if opensearch_template.count(marker) != 1:
            errors.append(
                "hardened OpenSearch StatefulSet must provide an exact 16Mi "
                f"in-memory writable config volume (`{marker}`)"
            )
    for forbidden_marker in (
        "plugins.security.disabled",
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
        "opensearchInitialAdminPassword",
    ):
        if forbidden_marker in combined:
            errors.append(
                "core-only OpenSearch fixture must not retain security-plugin password "
                f"marker `{forbidden_marker}`"
            )
    worker_env = _template_definition(
        templates["_helpers.tpl"], "hallu-defense.workerEnv"
    )
    for marker in (
        "HALLU_DEFENSE_RUNTIME_ROLE",
        "value: worker",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE",
        "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
        "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "HALLU_DEFENSE_VAULT_ADDR",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_INGESTION_MODE",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "HALLU_DEFENSE_INGESTION_WORKER_ID",
        "fieldPath: metadata.uid",
    ):
        if marker not in worker_env:
            errors.append(f"workerEnv missing `{marker}`")
    for forbidden in (
        "OIDC",
        "JWKS",
        "PROVIDER",
        "OPENAI",
        "CORS",
        "APPROVAL",
        "SANDBOX",
    ):
        if forbidden in worker_env:
            errors.append(
                f"workerEnv must not expose API-only configuration `{forbidden}`"
            )
    bootstrap_env = _template_definition(
        templates["_helpers.tpl"], "hallu-defense.opensearchBootstrapEnv"
    )
    for marker in (
        "HALLU_DEFENSE_RUNTIME_ROLE\n  value: opensearch-bootstrap",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND\n  value: opensearch",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "HALLU_DEFENSE_VAULT_ADDR",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED",
    ):
        if marker not in bootstrap_env:
            errors.append(f"opensearchBootstrapEnv missing `{marker}`")
    for forbidden in (
        "POSTGRES",
        "OIDC",
        "JWKS",
        "PROVIDER",
        "OPENAI",
        "OTEL",
        "SANDBOX",
        "REDIS",
    ):
        if forbidden in bootstrap_env:
            errors.append(
                "opensearchBootstrapEnv must not expose unrelated configuration "
                f"`{forbidden}`"
            )
    api_env = _template_definition(templates["_helpers.tpl"], "hallu-defense.apiEnv")
    for marker in (
        ".Values.otel.enabled",
        'required "otel.endpoint is required when otel.enabled=true"',
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED",
        "HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
        "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID",
        ".Values.approvalCommitment.activeSecretName",
        ".Values.approvalCommitment.activeKeyId",
        "previousSecretName, previousKeyId, and previousValidUntil",
        "HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
        "audit/request-commitment-key",
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
    ):
        if marker not in api_env:
            errors.append(
                f"apiEnv missing explicit OTLP configuration marker `{marker}`"
            )
    cleanup_grace_block = (
        "- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS\n"
        "  value: {{ .Values.sandbox.cleanupGraceSeconds | quote }}"
    )
    if cleanup_grace_block not in api_env:
        errors.append(
            "apiEnv must map sandbox.cleanupGraceSeconds to the exact Kubernetes "
            "cleanup grace environment variable"
        )
    if "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS" in worker_env:
        errors.append("workerEnv must not receive the Kubernetes sandbox cleanup grace")
    if "http://otel-collector:4318" in api_env:
        errors.append("apiEnv must not hardcode an undeployed OpenTelemetry Collector")
    application_policy = templates["application-egress-network-policies.yaml"]
    for marker in (
        "kind: NetworkPolicy",
        "-api-egress",
        "-worker-egress",
        "-console-egress",
        "-default-deny-ingress",
        "podSelector: {}",
        ".Values.networkPolicy.ingress.api.callers",
        ".Values.networkPolicy.ingress.api.metricsScrapers",
        ".Values.networkPolicy.ingress.worker.metricsScrapers",
        ".Values.networkPolicy.ingress.console.callers",
        "kubernetes.io/metadata.name: {{ $namespace | quote }}",
        "-migrations-egress",
        "-vault-bootstrap-egress",
        'range $component := list "pgvector" "opensearch" "vault"',
        "-{{ $component }}-egress",
        '$sources = list "api" "worker" "migrations"',
        '$sources = list "api" "worker"',
        '$sources = list "api" "worker" "vault-bootstrap" "redis"',
        "$port = 5432",
        "$port = 9200",
        "$port = 8200",
        "app.kubernetes.io/component: api",
        "app.kubernetes.io/component: worker",
        "app.kubernetes.io/component: console",
        "app.kubernetes.io/component: migrations",
        "app.kubernetes.io/component: vault-bootstrap",
        "app.kubernetes.io/component: pgvector",
        "app.kubernetes.io/component: vault",
        "app.kubernetes.io/component: redis",
        "app.kubernetes.io/component: opensearch",
        "networkPolicy.kubernetesApi",
        'regexMatch "^[0-9.]+/32$" $cidr',
        'regexMatch "^[0-9A-Fa-f:]+/128$" $cidr',
        ".Values.networkPolicy.api.external",
        ".Values.networkPolicy.console.external",
        ".Values.networkPolicy.worker.external",
        ".Values.networkPolicy.migrations.external",
        "cidr: {{ $peer.cidr | quote }}",
        "port: 5432",
        "port: 6379",
        "port: 8200",
        "port: 9200",
    ):
        if marker not in application_policy:
            errors.append(f"application egress NetworkPolicies missing `{marker}`")
    if (
        application_policy.count("range $peer := .Values.networkPolicy.kubernetesApi")
        != 2
    ):
        errors.append(
            "Kubernetes API CIDRs must be validated and rendered only for the API policy"
        )
    redis_policy = templates["redis-deployment.yaml"]
    for marker in (
        "kind: NetworkPolicy",
        "app.kubernetes.io/component: redis",
        "app.kubernetes.io/component: vault",
        "port: 8200",
    ):
        if marker not in redis_policy:
            errors.append(f"Redis least-privilege egress policy missing `{marker}`")
    runtime_secret_template = templates["secrets.yaml"].partition("---")[0]
    if "metrics-bearer-token" in runtime_secret_template:
        errors.append(
            "runtime Kubernetes Secret must not duplicate the Vault metrics token"
        )
    for template_name in (
        "api-deployment.yaml",
        "console-deployment.yaml",
        "worker-deployment.yaml",
    ):
        template = templates[template_name]
        for marker in (
            "hallu-defense.containerSecurityContext",
            "livenessProbe:",
            "readinessProbe:",
            "resources:",
        ):
            if marker not in template:
                errors.append(f"{template_name} missing `{marker}`")
    for template_name in ("api-deployment.yaml", "worker-deployment.yaml"):
        if "hallu-defense.migrationWaitInitContainer" not in templates[template_name]:
            errors.append(f"{template_name} must wait for PostgreSQL migrations")
    migration_template = templates["migration-job.yaml"]
    if "hallu-defense.postgresWaitInitContainer" not in migration_template:
        errors.append("migration Job must wait for PostgreSQL readiness")
    if "{{ .Release.Revision }}" not in migration_template:
        errors.append("migration Job name must be revision-scoped for Helm upgrades")
    pgvector_template = templates["pgvector-statefulset.yaml"]
    for marker in (
        "- name: PGDATA",
        "value: /var/lib/postgresql/data/pgdata",
        "mountPath: /var/lib/postgresql/data",
        "runAsUser: 70",
        "runAsGroup: 70",
        "fsGroup: 70",
    ):
        if marker not in pgvector_template:
            errors.append(f"pgvector StatefulSet missing safe PVC marker `{marker}`")
    if "value: /var/lib/postgresql/data\n" in pgvector_template:
        errors.append("pgvector PGDATA must not point at the local-path PVC mount root")
    vault_template = templates["vault-deployment.yaml"]
    for marker in (
        "-dev",
        "-dev-listen-address=127.0.0.1:18200",
        "tls_disable = 0",
        "tls_cert_file",
        "tls_key_file",
        "readOnlyRootFilesystem: true",
        "automountServiceAccountToken: false",
    ):
        if marker not in vault_template:
            errors.append(f"kind Vault template missing `{marker}`")
    bootstrap_template = templates["vault-bootstrap-job.yaml"]
    for marker in (
        "bootstrap_kind_vault.py",
        "HALLU_DEFENSE_KIND_METRICS_SECRET_NAME",
        "HALLU_DEFENSE_KIND_APPROVAL_COMMITMENT_SECRET_NAME",
        "HALLU_DEFENSE_KIND_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
        ".Values.approvalCommitment.activeSecretName",
        "audit/request-commitment-key",
        "root-token",
        "ca.crt",
        "ttlSecondsAfterFinished: 600",
    ):
        if marker not in bootstrap_template:
            errors.append(f"kind Vault bootstrap Job missing `{marker}`")

    _validate_sandbox_templates(templates, errors)
    _validate_redis_templates(templates, errors)


def _validate_migration_readiness_contract(
    *,
    templates: Mapping[str, str],
    readiness_text: str,
    errors: list[str],
) -> None:
    helper = templates.get("_helpers.tpl", "")
    migration_wait = _template_definition(
        helper,
        "hallu-defense.migrationWaitInitContainer",
    )
    for marker in (
        "PostgresMigrationsReadinessCheck",
        "PsycopgMigrationLedgerReader",
        "ReadinessCheckError",
        "discover_expected_migrations",
        'Path("/app/infra/rag/pgvector")',
        "expected_migrations=expected_migrations",
        "migration_check.run()",
    ):
        if marker not in migration_wait:
            errors.append(
                "Helm migration wait must verify exact versions and SHA-256 checksums; "
                f"missing `{marker}`"
            )
    for forbidden in (
        "SELECT count(*) FROM schema_migrations",
        ".Values.migrations.expectedCount",
    ):
        if forbidden in migration_wait:
            errors.append(
                "Helm migration wait must not accept count-only migration evidence; "
                f"found `{forbidden}`"
            )

    for marker in (
        "SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version ASC",
        "if applied != self._expected:",
        'hashlib.sha256(statement.encode("utf-8")).hexdigest()',
        'path.read_text(encoding="utf-8")',
    ):
        if marker not in readiness_text:
            errors.append(
                "Runtime migration readiness must compare the exact canonical checksum "
                f"ledger; missing `{marker}`"
            )
    for version in EXPECTED_MIGRATION_VERSIONS:
        if f'"{version}"' not in readiness_text:
            errors.append(
                "Runtime migration readiness inventory is missing "
                f"committed version {version}"
            )


def _validate_sandbox_templates(
    templates: Mapping[str, str],
    errors: list[str],
) -> None:
    helpers = templates["_helpers.tpl"]
    for marker in (
        'define "hallu-defense.validatedWorkloadImage"',
        "image.reference must use repository@sha256:<64 lowercase hex> outside kind",
        'define "hallu-defense.apiImage"',
        'define "hallu-defense.consoleImage"',
        'define "hallu-defense.workerImage"',
        'define "hallu-defense.migrationsImage"',
        'required "sandbox.image.reference is required"',
        "repository@sha256:<64 lowercase hex>",
        "production requires an existing RWX claim",
        "sandbox.tenantId is required for one-tenant-per-workspace isolation",
        'sha256sum (printf "%s/%s" .Release.Namespace (include "hallu-defense.sandboxNamespace" .))',
        "HALLU_DEFENSE_OPA_ENABLED",
        "HALLU_DEFENSE_OPA_PATH",
        "/usr/local/bin/opa",
        "HALLU_DEFENSE_OPA_POLICY_DIR",
        "/app/infra/opa/policies",
    ):
        if marker not in helpers:
            errors.append(f"Helm helpers missing sandbox/OPA invariant `{marker}`")
    worker_env = _template_definition(helpers, "hallu-defense.workerEnv")
    if "HALLU_DEFENSE_OPA_" in worker_env:
        errors.append("workerEnv must not receive API-only OPA configuration")

    rbac = templates["sandbox-rbac.yaml"]
    for marker in (
        "kind: ServiceAccount",
        "automountServiceAccountToken: false",
        "kind: Role",
        "kind: RoleBinding",
        "resources:\n      - jobs\n    verbs:\n      - create\n      - get\n      - delete",
        "resources:\n      - pods\n    verbs:\n      - list",
        "resources:\n      - pods/log\n    verbs:\n      - get",
        "resources:\n      - networkpolicies\n    verbs:\n      - list",
        'include "hallu-defense.apiServiceAccountName"',
        'namespace: {{ include "hallu-defense.sandboxNamespace" . }}',
        "namespace: {{ .Release.Namespace }}",
    ):
        if marker not in rbac:
            errors.append(
                f"sandbox RBAC missing exact least-privilege marker `{marker}`"
            )
    for forbidden in (
        "      - update\n",
        "      - patch\n",
        "      - watch\n",
        "      - *\n",
    ):
        if forbidden in rbac:
            errors.append(
                f"sandbox RBAC contains forbidden permission `{forbidden.strip()}`"
            )

    network_policy = templates["sandbox-network-policy.yaml"]
    for marker in (
        "apiVersion: networking.k8s.io/v1",
        "hallu-defense.openai.com/network-policy: deny-egress",
        "policyTypes:\n    - Ingress\n    - Egress",
        "ingress: []",
        "egress: []",
    ):
        if marker not in network_policy:
            errors.append(f"sandbox NetworkPolicy missing `{marker}`")

    admission = templates["sandbox-validating-admission-policy.yaml"]
    if "matchConditions:" in admission:
        errors.append(
            "sandbox admission identity must be a denying validation, not a bypassable matchCondition"
        )
    for marker in (
        "apiVersion: admissionregistration.k8s.io/v1",
        "kind: ValidatingAdmissionPolicy",
        "kind: ValidatingAdmissionPolicyBinding",
        "failurePolicy: Fail\n  matchConstraints:\n    matchPolicy: Equivalent",
        "request.userInfo.username",
        "request.namespace == '{{ include \"hallu-defense.sandboxNamespace\" . }}'",
        "namespaceSelector:",
        "validationActions:\n    - Deny",
        "object.metadata.annotations.size() == 1",
        "!has(object.metadata.generateName) || object.metadata.generateName == ''",
        "object.metadata.finalizers.size() == 0",
        "object.metadata.ownerReferences.size() == 0",
        "object.spec.template.metadata.labels.size() == 6",
        "object.spec.template.metadata.labels['job-name'] == object.metadata.name",
        "object.spec.template.metadata.labels['batch.kubernetes.io/job-name'] == object.metadata.name",
        "object.spec.template.metadata.labels['controller-uid'] == string(object.metadata.uid)",
        "object.spec.template.metadata.labels['batch.kubernetes.io/controller-uid'] == string(object.metadata.uid)",
        "object.spec.manualSelector == false",
        "object.spec.selector.matchLabels.size() == 1",
        "object.spec.selector.matchLabels['batch.kubernetes.io/controller-uid'] == string(object.metadata.uid)",
        "object.spec.suspend == false",
        "!has(object.spec.template.spec.hostIPC) ||",
        "!has(object.spec.template.spec.hostNetwork) ||",
        "!has(object.spec.template.spec.hostPID) ||",
        "c.image ==",
        "quantity(c.resources.limits['cpu']).compareTo(",
        "quantity(c.resources.limits['memory']).compareTo(",
        "(!has(c.envFrom) || c.envFrom.size() == 0)",
        "!has(e.valueFrom)",
        "volumeMounts.size() == 4",
        "object.spec.template.spec.volumes.size() == 4",
        "m.name == 'source'",
        "m.mountPath == '/hallu-source'",
        "m.readOnly == true",
        "v.name == 'source'",
        "v.name == 'workspace' && has(v.emptyDir)",
        "quantity(v.emptyDir.sizeLimit).compareTo(quantity('512Mi')) == 0",
        "has(m.subPath) && m.subPath != ''",
        "has(v.persistentVolumeClaim)",
        "has(v.emptyDir)",
        "has(v.emptyDir.sizeLimit)",
        "quantity(v.emptyDir.sizeLimit).compareTo(q) == 0",
        "quantity(v.emptyDir.sizeLimit).compareTo(quantity('64Mi')) == 0",
        "quantity('1Mi'), quantity('2Mi')",
        "quantity('15Mi'), quantity('16Mi')",
        "(!has(c.ports) || c.ports.size() == 0)",
        "!has(c.lifecycle)",
        "!has(c.startupProbe)",
        "!has(c.livenessProbe)",
        "!has(c.readinessProbe)",
        "c.securityContext.procMount == 'Default'",
        "appArmorProfile.type != 'Unconfined'",
        "securityContext.sysctls.size() == 0",
        "securityContext.supplementalGroups.size() == 0",
        "!has(c.securityContext.seLinuxOptions)",
        "!has(c.securityContext.windowsOptions)",
        "c.command == ['python', '/opt/hallu-defense/sandbox_runner.py']",
        "c.command == ['python', '/opt/hallu-defense/sandbox_stream_exporter.py']",
        "c.args.size() >= 4 && c.args.size() <= 259",
        "c.args[1] == '50000'",
        "c.args[2] == '536870912'",
        "!has(c.stdin) || c.stdin == false",
        "!has(c.tty) || c.tty == false",
    ):
        if marker not in admission:
            errors.append(f"sandbox admission policy missing `{marker}`")
    for marker in (
        "quantity(c.resources.limits['cpu']).compareTo(",
        "quantity(c.resources.limits['memory']).compareTo(",
    ):
        if admission.count(marker) != 2:
            errors.append(
                f"sandbox admission policy must pin `{marker}` for runner and exporters"
            )
    for forbidden in ("hostPath", "secretRef", "configMapRef"):
        if forbidden in admission:
            errors.append(
                f"sandbox admission allow-policy must not contain allowed source `{forbidden}`"
            )
    for invalid_quantity_comparison in (
        "c.resources.requests['cpu'] == quantity",
        "c.resources.requests['memory'] == quantity",
        "c.resources.limits['cpu'] == quantity",
        "c.resources.limits['memory'] == quantity",
        "v.emptyDir.sizeLimit in [",
        "v.emptyDir.sizeLimit == quantity",
        "v.emptyDir.sizeLimit >= quantity",
        "v.emptyDir.sizeLimit <= quantity",
    ):
        if invalid_quantity_comparison in admission:
            errors.append(
                "sandbox admission must not order-compare dynamically typed Volume quantities"
            )

    api_template = templates["api-deployment.yaml"]
    for marker in (
        "serviceAccountName:",
        "automountServiceAccountToken: false",
        "serviceAccountToken:",
        "name: kube-api-access",
        "projected:\n            defaultMode: 0440\n            sources:",
        "expirationSeconds: 3600",
        "persistentVolumeClaim:",
        'include "hallu-defense.sandboxApiWorkspaceClaimName"',
        "readOnly: true",
    ):
        if marker not in api_template:
            errors.append(f"API sandbox integration missing `{marker}`")
    expected_workspace_mount = (
        "            - name: workspace\n"
        "              mountPath: {{ .Values.sandbox.workspace.mountPath | quote }}\n"
        "              readOnly: true"
    )
    if expected_workspace_mount not in api_template:
        errors.append("API workspace PVC mount must be explicitly read-only")
    if "prepare-sandbox-fixture" in api_template:
        errors.append("API Deployment must not prepare or mutate the sandbox fixture")
    fixture_template = templates["sandbox-fixture-job.yaml"]
    for marker in (
        'namespace: {{ include "hallu-defense.sandboxNamespace" . }}',
        "app.kubernetes.io/component: sandbox-fixture",
        'include "hallu-defense.sandboxWorkspaceClaimName"',
        "prepare-sandbox-fixture",
        "hallu-defense.openai.com/release-revision: {{ .Release.Revision | quote }}",
        "HALLU_FIXTURE_READY_MARKER",
        "HALLU_FIXTURE_READY_HOLD_SECONDS",
        "readinessProbe:",
        'marker.read_text(encoding="utf-8") == "ready\\n"',
        "sizeLimit: 1Mi",
        "ttlSecondsAfterFinished: 600",
    ):
        if marker not in fixture_template:
            errors.append(f"sandbox fixture Job missing `{marker}`")
    workspace_template = templates["sandbox-workspace-pvc.yaml"]
    for marker in (
        "kind: PersistentVolume",
        "kind: PersistentVolumeClaim",
        "namespace: {{ .Release.Namespace }}",
        "namespace: {{ $sandboxNamespace }}",
        'include "hallu-defense.sandboxApiWorkspaceClaimName"',
        'include "hallu-defense.sandboxWorkspaceClaimName"',
        "hostPath:",
        "/var/local/hallu-defense-sandbox/",
    ):
        if marker not in workspace_template:
            errors.append(f"kind dual workspace views missing `{marker}`")
    if (
        workspace_template.count("kind: PersistentVolume\n") != 2
        or workspace_template.count("kind: PersistentVolumeClaim\n") != 2
    ):
        errors.append(
            "kind workspace must contain exactly two PVs and two namespaced PVCs"
        )
    api_init_template = api_template.split("      containers:", maxsplit=1)[0]
    if "name: kube-api-access" in api_init_template:
        errors.append(
            "API init containers must not receive the projected Kubernetes token"
        )
    bootstrap_section = api_init_template.partition(
        "- name: bootstrap-opensearch-schema"
    )[2]
    for marker in (
        "name: vault-ca",
        "name: opensearch-ca",
        "/app/scripts/dev/bootstrap_opensearch_template.py",
        "OpenSearch schema bootstrap timed out",
    ):
        if marker not in bootstrap_section:
            errors.append(f"API OpenSearch bootstrap init missing `{marker}`")
    for forbidden in ("name: keycloak-jwks", "name: redis-ca", "name: kube-api-access"):
        if forbidden in bootstrap_section:
            errors.append(f"API OpenSearch bootstrap init must not mount `{forbidden}`")
    worker_template = templates["worker-deployment.yaml"]
    worker_init_template = worker_template.split("      containers:", maxsplit=1)[0]
    worker_bootstrap_section = worker_init_template.partition(
        "- name: bootstrap-opensearch-schema"
    )[2]
    for marker in (
        "name: vault-ca",
        "name: opensearch-ca",
        "/app/scripts/dev/bootstrap_opensearch_template.py",
        "OpenSearch schema bootstrap timed out",
    ):
        if marker not in worker_bootstrap_section:
            errors.append(f"worker OpenSearch bootstrap init missing `{marker}`")
    for template_name in (
        "api-deployment.yaml",
        "worker-deployment.yaml",
        "console-deployment.yaml",
        "migration-job.yaml",
        "vault-deployment.yaml",
        "vault-bootstrap-job.yaml",
    ):
        template = templates[template_name]
        if (
            "name: tmp" not in template
            or "sizeLimit: {{ .Values.global.tmpSizeLimit | quote }}" not in template
        ):
            errors.append(
                f"{template_name} must bound its /tmp emptyDir with global.tmpSizeLimit"
            )
        if "emptyDir: {}" in template:
            errors.append(f"{template_name} must not define an unbounded emptyDir")
    for template_name in (
        "worker-deployment.yaml",
        "console-deployment.yaml",
        "migration-job.yaml",
        "pgvector-statefulset.yaml",
        "opensearch-statefulset.yaml",
        "vault-deployment.yaml",
        "vault-bootstrap-job.yaml",
    ):
        if "automountServiceAccountToken: false" not in templates[template_name]:
            errors.append(
                f"{template_name} must disable ServiceAccount token automount"
            )
        if "kube-api-access" in templates[template_name]:
            errors.append(
                f"{template_name} must not mount the API ServiceAccount token"
            )


def _validate_redis_templates(
    templates: Mapping[str, str],
    errors: list[str],
) -> None:
    redis = templates["redis-deployment.yaml"]
    for marker in (
        ".Values.kindDependencies.redis.enabled",
        "automountServiceAccountToken: false",
        "secrets.token_hex(32)",
        "user default off",
        "user hallu-rate-limiter on >",
        "~hallu-defense:tool-validation-rate-limit:v1:*",
        "+ping +eval +incr +pexpire",
        '"port 0\\n"',
        '"tls-port 6379\\n"',
        '"tls-protocols \\"TLSv1.2 TLSv1.3\\"\\n"',
        '"save \\"\\"\\n"',
        '"appendonly no\\n"',
        "restartPolicy: Always",
        "-h 127.0.0.1 -p 6379 --user invalid --pass invalid",
        "HALLU_DEFENSE_KIND_VAULT_SEED_CORE_CREDENTIALS",
        "HALLU_DEFENSE_KIND_REDIS_SECRET_NAME",
        "HALLU_DEFENSE_KIND_REDIS_URL_PATH",
        "HALLU_DEFENSE_KIND_READY_MARKER_PATH",
        "defaultMode: 0440",
        "kind: NetworkPolicy",
        "app.kubernetes.io/component: api",
        "port: 6379",
        "kubernetes.io/metadata.name: kube-system",
        "app.kubernetes.io/component: vault",
        "port: 8200",
    ):
        if marker not in redis:
            errors.append(f"kind Redis template missing `{marker}`")
    if redis.count("defaultMode: 0440") < 2:
        errors.append("kind Redis TLS and Vault Secret volumes must both use mode 0440")
    if redis.count("-h 127.0.0.1 -p 6379 --user invalid --pass invalid") != 3:
        errors.append(
            "kind Redis startup/liveness/readiness probes must use supported redis-cli flags"
        )
    if "--host 127.0.0.1" in redis or "--port 6379" in redis:
        errors.append(
            "kind Redis probes must not use unsupported redis-cli long host/port flags"
        )

    helpers = templates["_helpers.tpl"]
    api_env = _template_definition(helpers, "hallu-defense.apiEnv")
    worker_env = _template_definition(helpers, "hallu-defense.workerEnv")
    for marker in (
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH",
    ):
        if marker not in api_env:
            errors.append(f"apiEnv missing Redis rate limit setting `{marker}`")
        if marker in worker_env:
            errors.append(
                f"workerEnv must not receive API Redis limiter setting `{marker}`"
            )
    if "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL\n" in api_env:
        errors.append(
            "apiEnv must not contain the Redis URL; it must resolve from Vault"
        )
    kind_local_image_block = (
        "{{- if .Values.kindDependencies.enabled }}\n"
        "- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE\n"
        '  value: "true"\n'
        "{{- end }}"
    )
    if kind_local_image_block not in api_env:
        errors.append(
            "apiEnv must emit the local sandbox image exception only for kind"
        )
    if "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE" in worker_env:
        errors.append(
            "workerEnv must not receive the kind-only sandbox image exception"
        )
    api_template = templates["api-deployment.yaml"]
    for marker in (
        'include "hallu-defense.redisCaSecretName"',
        "name: redis-ca",
        ".Values.rateLimit.redis.caPath",
    ):
        if marker not in api_template:
            errors.append(f"API Redis CA integration missing `{marker}`")


def _validate_api_image_contents(api_dockerfile_text: str, errors: list[str]) -> None:
    for marker in (
        "COPY scripts/dev/apply_postgres_migrations.py /app/scripts/dev/apply_postgres_migrations.py",
        "COPY infra/rag/pgvector /app/infra/rag/pgvector",
        "COPY scripts/dev/bootstrap_kind_vault.py /app/scripts/dev/bootstrap_kind_vault.py",
    ):
        if marker not in api_dockerfile_text:
            errors.append(f"API image must package migration runtime asset `{marker}`")


def _validate_runtime_role_boundaries(
    *,
    config_text: str,
    api_dependencies_text: str,
    worker_runtime_text: str,
    errors: list[str],
) -> None:
    for marker in (
        'RUNTIME_ROLE_API = "api"',
        'RUNTIME_ROLE_WORKER = "worker"',
        "validate_runtime_role_settings(settings, expected_runtime_role=expected_runtime_role)",
        "if runtime_role == RUNTIME_ROLE_API:",
        "validate_worker_runtime_settings(settings)",
        "Worker runtime requires a PostgreSQL audit ledger backend.",
        "Worker runtime requires a persistent RAG index backend.",
        "sandbox_kubernetes_kind_local_image: bool = False",
        '"HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE"',
        'backend != "kubernetes" and settings.sandbox_kubernetes_kind_local_image',
        'settings.sandbox_kubernetes_image != "hallu-defense-sandbox:ci"',
        "and not settings.sandbox_kubernetes_kind_local_image",
    ):
        if marker not in config_text:
            errors.append(f"runtime role validation missing `{marker}`")
    if (
        "load_settings(expected_runtime_role=RUNTIME_ROLE_API)"
        not in api_dependencies_text
    ):
        errors.append("API executable must pin the api runtime role")
    if (
        "load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)"
        not in worker_runtime_text
    ):
        errors.append("worker executable must pin the worker runtime role")


def _validate_kind_vault_bootstrap_script(text: str, errors: list[str]) -> None:
    for marker in (
        "secret_generator.token_urlsafe(32)",
        "PROVIDER_SECRET_NAME_ENV",
        "METRICS_SECRET_NAME_ENV",
        "APPROVAL_COMMITMENT_SECRET_NAME_ENV",
        "AUDIT_REQUEST_COMMITMENT_SECRET_NAME_ENV",
        "REDIS_SECRET_NAME_ENV",
        "REDIS_URL_PATH_ENV",
        "READY_MARKER_PATH_ENV",
        "config.redis_url_path.unlink()",
        "_validate_kind_redis_url(redis_url)",
        '"X-Vault-Token": vault_credential',
    ):
        if marker not in text:
            errors.append(f"kind Vault bootstrap script missing `{marker}`")
    for forbidden in (
        "HALLU_DEFENSE_KIND_PROVIDER_API_KEY_PATH",
        "HALLU_DEFENSE_KIND_METRICS_TOKEN_PATH",
    ):
        if forbidden in text:
            errors.append(
                f"kind Vault bootstrap must not read Kubernetes credential `{forbidden}`"
            )


def _validate_no_default_secrets(
    value: object, errors: list[str], path: str = "values"
) -> None:
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
    live_smoke_text: str,
    prod_compose_text: str,
    marketing_doc_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_helm_chart.py"
    if "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE" in prod_compose_text:
        errors.append(
            "docker-compose.prod.yml must never enable the kind-only image exception"
        )
    if 'fetch("http://127.0.0.1:3000/console"' not in live_smoke_text:
        errors.append("kind/Helm smoke Console probe must target /console")
    if 'fetch("http://127.0.0.1:3000/"' in live_smoke_text:
        errors.append("kind/Helm smoke Console probe must not target the public root")
    if 'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"' not in live_smoke_text:
        errors.append(
            "kind/Helm smoke Console probe must expect disabled demo intake"
        )
    for marker in (
        "## Production activation runbook",
        "five `0440` Secret projections",
        "Redis TLS/CA validation",
        "printable ASCII",
        "high-entropy",
        "## Abort criteria and rollback",
        "external Secret is not versioned by Helm",
        "strategy `Recreate`",
    ):
        if marker not in marketing_doc_text:
            errors.append(f"marketing deployment runbook missing `{marker}`")
    for marker in (
        "infra/k8s/helm/hallu-defense",
        "API, console, and worker Deployments",
        "worker.enabled=true",
        "Batch 6 ingestion worker runtime",
        "Vault, and TLS Redis fixtures",
        "values-kind.yaml",
        "synthetic production values",
        "helm upgrade --install",
        "all fourteen schema migrations",
        "011_rag_lifecycle_outbox.sql",
        "012_rag_tenant_deletion_fence.sql",
        "013_audit_history_integrity.sql",
        "secrets.migrations.name/secrets.migrations.postgresDsnKey",
        "migration identity alone has DDL privileges",
        "PGDATA=/var/lib/postgresql/data/pgdata",
        "core-only OpenSearch",
        "127.0.0.1:9300",
        "HALLU_DEFENSE_SECRETS_BACKEND=vault",
        "workerEnv",
        "Downward API worker ID",
        "exact worker environment isolation",
        "no plaintext equivalent",
        "No Pod receives both PostgreSQL refs",
        "Console production OIDC contract",
        "`values.schema.json`, the render-time guard, and the static gate",
        "`console.replicas` fail-closed at exactly `1`",
        "Restarting the Console invalidates active",
        "rag_tenant_deletion_tombstones",
        "`RagIndexTenantDeletedError`",
        "networkPolicy.console.external",
        "networkPolicy.ingress.worker.metricsScrapers",
        "NEXT_PUBLIC_*",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "Helm release history",
        "metrics token materializer",
        "otel.enabled=false",
        "repository@sha256:<64 hex>",
        "rateLimit.redis.caSecretName",
        "outboundHttps.allowedOrigins",
        "ValidatingAdmissionPolicy",
        "two namespaced RWX claim refs",
        "separate Helm releases, application/sandbox namespaces",
        "kindnet native NetworkPolicy",
        "authenticated `/metrics`",
        "`/32` for IPv4 or `/128` for IPv6",
        "Ingress is default-deny",
        "cannot list Pods, read Pod logs, or delete Jobs in the application namespace",
        "API mounts only the first view with `readOnly: true`",
        "/repo/checks/run",
        "zero sandbox Jobs and zero sandbox Pods",
        "ownerReferences[].uid",
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS",
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
    for workflow_name, workflow_text in (
        ("CI", ci_workflow_text),
        ("security", security_workflow_text),
    ):
        for marker in (
            "Install pinned Helm",
            "HELM_VERSION: v4.2.2",
            "HELM_SHA256: 9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6",
            'test "$(helm version --short)" = "v4.2.2+gb05881c"',
        ):
            if marker not in workflow_text:
                errors.append(
                    f"{workflow_name} workflow must install pinned Helm before chart gates (`{marker}`)"
                )
    if "kind-helm-live:" not in live_workflow_text:
        errors.append("live workflow must include kind-helm-live job")
    if "HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED" not in live_workflow_text:
        errors.append("kind-helm-live job must wire the kind/Helm smoke env gate")
    for marker in (
        "KIND_VERSION:",
        "HELM_VERSION:",
        "KUBECTL_VERSION:",
        "vm.max_map_count=262144",
        'HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED: "true"',
        "HALLU_DEFENSE_LIVE_KIND_HELM_RUN_ID: gha-${{ github.run_id }}-${{ github.run_attempt }}",
        "github.event_name == 'workflow_dispatch'",
        "github.event_name == 'schedule'",
        "Teardown only the exact scratch kind cluster and image tags",
        'kind delete cluster --name "${cluster}"',
        'docker image rm "${image}"',
        "docker image ls --format",
        'clusters_after="$(kind get clusters 2>&1)"',
        'images_after="$(docker image ls',
        'exit "${failures}"',
    ):
        if marker not in live_workflow_text:
            errors.append(f"kind-helm-live workflow missing `{marker}`")
    for marker in (
        "KIND_VERSION: v0.32.0",
        "HELM_VERSION: v4.2.2",
        "KUBECTL_VERSION: v1.36.1",
        "KIND_SHA256: 50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54",
        "HELM_SHA256: 9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6",
        "KUBECTL_SHA256: 629d3f410e09bf49b64ae7079f7f0bda1191efed311f7d37fdbab0ad5b0ec2b7",
    ):
        if marker not in live_workflow_text:
            errors.append(
                f"kind-helm-live workflow must pin the native-NetworkPolicy toolchain `{marker}`"
            )
    for marker in (
        "_new_kind_oidc_material()",
        "_new_kind_vault_tls_material(namespace=namespace)",
        "http://127.0.0.1:8000/ready",
        'EXPECTED_OPENSEARCH_SCHEMA_VERSION = "rag-opensearch-template.v3"',
        "EXPECTED_OPENSEARCH_TEMPLATE_REPLICAS = 1",
        '"bootstrap-opensearch-schema"',
        "kind_opensearch_schema_health",
        "opensearch_transport_loopback = True",
        '"/proc/net/tcp"',
        '"opensearch_transport_pod_ip_9300"',
        "_selected_opensearch_pod_ip(",
        'health.get("number_of_data_nodes")',
        'cluster_status not in {"green", "yellow"}',
        'encoding="utf-8"',
        'errors="replace"',
        'SANDBOX_IMAGE = "hallu-defense-sandbox:ci"',
        'PGVECTOR_IMAGE = "hallu-defense-pgvector:ci"',
        'OPENSEARCH_IMAGE = "hallu-defense-opensearch:ci"',
        '("infra/docker/pgvector.Dockerfile", effective_images["pgvector"])',
        '("infra/docker/opensearch.Dockerfile", effective_images["opensearch"])',
        'KIND_NETWORK_POLICY_PROVIDER = "kindnet"',
        'KIND_PLATFORM = "linux/amd64"',
        'KIND_NODE_IMAGE_ENV = "HALLU_DEFENSE_LIVE_KIND_NODE_IMAGE"',
        "kindest/node:v1.36.1@sha256:",
        "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
        "_validated_kind_node_image(effective_env)",
        '"default_cni_enabled": True',
        '"runtime_denials_verified": True',
        'DEFAULT_SANDBOX_NAMESPACE = "hallu-defense-sandbox"',
        "_kind_workspace_host_path(",
        "_verify_api_sandbox_rbac(",
        '"auth",',
        '"can-i",',
        "api_workspace_read_only = True",
        "application_ingress_allowlist_probe = True",
        '"sandbox_namespace": sandbox_namespace',
        "_preflight_admission_policy(",
        '"--show-only",',
        '"--server-side",',
        '"--dry-run=server",',
        "_verify_kubernetes_sandbox(",
        "_sandbox_admission_probe_manifests(namespace, image=sandbox_image)",
        "hallu-sandbox-admission-source-rw",
        "http://127.0.0.1:8000/repo/checks/run",
        "SANDBOX_TIMEOUT_RETURN_CODE",
        "SANDBOX_CLEANUP_GRACE_SECONDS = 20",
        "SANDBOX_CLEANUP_UID_PROBE_SCRIPT",
        "_repo_checks_request_with_cleanup_evidence(",
        "_validate_sandbox_cleanup_evidence(",
        "_assert_empty_sandbox_workload_inventory(",
        "egress-blocked",
        "SANDBOX_JOB_LABEL",
        "_kind_secret_manifests(",
        "_verify_helm_release_secret_boundary(",
        '"get",\n                "manifest",',
        '"get",\n                "values",',
        'revision_args = ["--revision", str(revision)]',
        'f"{RELEASE_NAME}-bootstrap"',
        '"precreated_secrets"',
        "CONSOLE_OIDC_RUNTIME_PROBE_SCRIPT",
        "_verify_console_oidc_runtime(",
        '"console_oidc"',
        'name.startsWith("NEXT_PUBLIC_")',
        "_verify_projected_runtime_secret_reads(",
        '"projected_secret_reads"',
        "VAULT_MANAGER_ROTATION_PROBE_SCRIPT",
        "_verify_runtime_secret_rotation(",
        '"runtime_secret_rotation"',
        "create_secret_manager(settings)",
        "_job_selector(component='migrations', revision=revision)",
        "EXPECTED_MIGRATION_CHECKSUMS",
        "EXPECTED_MIGRATION_CHECKSUM_AGGREGATE",
        "_wait_for_fixture_pod_ready(",
        "_wait_for_revision_jobs(",
        "_verify_migration_projected_secret_read(",
        "_verify_helm_history(",
        '"sandbox.fixture.enabled=false"',
        '"--kubeconfig"',
        "_ensure_scratch_images_absent(",
        "_remove_scratch_images(",
        '"raw_secret_env_absent": True',
        '"migration Pod has {migration_restarts} container restarts"',
        "HYBRID_LIFECYCLE_TOMBSTONE_PROBE_SCRIPT",
        "_verify_hybrid_lifecycle_tombstone(",
        '"hybrid_lifecycle_tombstone"',
        '"batched_commands": 2',
        "worker_metrics_authenticated_probe",
        "_verify_worker_metrics(",
        'connected("hallu-defense-worker", 9090)',
        "RagIndexTenantDeletedError",
        "rag_tenant_deletion_tombstones",
        '"apply",',
        '"--filename",',
        'connection.sendall(b"*1\\\\r\\\\n$4\\\\r\\\\nPING\\\\r\\\\n")',
    ):
        if marker not in live_smoke_text:
            errors.append(f"kind/Helm smoke missing runtime evidence marker `{marker}`")
    for forbidden_marker in (
        "KIND_OPENSEARCH_PASSWORD",
        "_new_kind_opensearch_password",
        "opensearchInitialAdminPassword",
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
        "_kind_secret_values",
        '"secrets.postgresDsn=',
        '"secrets.migrationsPostgresDsn=',
        '"secrets.vaultToken=',
        '"secrets.keycloakJwks=',
    ):
        if forbidden_marker in live_smoke_text:
            errors.append(
                "kind/Helm smoke must not pass sensitive values through Helm "
                f"`{forbidden_marker}`"
            )
    for forbidden_marker in (
        "disableDefaultCNI:",
        "raw.githubusercontent.com/project",
        "quay.io/",
    ):
        if forbidden_marker in live_smoke_text:
            errors.append(
                f"kind/Helm smoke must use the built-in kindnet provider, not `{forbidden_marker}`"
            )
    ordered_markers = (
        '"kind",\n                "create",\n                "cluster"',
        '"wait",\n                "nodes",',
        '"kind",\n                "load",\n                "docker-image"',
        '["helm", "lint"',
    )
    positions = [live_smoke_text.find(marker) for marker in ordered_markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append(
            "kind/Helm smoke must create with built-in kindnet, wait for nodes, load images, and only then render Helm"
        )


def _validate_rendered_manifest(rendered: str) -> None:
    docs = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, Mapping)]
    errors: list[str] = []
    kinds_by_component: set[tuple[str, str]] = set()
    workloads: dict[str, Mapping[str, object]] = {}
    for doc in docs:
        metadata = _mapping(doc.get("metadata"), "rendered.metadata", errors)
        labels = _mapping(metadata.get("labels"), "rendered.metadata.labels", errors)
        component = labels.get("app.kubernetes.io/component")
        if isinstance(component, str):
            kinds_by_component.add((str(doc.get("kind")), component))
            if doc.get("kind") in {"Deployment", "StatefulSet", "Job"}:
                workloads[component] = doc
        if doc.get("kind") == "Secret":
            errors.append(
                "rendered Helm chart must not own Secret objects; precreate them outside Helm"
            )
    for expected in (
        ("Deployment", "api"),
        ("Deployment", "console"),
        ("Deployment", "worker"),
        ("Job", "migrations"),
        ("Deployment", "vault"),
        ("Deployment", "redis"),
        ("Job", "vault-bootstrap"),
        ("Job", "sandbox-fixture"),
        ("StatefulSet", "pgvector"),
        ("StatefulSet", "opensearch"),
    ):
        if expected not in kinds_by_component:
            errors.append(f"rendered chart missing {expected[0]} for {expected[1]}")
    for component in ("migrations", "vault-bootstrap", "sandbox-fixture"):
        job = workloads.get(component)
        spec = (
            _mapping(job.get("spec"), f"rendered.{component}.spec", errors)
            if job is not None
            else {}
        )
        if spec.get("ttlSecondsAfterFinished") != 600:
            errors.append(
                f"rendered {component} Job must set ttlSecondsAfterFinished=600"
            )
    if "unsigned_headers" in rendered or "value: memory" in rendered:
        errors.append(
            "rendered chart contains fail-open auth or memory backend markers"
        )
    _validate_rendered_postgres_credentials(
        docs,
        errors,
        kind_profile=True,
    )
    for component in (
        "api",
        "console",
        "worker",
        "migrations",
        "vault",
        "vault-bootstrap",
    ):
        workload = workloads.get(component)
        if workload is None:
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            f"rendered.{component}.containers",
            errors,
        )
        if not containers:
            continue
        container = containers[0]
        security = _mapping(
            container.get("securityContext"),
            f"rendered.{component}.securityContext",
            errors,
        )
        for key, expected_value in (
            ("runAsNonRoot", True),
            ("allowPrivilegeEscalation", False),
            ("readOnlyRootFilesystem", True),
        ):
            if security.get(key) is not expected_value:
                errors.append(
                    f"rendered {component} container must set {key}={expected_value}"
                )
        resources = _mapping(
            container.get("resources"),
            f"rendered.{component}.resources",
            errors,
        )
        _mapping(resources.get("requests"), f"rendered.{component}.requests", errors)
        _mapping(resources.get("limits"), f"rendered.{component}.limits", errors)
        if component in {"api", "console", "worker", "vault"}:
            for probe in ("livenessProbe", "readinessProbe"):
                probe_config = container.get(probe)
                if not isinstance(probe_config, Mapping):
                    errors.append(f"rendered {component} container missing {probe}")
                elif (
                    component in {"api", "worker"}
                    and probe_config.get("timeoutSeconds") != 5
                ):
                    errors.append(
                        f"rendered {component} {probe} must set timeoutSeconds=5"
                    )
    for component, expected_init_name in (
        ("api", "wait-for-migrations"),
        ("worker", "wait-for-migrations"),
        ("migrations", "wait-for-postgres"),
    ):
        workload = workloads.get(component)
        if workload is None:
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        init_containers = _mapping_sequence(
            pod_spec.get("initContainers"),
            f"rendered.{component}.initContainers",
            errors,
        )
        if expected_init_name not in {item.get("name") for item in init_containers}:
            errors.append(f"rendered {component} workload missing {expected_init_name}")
        if component in {"api", "worker"} and "bootstrap-opensearch-schema" not in {
            item.get("name") for item in init_containers
        }:
            errors.append(
                f"rendered {component} must provision OpenSearch before startup"
            )
    worker_text = str(workloads.get("worker", {}))
    if "worker probe placeholder" in worker_text or "--check-ready" not in worker_text:
        errors.append("rendered worker readiness must use the bounded dependency CLI")
    _validate_rendered_api_and_worker_env(workloads, errors)
    _validate_rendered_worker_service(docs, profile="rendered kind", errors=errors)
    console = workloads.get("console")
    if console is not None:
        _validate_rendered_console_env(
            console,
            profile="rendered kind Console",
            public_origin="https://console.kind.invalid",
            api_origin="https://api.kind.invalid",
            issuer="https://auth.kind.invalid/realms/hallu-defense",
            client_id="hallu-defense-console",
            api_audience="hallu-defense-api",
            errors=errors,
        )
    _validate_rendered_application_network_policies(docs, errors, kind_profile=True)
    _validate_rendered_sandbox(docs, workloads, errors)
    _validate_rendered_redis(docs, workloads, errors)
    _validate_rendered_images(workloads, errors)
    pgvector_workload = workloads.get("pgvector")
    if pgvector_workload is not None:
        pod_spec = _rendered_pod_spec(pgvector_workload, "pgvector", errors)
        pod_security = _mapping(
            pod_spec.get("securityContext"),
            "rendered.pgvector.securityContext",
            errors,
        )
        if (
            pod_security.get("runAsUser") != 70
            or pod_security.get("runAsGroup") != 70
            or pod_security.get("fsGroup") != 70
        ):
            errors.append(
                "rendered pgvector must run as the Alpine postgres UID/GID 70"
            )
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            "rendered.pgvector.containers",
            errors,
        )
        if containers:
            pgvector_container = containers[0]
            environment = _mapping_sequence(
                pgvector_container.get("env"),
                "rendered.pgvector.env",
                errors,
            )
            pgdata = next(
                (item for item in environment if item.get("name") == "PGDATA"), None
            )
            if (
                pgdata is None
                or pgdata.get("value") != "/var/lib/postgresql/data/pgdata"
            ):
                errors.append(
                    "rendered pgvector PGDATA must use a writable subdirectory below the PVC root"
                )
            volume_mounts = _mapping_sequence(
                pgvector_container.get("volumeMounts"),
                "rendered.pgvector.volumeMounts",
                errors,
            )
            data_mount = next(
                (item for item in volume_mounts if item.get("name") == "data"),
                None,
            )
            if (
                data_mount is None
                or data_mount.get("mountPath") != "/var/lib/postgresql/data"
            ):
                errors.append(
                    "rendered pgvector data PVC must mount at the PGDATA parent directory"
                )
    if errors:
        raise HelmChartConfigError("\n".join(errors))


def _rendered_pod_spec(
    workload: Mapping[str, object],
    component: str,
    errors: list[str],
) -> Mapping[str, object]:
    spec = _mapping(workload.get("spec"), f"rendered.{component}.spec", errors)
    template = _mapping(spec.get("template"), f"rendered.{component}.template", errors)
    return _mapping(template.get("spec"), f"rendered.{component}.podSpec", errors)


def _validate_rendered_console_env(
    workload: Mapping[str, object],
    *,
    profile: str,
    public_origin: str,
    api_origin: str,
    issuer: str,
    client_id: str,
    api_audience: str,
    errors: list[str],
) -> None:
    pod_spec = _rendered_pod_spec(workload, profile, errors)
    containers = _mapping_sequence(
        pod_spec.get("containers"), f"{profile}.containers", errors
    )
    if not containers:
        return
    environment = _mapping_sequence(containers[0].get("env"), f"{profile}.env", errors)
    environment_by_name = {
        str(item.get("name")): item.get("value")
        for item in environment
        if isinstance(item.get("name"), str)
    }
    expected = {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_DEMO_REQUESTS_ENABLED": "false",
        "HALLU_DEFENSE_CONSOLE_AUTH_MODE": "oidc",
        "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN": public_origin,
        "HALLU_DEFENSE_CONSOLE_API_ORIGIN": api_origin,
        "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER": issuer,
        "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID": client_id,
        "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE": api_audience,
        "HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM": "tenant_id",
        "HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM": "roles",
        "HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES": (
            "verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator"
        ),
    }
    if len(environment) != len(expected) or environment_by_name != expected:
        errors.append(
            f"{profile} environment must equal the exact production OIDC contract"
        )
    for name in environment_by_name:
        if (
            name.startswith("NEXT_PUBLIC_")
            or name.startswith("HALLU_DEFENSE_CONSOLE_ALLOW_")
            or name.startswith("HALLU_DEFENSE_CONSOLE_LOCAL_")
        ):
            errors.append(f"{profile} contains forbidden environment variable {name}")


def _validate_rendered_demo_intake_manifest(
    rendered: str,
    *,
    profile: str,
    webhook_cidr: str,
    webhook_port: int,
    redis_cidr: str,
    redis_port: int,
) -> None:
    docs = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, Mapping)]
    errors: list[str] = []
    if any(doc.get("kind") == "Secret" for doc in docs):
        errors.append(f"{profile} must not render Secret objects")
    console = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "Deployment"
            and _mapping(doc.get("metadata"), f"{profile}.metadata", errors).get(
                "name"
            )
            == "hallu-defense-console"
        ),
        None,
    )
    if console is None:
        errors.append(f"{profile} missing Console Deployment")
    else:
        deployment_spec = _mapping(
            console.get("spec"), f"{profile}.console.spec", errors
        )
        if deployment_spec.get("strategy") != {"type": "Recreate"}:
            errors.append(f"{profile} Console must use strategy Recreate")
        pod_spec = _rendered_pod_spec(console, f"{profile}.console", errors)
        pod_security = _mapping(
            pod_spec.get("securityContext"),
            f"{profile}.console.podSecurityContext",
            errors,
        )
        if (
            pod_security.get("runAsUser") != 10001
            or pod_security.get("runAsGroup") != 10001
            or pod_security.get("fsGroup") != 10001
        ):
            errors.append(
                f"{profile} Console POSIX identity must read group-mode 0440 projections"
            )
        containers = _mapping_sequence(
            pod_spec.get("containers"), f"{profile}.console.containers", errors
        )
        if containers:
            container = containers[0]
            environment = _mapping_sequence(
                container.get("env"), f"{profile}.console.env", errors
            )
            demo_environment = {
                str(item.get("name")): item.get("value")
                for item in environment
                if str(item.get("name", "")).startswith("HALLU_DEFENSE_DEMO_")
                or str(item.get("name", "")).startswith("HALLU_DEFENSE_PRIVACY_")
                or str(item.get("name", "")).startswith(
                    "HALLU_DEFENSE_CONSOLE_METRICS_BEARER"
                )
            }
            expected_demo_environment = {
                "HALLU_DEFENSE_DEMO_REQUESTS_ENABLED": "true",
                "HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL": "privacy@example.invalid",
                "HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE": (
                    "/run/hallu-defense/demo/webhook-url"
                ),
                "HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE": (
                    "/run/hallu-defense/demo/webhook-hmac-secret"
                ),
                "HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN": (
                    "https://crm.kind.invalid"
                ),
                "HALLU_DEFENSE_DEMO_REDIS_URL_FILE": (
                    "/run/hallu-defense/demo/redis-url"
                ),
                "HALLU_DEFENSE_DEMO_REDIS_CA_PATH": (
                    "/run/hallu-defense/demo/redis-ca.pem"
                ),
                "HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE": (
                    "/run/hallu-defense/demo/metrics-bearer"
                ),
            }
            if demo_environment != expected_demo_environment:
                errors.append(
                    f"{profile} Console demo environment must contain only the enabled flag, public metadata, and five file pointers"
                )
            for probe_name in ("livenessProbe", "readinessProbe"):
                probe = _mapping(
                    container.get(probe_name),
                    f"{profile}.console.{probe_name}",
                    errors,
                )
                http_get = _mapping(
                    probe.get("httpGet"),
                    f"{profile}.console.{probe_name}.httpGet",
                    errors,
                )
                if http_get.get("path") != "/console":
                    errors.append(
                        f"{profile} Console {probe_name} must target /console"
                    )
                if probe.get("timeoutSeconds") != 5:
                    errors.append(
                        f"{profile} Console {probe_name} must set timeoutSeconds=5"
                    )
            volume_mounts = _mapping_sequence(
                container.get("volumeMounts"),
                f"{profile}.console.volumeMounts",
                errors,
            )
            demo_mount = next(
                (mount for mount in volume_mounts if mount.get("name") == "demo-secrets"),
                None,
            )
            if demo_mount != {
                "name": "demo-secrets",
                "mountPath": "/run/hallu-defense/demo",
                "readOnly": True,
            }:
                errors.append(
                    f"{profile} Console must mount demo-secrets read-only at the exact path"
                )
        volumes = _mapping_sequence(
            pod_spec.get("volumes"), f"{profile}.console.volumes", errors
        )
        demo_volume = next(
            (volume for volume in volumes if volume.get("name") == "demo-secrets"),
            None,
        )
        if demo_volume is None:
            errors.append(f"{profile} Console missing demo-secrets volume")
        else:
            secret = _mapping(
                demo_volume.get("secret"), f"{profile}.console.demoSecret", errors
            )
            expected_items = [
                {"key": "webhook-url", "path": "webhook-url"},
                {"key": "webhook-hmac-secret", "path": "webhook-hmac-secret"},
                {"key": "redis-url", "path": "redis-url"},
                {"key": "redis-ca.pem", "path": "redis-ca.pem"},
                {"key": "metrics-bearer", "path": "metrics-bearer"},
            ]
            if secret != {
                "secretName": "hallu-defense-demo-v1",
                "defaultMode": 0o440,
                "items": expected_items,
            }:
                errors.append(
                    f"{profile} must project exactly five demo Secret files with mode 0440"
                )

    console_policy = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "NetworkPolicy"
            and _mapping(doc.get("metadata"), f"{profile}.policy.metadata", errors).get(
                "name"
            )
            == "hallu-defense-console-egress"
        ),
        None,
    )
    if console_policy is None:
        errors.append(f"{profile} missing Console NetworkPolicy")
    else:
        policy_spec = _mapping(
            console_policy.get("spec"), f"{profile}.policy.spec", errors
        )
        egress = _mapping_sequence(
            policy_spec.get("egress"), f"{profile}.policy.egress", errors
        )
        ip_destinations: list[tuple[str, int]] = []
        for rule in egress:
            destinations = _mapping_sequence(
                rule.get("to"), f"{profile}.policy.egress.to", errors
            )
            ports = _mapping_sequence(
                rule.get("ports"), f"{profile}.policy.egress.ports", errors
            )
            for destination in destinations:
                ip_block = destination.get("ipBlock")
                if not isinstance(ip_block, Mapping):
                    continue
                cidr = ip_block.get("cidr")
                for port in ports:
                    if isinstance(cidr, str) and isinstance(port.get("port"), int):
                        ip_destinations.append((cidr, int(port["port"])))
        expected_ip_destinations = {
            (webhook_cidr, webhook_port),
            (redis_cidr, redis_port),
        }
        if "production" in profile:
            expected_ip_destinations.add(("198.51.100.20/32", 443))
        if len(ip_destinations) != len(expected_ip_destinations) or set(
            ip_destinations
        ) != expected_ip_destinations:
            errors.append(
                f"{profile} Console egress must contain only OIDC (production), webhook, and Redis host destinations"
            )
    if errors:
        raise HelmChartConfigError("\n".join(errors))


def _validate_rendered_postgres_credentials(
    docs: Sequence[Mapping[str, object]],
    errors: list[str],
    *,
    kind_profile: bool,
) -> None:
    if any(doc.get("kind") == "Secret" for doc in docs):
        errors.append(
            "rendered chart must not contain Secret objects; credentials are precreated"
        )

    workloads: dict[str, Mapping[str, object]] = {}
    for doc in docs:
        if doc.get("kind") not in {"Deployment", "Job"}:
            continue
        metadata = _mapping(doc.get("metadata"), "rendered.workload.metadata", errors)
        labels = _mapping(
            metadata.get("labels"),
            "rendered.workload.metadata.labels",
            errors,
        )
        component = labels.get("app.kubernetes.io/component")
        if isinstance(component, str):
            workloads[component] = doc

    runtime_secret_name = (
        "hallu-defense-runtime" if kind_profile else "prod-runtime-secret"
    )
    bootstrap_secret_name = (
        "hallu-defense-bootstrap" if kind_profile else "prod-bootstrap-secret"
    )
    migrations_secret_name = (
        "hallu-defense-migrations" if kind_profile else "prod-migrations-secret"
    )
    if len({runtime_secret_name, bootstrap_secret_name, migrations_secret_name}) != 3:
        errors.append("rendered credential Secret references must be distinct")
    postgres_transport_environment = (
        {"HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED": "true"}
        if kind_profile
        else {
            "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": (
                "/run/hallu-defense/postgres-ca.pem"
            )
        }
    )

    for component in ("api", "worker"):
        workload = workloads.get(component)
        if workload is None:
            errors.append(f"rendered chart missing {component} PostgreSQL consumer")
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        _validate_secret_volume(
            pod_spec,
            profile=f"rendered {component}",
            volume_name="runtime-secrets",
            secret_name=runtime_secret_name,
            expected_items=[
                {"key": "vault-token", "path": "hallu_defense_vault_token"},
                {"key": "postgres-dsn", "path": "hallu_defense_postgres_dsn"},
            ],
            errors=errors,
        )
        if not kind_profile:
            _validate_secret_volume(
                pod_spec,
                profile=f"rendered {component}",
                volume_name="postgres-ca",
                secret_name="managed-postgres-ca",
                expected_items=[{"key": "ca.crt", "path": "ca.crt"}],
                errors=errors,
            )
        _validate_secret_volume(
            pod_spec,
            profile=f"rendered {component}",
            volume_name="runtime-postgres-secret",
            secret_name=runtime_secret_name,
            expected_items=[
                {"key": "postgres-dsn", "path": "hallu_defense_postgres_dsn"}
            ],
            errors=errors,
        )
        _validate_secret_volume(
            pod_spec,
            profile=f"rendered {component}",
            volume_name="bootstrap-secrets",
            secret_name=bootstrap_secret_name,
            expected_items=[
                {"key": "vault-token", "path": "hallu_defense_vault_token"}
            ],
            errors=errors,
        )
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            f"rendered.{component}.containers",
            errors,
        )
        if containers:
            _validate_credential_file_container(
                containers[0],
                profile=f"rendered {component}",
                volume_name="runtime-secrets",
                expected_environment={
                    "HALLU_DEFENSE_VAULT_TOKEN_FILE": (
                        "/run/secrets/hallu_defense_vault_token"
                    ),
                    "HALLU_DEFENSE_POSTGRES_DSN_FILE": (
                        "/run/secrets/hallu_defense_postgres_dsn"
                    ),
                    **postgres_transport_environment,
                },
                errors=errors,
            )
            if not kind_profile:
                _validate_readonly_mount(
                    containers[0],
                    profile=f"rendered {component}",
                    volume_name="postgres-ca",
                    mount_path="/run/hallu-defense/postgres-ca.pem",
                    errors=errors,
                )
        init_containers = _mapping_sequence(
            pod_spec.get("initContainers"),
            f"rendered.{component}.initContainers",
            errors,
        )
        wait_container = next(
            (
                item
                for item in init_containers
                if item.get("name") == "wait-for-migrations"
            ),
            None,
        )
        if wait_container is None:
            errors.append(f"rendered {component} missing wait-for-migrations")
        else:
            _validate_credential_file_container(
                wait_container,
                profile=f"rendered {component} wait-for-migrations",
                volume_name="runtime-postgres-secret",
                expected_environment={
                    "HALLU_DEFENSE_POSTGRES_DSN_FILE": (
                        "/run/secrets/hallu_defense_postgres_dsn"
                    ),
                    **postgres_transport_environment,
                },
                errors=errors,
            )
            if not kind_profile:
                _validate_readonly_mount(
                    wait_container,
                    profile=f"rendered {component} wait-for-migrations",
                    volume_name="postgres-ca",
                    mount_path="/run/hallu-defense/postgres-ca.pem",
                    errors=errors,
                )
        bootstrap_container = next(
            (
                item
                for item in init_containers
                if item.get("name") == "bootstrap-opensearch-schema"
            ),
            None,
        )
        if bootstrap_container is None:
            errors.append(f"rendered {component} missing bootstrap-opensearch-schema")
        else:
            _validate_credential_file_container(
                bootstrap_container,
                profile=f"rendered {component} bootstrap-opensearch-schema",
                volume_name="bootstrap-secrets",
                expected_environment={
                    "HALLU_DEFENSE_VAULT_TOKEN_FILE": (
                        "/run/secrets/hallu_defense_vault_token"
                    )
                },
                errors=errors,
            )
        _reject_secret_reference(pod_spec, migrations_secret_name, component, errors)

    migration_workload = workloads.get("migrations")
    if migration_workload is None:
        errors.append("rendered chart missing migrations PostgreSQL consumer")
        return
    migration_pod_spec = _rendered_pod_spec(migration_workload, "migrations", errors)
    _validate_secret_volume(
        migration_pod_spec,
        profile="rendered migrations",
        volume_name="migration-secrets",
        secret_name=migrations_secret_name,
        expected_items=[
            {
                "key": "migrations-postgres-dsn",
                "path": "hallu_defense_postgres_dsn",
            }
        ],
        errors=errors,
    )
    if not kind_profile:
        _validate_secret_volume(
            migration_pod_spec,
            profile="rendered migrations",
            volume_name="postgres-ca",
            secret_name="managed-postgres-ca",
            expected_items=[{"key": "ca.crt", "path": "ca.crt"}],
            errors=errors,
        )
    migration_containers = _mapping_sequence(
        migration_pod_spec.get("containers"),
        "rendered.migrations.containers",
        errors,
    )
    migration_init = _mapping_sequence(
        migration_pod_spec.get("initContainers"),
        "rendered.migrations.initContainers",
        errors,
    )
    for profile, container in (
        (
            "rendered migrations",
            migration_containers[0] if migration_containers else None,
        ),
        (
            "rendered migrations wait-for-postgres",
            next(
                (
                    item
                    for item in migration_init
                    if item.get("name") == "wait-for-postgres"
                ),
                None,
            ),
        ),
    ):
        if container is None:
            errors.append(f"{profile} container is missing")
            continue
        _validate_credential_file_container(
            container,
            profile=profile,
            volume_name="migration-secrets",
            expected_environment={
                "HALLU_DEFENSE_POSTGRES_DSN_FILE": (
                    "/run/secrets/hallu_defense_postgres_dsn"
                ),
                **postgres_transport_environment,
            },
            errors=errors,
        )
        if not kind_profile:
            _validate_readonly_mount(
                container,
                profile=profile,
                volume_name="postgres-ca",
                mount_path="/run/hallu-defense/postgres-ca.pem",
                errors=errors,
            )
    _reject_secret_reference(
        migration_pod_spec, runtime_secret_name, "migrations", errors
    )
    _reject_secret_reference(
        migration_pod_spec, bootstrap_secret_name, "migrations", errors
    )


def _validate_secret_volume(
    pod_spec: Mapping[str, object],
    *,
    profile: str,
    volume_name: str,
    secret_name: str,
    expected_items: list[dict[str, str]],
    errors: list[str],
) -> None:
    volumes = _mapping_sequence(pod_spec.get("volumes"), f"{profile}.volumes", errors)
    volume = next((item for item in volumes if item.get("name") == volume_name), None)
    if volume is None:
        errors.append(f"{profile} missing {volume_name} volume")
        return
    secret = _mapping(volume.get("secret"), f"{profile}.{volume_name}.secret", errors)
    if secret != {
        "secretName": secret_name,
        "defaultMode": 0o440,
        "items": expected_items,
    }:
        errors.append(
            f"{profile} {volume_name} must reference only the expected precreated Secret keys"
        )


def _validate_credential_file_container(
    container: Mapping[str, object],
    *,
    profile: str,
    volume_name: str,
    expected_environment: Mapping[str, str],
    errors: list[str],
) -> None:
    environment = _mapping_sequence(
        container.get("env"),
        f"{profile}.env",
        errors,
    )
    environment_by_name = {
        str(item.get("name")): item
        for item in environment
        if isinstance(item.get("name"), str)
    }
    for name, expected_value in expected_environment.items():
        item = environment_by_name.get(name)
        if item != {"name": name, "value": expected_value}:
            errors.append(f"{profile} must set literal file pointer {name}")
    for forbidden_name in (
        "HALLU_DEFENSE_POSTGRES_DSN",
        "HALLU_DEFENSE_RUNTIME_VAULT_TOKEN",
        "HALLU_DEFENSE_VAULT_TOKEN",
    ):
        if forbidden_name in environment_by_name:
            errors.append(
                f"{profile} must not expose raw credential env {forbidden_name}"
            )
    mounts = _mapping_sequence(
        container.get("volumeMounts"), f"{profile}.volumeMounts", errors
    )
    mount = next((item for item in mounts if item.get("name") == volume_name), None)
    if mount != {
        "name": volume_name,
        "mountPath": "/run/secrets",
        "readOnly": True,
    }:
        errors.append(f"{profile} must mount {volume_name} read-only at /run/secrets")


def _validate_readonly_mount(
    container: Mapping[str, object],
    *,
    profile: str,
    volume_name: str,
    mount_path: str,
    errors: list[str],
) -> None:
    mounts = _mapping_sequence(
        container.get("volumeMounts"), f"{profile}.volumeMounts", errors
    )
    mount = next((item for item in mounts if item.get("name") == volume_name), None)
    if (
        mount is None
        or mount.get("mountPath") != mount_path
        or mount.get("readOnly") is not True
    ):
        errors.append(f"{profile} must mount {volume_name} read-only at {mount_path}")


def _reject_secret_reference(
    pod_spec: Mapping[str, object],
    secret_name: str,
    profile: str,
    errors: list[str],
) -> None:
    volumes = _mapping_sequence(
        pod_spec.get("volumes"), f"rendered.{profile}.volumes", errors
    )
    for volume in volumes:
        secret = volume.get("secret")
        if isinstance(secret, Mapping) and secret.get("secretName") == secret_name:
            errors.append(f"rendered {profile} must not reference Secret {secret_name}")


def _validate_rendered_application_network_policies(
    docs: Sequence[Mapping[str, object]],
    errors: list[str],
    *,
    kind_profile: bool,
) -> None:
    policies = {
        str(
            _mapping(
                doc.get("metadata"), "rendered.networkPolicy.metadata", errors
            ).get("name")
        ): doc
        for doc in docs
        if doc.get("kind") == "NetworkPolicy"
    }

    dns_rule = {
        "to": [
            {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                },
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }
        ],
        "ports": [
            {"protocol": "UDP", "port": 53},
            {"protocol": "TCP", "port": 53},
        ],
    }

    def pod_rule(component: str, port: int) -> dict[str, object]:
        return {
            "to": [
                {
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "hallu-defense",
                            "app.kubernetes.io/instance": "hallu-defense",
                            "app.kubernetes.io/component": component,
                        }
                    }
                }
            ],
            "ports": [{"protocol": "TCP", "port": port}],
        }

    def ip_rule(cidr: str, port: int) -> dict[str, object]:
        return {
            "to": [{"ipBlock": {"cidr": cidr}}],
            "ports": [{"protocol": "TCP", "port": port}],
        }

    def ingress_rule(components: Sequence[str], port: int) -> dict[str, object]:
        return {
            "from": [
                {
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "hallu-defense",
                            "app.kubernetes.io/instance": "hallu-defense",
                            "app.kubernetes.io/component": component,
                        }
                    }
                }
                for component in components
            ],
            "ports": [{"protocol": "TCP", "port": port}],
        }

    def external_ingress_rule(
        namespace: str,
        label_key: str,
        label_value: str,
        port: int,
    ) -> dict[str, object]:
        return {
            "from": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": namespace}
                    },
                    "podSelector": {"matchLabels": {label_key: label_value}},
                }
            ],
            "ports": [{"protocol": "TCP", "port": port}],
        }

    default_deny = policies.get("hallu-defense-default-deny-ingress")
    if default_deny is None:
        errors.append("rendered chart missing application default-deny ingress policy")
    else:
        default_spec = _mapping(
            default_deny.get("spec"), "rendered.defaultDenyIngress.spec", errors
        )
        if default_spec != {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [],
        }:
            errors.append("application default-deny ingress policy must be exact")

    expected: dict[
        str,
        tuple[
            str,
            list[dict[str, object]] | None,
            list[dict[str, object]],
            list[str],
        ],
    ] = {
        "console": (
            "hallu-defense-console-egress",
            [
                external_ingress_rule(
                    HELM_RELEASE_NAMESPACE if kind_profile else "ingress-system",
                    (
                        "hallu-defense.openai.com/network-client"
                        if kind_profile
                        else "app.kubernetes.io/name"
                    ),
                    "console" if kind_profile else "ingress-nginx",
                    3000,
                )
            ],
            (
                [dns_rule]
                if kind_profile
                else [dns_rule, ip_rule("198.51.100.20/32", 443)]
            ),
            ["Ingress", "Egress"],
        ),
    }
    if kind_profile:
        expected.update(
            {
                "api": (
                    "hallu-defense-api-egress",
                    [
                        external_ingress_rule(
                            HELM_RELEASE_NAMESPACE,
                            "hallu-defense.openai.com/network-client",
                            "api",
                            8000,
                        ),
                        external_ingress_rule(
                            HELM_RELEASE_NAMESPACE,
                            "hallu-defense.openai.com/network-client",
                            "metrics",
                            8000,
                        ),
                    ],
                    [
                        dns_rule,
                        pod_rule("pgvector", 5432),
                        pod_rule("vault", 8200),
                        pod_rule("redis", 6379),
                        pod_rule("opensearch", 9200),
                        ip_rule("10.96.0.1/32", 443),
                    ],
                    ["Ingress", "Egress"],
                ),
                "worker": (
                    "hallu-defense-worker-egress",
                    [
                        external_ingress_rule(
                            HELM_RELEASE_NAMESPACE,
                            "hallu-defense.openai.com/network-client",
                            "metrics",
                            9090,
                        )
                    ],
                    [
                        dns_rule,
                        pod_rule("pgvector", 5432),
                        pod_rule("vault", 8200),
                        pod_rule("opensearch", 9200),
                    ],
                    ["Ingress", "Egress"],
                ),
                "migrations": (
                    "hallu-defense-migrations-egress",
                    None,
                    [dns_rule, pod_rule("pgvector", 5432)],
                    ["Egress"],
                ),
                "vault-bootstrap": (
                    "hallu-defense-vault-bootstrap-egress",
                    None,
                    [dns_rule, pod_rule("vault", 8200)],
                    ["Egress"],
                ),
                "pgvector": (
                    "hallu-defense-pgvector-egress",
                    [ingress_rule(("api", "worker", "migrations"), 5432)],
                    [],
                    ["Ingress", "Egress"],
                ),
                "opensearch": (
                    "hallu-defense-opensearch-egress",
                    [ingress_rule(("api", "worker"), 9200)],
                    [],
                    ["Ingress", "Egress"],
                ),
                "vault": (
                    "hallu-defense-vault-egress",
                    [ingress_rule(("api", "worker", "vault-bootstrap", "redis"), 8200)],
                    [],
                    ["Ingress", "Egress"],
                ),
                "redis": (
                    "hallu-defense-redis",
                    [ingress_rule(("api",), 6379)],
                    [dns_rule, pod_rule("vault", 8200)],
                    ["Ingress", "Egress"],
                ),
            }
        )
    else:
        expected.update(
            {
                "api": (
                    "hallu-defense-api-egress",
                    [
                        external_ingress_rule(
                            "ingress-system",
                            "app.kubernetes.io/name",
                            "ingress-nginx",
                            8000,
                        ),
                        external_ingress_rule(
                            "observability",
                            "app.kubernetes.io/name",
                            "prometheus",
                            8000,
                        ),
                    ],
                    [
                        dns_rule,
                        ip_rule("192.0.2.10/32", 443),
                        ip_rule("198.51.100.10/32", 443),
                        ip_rule("198.51.100.11/32", 5432),
                        ip_rule("198.51.100.12/32", 6379),
                    ],
                    ["Ingress", "Egress"],
                ),
                "worker": (
                    "hallu-defense-worker-egress",
                    [
                        external_ingress_rule(
                            "observability",
                            "app.kubernetes.io/name",
                            "prometheus",
                            9090,
                        )
                    ],
                    [
                        dns_rule,
                        ip_rule("203.0.113.10/32", 443),
                        ip_rule("203.0.113.11/32", 5432),
                    ],
                    ["Ingress", "Egress"],
                ),
                "migrations": (
                    "hallu-defense-migrations-egress",
                    None,
                    [dns_rule, ip_rule("203.0.113.20/32", 5432)],
                    ["Egress"],
                ),
            }
        )

    for component, (
        policy_name,
        expected_ingress,
        expected_egress,
        expected_policy_types,
    ) in expected.items():
        policy = policies.get(policy_name)
        if policy is None:
            errors.append(f"rendered chart missing {component} egress NetworkPolicy")
            continue
        spec = _mapping(policy.get("spec"), f"rendered.{component}Policy.spec", errors)
        if spec.get("podSelector") != {
            "matchLabels": {
                "app.kubernetes.io/name": "hallu-defense",
                "app.kubernetes.io/instance": "hallu-defense",
                "app.kubernetes.io/component": component,
            }
        }:
            errors.append(f"rendered {component} egress policy selector is not exact")
        if spec.get("policyTypes") != expected_policy_types:
            errors.append(f"rendered {component} policy types are not exact")
        if expected_ingress is None:
            if "ingress" in spec:
                errors.append(f"rendered {component} policy must not isolate Ingress")
        else:
            ingress = _mapping_sequence(
                spec.get("ingress"),
                f"rendered.{component}Policy.ingress",
                errors,
            )
            if ingress != expected_ingress:
                errors.append(
                    f"rendered {component} ingress rules are not the exact allowlist"
                )
        egress = _mapping_sequence(
            spec.get("egress"),
            f"rendered.{component}Policy.egress",
            errors,
        )
        if egress != expected_egress:
            errors.append(
                f"rendered {component} egress rules are not the exact allowlist"
            )


def _validate_rendered_opensearch_bootstrap(
    container: Mapping[str, object],
    *,
    profile: str,
    production: bool,
    errors: list[str],
) -> None:
    environment = _mapping_sequence(
        container.get("env"),
        f"{profile}.opensearchBootstrap.env",
        errors,
    )
    env_by_name = {
        str(item.get("name")): item
        for item in environment
        if isinstance(item.get("name"), str)
    }
    expected_names = {
        "HALLU_DEFENSE_ENV",
        "HALLU_DEFENSE_RUNTIME_ROLE",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "HALLU_DEFENSE_VAULT_ADDR",
        "HALLU_DEFENSE_VAULT_MOUNT",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME",
    }
    if production:
        expected_names.update(
            {
                "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
                "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
            }
        )
        expected_values = {
            "HALLU_DEFENSE_VAULT_ADDR": "https://vault.prod.invalid",
            "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://opensearch.prod.invalid",
            "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": (
                "rag/opensearch/authorization"
            ),
            "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": (
                "/run/hallu-defense/opensearch-ca.pem"
            ),
        }
        expected_mounts = {"bootstrap-secrets", "vault-ca", "opensearch-ca", "tmp"}
    else:
        expected_names.add("HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED")
        expected_values = {
            "HALLU_DEFENSE_VAULT_ADDR": "https://hallu-defense-vault:8200",
            "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "http://hallu-defense-opensearch:9200",
            "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED": "true",
        }
        expected_mounts = {"bootstrap-secrets", "vault-ca", "tmp"}
    expected_values.update(
        {
            "HALLU_DEFENSE_ENV": "production",
            "HALLU_DEFENSE_RUNTIME_ROLE": "opensearch-bootstrap",
            "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
            "HALLU_DEFENSE_VAULT_TOKEN_FILE": (
                "/run/secrets/hallu_defense_vault_token"
            ),
            "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
            "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS": "5",
            "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
        }
    )
    if set(env_by_name) != expected_names:
        errors.append(
            f"{profile} OpenSearch bootstrap environment must contain only bootstrap settings"
        )
    for name, expected in expected_values.items():
        if env_by_name.get(name, {}).get("value") != expected:
            errors.append(f"{profile} OpenSearch bootstrap must set {name}={expected}")
    mounts = _mapping_sequence(
        container.get("volumeMounts"),
        f"{profile}.opensearchBootstrap.volumeMounts",
        errors,
    )
    if {item.get("name") for item in mounts} != expected_mounts:
        errors.append(
            f"{profile} OpenSearch bootstrap must mount only its credential, CA inputs, and scratch"
        )
    if any(
        item.get("readOnly") is not True for item in mounts if item.get("name") != "tmp"
    ):
        errors.append(f"{profile} OpenSearch bootstrap CA mounts must be read-only")


def _validate_rendered_production_sandbox(rendered: str) -> None:
    docs = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, Mapping)]
    errors: list[str] = []
    _validate_rendered_postgres_credentials(
        docs,
        errors,
        kind_profile=False,
    )
    _validate_rendered_application_network_policies(docs, errors, kind_profile=False)
    if any(
        doc.get("kind") == "Deployment"
        and _mapping(doc.get("metadata"), "production.deployment.metadata", errors).get(
            "name"
        )
        == "hallu-defense-redis"
        for doc in docs
    ):
        errors.append("production chart must not deploy the kind Redis dependency")
    for component, expected_image in PRODUCTION_WORKLOAD_DIGESTS.items():
        workload = next(
            (
                doc
                for doc in docs
                if doc.get("kind") in {"Deployment", "Job"}
                and _mapping(
                    _mapping(
                        doc.get("metadata"), "production.workload.metadata", errors
                    ).get("labels"),
                    "production.workload.labels",
                    errors,
                ).get("app.kubernetes.io/component")
                == component
            ),
            None,
        )
        if workload is None:
            errors.append(f"production render missing {component} workload")
            continue
        pod_spec = _rendered_pod_spec(workload, f"production-{component}", errors)
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            f"production.{component}.containers",
            errors,
        )
        if not containers or containers[0].get("image") != expected_image:
            errors.append(f"production {component} must use its immutable image digest")
    console = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "Deployment"
            and _mapping(
                doc.get("metadata"), "production.console.metadata", errors
            ).get("name")
            == "hallu-defense-console"
        ),
        None,
    )
    if console is None:
        errors.append("production render missing Console Deployment")
    else:
        _validate_rendered_console_env(
            console,
            profile="production Console",
            public_origin="https://console.prod.invalid",
            api_origin="https://api.prod.invalid",
            issuer="https://auth.prod.invalid/realms/hallu-defense",
            client_id="hallu-defense-console",
            api_audience="hallu-defense-api",
            errors=errors,
        )
    if any(
        doc.get("kind") in {"PersistentVolume", "PersistentVolumeClaim"} for doc in docs
    ):
        errors.append("production chart must not create workspace PV/PVC resources")
    api = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "Deployment"
            and _mapping(doc.get("metadata"), "production.api.metadata", errors).get(
                "name"
            )
            == "hallu-defense-api"
        ),
        None,
    )
    if api is None:
        errors.append("production render missing API Deployment")
    else:
        pod_spec = _rendered_pod_spec(api, "production-api", errors)
        volumes = _mapping_sequence(
            pod_spec.get("volumes"),
            "production.api.volumes",
            errors,
        )
        workspace = next(
            (item for item in volumes if item.get("name") == "workspace"), None
        )
        if workspace is None or workspace.get("persistentVolumeClaim") != {
            "claimName": "prod-sandbox-rwx-reader"
        }:
            errors.append("production API must mount the app-namespace reader claim")
        init_containers = _mapping_sequence(
            pod_spec.get("initContainers"),
            "production.api.initContainers",
            errors,
        )
        if "prepare-sandbox-fixture" in {item.get("name") for item in init_containers}:
            errors.append("production API must not prepare the kind sandbox fixture")
        api_bootstrap = next(
            (
                item
                for item in init_containers
                if item.get("name") == "bootstrap-opensearch-schema"
            ),
            None,
        )
        if api_bootstrap is None:
            errors.append("production API missing OpenSearch bootstrap init container")
        else:
            _validate_rendered_opensearch_bootstrap(
                api_bootstrap,
                profile="production API",
                production=True,
                errors=errors,
            )
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            "production.api.containers",
            errors,
        )
        if containers:
            volume_mounts = _mapping_sequence(
                containers[0].get("volumeMounts"),
                "production.api.volumeMounts",
                errors,
            )
            workspace_mount = next(
                (item for item in volume_mounts if item.get("name") == "workspace"),
                None,
            )
            if workspace_mount is None or workspace_mount.get("readOnly") is not True:
                errors.append("production API workspace mount must be read-only")
            environment = _mapping_sequence(
                containers[0].get("env"),
                "production.api.env",
                errors,
            )
            env_by_name = {str(item.get("name")): item for item in environment}
            if (
                env_by_name.get("HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE", {}).get(
                    "value"
                )
                != PRODUCTION_SANDBOX_DIGEST
            ):
                errors.append(
                    "production API must use the immutable sandbox image digest"
                )
            if (
                env_by_name.get("HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID", {}).get(
                    "value"
                )
                != "prod-tenant"
            ):
                errors.append("production API must bind the workspace to one tenant")
            if (
                env_by_name.get("HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE", {}).get(
                    "value"
                )
                != "prod-sandbox"
            ):
                errors.append(
                    "production API must target the dedicated sandbox namespace"
                )
            if "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE" in env_by_name:
                errors.append(
                    "production API must not enable the kind-only image exception"
                )
            if (
                env_by_name.get(
                    "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS", {}
                ).get("value")
                != "20"
            ):
                errors.append(
                    "production API must receive the bounded Kubernetes cleanup grace"
                )
            for name, expected in (
                (
                    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
                    "approvals/tool-call-commitment-key",
                ),
                (
                    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID",
                    "approval-active-v1",
                ),
                (
                    "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
                    "/run/hallu-defense/postgres-ca.pem",
                ),
                ("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid"),
                (
                    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
                    "https://opensearch.prod.invalid",
                ),
                (
                    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
                    "rag/opensearch/authorization",
                ),
                (
                    "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
                    "/run/hallu-defense/opensearch-ca.pem",
                ),
            ):
                if env_by_name.get(name, {}).get("value") != expected:
                    errors.append(f"production API must set {name}={expected}")
            if "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED" in env_by_name:
                errors.append("production API must not enable kind OpenSearch HTTP")
            if (
                env_by_name.get(
                    "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
                    {},
                ).get("value")
                != "quotas/tool-validation/redis-url"
            ):
                errors.append("production API must resolve the Redis URL from Vault")
            if "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL" in env_by_name:
                errors.append("production API must not receive a direct Redis URL")
            mounts = _mapping_sequence(
                containers[0].get("volumeMounts"),
                "production.api.volumeMounts",
                errors,
            )
            redis_ca = next(
                (item for item in mounts if item.get("name") == "redis-ca"), None
            )
            if redis_ca is None or redis_ca.get("mountPath") != (
                "/run/hallu-defense/redis-ca.pem"
            ):
                errors.append("production API must mount the managed Redis CA")
            vault_ca = next(
                (item for item in mounts if item.get("name") == "vault-ca"), None
            )
            if vault_ca is None or vault_ca.get("mountPath") != (
                "/run/hallu-defense/vault-ca.pem"
            ):
                errors.append("production API must mount the managed Vault CA")
            postgres_ca = next(
                (item for item in mounts if item.get("name") == "postgres-ca"), None
            )
            if postgres_ca is None or postgres_ca.get("mountPath") != (
                "/run/hallu-defense/postgres-ca.pem"
            ):
                errors.append("production API must mount the managed PostgreSQL CA")
            opensearch_ca = next(
                (item for item in mounts if item.get("name") == "opensearch-ca"),
                None,
            )
            if opensearch_ca is None or opensearch_ca.get("mountPath") != (
                "/run/hallu-defense/opensearch-ca.pem"
            ):
                errors.append("production API must mount the configured OpenSearch CA")
        volumes = _mapping_sequence(
            pod_spec.get("volumes"),
            "production.api.volumes",
            errors,
        )
        for name, expected_secret in (
            ("vault-ca", "managed-vault-ca"),
            ("postgres-ca", "managed-postgres-ca"),
            ("redis-ca", "managed-redis-ca"),
            ("opensearch-ca", "managed-opensearch-ca"),
        ):
            volume = next((item for item in volumes if item.get("name") == name), None)
            secret = (
                _mapping(volume.get("secret"), f"production.api.{name}.secret", errors)
                if volume is not None
                else {}
            )
            if (
                secret.get("secretName") != expected_secret
                or secret.get("defaultMode") != 0o440
            ):
                errors.append(
                    f"production API must mount {expected_secret} with mode 0440"
                )
    worker = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "Deployment"
            and _mapping(doc.get("metadata"), "production.worker.metadata", errors).get(
                "name"
            )
            == "hallu-defense-worker"
        ),
        None,
    )
    if worker is None:
        errors.append("production render missing worker Deployment")
    else:
        _validate_rendered_worker_metrics(
            worker,
            profile="production worker",
            errors=errors,
        )
        _validate_rendered_worker_service(
            docs,
            profile="production",
            errors=errors,
        )
        worker_spec = _rendered_pod_spec(worker, "production-worker", errors)
        worker_init_containers = _mapping_sequence(
            worker_spec.get("initContainers"),
            "production.worker.initContainers",
            errors,
        )
        worker_bootstrap = next(
            (
                item
                for item in worker_init_containers
                if item.get("name") == "bootstrap-opensearch-schema"
            ),
            None,
        )
        if worker_bootstrap is None:
            errors.append(
                "production worker missing OpenSearch bootstrap init container"
            )
        else:
            _validate_rendered_opensearch_bootstrap(
                worker_bootstrap,
                profile="production worker",
                production=True,
                errors=errors,
            )
        containers = _mapping_sequence(
            worker_spec.get("containers"),
            "production.worker.containers",
            errors,
        )
        if containers:
            environment = _mapping_sequence(
                containers[0].get("env"),
                "production.worker.env",
                errors,
            )
            env_by_name = {str(item.get("name")): item for item in environment}
            for name, expected in (
                ("HALLU_DEFENSE_SECRETS_BACKEND", "vault"),
                (
                    "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
                    "observability/metrics-scrape-token",
                ),
                (
                    "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
                    "/run/hallu-defense/postgres-ca.pem",
                ),
                ("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid"),
                (
                    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
                    "https://opensearch.prod.invalid",
                ),
                (
                    "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
                    "rag/opensearch/authorization",
                ),
                (
                    "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH",
                    "/run/hallu-defense/opensearch-ca.pem",
                ),
            ):
                if env_by_name.get(name, {}).get("value") != expected:
                    errors.append(f"production worker must set {name}={expected}")
            mounts = _mapping_sequence(
                containers[0].get("volumeMounts"),
                "production.worker.volumeMounts",
                errors,
            )
            for name, path in (
                ("vault-ca", "/run/hallu-defense/vault-ca.pem"),
                ("postgres-ca", "/run/hallu-defense/postgres-ca.pem"),
                ("opensearch-ca", "/run/hallu-defense/opensearch-ca.pem"),
            ):
                mount = next(
                    (item for item in mounts if item.get("name") == name), None
                )
                if (
                    mount is None
                    or mount.get("mountPath") != path
                    or mount.get("readOnly") is not True
                ):
                    errors.append(
                        f"production worker must mount {name} read-only at {path}"
                    )
            readiness = _mapping(
                containers[0].get("readinessProbe"),
                "production.worker.readinessProbe",
                errors,
            )
            readiness_exec = _mapping(
                readiness.get("exec"),
                "production.worker.readinessProbe.exec",
                errors,
            )
            if readiness_exec.get("command") != [
                "python",
                "-m",
                "hallu_defense.worker",
                "--check-ready",
            ]:
                errors.append(
                    "production worker readiness must check PostgreSQL and OpenSearch"
                )
    for kind, name in (
        ("Role", "hallu-defense-api-sandbox"),
        ("RoleBinding", "hallu-defense-api-sandbox"),
        ("NetworkPolicy", "hallu-defense-sandbox-deny-egress"),
    ):
        resource = next(
            (
                doc
                for doc in docs
                if doc.get("kind") == kind
                and _mapping(
                    doc.get("metadata"),
                    f"production.{kind}.metadata",
                    errors,
                ).get("name")
                == name
            ),
            None,
        )
        if (
            resource is None
            or _mapping(
                resource.get("metadata"), f"production.{kind}.metadata", errors
            ).get("namespace")
            != "prod-sandbox"
        ):
            errors.append(f"production {kind} {name} must use prod-sandbox")
    if errors:
        raise HelmChartConfigError("\n".join(errors))


def _rendered_name_for_kind(rendered: str, kind: str) -> str:
    docs = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, Mapping)]
    matches = [doc for doc in docs if doc.get("kind") == kind]
    if len(matches) != 1:
        raise HelmChartConfigError(f"rendered chart must contain exactly one {kind}")
    metadata = matches[0].get("metadata")
    if not isinstance(metadata, Mapping) or not isinstance(metadata.get("name"), str):
        raise HelmChartConfigError(f"rendered {kind} must have a name")
    return str(metadata["name"])


def _validate_rendered_api_and_worker_env(
    workloads: Mapping[str, Mapping[str, object]],
    errors: list[str],
) -> None:
    api = workloads.get("api")
    if api is not None:
        api_spec = _rendered_pod_spec(api, "api", errors)
        api_containers = _mapping_sequence(
            api_spec.get("containers"), "rendered.api.containers", errors
        )
        if api_containers:
            readiness = _mapping(
                api_containers[0].get("readinessProbe"),
                "rendered.api.readinessProbe",
                errors,
            )
            http_get = _mapping(
                readiness.get("httpGet"), "rendered.api.readinessProbe.httpGet", errors
            )
            if http_get.get("path") != "/ready":
                errors.append("rendered API readinessProbe must use /ready")
            api_environment = _mapping_sequence(
                api_containers[0].get("env"),
                "rendered.api.env",
                errors,
            )
            api_env_by_name = {
                str(item.get("name")): item
                for item in api_environment
                if isinstance(item.get("name"), str)
            }
            if (
                api_env_by_name.get("HALLU_DEFENSE_OTEL_ENABLED", {}).get("value")
                != "false"
            ):
                errors.append("rendered kind API must disable OTLP without a collector")
            for name, expected in (
                (
                    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME",
                    "approvals/tool-call-commitment-key",
                ),
                (
                    "HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID",
                    "approval-active-v1",
                ),
                (
                    "HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
                    "audit/request-commitment-key",
                ),
                ("HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED", "true"),
                ("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid"),
                (
                    "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
                    "http://hallu-defense-opensearch:9200",
                ),
                ("HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED", "true"),
            ):
                if api_env_by_name.get(name, {}).get("value") != expected:
                    errors.append(f"rendered kind API must set {name}={expected}")
            if "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME" in api_env_by_name:
                errors.append(
                    "rendered kind API must not receive OpenSearch credentials"
                )
            for forbidden_name in (
                "HALLU_DEFENSE_OTEL_EXPORTER",
                "HALLU_DEFENSE_OTEL_ENDPOINT",
            ):
                if forbidden_name in api_env_by_name:
                    errors.append(
                        f"rendered kind API must not configure {forbidden_name} without a collector"
                    )
    worker = workloads.get("worker")
    if worker is None:
        return
    _validate_rendered_worker_metrics(
        worker,
        profile="rendered kind worker",
        errors=errors,
    )
    worker_spec = _rendered_pod_spec(worker, "worker", errors)
    worker_containers = _mapping_sequence(
        worker_spec.get("containers"),
        "rendered.worker.containers",
        errors,
    )
    if not worker_containers:
        return
    environment = _mapping_sequence(
        worker_containers[0].get("env"),
        "rendered.worker.env",
        errors,
    )
    env_by_name = {
        str(item.get("name")): item
        for item in environment
        if isinstance(item.get("name"), str)
    }
    expected_names = {
        "HALLU_DEFENSE_ENV",
        "HALLU_DEFENSE_RUNTIME_ROLE",
        "HALLU_DEFENSE_SECRETS_BACKEND",
        "HALLU_DEFENSE_VAULT_ADDR",
        "HALLU_DEFENSE_VAULT_MOUNT",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE",
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH",
        "HALLU_DEFENSE_POSTGRES_DSN_FILE",
        "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
        "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED",
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND",
        "HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
        "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND",
        "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME",
        "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED",
        "HALLU_DEFENSE_INGESTION_MODE",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "HALLU_DEFENSE_INGESTION_WORKER_ID",
    }
    if set(env_by_name) != expected_names:
        errors.append(
            "rendered worker environment must contain only worker-required settings"
        )
    for name, expected in (
        ("HALLU_DEFENSE_SECRETS_BACKEND", "vault"),
        ("HALLU_DEFENSE_VAULT_ADDR", "https://hallu-defense-vault:8200"),
        (
            "HALLU_DEFENSE_VAULT_TOKEN_FILE",
            "/run/secrets/hallu_defense_vault_token",
        ),
        (
            "HALLU_DEFENSE_POSTGRES_DSN_FILE",
            "/run/secrets/hallu_defense_postgres_dsn",
        ),
        (
            "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
            "observability/metrics-scrape-token",
        ),
        ("HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED", "true"),
        (
            "HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME",
            "audit/request-commitment-key",
        ),
        ("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid"),
        ("HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS", "5"),
        ("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://hallu-defense-opensearch:9200"),
        ("HALLU_DEFENSE_OPENSEARCH_INDEX_NAME", "hallu_evidence"),
        ("HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED", "true"),
    ):
        if env_by_name.get(name, {}).get("value") != expected:
            errors.append(f"rendered kind worker must set {name}={expected}")
    expected_outbound = (
        "https://hallu-defense-vault:8200,https://auth.kind.invalid,"
        "https://llm-gateway.kind.invalid"
    )
    if (
        env_by_name.get("HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS", {}).get("value")
        != expected_outbound
    ):
        errors.append(
            "rendered worker must use the exact kind outbound HTTPS allowlist"
        )
    worker_id = env_by_name.get("HALLU_DEFENSE_INGESTION_WORKER_ID", {})
    value_from = _mapping(
        worker_id.get("valueFrom"), "rendered.worker.workerId.valueFrom", errors
    )
    field_ref = _mapping(
        value_from.get("fieldRef"), "rendered.worker.workerId.fieldRef", errors
    )
    if field_ref.get("fieldPath") != "metadata.uid":
        errors.append("rendered worker ID must come from metadata.uid")
    volume_mounts = _mapping_sequence(
        worker_containers[0].get("volumeMounts"),
        "rendered.worker.volumeMounts",
        errors,
    )
    mount_names = {item.get("name") for item in volume_mounts}
    if "vault-ca" not in mount_names:
        errors.append("rendered worker must mount the Vault CA for SecretManager")
    if "keycloak-jwks" in mount_names or "opensearch-ca" in mount_names:
        errors.append(
            "rendered kind worker must not mount API JWKS or a managed OpenSearch CA"
        )
    readiness = _mapping(
        worker_containers[0].get("readinessProbe"),
        "rendered.worker.readinessProbe",
        errors,
    )
    readiness_exec = _mapping(
        readiness.get("exec"),
        "rendered.worker.readinessProbe.exec",
        errors,
    )
    if readiness_exec.get("command") != [
        "python",
        "-m",
        "hallu_defense.worker",
        "--check-ready",
    ]:
        errors.append(
            "rendered worker readinessProbe must invoke the exact dependency CLI"
        )
    worker_init_containers = _mapping_sequence(
        worker_spec.get("initContainers"),
        "rendered.worker.initContainers",
        errors,
    )
    worker_bootstrap = next(
        (
            item
            for item in worker_init_containers
            if item.get("name") == "bootstrap-opensearch-schema"
        ),
        None,
    )
    if worker_bootstrap is None:
        errors.append(
            "rendered kind worker missing OpenSearch schema bootstrap init container"
        )
    else:
        _validate_rendered_opensearch_bootstrap(
            worker_bootstrap,
            profile="rendered kind worker",
            production=False,
            errors=errors,
        )


def _validate_rendered_worker_metrics(
    workload: Mapping[str, object],
    *,
    profile: str,
    errors: list[str],
) -> None:
    pod_spec = _rendered_pod_spec(workload, profile, errors)
    containers = _mapping_sequence(
        pod_spec.get("containers"), f"{profile}.containers", errors
    )
    if containers and containers[0].get("ports") != [
        {"name": "metrics", "containerPort": 9090, "protocol": "TCP"}
    ]:
        errors.append(f"{profile} must expose only authenticated metrics port 9090")
    workload_spec = _mapping(workload.get("spec"), f"{profile}.spec", errors)
    template = _mapping(workload_spec.get("template"), f"{profile}.template", errors)
    metadata = _mapping(template.get("metadata"), f"{profile}.metadata", errors)
    if metadata.get("annotations") != {
        "prometheus.io/scrape": "true",
        "prometheus.io/path": "/metrics",
        "prometheus.io/port": "9090",
    }:
        errors.append(f"{profile} must publish exact Prometheus pod annotations")


def _validate_rendered_worker_service(
    docs: Sequence[Mapping[str, object]],
    *,
    profile: str,
    errors: list[str],
) -> None:
    services = [
        doc
        for doc in docs
        if doc.get("kind") == "Service"
        and _mapping(
            _mapping(doc.get("metadata"), f"{profile}.workerService.metadata", errors).get(
                "labels"
            ),
            f"{profile}.workerService.labels",
            errors,
        ).get("app.kubernetes.io/component")
        == "worker"
    ]
    if len(services) != 1:
        errors.append(f"{profile} must render exactly one worker metrics Service")
        return
    service = services[0]
    metadata = _mapping(
        service.get("metadata"), f"{profile}.workerService.metadata", errors
    )
    if metadata.get("name") != "hallu-defense-worker":
        errors.append(f"{profile} worker metrics Service must use the worker DNS name")
    spec = _mapping(service.get("spec"), f"{profile}.workerService.spec", errors)
    if spec.get("type") != "ClusterIP" or spec.get("sessionAffinity") != "None":
        errors.append(f"{profile} worker metrics Service must be an internal ClusterIP")
    if spec.get("selector") != {
        "app.kubernetes.io/name": "hallu-defense",
        "app.kubernetes.io/instance": "hallu-defense",
        "app.kubernetes.io/component": "worker",
    }:
        errors.append(f"{profile} worker metrics Service selector must target only worker Pods")
    if spec.get("ports") != [
        {
            "name": "metrics",
            "protocol": "TCP",
            "port": 9090,
            "targetPort": "metrics",
        }
    ]:
        errors.append(f"{profile} worker metrics Service must expose only port 9090")


def _validate_rendered_sandbox(
    docs: Sequence[Mapping[str, object]],
    workloads: Mapping[str, Mapping[str, object]],
    errors: list[str],
) -> None:
    def resources(kind: str) -> list[Mapping[str, object]]:
        return [doc for doc in docs if doc.get("kind") == kind]

    service_accounts = resources("ServiceAccount")
    api_service_account = next(
        (
            item
            for item in service_accounts
            if _mapping(
                item.get("metadata"), "rendered.serviceAccount.metadata", errors
            ).get("name")
            == "hallu-defense-api"
        ),
        None,
    )
    if api_service_account is None:
        errors.append("rendered chart missing the dedicated API ServiceAccount")
    else:
        service_account_metadata = _mapping(
            api_service_account.get("metadata"),
            "rendered.serviceAccount.metadata",
            errors,
        )
        if service_account_metadata.get("namespace") != HELM_RELEASE_NAMESPACE:
            errors.append(
                "rendered API ServiceAccount must remain in the application namespace"
            )
        if api_service_account.get("automountServiceAccountToken") is not False:
            errors.append(
                "rendered API ServiceAccount must disable automatic token mounts"
            )

    roles = resources("Role")
    sandbox_role = next(
        (
            item
            for item in roles
            if _mapping(item.get("metadata"), "rendered.role.metadata", errors).get(
                "name"
            )
            == "hallu-defense-api-sandbox"
        ),
        None,
    )
    expected_rules = [
        {
            "apiGroups": ["batch"],
            "resources": ["jobs"],
            "verbs": ["create", "get", "delete"],
        },
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
        {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
        {
            "apiGroups": ["networking.k8s.io"],
            "resources": ["networkpolicies"],
            "verbs": ["list"],
        },
    ]
    if sandbox_role is None or sandbox_role.get("rules") != expected_rules:
        errors.append(
            "rendered sandbox Role must contain only the exact least-privilege rules"
        )
    elif (
        _mapping(sandbox_role.get("metadata"), "rendered.role.metadata", errors).get(
            "namespace"
        )
        != "hallu-defense-sandbox"
    ):
        errors.append(
            "rendered sandbox Role must be in the dedicated sandbox namespace"
        )

    role_bindings = resources("RoleBinding")
    sandbox_binding = next(
        (
            item
            for item in role_bindings
            if _mapping(
                item.get("metadata"), "rendered.roleBinding.metadata", errors
            ).get("name")
            == "hallu-defense-api-sandbox"
        ),
        None,
    )
    expected_subjects = [
        {
            "kind": "ServiceAccount",
            "name": "hallu-defense-api",
            "namespace": HELM_RELEASE_NAMESPACE,
        }
    ]
    if sandbox_binding is None:
        errors.append("rendered chart missing sandbox RoleBinding")
    else:
        if (
            _mapping(
                sandbox_binding.get("metadata"),
                "rendered.roleBinding.metadata",
                errors,
            ).get("namespace")
            != "hallu-defense-sandbox"
        ):
            errors.append(
                "rendered sandbox RoleBinding must be in the dedicated sandbox namespace"
            )
        if sandbox_binding.get("subjects") != expected_subjects:
            errors.append(
                "rendered sandbox RoleBinding must bind only the API ServiceAccount"
            )
        if sandbox_binding.get("roleRef") != {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "hallu-defense-api-sandbox",
        }:
            errors.append(
                "rendered sandbox RoleBinding must reference the sandbox Role"
            )

    policies = resources("NetworkPolicy")
    sandbox_network_policy = next(
        (
            item
            for item in policies
            if _mapping(
                item.get("metadata"), "rendered.networkPolicy.metadata", errors
            ).get("name")
            == "hallu-defense-sandbox-deny-egress"
        ),
        None,
    )
    expected_policy_spec = {
        "podSelector": {
            "matchLabels": {"hallu-defense.openai.com/network-policy": "deny-egress"}
        },
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": [],
    }
    if (
        sandbox_network_policy is None
        or sandbox_network_policy.get("spec") != expected_policy_spec
    ):
        errors.append("rendered sandbox NetworkPolicy must deny all ingress and egress")
    elif (
        _mapping(
            sandbox_network_policy.get("metadata"),
            "rendered.sandboxNetworkPolicy.metadata",
            errors,
        ).get("namespace")
        != "hallu-defense-sandbox"
    ):
        errors.append("rendered sandbox NetworkPolicy must use the sandbox namespace")

    claims = resources("PersistentVolumeClaim")
    sandbox_claim = next(
        (
            item
            for item in claims
            if _mapping(item.get("metadata"), "rendered.pvc.metadata", errors).get(
                "name"
            )
            == "hallu-defense-sandbox-workspace"
        ),
        None,
    )
    if sandbox_claim is None:
        errors.append("rendered kind chart missing its isolated sandbox PVC")
    else:
        if (
            _mapping(
                sandbox_claim.get("metadata"), "rendered.sandboxPvc.metadata", errors
            ).get("namespace")
            != "hallu-defense-sandbox"
        ):
            errors.append(
                "rendered sandbox runner PVC must be in the sandbox namespace"
            )
        claim_spec = _mapping(
            sandbox_claim.get("spec"), "rendered.sandboxPvc.spec", errors
        )
        if claim_spec.get("accessModes") != ["ReadWriteOnce"]:
            errors.append("rendered kind sandbox PVC must use ReadWriteOnce")
    reader_claim = next(
        (
            item
            for item in claims
            if _mapping(
                item.get("metadata"), "rendered.readerPvc.metadata", errors
            ).get("name")
            == "hallu-defense-sandbox-workspace-reader"
        ),
        None,
    )
    if reader_claim is None:
        errors.append("rendered kind chart missing its API reader PVC")
    elif (
        _mapping(
            reader_claim.get("metadata"), "rendered.readerPvc.metadata", errors
        ).get("namespace")
        != HELM_RELEASE_NAMESPACE
    ):
        errors.append(
            "rendered API reader PVC must remain in the application namespace"
        )
    persistent_volumes = resources("PersistentVolume")
    if len(persistent_volumes) != 2:
        errors.append(
            "rendered kind chart must create two namespaced workspace PV views"
        )
    else:
        host_paths = {
            str(
                _mapping(
                    _mapping(volume.get("spec"), "rendered.pv.spec", errors).get(
                        "hostPath"
                    ),
                    "rendered.pv.hostPath",
                    errors,
                ).get("path")
            )
            for volume in persistent_volumes
        }
        if len(host_paths) != 1 or not next(iter(host_paths)).startswith(
            "/var/local/hallu-defense-sandbox/"
        ):
            errors.append(
                "rendered kind PV views must share one isolated hostPath backend"
            )

    admission_policies = resources("ValidatingAdmissionPolicy")
    admission_bindings = resources("ValidatingAdmissionPolicyBinding")
    if len(admission_policies) != 1 or len(admission_bindings) != 1:
        errors.append(
            "rendered chart must contain one sandbox admission policy and binding"
        )
    else:
        admission_policy = admission_policies[0]
        admission_binding = admission_bindings[0]
        policy_metadata = _mapping(
            admission_policy.get("metadata"),
            "rendered.admissionPolicy.metadata",
            errors,
        )
        binding_metadata = _mapping(
            admission_binding.get("metadata"),
            "rendered.admissionBinding.metadata",
            errors,
        )
        policy_name = policy_metadata.get("name")
        if (
            not isinstance(policy_name, str)
            or not policy_name.startswith("hallu-defense-sandbox-jobs-")
            or len(policy_name.rsplit("-", 1)[-1]) != 8
        ):
            errors.append(
                "rendered admission policy name must include the namespace hash"
            )
        if binding_metadata.get("name") != policy_name:
            errors.append("rendered admission policy and binding names must match")
        admission_spec = _mapping(
            admission_policy.get("spec"),
            "rendered.admissionPolicy.spec",
            errors,
        )
        if admission_spec.get("failurePolicy") != "Fail":
            errors.append("rendered sandbox admission policy must fail closed")
        if "matchConditions" in admission_spec:
            errors.append(
                "rendered sandbox admission identity must not use bypassable matchConditions"
            )
        if "matchPolicy" in admission_spec:
            errors.append(
                "rendered admission matchPolicy must not use the invalid spec root"
            )
        match_constraints = _mapping(
            admission_spec.get("matchConstraints"),
            "rendered.admissionPolicy.matchConstraints",
            errors,
        )
        if match_constraints.get("matchPolicy") != "Equivalent":
            errors.append(
                "rendered admission matchConstraints must use Equivalent matching"
            )
        if match_constraints.get("namespaceSelector") != {
            "matchLabels": {"kubernetes.io/metadata.name": "hallu-defense-sandbox"}
        }:
            errors.append(
                "rendered admission policy must select only the sandbox namespace"
            )
        validations = _mapping_sequence(
            admission_spec.get("validations"),
            "rendered.admissionPolicy.validations",
            errors,
        )
        expressions = "\n".join(str(item.get("expression", "")) for item in validations)
        expected_creator = (
            f"system:serviceaccount:{HELM_RELEASE_NAMESPACE}:hallu-defense-api"
        )
        identity_validations = [
            item
            for item in validations
            if expected_creator in str(item.get("expression", ""))
            and "request.userInfo.username" in str(item.get("expression", ""))
        ]
        if (
            len(identity_validations) != 1
            or identity_validations[0].get("reason") != "Forbidden"
        ):
            errors.append(
                "rendered sandbox admission policy must deny every non-API creator"
            )
        for marker in (
            "busybox:latest",
            "hostPath",
        ):
            if marker in expressions:
                errors.append(
                    f"rendered sandbox admission policy unexpectedly allows `{marker}`"
                )
        for marker in (
            "envFrom",
            "valueFrom",
            "volumeMounts.size() == 4",
            "volumes.size() == 4",
            "mountPath == '/hallu-source'",
            "readOnly == true",
            "quantity('512Mi')",
            "args[1] == '50000'",
            "args[2] == '536870912'",
            "procMount",
            "procMount == 'Default'",
            "sysctls",
            "supplementalGroups",
            "finalizers",
            "labels.size() == 6",
            "manualSelector == false",
            "selector.matchLabels.size() == 1",
            "batch.kubernetes.io/controller-uid",
            "/opt/hallu-defense/sandbox_runner.py",
            "quantity('64Mi')",
            "quantity(v.emptyDir.sizeLimit).compareTo(q) == 0",
            "quantity('1Mi')",
            "quantity('16Mi')",
            "request.namespace == 'hallu-defense-sandbox'",
        ):
            if marker not in expressions:
                errors.append(f"rendered sandbox admission policy missing `{marker}`")
        for invalid_quantity_comparison in (
            "c.resources.requests['cpu'] == quantity",
            "c.resources.requests['memory'] == quantity",
            "c.resources.limits['cpu'] == quantity",
            "c.resources.limits['memory'] == quantity",
            "v.emptyDir.sizeLimit in [",
            "v.emptyDir.sizeLimit == quantity",
            "v.emptyDir.sizeLimit >= quantity",
            "v.emptyDir.sizeLimit <= quantity",
        ):
            if invalid_quantity_comparison in expressions:
                errors.append(
                    "rendered admission uses an unconverted dynamic quantity comparison: "
                    f"`{invalid_quantity_comparison}`"
                )
        binding_spec = _mapping(
            admission_binding.get("spec"),
            "rendered.admissionBinding.spec",
            errors,
        )
        if binding_spec.get("policyName") != policy_name or binding_spec.get(
            "validationActions"
        ) != ["Deny"]:
            errors.append("rendered sandbox admission binding must enforce Deny")
        if binding_spec.get("matchResources") != {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "hallu-defense-sandbox"}
            }
        }:
            errors.append(
                "rendered admission binding must target only the sandbox namespace"
            )

    api = workloads.get("api")
    if api is None:
        return
    api_spec = _rendered_pod_spec(api, "api", errors)
    if api_spec.get("serviceAccountName") != "hallu-defense-api":
        errors.append("rendered API must use its dedicated ServiceAccount")
    if api_spec.get("automountServiceAccountToken") is not False:
        errors.append("rendered API must disable automatic ServiceAccount token mounts")
    api_containers = _mapping_sequence(
        api_spec.get("containers"), "rendered.api.containers", errors
    )
    if api_containers:
        api_container = api_containers[0]
        environment = _mapping_sequence(
            api_container.get("env"), "rendered.api.env", errors
        )
        env_by_name = {str(item.get("name")): item for item in environment}
        expected_values = {
            "HALLU_DEFENSE_SANDBOX_BACKEND": "kubernetes",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE": "hallu-defense-sandbox:ci",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE": "hallu-defense-sandbox",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME": "hallu-defense-sandbox-workspace",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH": "/workspace",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME": "hallu-defense-sandbox-deny-egress",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID": "kind-smoke-tenant",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS": "20",
            "HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE": "true",
            "HALLU_DEFENSE_OPA_ENABLED": "true",
            "HALLU_DEFENSE_OPA_PATH": "/usr/local/bin/opa",
            "HALLU_DEFENSE_OPA_POLICY_DIR": "/app/infra/opa/policies",
            "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
                "https://hallu-defense-vault:8200,https://auth.kind.invalid,"
                "https://llm-gateway.kind.invalid"
            ),
        }
        for name, value in expected_values.items():
            if env_by_name.get(name, {}).get("value") != value:
                errors.append(f"rendered API environment must set {name}={value}")
        if any(
            name
            in {
                "HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE",
                "HALLU_DEFENSE_SANDBOX_DOCKER_PATH",
            }
            for name in env_by_name
        ):
            errors.append(
                "rendered Kubernetes API must not configure the Docker sandbox"
            )
        api_mounts = _mapping_sequence(
            api_container.get("volumeMounts"),
            "rendered.api.volumeMounts",
            errors,
        )
        kube_mounts = [
            item for item in api_mounts if item.get("name") == "kube-api-access"
        ]
        if kube_mounts != [
            {
                "name": "kube-api-access",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": True,
            }
        ]:
            errors.append(
                "rendered API container must be the sole explicit token consumer"
            )
        for name, path in (
            ("vault-ca", "/run/hallu-defense/vault-ca.pem"),
            ("redis-ca", "/run/hallu-defense/redis-ca.pem"),
        ):
            mount = next(
                (item for item in api_mounts if item.get("name") == name), None
            )
            if (
                mount is None
                or mount.get("mountPath") != path
                or mount.get("readOnly") is not True
            ):
                errors.append(f"rendered API must mount {name} read-only at {path}")
        workspace_mount = next(
            (item for item in api_mounts if item.get("name") == "workspace"), None
        )
        if workspace_mount != {
            "name": "workspace",
            "mountPath": "/workspace",
            "readOnly": True,
        }:
            errors.append("rendered API workspace view must be mounted read-only")
    api_volumes = _mapping_sequence(
        api_spec.get("volumes"), "rendered.api.volumes", errors
    )
    kube_volume = next(
        (item for item in api_volumes if item.get("name") == "kube-api-access"),
        None,
    )
    projected = (
        _mapping(
            kube_volume.get("projected"), "rendered.api.kubeToken.projected", errors
        )
        if kube_volume is not None
        else {}
    )
    if projected.get("defaultMode") != 0o440:
        errors.append("rendered API projected token must use mode 0440")
    projected_sources = _mapping_sequence(
        projected.get("sources"),
        "rendered.api.kubeToken.sources",
        errors,
    )
    token_sources = [
        _mapping(
            source.get("serviceAccountToken"), "rendered.api.kubeToken.source", errors
        )
        for source in projected_sources
        if "serviceAccountToken" in source
    ]
    if token_sources != [{"expirationSeconds": 3600, "path": "token"}]:
        errors.append(
            "rendered API must project one hourly-rotated ServiceAccount token"
        )
    api_pod_security = _mapping(
        api_spec.get("securityContext"),
        "rendered.api.securityContext",
        errors,
    )
    if (
        api_pod_security.get("runAsUser") != 10001
        or api_pod_security.get("fsGroup") != 10001
    ):
        errors.append("rendered API token reader must run non-root in fsGroup 10001")
    for name in ("vault-ca", "redis-ca"):
        volume = next((item for item in api_volumes if item.get("name") == name), None)
        secret = (
            _mapping(volume.get("secret"), f"rendered.api.{name}.secret", errors)
            if volume is not None
            else {}
        )
        if secret.get("defaultMode") != 0o440:
            errors.append(f"rendered API {name} must be mode 0440 for non-root access")
    workspace_volume = next(
        (item for item in api_volumes if item.get("name") == "workspace"), None
    )
    if workspace_volume is None or workspace_volume.get("persistentVolumeClaim") != {
        "claimName": "hallu-defense-sandbox-workspace-reader"
    }:
        errors.append(
            "rendered API must use only its application-namespace reader claim"
        )
    init_containers = _mapping_sequence(
        api_spec.get("initContainers"),
        "rendered.api.initContainers",
        errors,
    )
    if "prepare-sandbox-fixture" in {item.get("name") for item in init_containers}:
        errors.append(
            "rendered API must not mutate the sandbox workspace during startup"
        )
    bootstrap_init = next(
        (
            item
            for item in init_containers
            if item.get("name") == "bootstrap-opensearch-schema"
        ),
        None,
    )
    if bootstrap_init is None:
        errors.append(
            "rendered kind API missing OpenSearch schema bootstrap init container"
        )
    else:
        _validate_rendered_opensearch_bootstrap(
            bootstrap_init,
            profile="rendered kind API",
            production=False,
            errors=errors,
        )
    fixture_jobs = [
        doc
        for doc in docs
        if doc.get("kind") == "Job"
        and _mapping(doc.get("metadata"), "rendered.fixture.metadata", errors).get(
            "labels"
        )
        and _mapping(
            _mapping(doc.get("metadata"), "rendered.fixture.metadata", errors).get(
                "labels"
            ),
            "rendered.fixture.labels",
            errors,
        ).get("app.kubernetes.io/component")
        == "sandbox-fixture"
    ]
    if len(fixture_jobs) != 1:
        errors.append("rendered kind chart must prepare the fixture in one sandbox Job")
    else:
        fixture = fixture_jobs[0]
        if (
            _mapping(fixture.get("metadata"), "rendered.fixture.metadata", errors).get(
                "namespace"
            )
            != "hallu-defense-sandbox"
        ):
            errors.append("rendered fixture Job must run in the sandbox namespace")
        fixture_spec = _rendered_pod_spec(fixture, "sandbox-fixture", errors)
        fixture_volumes = _mapping_sequence(
            fixture_spec.get("volumes"), "rendered.fixture.volumes", errors
        )
        fixture_workspace = next(
            (item for item in fixture_volumes if item.get("name") == "workspace"),
            None,
        )
        if fixture_workspace is None or fixture_workspace.get(
            "persistentVolumeClaim"
        ) != {"claimName": "hallu-defense-sandbox-workspace"}:
            errors.append("rendered fixture Job must use the sandbox runner claim")
    for container in init_containers:
        mounts = _mapping_sequence(
            container.get("volumeMounts", []),
            "rendered.api.initContainer.volumeMounts",
            errors,
        )
        if any(item.get("name") == "kube-api-access" for item in mounts):
            errors.append(
                "rendered API init containers must not receive the Kubernetes token"
            )

    for component in (
        "console",
        "worker",
        "migrations",
        "vault",
        "vault-bootstrap",
        "pgvector",
        "opensearch",
    ):
        workload = workloads.get(component)
        if workload is None:
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        if pod_spec.get("automountServiceAccountToken") is not False:
            errors.append(
                f"rendered {component} must disable ServiceAccount token automount"
            )
        if "serviceAccountName" in pod_spec:
            errors.append(f"rendered {component} must not use the API ServiceAccount")

    for component in (
        "api",
        "console",
        "worker",
        "migrations",
        "vault",
        "vault-bootstrap",
    ):
        workload = workloads.get(component)
        if workload is None:
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        volumes = _mapping_sequence(
            pod_spec.get("volumes"),
            f"rendered.{component}.volumes",
            errors,
        )
        tmp_volume = next((item for item in volumes if item.get("name") == "tmp"), None)
        tmp_empty_dir = (
            _mapping(tmp_volume.get("emptyDir"), f"rendered.{component}.tmp", errors)
            if tmp_volume is not None
            else {}
        )
        if tmp_empty_dir.get("sizeLimit") != "64Mi":
            errors.append(f"rendered {component} /tmp emptyDir must be bounded to 64Mi")


def _validate_rendered_redis(
    docs: Sequence[Mapping[str, object]],
    workloads: Mapping[str, Mapping[str, object]],
    errors: list[str],
) -> None:
    redis = workloads.get("redis")
    if redis is None:
        errors.append("rendered kind chart missing Redis Deployment")
        return
    pod_spec = _rendered_pod_spec(redis, "redis", errors)
    if pod_spec.get("automountServiceAccountToken") is not False:
        errors.append("rendered Redis must disable ServiceAccount token automount")
    containers = _mapping_sequence(
        pod_spec.get("containers"),
        "rendered.redis.containers",
        errors,
    )
    if [item.get("name") for item in containers] != ["redis-guard"]:
        errors.append("rendered Redis main container must be the credential-free guard")
    elif containers:
        guard_mounts = _mapping_sequence(
            containers[0].get("volumeMounts"),
            "rendered.redis.guard.volumeMounts",
            errors,
        )
        if {item.get("name") for item in guard_mounts} != {"redis-status", "tmp"}:
            errors.append(
                "rendered Redis guard must not mount auth, Vault, or TLS material"
            )

    init_containers = _mapping_sequence(
        pod_spec.get("initContainers"),
        "rendered.redis.initContainers",
        errors,
    )
    expected_names = ["generate-redis-auth", "redis", "seed-redis-url-in-vault"]
    if [item.get("name") for item in init_containers] != expected_names:
        errors.append("rendered Redis native-sidecar init ordering is invalid")
        return
    generator, redis_server, seeder = init_containers
    if redis_server.get("restartPolicy") != "Always":
        errors.append("rendered Redis server must be a native sidecar")
    if redis_server.get("image") != (
        "redis:7-alpine@sha256:"
        "6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    ):
        errors.append("rendered Redis server image must use the verified digest")
    for item, label in (
        (generator, "generator"),
        (redis_server, "server"),
        (seeder, "seeder"),
    ):
        security = _mapping(
            item.get("securityContext"),
            f"rendered.redis.{label}.securityContext",
            errors,
        )
        if (
            security.get("runAsNonRoot") is not True
            or security.get("readOnlyRootFilesystem") is not True
        ):
            errors.append(
                f"rendered Redis {label} must run non-root with read-only root"
            )
        resources = _mapping(
            item.get("resources"),
            f"rendered.redis.{label}.resources",
            errors,
        )
        _mapping(resources.get("requests"), f"rendered.redis.{label}.requests", errors)
        _mapping(resources.get("limits"), f"rendered.redis.{label}.limits", errors)
    redis_mounts = _mapping_sequence(
        redis_server.get("volumeMounts"),
        "rendered.redis.server.volumeMounts",
        errors,
    )
    if {item.get("name") for item in redis_mounts} != {
        "redis-auth",
        "redis-tls",
        "tmp",
    }:
        errors.append("rendered Redis server must be the only TLS-key consumer")
    for item in (generator, seeder, *containers):
        mounts = _mapping_sequence(
            item.get("volumeMounts"),
            "rendered.redis.nonServer.volumeMounts",
            errors,
        )
        if any(mount.get("name") == "redis-tls" for mount in mounts):
            errors.append("only the Redis server may mount its TLS key")
    volumes = _mapping_sequence(
        pod_spec.get("volumes"), "rendered.redis.volumes", errors
    )
    expected_secret_names = {
        "redis-tls": "hallu-defense-kind-redis-tls",
        "kind-vault": "hallu-defense-kind-vault",
    }
    for name, expected_secret_name in expected_secret_names.items():
        volume = next((item for item in volumes if item.get("name") == name), None)
        if volume is None:
            errors.append(f"rendered Redis missing {name} Secret volume")
            continue
        secret = _mapping(
            volume.get("secret"),
            f"rendered.redis.{name}.secret",
            errors,
        )
        if secret.get("defaultMode") != 0o440:
            errors.append(
                f"rendered Redis {name} must be group-readable by non-root uid"
            )
        if secret.get("secretName") != expected_secret_name:
            errors.append(
                f"rendered Redis {name} must reference precreated Secret {expected_secret_name}"
            )

    redis_policy = next(
        (
            doc
            for doc in docs
            if doc.get("kind") == "NetworkPolicy"
            and _mapping(
                doc.get("metadata"), "rendered.redisPolicy.metadata", errors
            ).get("name")
            == "hallu-defense-redis"
        ),
        None,
    )
    if redis_policy is None:
        errors.append("rendered kind Redis missing ingress/egress NetworkPolicy")
    else:
        policy_spec = _mapping(
            redis_policy.get("spec"), "rendered.redisPolicy.spec", errors
        )
        if policy_spec.get("policyTypes") != ["Ingress", "Egress"]:
            errors.append(
                "rendered Redis NetworkPolicy must isolate ingress and egress"
            )
        policy_text = str(policy_spec)
        for marker in ("api", "6379", "kube-system", "kube-dns", "vault", "8200"):
            if marker not in policy_text:
                errors.append(f"rendered Redis NetworkPolicy missing `{marker}`")


def _validate_rendered_images(
    workloads: Mapping[str, Mapping[str, object]],
    errors: list[str],
) -> None:
    expected_images = {
        "api": "hallu-defense-api:ci",
        "console": "hallu-defense-console:ci",
        "worker": "hallu-defense-api:ci",
        "migrations": "hallu-defense-api:ci",
        "vault": "hallu-defense-vault:ci",
        "pgvector": "hallu-defense-pgvector:ci",
        "opensearch": "hallu-defense-opensearch:ci",
        "vault-bootstrap": "hallu-defense-api:ci",
        "redis": "hallu-defense-api:ci",
    }
    for component, expected_image in expected_images.items():
        workload = workloads.get(component)
        if workload is None:
            continue
        pod_spec = _rendered_pod_spec(workload, component, errors)
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            f"rendered.{component}.containers",
            errors,
        )
        if not containers or containers[0].get("image") != expected_image:
            errors.append(f"rendered {component} must use image {expected_image}")
    opensearch = workloads.get("opensearch")
    if opensearch is not None:
        pod_spec = _rendered_pod_spec(opensearch, "opensearch", errors)
        containers = _mapping_sequence(
            pod_spec.get("containers"),
            "rendered.opensearch.containers",
            errors,
        )
        if containers:
            environment = _mapping_sequence(
                containers[0].get("env"),
                "rendered.opensearch.env",
                errors,
            )
            environment_by_name = {
                str(item.get("name")): item.get("value") for item in environment
            }
            expected_environment = {
                "discovery.type": "single-node",
                "transport.host": "127.0.0.1",
                "DISABLE_INSTALL_DEMO_CONFIG": "true",
                "DISABLE_SECURITY_PLUGIN": "true",
                "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI": "true",
                "OPENSEARCH_JAVA_OPTS": (
                    "-Xms512m -Xmx512m -Dorg.bouncycastle.native.cpu_variant=java"
                ),
            }
            if environment_by_name != expected_environment:
                errors.append(
                    "rendered core-only OpenSearch environment must be exact and password-free"
                )
            security = _mapping(
                containers[0].get("securityContext"),
                "rendered.opensearch.securityContext",
                errors,
            )
            if security.get("readOnlyRootFilesystem") is not True:
                errors.append(
                    "rendered OpenSearch container must use a read-only root filesystem"
                )
            mounts = _mapping_sequence(
                containers[0].get("volumeMounts"),
                "rendered.opensearch.volumeMounts",
                errors,
            )
            mount_paths = {
                str(item.get("name")): item.get("mountPath") for item in mounts
            }
            if mount_paths != {
                "data": "/usr/share/opensearch/data",
                "tmp": "/tmp",
                "logs": "/usr/share/opensearch/logs",
                "config": "/usr/share/opensearch/config",
            }:
                errors.append(
                    "rendered OpenSearch must mount only data plus dedicated tmp/logs scratch"
                )
        volumes = _mapping_sequence(
            pod_spec.get("volumes"),
            "rendered.opensearch.volumes",
            errors,
        )
        volumes_by_name = {str(item.get("name")): item for item in volumes}
        if set(volumes_by_name) != {"tmp", "logs", "config"}:
            errors.append(
                "rendered OpenSearch must define exactly tmp/logs/config writable volumes"
            )
        for name in ("tmp", "logs"):
            volume = volumes_by_name.get(name)
            empty_dir = _mapping(
                volume.get("emptyDir") if isinstance(volume, Mapping) else None,
                f"rendered.opensearch.{name}.emptyDir",
                errors,
            )
            if empty_dir.get("sizeLimit") != "64Mi":
                errors.append(
                    f"rendered OpenSearch {name} emptyDir must be bounded to 64Mi"
                )
        config_volume = volumes_by_name.get("config")
        config_empty_dir = _mapping(
            config_volume.get("emptyDir")
            if isinstance(config_volume, Mapping)
            else None,
            "rendered.opensearch.config.emptyDir",
            errors,
        )
        if config_empty_dir != {"medium": "Memory", "sizeLimit": "16Mi"}:
            errors.append(
                "rendered OpenSearch config emptyDir must be exact 16Mi Memory storage"
            )
    redis = workloads.get("redis")
    if redis is not None:
        pod_spec = _rendered_pod_spec(redis, "redis", errors)
        init_containers = _mapping_sequence(
            pod_spec.get("initContainers"),
            "rendered.redis.initContainers",
            errors,
        )
        expected_init_images = {
            "generate-redis-auth": "hallu-defense-api:ci",
            "redis": (
                "redis:7-alpine@sha256:"
                "6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
            ),
            "seed-redis-url-in-vault": "hallu-defense-api:ci",
        }
        for container in init_containers:
            container_name = container.get("name")
            if isinstance(container_name, str) and container.get(
                "image"
            ) != expected_init_images.get(container_name):
                errors.append(
                    f"rendered Redis init container {container_name} has an unpinned image"
                )


def _mapping_sequence(
    value: object,
    path: str,
    errors: list[str],
) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        errors.append(f"{path} must be an array")
        return []
    result = [item for item in value if isinstance(item, Mapping)]
    if len(result) != len(value):
        errors.append(f"{path} must contain only objects")
    return result


def _template_definition(template: str, name: str) -> str:
    marker = f'{{{{- define "{name}" -}}}}'
    body = template.partition(marker)[2]
    return body.partition("{{- end -}}")[0] if body else ""


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    phony_line = next(
        (line for line in makefile_text.splitlines() if line.startswith(".PHONY:")), ""
    )
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
        kind_values=load_yaml_file(KIND_VALUES_PATH),
        templates=load_template_texts(),
        api_dockerfile_text=API_DOCKERFILE_PATH.read_text(encoding="utf-8"),
        deployment_doc_text=DEPLOYMENT_DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        live_smoke_text=LIVE_SMOKE_PATH.read_text(encoding="utf-8"),
        prod_compose_text=PROD_COMPOSE_PATH.read_text(encoding="utf-8"),
        config_text=CONFIG_PATH.read_text(encoding="utf-8"),
        api_dependencies_text=API_DEPENDENCIES_PATH.read_text(encoding="utf-8"),
        worker_runtime_text=WORKER_RUNTIME_PATH.read_text(encoding="utf-8"),
        readiness_text=READINESS_PATH.read_text(encoding="utf-8"),
        kind_vault_bootstrap_text=KIND_VAULT_BOOTSTRAP_PATH.read_text(encoding="utf-8"),
        marketing_doc_text=MARKETING_DOC_PATH.read_text(encoding="utf-8"),
    )
    template_result = run_helm_template_if_available()
    suffix = (
        "Helm lint/template skipped because helm is unavailable."
        if template_result["status"] == "skipped"
        else "Helm lint/template passed."
    )
    print("Validated Helm chart scaffold and static deployment invariants. " + suffix)


if __name__ == "__main__":
    main()
