"""Fail-closed kind + Helm deployment smoke for the hallu-defense chart."""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets as secret_generator
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from string import Template
from typing import Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "infra" / "k8s" / "helm" / "hallu-defense"
KIND_VALUES_PATH = CHART_DIR / "values-kind.yaml"
MIGRATIONS_DIR = ROOT / "infra" / "rag" / "pgvector"

ENABLED_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED"
CLUSTER_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_CLUSTER"
NAMESPACE_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_NAMESPACE"
RUN_ID_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_RUN_ID"
DEFAULT_CLUSTER = "hallu-defense-smoke"
DEFAULT_NAMESPACE = "hallu-defense"
DEFAULT_SANDBOX_NAMESPACE = "hallu-defense-sandbox"
RELEASE_NAME = "hallu-defense"
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
EXPECTED_MIGRATION_LEDGER = tuple(EXPECTED_MIGRATION_CHECKSUMS.items())
EXPECTED_MIGRATION_CHECKSUM_AGGREGATE = hashlib.sha256(
    "".join(
        f"{version}\0{checksum}\n" for version, checksum in EXPECTED_MIGRATION_LEDGER
    ).encode("utf-8")
).hexdigest()
EXPECTED_OPENSEARCH_SCHEMA_VERSION = "rag-opensearch-template.v3"
EXPECTED_OPENSEARCH_TEMPLATE_REPLICAS = 1
REQUIRED_TOOLS = ("docker", "kind", "kubectl", "helm")
API_IMAGE = "hallu-defense-api:ci"
CONSOLE_IMAGE = "hallu-defense-console:ci"
SANDBOX_IMAGE = "hallu-defense-sandbox:ci"
PGVECTOR_IMAGE = "hallu-defense-pgvector:ci"
OPENSEARCH_IMAGE = "hallu-defense-opensearch:ci"
VAULT_IMAGE = "hallu-defense-vault:ci"
SCRATCH_IMAGE_REPOSITORIES = {
    "api": "hallu-defense-api",
    "console": "hallu-defense-console",
    "sandbox": "hallu-defense-sandbox",
    "pgvector": "hallu-defense-pgvector",
    "opensearch": "hallu-defense-opensearch",
    "vault": "hallu-defense-vault",
}
KIND_POD_SUBNET = "192.168.0.0/16"
KIND_NETWORK_POLICY_PROVIDER = "kindnet"
KIND_PLATFORM = "linux/amd64"
DEFAULT_KIND_KUBERNETES_API_PEERS: tuple[Mapping[str, object], ...] = (
    {"cidr": "10.96.0.1/32", "port": 443},
    {"cidr": "172.19.0.2/32", "port": 6443},
)
KIND_NODE_IMAGE_ENV = "HALLU_DEFENSE_LIVE_KIND_NODE_IMAGE"
KIND_NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
OIDC_ISSUER = "https://auth.kind.invalid/realms/hallu-defense"
OIDC_AUDIENCE = "hallu-defense-api"
SANDBOX_JOB_LABEL = "hallu-defense.openai.com/sandbox=true"
SANDBOX_TIMEOUT_RETURN_CODE = 124
# Sandbox request timeout budget. Every inner/outer timeout used to probe an
# authenticated /repo/checks/run request is derived from these named pieces
# instead of a bare literal: the chart's own setup/command/cleanup grace
# defaults (sandbox.setupGraceSeconds / sandbox.commandTimeoutSeconds /
# sandbox.cleanupGraceSeconds), a named Kubernetes API poll allowance for
# kubectl exec and API-server round trips, and a fixed safety margin.
SANDBOX_SETUP_BUDGET_SECONDS = 15
SANDBOX_COMMAND_BUDGET_SECONDS = 30
SANDBOX_CLEANUP_GRACE_SECONDS = 20
SANDBOX_CLEANUP_GRACE_MIN_SECONDS = 15
SANDBOX_CLEANUP_GRACE_MAX_SECONDS = 30
SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS = 5
SANDBOX_KUBE_API_POLL_REQUESTS = 3
SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS = (
    SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS * SANDBOX_KUBE_API_POLL_REQUESTS
)
SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS = 5
SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS = (
    SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS
)
SANDBOX_CLEANUP_OUTER_SAFETY_MARGIN_SECONDS = 5
SANDBOX_JOB_CAPTURE_POLL_INTERVAL_SECONDS = 0.1
SANDBOX_CLEANUP_POLL_INTERVAL_SECONDS = 0.2
SANDBOX_MAX_COMMANDS = 10


def _sandbox_supported_request_path_seconds(
    command_count: int,
    cleanup_grace_seconds: int,
) -> int:
    if (
        isinstance(command_count, bool)
        or not isinstance(command_count, int)
        or not 1 <= command_count <= SANDBOX_MAX_COMMANDS
    ):
        raise LiveKindHelmSmokeError(
            f"sandbox request must contain between 1 and {SANDBOX_MAX_COMMANDS} commands"
        )
    if (
        isinstance(cleanup_grace_seconds, bool)
        or not isinstance(cleanup_grace_seconds, int)
        or not SANDBOX_CLEANUP_GRACE_MIN_SECONDS
        <= cleanup_grace_seconds
        <= SANDBOX_CLEANUP_GRACE_MAX_SECONDS
    ):
        raise LiveKindHelmSmokeError(
            "sandbox cleanup grace must be an integer between "
            f"{SANDBOX_CLEANUP_GRACE_MIN_SECONDS} and "
            f"{SANDBOX_CLEANUP_GRACE_MAX_SECONDS} seconds"
        )
    return (
        SANDBOX_SETUP_BUDGET_SECONDS
        + SANDBOX_COMMAND_BUDGET_SECONDS * command_count
        + cleanup_grace_seconds
    )


def _sandbox_request_timeout_seconds(
    command_count: int,
    cleanup_grace_seconds: int,
) -> int:
    return (
        _sandbox_supported_request_path_seconds(command_count, cleanup_grace_seconds)
        + SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS
    )


def _sandbox_request_exec_timeout_seconds(
    command_count: int,
    cleanup_grace_seconds: int,
) -> int:
    return (
        _sandbox_request_timeout_seconds(command_count, cleanup_grace_seconds)
        + SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS
    )


# Default single-command values remain exported for checker/documentation drift
# detection; request helpers derive their actual timeout from each payload.
SANDBOX_REQUEST_TIMEOUT_SECONDS = _sandbox_request_timeout_seconds(
    1,
    SANDBOX_CLEANUP_GRACE_SECONDS,
)
SANDBOX_REQUEST_EXEC_TIMEOUT_SECONDS = _sandbox_request_exec_timeout_seconds(
    1,
    SANDBOX_CLEANUP_GRACE_SECONDS,
)
ADMISSION_POLICY_ACTIVATION_ATTEMPTS = 40
ADMISSION_POLICY_ACTIVATION_INTERVAL_SECONDS = 0.25
HELM_EXECUTOR_TIMEOUT_SECONDS = 960
JOB_WAIT_TIMEOUT_SECONDS = {
    "migrations": 930,
    "vault-bootstrap": 630,
    "sandbox-fixture": 150,
}
ROLLOUT_WAIT_TIMEOUT_SECONDS = 660
EXPECTED_WORKLOAD_COMPONENTS = (
    "api",
    "console",
    "worker",
    "vault",
    "redis",
    "pgvector",
    "opensearch",
)
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
RUN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BASIC_AUTH_URI_PATTERN = re.compile(
    r"(?i)\b(https?|postgres(?:ql)?|redis)://[^\s:/@]+:[^\s/@]+@"
)
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(token|password|secret|api[-_]?key|authorization|dsn)"
    r"(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
OPENSEARCH_SCHEMA_HEALTH_SCRIPT = r"""
import json
import os
from urllib.request import urlopen

endpoint = os.environ["HALLU_DEFENSE_OPENSEARCH_ENDPOINT"].rstrip("/")

def load_json(path):
    with urlopen(endpoint + path, timeout=5) as response:
        return json.load(response)

template_response = load_json("/_index_template/hallu_evidence_template")
templates = template_response.get("index_templates")
matches = [
    item
    for item in templates if isinstance(item, dict)
    and item.get("name") == "hallu_evidence_template"
] if isinstance(templates, list) else []
if len(matches) != 1:
    raise RuntimeError("OpenSearch template readback did not contain one exact match")
installed = matches[0].get("index_template")
template = installed.get("template") if isinstance(installed, dict) else None
settings = template.get("settings") if isinstance(template, dict) else None
index_settings = settings.get("index") if isinstance(settings, dict) else None
replica_value = (
    index_settings.get("number_of_replicas")
    if isinstance(index_settings, dict)
    else None
)
if isinstance(replica_value, bool) or not isinstance(replica_value, (int, str)):
    raise RuntimeError("OpenSearch template replica count was invalid")
try:
    replica_count = int(replica_value)
except ValueError as exc:
    raise RuntimeError("OpenSearch template replica count was invalid") from exc

health = load_json("/_cluster/health")
kind_opensearch_schema_health = {
    "template_replicas": replica_count,
    "cluster_status": health.get("status"),
    "cluster_timed_out": health.get("timed_out"),
    "data_nodes": health.get("number_of_data_nodes"),
}
print(json.dumps(kind_opensearch_schema_health, sort_keys=True))
"""
PROJECTED_RUNTIME_SECRET_READ_SCRIPT = r"""
import json
import os

from hallu_defense.runtime_secrets import read_runtime_secret_file

raw_variables = (
    "HALLU_DEFENSE_VAULT_TOKEN",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV",
    "HALLU_DEFENSE_POSTGRES_DSN",
)
if any(os.environ.get(name) is not None for name in raw_variables):
    raise RuntimeError("raw runtime secret environment variable is present")

vault_token = read_runtime_secret_file(
    "/run/secrets/hallu_defense_vault_token",
    variable_name="HALLU_DEFENSE_VAULT_TOKEN_FILE",
)
postgres_dsn = read_runtime_secret_file(
    "/run/secrets/hallu_defense_postgres_dsn",
    variable_name="HALLU_DEFENSE_POSTGRES_DSN_FILE",
)
if not vault_token or not postgres_dsn.startswith("postgresql://"):
    raise RuntimeError("projected runtime secret content is invalid")

projected_runtime_secret_probe = {
    "postgres_dsn_file_read": True,
    "raw_secret_env_absent": True,
    "vault_token_file_read": True,
}
print(json.dumps(projected_runtime_secret_probe, sort_keys=True))
"""
CONSOLE_OIDC_RUNTIME_PROBE_SCRIPT = r"""
const expected = Object.freeze({
  HALLU_DEFENSE_ENV: "production",
  HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.kind.invalid",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.kind.invalid",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://auth.kind.invalid/realms/hallu-defense",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM: "tenant_id",
  HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM: "roles",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES:
    "verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator",
});

const halluNames = Object.keys(process.env)
  .filter((name) => name.startsWith("HALLU_DEFENSE_"))
  .sort();
const expectedNames = Object.keys(expected).sort();
if (
  JSON.stringify(halluNames) !== JSON.stringify(expectedNames) ||
  Object.entries(expected).some(([name, value]) => process.env[name] !== value)
) {
  throw new Error("Console runtime environment is not the exact OIDC contract");
}
const forbiddenNames = Object.keys(process.env).filter(
  (name) =>
    name.startsWith("NEXT_PUBLIC_") ||
    name.startsWith("HALLU_DEFENSE_CONSOLE_ALLOW_") ||
    name.startsWith("HALLU_DEFENSE_CONSOLE_LOCAL_")
);
if (forbiddenNames.length !== 0) {
  throw new Error("Console runtime contains forbidden client/local configuration");
}

(async () => {
  const response = await fetch("http://127.0.0.1:3000/console", {
    redirect: "manual",
    signal: AbortSignal.timeout(5000),
  });
  await response.body?.cancel();
  if (response.status !== 200) {
    throw new Error("Console runtime configuration did not serve a healthy page");
  }
  const console_oidc_runtime_probe = {
    api_audience: expected.HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE,
    api_origin: expected.HALLU_DEFENSE_CONSOLE_API_ORIGIN,
    auth_mode: expected.HALLU_DEFENSE_CONSOLE_AUTH_MODE,
    environment: expected.HALLU_DEFENSE_ENV,
    forbidden_env_absent: true,
    http_status: response.status,
    issuer: expected.HALLU_DEFENSE_CONSOLE_OIDC_ISSUER,
    public_origin: expected.HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN,
    required_roles: expected.HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES,
    roles_claim: expected.HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM,
    tenant_claim: expected.HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM,
  };
  console.log(JSON.stringify(console_oidc_runtime_probe));
})().catch(() => {
  process.exitCode = 1;
});
"""
VAULT_MANAGER_ROTATION_PROBE_SCRIPT = r"""
import hashlib
import json
import os

from hallu_defense.config import load_settings
from hallu_defense.services.secrets import VaultSecretManager, create_secret_manager

settings = load_settings(expected_runtime_role=os.environ["HALLU_DEFENSE_RUNTIME_ROLE"])
manager = create_secret_manager(settings)
if not isinstance(manager, VaultSecretManager):
    raise RuntimeError("VaultSecretManager was not selected")
captured = {}

def fake_vault_get(url, headers, timeout):
    del url, timeout
    captured.update(headers)
    return {"data": {"data": {"value": "probe-only"}}}

manager._http_get_json = fake_vault_get
manager.get_secret("smoke/runtime-token-probe")
credential = captured.get("X-Vault-Token")
if not isinstance(credential, str) or not credential:
    raise RuntimeError("VaultSecretManager did not read a projected token")
configured_path = os.environ["HALLU_DEFENSE_VAULT_TOKEN_FILE"]
vault_manager_projected_rotation_probe = {
    "lexical_path_preserved": str(settings.vault_token_file) == configured_path,
    "manager_type": type(manager).__name__,
    "token_sha256": hashlib.sha256(credential.encode("utf-8")).hexdigest(),
}
print(json.dumps(vault_manager_projected_rotation_probe, sort_keys=True))
"""
HYBRID_LIFECYCLE_TOMBSTONE_PROBE_SCRIPT = r"""
import json
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.request import Request, urlopen

from hallu_defense.config import RUNTIME_ROLE_API, load_settings
from hallu_defense.domain.models import Authority, Freshness, StalenessClass
from hallu_defense.services.audit import AuditLedger, PostgresAuditLedgerStorage
from hallu_defense.services.data_lifecycle import DataLifecyclePolicy, DataLifecycleService
from hallu_defense.services.postgres import build_postgres_provider
from hallu_defense.services.rag_index import (
    HybridRagIndexBackend,
    RagChunk,
    RagIndexTenantDeletedError,
    create_rag_index_backend,
)

tenant_id = "kind-lifecycle-deleted"
evidence_id = "ev_kind_lifecycle_deleted"
actor_id = "kind-lifecycle-smoke"
trace_id = "trace-kind-lifecycle-smoke"
settings = load_settings(expected_runtime_role=RUNTIME_ROLE_API)
connection = build_postgres_provider(settings)

def scalar_count(statement, parameters):
    rows = connection.fetch_all(statement, parameters)
    if len(rows) != 1:
        raise RuntimeError("lifecycle count query did not return exactly one row")
    value = rows[0].get("count")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError("lifecycle count query returned an invalid value")
    return value

def opensearch_count():
    endpoint = settings.opensearch_endpoint.rstrip("/")
    index_name = quote(settings.opensearch_index_name, safe="")
    payload = json.dumps(
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"tenant_id": tenant_id}},
                        {"term": {"evidence_id": evidence_id}},
                    ]
                }
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        f"{endpoint}/{index_name}/_count",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=settings.rag_index_timeout_seconds) as response:
        result = json.load(response)
    count = result.get("count") if isinstance(result, dict) else None
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise RuntimeError("OpenSearch lifecycle count returned an invalid value")
    return count

try:
    backend = create_rag_index_backend(settings)
    if not isinstance(backend, HybridRagIndexBackend):
        raise RuntimeError("Kind lifecycle probe requires the real hybrid backend")
    chunk = RagChunk(
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        source_ref="kind://lifecycle/deleted-tenant",
        content="kind lifecycle deletion parity probe",
        authority=Authority.INTERNAL,
        freshness=Freshness(
            retrieved_at=datetime.now(timezone.utc),
            staleness_class=StalenessClass.FRESH,
        ),
        metadata={
            "corpus_id": "kind-lifecycle-corpus",
            "document_revision": "rev-1",
        },
    )
    write = backend.index_chunks([chunk])
    if write.indexed_count != 1 or write.evidence_ids != [evidence_id]:
        raise RuntimeError("hybrid lifecycle fixture write was not acknowledged")
    initial_pgvector = scalar_count(
        "SELECT count(*) AS count FROM rag_evidence_chunks "
        "WHERE tenant_id = %s AND evidence_id = %s",
        (tenant_id, evidence_id),
    )
    initial_opensearch = opensearch_count()
    if (initial_pgvector, initial_opensearch) != (1, 1):
        raise RuntimeError("hybrid lifecycle fixture was not present in both stores")

    def transactional_audit(transaction):
        return AuditLedger(
            storage=PostgresAuditLedgerStorage(connection=transaction)
        )

    lifecycle = DataLifecycleService(
        connection=connection,
        audit=AuditLedger(),
        transactional_audit_factory=transactional_audit,
        policy=DataLifecyclePolicy(
            class_minimum_days={},
            postgres_retention_days={},
        ),
        rag_index_backend="hybrid",
        rag_deletion_backend=backend,
    )
    report = lifecycle.delete_tenant_data(
        tenant_id,
        actor_id=actor_id,
        trace_id=trace_id,
    )
    if report.dry_run or report.tenant_id != tenant_id:
        raise RuntimeError("hybrid lifecycle deletion did not execute")
    evidence_results = [item for item in report.tables if item.table == "rag_evidence_chunks"]
    if len(evidence_results) != 1 or evidence_results[0].affected_count != 1:
        raise RuntimeError("hybrid lifecycle deletion did not remove one PostgreSQL row")

    journal = connection.fetch_all(
        "SELECT status, external_deleted_count FROM rag_lifecycle_operations "
        "WHERE operation_id = %s",
        (report.run_id,),
    )
    if journal != [{"status": "completed", "external_deleted_count": 1}]:
        raise RuntimeError("hybrid lifecycle journal did not complete with exact parity")
    tombstone = connection.fetch_all(
        "SELECT operation_id, actor_id, trace_id FROM rag_tenant_deletion_tombstones "
        "WHERE tenant_id = %s",
        (tenant_id,),
    )
    if tombstone != [
        {
            "operation_id": report.run_id,
            "actor_id": actor_id,
            "trace_id": trace_id,
        }
    ]:
        raise RuntimeError("hybrid lifecycle tenant tombstone was not durable and exact")
    audit_rows = connection.fetch_all(
        "SELECT payload FROM audit_events WHERE event_id = %s",
        (report.audit_event_id,),
    )
    audit_payload = audit_rows[0].get("payload") if len(audit_rows) == 1 else None
    if not isinstance(audit_payload, dict) or audit_payload.get("outcome") != "success":
        raise RuntimeError("hybrid lifecycle success audit was not committed")
    audit_metadata = audit_payload.get("metadata")
    if not isinstance(audit_metadata, dict) or (
        audit_metadata.get("rag_lifecycle_operation_id") != report.run_id
        or audit_metadata.get("rag_external_deleted_count") != 1
        or audit_metadata.get("rag_external_parity_verified") is not True
    ):
        raise RuntimeError("hybrid lifecycle audit parity metadata was invalid")

    pgvector_after_delete = scalar_count(
        "SELECT count(*) AS count FROM rag_evidence_chunks "
        "WHERE tenant_id = %s AND evidence_id = %s",
        (tenant_id, evidence_id),
    )
    opensearch_after_delete = opensearch_count()
    if (pgvector_after_delete, opensearch_after_delete) != (0, 0):
        raise RuntimeError("hybrid lifecycle deletion left persistent evidence")

    reingest_rejected = False
    try:
        backend.index_chunks([chunk])
    except RagIndexTenantDeletedError:
        reingest_rejected = True
    if not reingest_rejected:
        raise RuntimeError("deleted tenant reingestion was not rejected by its durable fence")

    pgvector_after_reingest = scalar_count(
        "SELECT count(*) AS count FROM rag_evidence_chunks "
        "WHERE tenant_id = %s AND evidence_id = %s",
        (tenant_id, evidence_id),
    )
    opensearch_after_reingest = opensearch_count()
    if (pgvector_after_reingest, opensearch_after_reingest) != (0, 0):
        raise RuntimeError("rejected tenant reingestion mutated a persistent store")

    hybrid_lifecycle_tombstone_probe = {
        "audit_parity": True,
        "backend": "hybrid",
        "external_deleted_count": 1,
        "journal_completed": True,
        "opensearch_after_delete": opensearch_after_delete,
        "opensearch_after_reingest": opensearch_after_reingest,
        "pgvector_after_delete": pgvector_after_delete,
        "pgvector_after_reingest": pgvector_after_reingest,
        "reingest_rejected": reingest_rejected,
        "tombstone_persisted": True,
    }
    print(json.dumps(hybrid_lifecycle_tombstone_probe, sort_keys=True))
finally:
    connection.close()
"""


class LiveKindHelmSmokeError(RuntimeError):
    pass


class CommandExecutor(Protocol):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


ToolLocator = Callable[[str], str | None]


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    tool_locator: ToolLocator | None = None,
    executor: CommandExecutor | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the kind/Helm live smoke",
            "required_tools": list(REQUIRED_TOOLS),
        }

    _validated_kind_node_image(effective_env)
    locator = tool_locator or (
        lambda tool: shutil.which(tool, path=effective_env.get("PATH"))
    )
    missing_tools = [tool for tool in REQUIRED_TOOLS if locator(tool) is None]
    if missing_tools:
        raise LiveKindHelmSmokeError(
            "required live tools are unavailable: " + ", ".join(missing_tools)
        )

    run_id = _validated_run_id(
        _optional(effective_env, RUN_ID_ENV) or secret_generator.token_hex(6)
    )
    cluster = _validated_dns_label(
        _optional(effective_env, CLUSTER_ENV) or f"{DEFAULT_CLUSTER}-{run_id}",
        CLUSTER_ENV,
    )
    namespace = _validated_dns_label(
        _optional(effective_env, NAMESPACE_ENV) or DEFAULT_NAMESPACE,
        NAMESPACE_ENV,
    )
    return run_smoke(
        cluster=cluster,
        namespace=namespace,
        images=_scratch_image_references(run_id),
        executor=executor,
    )


def _discover_kind_kubernetes_api_peers(
    execute: CommandExecutor,
    *,
    kubectl_cluster: Sequence[str],
) -> list[dict[str, object]]:
    """Return exact pre- and post-DNAT Kubernetes API destinations for Kind."""

    def inventory(arguments: Sequence[str], description: str) -> object:
        result = execute([*kubectl_cluster, *arguments], timeout_seconds=30)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                f"{description} inventory did not return JSON"
            ) from exc

    service_payload = inventory(
        ["--namespace", "default", "get", "service", "kubernetes", "--output=json"],
        "Kubernetes API Service",
    )
    service_spec = (
        service_payload.get("spec") if isinstance(service_payload, Mapping) else None
    )
    cluster_ip = (
        service_spec.get("clusterIP") if isinstance(service_spec, Mapping) else None
    )
    service_ports = (
        service_spec.get("ports") if isinstance(service_spec, Mapping) else None
    )
    try:
        service_address = (
            ipaddress.ip_address(cluster_ip) if isinstance(cluster_ip, str) else None
        )
    except ValueError as exc:
        raise LiveKindHelmSmokeError(
            "Kubernetes API Service ClusterIP is invalid"
        ) from exc
    if service_address is None or service_address.version != 4:
        raise LiveKindHelmSmokeError(
            "Kubernetes API Service must expose one valid IPv4 ClusterIP"
        )
    if service_ports != [
        {
            "name": "https",
            "port": 443,
            "protocol": "TCP",
            "targetPort": 6443,
        }
    ]:
        raise LiveKindHelmSmokeError(
            "Kubernetes API Service must expose only https/TCP 443 to targetPort 6443"
        )

    slice_payload = inventory(
        [
            "--namespace",
            "default",
            "get",
            "endpointslice",
            "--selector=kubernetes.io/service-name=kubernetes",
            "--output=json",
        ],
        "Kubernetes API EndpointSlice",
    )
    slice_items = (
        slice_payload.get("items") if isinstance(slice_payload, Mapping) else None
    )
    if not isinstance(slice_items, list) or len(slice_items) != 1:
        raise LiveKindHelmSmokeError(
            "Kubernetes API must have exactly one EndpointSlice in the Kind smoke"
        )
    endpoint_slice = slice_items[0]
    endpoints = (
        endpoint_slice.get("endpoints") if isinstance(endpoint_slice, Mapping) else None
    )
    endpoint_ports = (
        endpoint_slice.get("ports") if isinstance(endpoint_slice, Mapping) else None
    )
    if endpoint_ports != [{"name": "https", "port": 6443, "protocol": "TCP"}]:
        raise LiveKindHelmSmokeError(
            "Kubernetes API EndpointSlice must expose only https/TCP port 6443"
        )
    if not isinstance(endpoints, list) or len(endpoints) != 1:
        raise LiveKindHelmSmokeError(
            "Kubernetes API EndpointSlice must contain exactly one endpoint"
        )
    endpoint = endpoints[0]
    conditions = endpoint.get("conditions") if isinstance(endpoint, Mapping) else None
    addresses = endpoint.get("addresses") if isinstance(endpoint, Mapping) else None
    if not isinstance(conditions, Mapping) or conditions.get("ready") is not True:
        raise LiveKindHelmSmokeError("Kubernetes API endpoint must be explicitly Ready")
    if not isinstance(addresses, list) or len(addresses) != 1:
        raise LiveKindHelmSmokeError(
            "Kubernetes API endpoint must expose exactly one address"
        )
    try:
        endpoint_address = ipaddress.ip_address(addresses[0])
    except (TypeError, ValueError) as exc:
        raise LiveKindHelmSmokeError(
            "Kubernetes API endpoint address is invalid"
        ) from exc
    if endpoint_address.version != 4:
        raise LiveKindHelmSmokeError("Kubernetes API endpoint must be IPv4 in Kind")

    node_payload = inventory(
        [
            "get",
            "nodes",
            "--selector=node-role.kubernetes.io/control-plane",
            "--output=json",
        ],
        "Kind control-plane Node",
    )
    node_items = (
        node_payload.get("items") if isinstance(node_payload, Mapping) else None
    )
    if not isinstance(node_items, list) or len(node_items) != 1:
        raise LiveKindHelmSmokeError(
            "Kind smoke must contain exactly one control-plane Node"
        )
    node_status = (
        node_items[0].get("status") if isinstance(node_items[0], Mapping) else None
    )
    node_addresses = (
        node_status.get("addresses") if isinstance(node_status, Mapping) else None
    )
    if not isinstance(node_addresses, list):
        raise LiveKindHelmSmokeError(
            "Kind control-plane Node address inventory is invalid"
        )
    internal_ips = [
        address.get("address")
        for address in node_addresses
        if isinstance(address, Mapping) and address.get("type") == "InternalIP"
    ]
    if len(internal_ips) != 1 or internal_ips[0] != str(endpoint_address):
        raise LiveKindHelmSmokeError(
            "Kubernetes API endpoint must equal the sole control-plane InternalIP"
        )

    return [
        {"cidr": f"{service_address}/32", "port": 443},
        {"cidr": f"{endpoint_address}/32", "port": 6443},
    ]


def run_smoke(
    *,
    cluster: str,
    namespace: str,
    images: Mapping[str, str] | None = None,
    executor: CommandExecutor | None = None,
) -> dict[str, object]:
    execute = executor or _run
    effective_images = dict(
        images
        if images is not None
        else _scratch_image_references(secret_generator.token_hex(6))
    )
    _validate_scratch_image_references(effective_images)
    context = f"kind-{cluster}"
    sandbox_namespace = DEFAULT_SANDBOX_NAMESPACE
    if namespace == sandbox_namespace:
        raise LiveKindHelmSmokeError(
            "application and sandbox namespaces must be distinct"
        )
    created = False
    baseline_clusters: set[str] | None = None
    scratch_images = [
        effective_images[component] for component in SCRATCH_IMAGE_REPOSITORIES
    ]
    image_cleanup_authorized = False
    result: dict[str, object] | None = None
    cleanup_evidence: dict[str, object] | None = None
    cleanup_failure: str | None = None
    bootstrap_directory = tempfile.TemporaryDirectory(prefix="hallu-kind-bootstrap-")
    try:
        bootstrap_root = Path(bootstrap_directory.name)
        kind_config_path = bootstrap_root / "kind-config.yaml"
        kubeconfig_path = bootstrap_root / "kubeconfig"
        _write_kind_config(kind_config_path)

        docker_info = execute(
            ["docker", "info", "--format", "{{.Architecture}}"],
            timeout_seconds=30,
        )
        docker_architecture = docker_info.stdout.strip().lower()
        if docker_architecture not in {"amd64", "x86_64"}:
            raise LiveKindHelmSmokeError(
                "kind smoke requires an amd64 Docker server for its digest-pinned toolchain"
            )
        baseline_clusters = _kind_cluster_names(execute)
        if cluster in baseline_clusters:
            raise LiveKindHelmSmokeError(
                f"refusing to reuse or delete existing kind cluster {cluster!r}"
            )
        _ensure_scratch_images_absent(execute, scratch_images)
        execute(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                cluster,
                "--config",
                str(kind_config_path),
                "--image",
                KIND_NODE_IMAGE,
                "--kubeconfig",
                str(kubeconfig_path),
            ],
            timeout_seconds=300,
        )
        created = True
        image_cleanup_authorized = True
        kubectl_cluster = [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig_path),
            "--context",
            context,
        ]
        execute(
            [*kubectl_cluster, "create", "namespace", namespace],
            timeout_seconds=60,
        )
        execute(
            [
                *kubectl_cluster,
                "create",
                "namespace",
                sandbox_namespace,
            ],
            timeout_seconds=60,
        )
        workspace_host_path = _kind_workspace_host_path(
            namespace=namespace,
            sandbox_namespace=sandbox_namespace,
        )
        execute(
            [
                "docker",
                "exec",
                f"{cluster}-control-plane",
                "install",
                "-d",
                "-m",
                "0770",
                "-o",
                "10001",
                "-g",
                "10001",
                workspace_host_path,
            ],
            timeout_seconds=30,
        )
        _preflight_admission_policy(
            execute,
            context=context,
            namespace=namespace,
            kubeconfig=kubeconfig_path,
        )
        for dockerfile, image in (
            ("infra/docker/api.Dockerfile", effective_images["api"]),
            ("infra/docker/console.Dockerfile", effective_images["console"]),
            ("infra/docker/sandbox.Dockerfile", effective_images["sandbox"]),
            ("infra/docker/pgvector.Dockerfile", effective_images["pgvector"]),
            ("infra/docker/opensearch.Dockerfile", effective_images["opensearch"]),
            ("infra/docker/vault.Dockerfile", effective_images["vault"]),
        ):
            execute(
                ["docker", "build", "--file", dockerfile, "--tag", image, "."],
                timeout_seconds=900,
            )
        execute(
            [
                *kubectl_cluster,
                "wait",
                "nodes",
                "--all",
                "--for=condition=Ready",
                "--timeout=300s",
            ],
            timeout_seconds=330,
        )
        kubernetes_api_peers = _discover_kind_kubernetes_api_peers(
            execute,
            kubectl_cluster=kubectl_cluster,
        )
        execute(
            [
                "kind",
                "load",
                "docker-image",
                "--name",
                cluster,
                *scratch_images,
            ],
            timeout_seconds=300,
        )
        oidc_material = _new_kind_oidc_material()
        secret_manifests = _kind_secret_manifests(
            namespace=namespace,
            oidc_jwks=oidc_material["jwks"],
        )
        for manifest in secret_manifests:
            execute(
                [
                    *kubectl_cluster,
                    "--namespace",
                    namespace,
                    "apply",
                    "--server-side",
                    "--field-manager=hallu-defense-live-smoke",
                    "--filename",
                    "-",
                ],
                input_text=json.dumps(manifest, separators=(",", ":")),
                timeout_seconds=30,
            )
        precreated_secret_names = [
            str(manifest["metadata"]["name"]) for manifest in secret_manifests
        ]

        common_helm_args = [
            "--namespace",
            namespace,
            "--values",
            str(KIND_VALUES_PATH),
            "--set-string",
            f"api.image.reference={effective_images['api']}",
            "--set-string",
            f"worker.image.reference={effective_images['api']}",
            "--set-string",
            f"migrations.image.reference={effective_images['api']}",
            "--set-string",
            f"console.image.reference={effective_images['console']}",
            "--set-string",
            f"sandbox.image.reference={effective_images['sandbox']}",
            "--set-string",
            f"kindDependencies.pgvector.image={effective_images['pgvector']}",
            "--set-string",
            f"kindDependencies.opensearch.image={effective_images['opensearch']}",
            "--set-string",
            f"kindDependencies.vault.image={effective_images['vault']}",
            "--set-json",
            "networkPolicy.kubernetesApi="
            + json.dumps(kubernetes_api_peers, separators=(",", ":")),
        ]
        helm_cluster_args = [
            "--kubeconfig",
            str(kubeconfig_path),
            "--kube-context",
            context,
        ]
        execute(
            ["helm", "lint", str(CHART_DIR), *common_helm_args],
            timeout_seconds=120,
        )
        execute(
            [
                "helm",
                "template",
                RELEASE_NAME,
                str(CHART_DIR),
                *common_helm_args,
            ],
            timeout_seconds=120,
        )
        execute(
            [
                "helm",
                "upgrade",
                "--install",
                RELEASE_NAME,
                str(CHART_DIR),
                *common_helm_args,
                *helm_cluster_args,
                "--timeout",
                "15m",
            ],
            timeout_seconds=HELM_EXECUTOR_TIMEOUT_SECONDS,
        )

        kubectl = [*kubectl_cluster, "--namespace", namespace]
        sandbox_kubectl = [
            *kubectl_cluster,
            "--namespace",
            sandbox_namespace,
        ]
        fixture_readiness = _wait_for_fixture_pod_ready(
            execute,
            kubectl=sandbox_kubectl,
            revision=1,
        )
        first_revision_jobs = _wait_for_revision_jobs(
            execute,
            component_kubectls={
                "migrations": kubectl,
                "vault-bootstrap": kubectl,
                "sandbox-fixture": sandbox_kubectl,
            },
            revision=1,
        )
        _wait_for_rollouts(execute, kubectl=kubectl)

        execute(
            [
                "helm",
                "upgrade",
                RELEASE_NAME,
                str(CHART_DIR),
                *common_helm_args,
                "--set",
                "sandbox.fixture.enabled=false",
                *helm_cluster_args,
                "--timeout",
                "15m",
            ],
            timeout_seconds=HELM_EXECUTOR_TIMEOUT_SECONDS,
        )
        migration_secret_evidence: dict[str, object] = {}

        def capture_revision_two_migration_evidence() -> None:
            if migration_secret_evidence:
                raise LiveKindHelmSmokeError(
                    "revision 2 migration evidence callback ran more than once"
                )
            migration_secret_evidence.update(
                _verify_migration_projected_secret_read(
                    execute,
                    kubectl=kubectl,
                    revision=2,
                )
            )

        second_revision_jobs = _wait_for_revision_jobs(
            execute,
            component_kubectls={
                "migrations": kubectl,
                "vault-bootstrap": kubectl,
            },
            revision=2,
            on_complete={"migrations": capture_revision_two_migration_evidence},
        )
        if not migration_secret_evidence:
            raise LiveKindHelmSmokeError(
                "revision 2 migration completion was not captured before TTL cleanup"
            )
        _wait_for_rollouts(execute, kubectl=kubectl)
        helm_history = _verify_helm_history(
            execute,
            namespace=namespace,
            context=context,
            kubeconfig=kubeconfig_path,
        )
        helm_secret_boundary = _verify_helm_release_secret_boundary(
            execute,
            context=context,
            namespace=namespace,
            kubeconfig=kubeconfig_path,
        )
        workloads = _workload_evidence(execute, kubectl=kubectl)
        projected_secret_reads = _verify_projected_runtime_secret_reads(
            execute,
            kubectl=kubectl,
            revision=2,
            migration_evidence=migration_secret_evidence,
        )
        runtime_secret_rotation = _verify_runtime_secret_rotation(
            execute,
            kubectl=kubectl,
            secret_manifests=secret_manifests,
        )
        workloads = _workload_evidence(execute, kubectl=kubectl)
        runtime_secret_rotation["api_restarts"] = 0

        migration_result = execute(
            [
                *kubectl,
                "exec",
                f"statefulset/{RELEASE_NAME}-pgvector",
                "--",
                "psql",
                "--username",
                "prod_user",
                "--dbname",
                "prod_db",
                "--tuples-only",
                "--no-align",
                "--command",
                (
                    "SELECT version || '|' || COALESCE(checksum_sha256, '<NULL>') "
                    "FROM schema_migrations ORDER BY version;"
                ),
            ],
            timeout_seconds=60,
        )
        migration_ledger: list[tuple[str, str]] = []
        for raw_line in migration_result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            version, separator, checksum = line.partition("|")
            if (
                separator != "|"
                or not version
                or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
            ):
                raise LiveKindHelmSmokeError(
                    "schema migration ledger contained a malformed or null checksum"
                )
            migration_ledger.append((version, checksum))
        if tuple(migration_ledger) != EXPECTED_MIGRATION_LEDGER:
            raise LiveKindHelmSmokeError(
                f"expected {EXPECTED_MIGRATION_COUNT} applied migrations with exact "
                f"checksums, found {migration_ledger!r}"
            )
        migration_versions = tuple(version for version, _ in migration_ledger)

        health_result = execute(
            [
                *kubectl,
                "exec",
                f"deployment/{RELEASE_NAME}-api",
                "--",
                "python",
                "-c",
                (
                    "import urllib.request;"
                    "print(urllib.request.urlopen("
                    "'http://127.0.0.1:8000/health',timeout=5).read().decode())"
                ),
            ],
            timeout_seconds=30,
        )
        health = _health_payload(health_result.stdout)
        ready_result = execute(
            [
                *kubectl,
                "exec",
                f"deployment/{RELEASE_NAME}-api",
                "--",
                "python",
                "-c",
                (
                    "import urllib.request;"
                    "print(urllib.request.urlopen("
                    "'http://127.0.0.1:8000/ready',timeout=5).read().decode())"
                ),
            ],
            timeout_seconds=30,
        )
        readiness = _ready_payload(ready_result.stdout)
        console_oidc = _verify_console_oidc_runtime(execute, kubectl=kubectl)
        redis = _verify_kind_redis(execute, kubectl=kubectl)
        opensearch_schema = _verify_opensearch_schema(execute, kubectl=kubectl)
        worker_readiness = _verify_worker_hybrid_readiness(execute, kubectl=kubectl)
        worker_metrics = _verify_worker_metrics(execute, kubectl=kubectl)
        hybrid_lifecycle_tombstone = _verify_hybrid_lifecycle_tombstone(
            execute,
            kubectl=kubectl,
        )
        application_egress = _verify_application_egress(
            execute,
            kubectl=kubectl,
            probe_image=effective_images["api"],
            kubernetes_api_peers=kubernetes_api_peers,
        )
        sandbox = _verify_kubernetes_sandbox(
            execute,
            application_kubectl=kubectl,
            sandbox_kubectl=sandbox_kubectl,
            application_namespace=namespace,
            sandbox_namespace=sandbox_namespace,
            bearer_token=str(oidc_material["token"]),
            sandbox_image=effective_images["sandbox"],
        )

        result = {
            "status": "passed",
            "cluster": cluster,
            "namespace": namespace,
            "sandbox_namespace": sandbox_namespace,
            "images": scratch_images,
            "network_policy_engine": {
                "provider": KIND_NETWORK_POLICY_PROVIDER,
                "node_image": KIND_NODE_IMAGE,
                "platform": KIND_PLATFORM,
                "native": True,
                "default_cni_enabled": True,
                "runtime_denials_verified": True,
            },
            "kubernetes_api_network_peers": kubernetes_api_peers,
            "migration_count": len(migration_versions),
            "migration_versions": list(migration_versions),
            "migration_checksums": dict(migration_ledger),
            "migration_checksum_aggregate": EXPECTED_MIGRATION_CHECKSUM_AGGREGATE,
            "bootstrap_jobs": {
                "revision_1": first_revision_jobs,
                "revision_2": second_revision_jobs,
            },
            "fixture_readiness": fixture_readiness,
            "helm_history": helm_history,
            "precreated_secrets": precreated_secret_names,
            "helm_secret_boundary": helm_secret_boundary,
            "health": health,
            "readiness": readiness,
            "console_oidc": console_oidc,
            "redis": redis,
            "opensearch_schema": opensearch_schema,
            "worker_metrics": worker_metrics,
            "workloads": workloads,
            "projected_secret_reads": projected_secret_reads,
            "runtime_secret_rotation": runtime_secret_rotation,
            "worker_readiness": worker_readiness,
            "hybrid_lifecycle_tombstone": hybrid_lifecycle_tombstone,
            "application_egress": application_egress,
            "sandbox": sandbox,
            "checks": [
                "docker image build",
                "kindnet native NetworkPolicy runtime enforcement",
                "kind image load",
                "helm lint",
                "helm template",
                "helm upgrade --install",
                "second helm upgrade revision",
                "revision-scoped migration Jobs complete",
                "Vault provider secret bootstrap Job complete",
                "fixture Pod Ready before Job completion",
                "workload rollouts",
                "schema migration count and checksum ledger",
                "api /health",
                "api /ready",
                "Console exact production OIDC runtime environment and healthy page",
                "Redis invalid AUTH, plaintext, and ACL rejection",
                "Redis TLS + CA + Vault URL health",
                "OpenSearch template v3 provisioning and readback",
                "OpenSearch transport 9300 loopback binding and remote denial",
                "worker PostgreSQL + hybrid OpenSearch readiness",
                "hybrid lifecycle deletion parity, durable tombstone, and no-reingestion fence",
                "complete workload NetworkPolicy coverage and default-deny egress",
                "workload Ready state and zero restarts",
                "API/worker projected token and DSN reads plus migration DSN consumption",
                "projected Vault token rotation observed through load_settings and VaultSecretManager",
                "authenticated Kubernetes sandbox stdout/stderr/exit/artifact",
                "sandbox workspace path escape rejection",
                "sandbox timeout cleanup",
                "kindnet-enforced sandbox egress denial",
                "zero residual sandbox Jobs",
            ],
        }
    except Exception:
        if created:
            _emit_diagnostics(
                execute,
                context=context,
                namespace=namespace,
                sandbox_namespace=sandbox_namespace,
                kubeconfig=kubeconfig_path,
            )
        raise
    finally:
        primary_error_active = sys.exc_info()[0] is not None
        cleanup_failures: list[str] = []
        cleanup_details: dict[str, object] = {}
        if created:
            try:
                delete_result = execute(
                    ["kind", "delete", "cluster", "--name", cluster],
                    check=False,
                    timeout_seconds=180,
                )
                if delete_result.returncode != 0:
                    cleanup_failures.append(
                        delete_result.stderr.strip()
                        or delete_result.stdout.strip()
                        or f"exit {delete_result.returncode}"
                    )
                else:
                    remaining_clusters = _kind_cluster_names(execute)
                    if cluster in remaining_clusters:
                        cleanup_failures.append(
                            f"kind cluster {cluster!r} still exists after exact delete"
                        )
                    else:
                        cleanup_details.update(
                            {
                                "cluster_deleted": True,
                                "verified_absent": True,
                                "baseline_clusters_before": sorted(
                                    baseline_clusters or set()
                                ),
                                "unrelated_clusters_after": sorted(remaining_clusters),
                            }
                        )
            except Exception as exc:
                cleanup_failures.append(f"{type(exc).__name__}: {exc}")
        if image_cleanup_authorized:
            try:
                removed_images = _remove_scratch_images(execute, scratch_images)
                cleanup_details.update(
                    {
                        "scratch_images_deleted": removed_images,
                        "scratch_images_verified_absent": True,
                    }
                )
            except Exception as exc:
                cleanup_failures.append(f"{type(exc).__name__}: {exc}")
        try:
            bootstrap_directory.cleanup()
        except Exception as exc:
            cleanup_failures.append(
                f"temporary bootstrap cleanup {type(exc).__name__}: {exc}"
            )
        if created and not cleanup_failures:
            cleanup_evidence = cleanup_details
        if cleanup_failures:
            cleanup_failure = "; ".join(cleanup_failures)
            if primary_error_active:
                print(f"kind cleanup failed: {cleanup_failure[:1000]}", file=sys.stderr)
        if cleanup_failure and not primary_error_active:
            raise LiveKindHelmSmokeError(
                f"kind cleanup failed after successful smoke: {cleanup_failure[:1000]}"
            )
    if result is None or cleanup_evidence is None:
        raise LiveKindHelmSmokeError(
            "kind smoke completed without structured result evidence"
        )
    result["cleanup"] = cleanup_evidence
    return result


def _write_kind_config(destination: Path) -> None:
    destination.write_text(
        "\n".join(
            (
                "kind: Cluster",
                "apiVersion: kind.x-k8s.io/v1alpha4",
                "networking:",
                f"  podSubnet: {KIND_POD_SUBNET}",
                "nodes:",
                "  - role: control-plane",
                "",
            )
        ),
        encoding="utf-8",
    )


def _kind_workspace_host_path(*, namespace: str, sandbox_namespace: str) -> str:
    identity = f"{namespace}/{sandbox_namespace}/{RELEASE_NAME}"
    workspace_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"/var/local/hallu-defense-sandbox/{workspace_hash}"


def _scratch_image_references(run_id: str) -> dict[str, str]:
    validated = _validated_run_id(run_id)
    return {
        component: f"{repository}:kind-{validated}"
        for component, repository in SCRATCH_IMAGE_REPOSITORIES.items()
    }


def _validate_scratch_image_references(images: Mapping[str, str]) -> None:
    if set(images) != set(SCRATCH_IMAGE_REPOSITORIES):
        raise LiveKindHelmSmokeError(
            "scratch image map must contain exactly api, console, sandbox, pgvector, "
            "and opensearch"
        )
    run_ids: set[str] = set()
    for component, repository in SCRATCH_IMAGE_REPOSITORIES.items():
        reference = images.get(component)
        if not isinstance(reference, str):
            raise LiveKindHelmSmokeError(f"scratch image {component} must be text")
        match = re.fullmatch(rf"{re.escape(repository)}:kind-([a-z0-9-]+)", reference)
        if match is None:
            raise LiveKindHelmSmokeError(
                f"scratch image {component} must use repository {repository!r} and a "
                ":kind-<run-id> tag"
            )
        run_ids.add(_validated_run_id(match.group(1)))
    if len(run_ids) != 1:
        raise LiveKindHelmSmokeError("all scratch images must share one exact run id")


def _ensure_scratch_images_absent(
    execute: CommandExecutor,
    images: Sequence[str],
) -> None:
    for image in images:
        result = execute(
            ["docker", "image", "inspect", image],
            check=False,
            timeout_seconds=30,
        )
        if result.returncode == 0:
            raise LiveKindHelmSmokeError(
                f"refusing to overwrite or later delete existing scratch image {image!r}"
            )
        if not _docker_reports_missing_image(result):
            detail = _redact_sensitive_output(
                result.stderr.strip()
                or result.stdout.strip()
                or f"exit {result.returncode}"
            )
            raise LiveKindHelmSmokeError(
                f"could not prove scratch image {image!r} absent: {detail[:1000]}"
            )


def _remove_scratch_images(
    execute: CommandExecutor,
    images: Sequence[str],
) -> list[str]:
    failures: list[str] = []
    for image in images:
        removal = execute(
            ["docker", "image", "rm", image],
            check=False,
            timeout_seconds=60,
        )
        if removal.returncode != 0 and not _docker_reports_missing_image(removal):
            detail = _redact_sensitive_output(
                removal.stderr.strip()
                or removal.stdout.strip()
                or f"exit {removal.returncode}"
            )
            failures.append(f"removal failed for {image!r}: {detail[:1000]}")
    remaining: list[str] = []
    for image in images:
        inspection = execute(
            ["docker", "image", "inspect", image],
            check=False,
            timeout_seconds=30,
        )
        if inspection.returncode == 0:
            remaining.append(image)
        elif not _docker_reports_missing_image(inspection):
            detail = _redact_sensitive_output(
                inspection.stderr.strip()
                or inspection.stdout.strip()
                or f"exit {inspection.returncode}"
            )
            failures.append(
                f"absence verification failed for {image!r}: {detail[:1000]}"
            )
    if remaining:
        failures.append(f"exact tags remain: {remaining!r}")
    if failures:
        raise LiveKindHelmSmokeError(
            "scratch image cleanup failed: " + "; ".join(failures)
        )
    return list(images)


def _docker_reports_missing_image(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode != 1:
        return False
    detail = f"{result.stdout}\n{result.stderr}".lower()
    return "no such image" in detail or "no such object" in detail


def _kind_cluster_names(execute: CommandExecutor) -> set[str]:
    result = execute(
        ["kind", "get", "clusters"],
        check=False,
        timeout_seconds=30,
    )
    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit {result.returncode}"
        )
        raise LiveKindHelmSmokeError(f"kind cluster inventory failed: {detail[:1000]}")
    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().lower().startswith("no kind clusters")
    }


def _job_selector(*, component: str, revision: int) -> str:
    return (
        f"app.kubernetes.io/component={component},"
        f"hallu-defense.openai.com/release-revision={revision}"
    )


def _wait_for_job_complete(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    component: str,
    revision: int,
) -> dict[str, object]:
    return _wait_for_revision_jobs(
        execute,
        component_kubectls={component: kubectl},
        revision=revision,
    )[component]


def _wait_for_revision_jobs(
    execute: CommandExecutor,
    *,
    component_kubectls: Mapping[str, Sequence[str]],
    revision: int,
    on_complete: Mapping[str, Callable[[], None]] | None = None,
    attempts: int | None = None,
    interval_seconds: float = 1.0,
) -> dict[str, dict[str, object]]:
    if not component_kubectls:
        raise LiveKindHelmSmokeError("revision-scoped Job set must not be empty")
    if attempts is not None and attempts < 1:
        raise ValueError("revision Job attempts must be positive")
    if interval_seconds < 0:
        raise ValueError("revision Job poll interval must not be negative")
    callbacks = dict(on_complete or {})
    unknown_callbacks = set(callbacks).difference(component_kubectls)
    if unknown_callbacks:
        raise LiveKindHelmSmokeError(
            f"revision Job callbacks reference unknown components: {sorted(unknown_callbacks)}"
        )
    started_at = time.monotonic()
    deadlines: dict[str, float] = {}
    for component in component_kubectls:
        wait_timeout = JOB_WAIT_TIMEOUT_SECONDS.get(component)
        if wait_timeout is None:
            raise LiveKindHelmSmokeError(
                f"unsupported revision-scoped Job {component!r}"
            )
        deadlines[component] = started_at + wait_timeout

    pending = dict(component_kubectls)
    completed: dict[str, dict[str, object]] = {}
    polls = 0
    while pending:
        polls += 1
        for component, component_kubectl in tuple(pending.items()):
            remaining_seconds = deadlines[component] - time.monotonic()
            if remaining_seconds <= 0:
                raise LiveKindHelmSmokeError(
                    f"{component} Job for Helm revision {revision} did not complete "
                    "within its bounded wait"
                )
            observation = _observe_revision_job(
                execute,
                kubectl=component_kubectl,
                component=component,
                revision=revision,
                timeout_seconds=min(30.0, remaining_seconds),
            )
            observed_at = time.monotonic()
            if observed_at > deadlines[component]:
                raise LiveKindHelmSmokeError(
                    f"{component} Job for Helm revision {revision} did not complete "
                    "within its bounded wait"
                )
            if observation is not None:
                callback = callbacks.get(component)
                if callback is not None:
                    callback()
                completed[component] = observation
                del pending[component]
                continue
            if time.monotonic() >= deadlines[component]:
                raise LiveKindHelmSmokeError(
                    f"{component} Job for Helm revision {revision} did not complete "
                    "within its bounded wait"
                )
        if not pending:
            break
        if attempts is not None and polls >= attempts:
            missing = ", ".join(sorted(pending))
            raise LiveKindHelmSmokeError(
                f"revision {revision} Jobs did not complete after {polls} polls: {missing}"
            )
        time.sleep(interval_seconds)
    return completed


def _observe_revision_job(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    component: str,
    revision: int,
    timeout_seconds: float = 30,
) -> dict[str, object] | None:
    selector = _job_selector(component=component, revision=revision)
    inventory = execute(
        [*kubectl, "get", "jobs", f"--selector={selector}", "--output=json"],
        timeout_seconds=timeout_seconds,
    )
    try:
        payload = json.loads(inventory.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            f"{component} revision {revision} Job inventory did not return JSON"
        ) from exc
    items = payload.get("items") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise LiveKindHelmSmokeError(
            f"{component} revision {revision} Job inventory lacked an items list"
        )
    if not items:
        return None
    if len(items) != 1:
        raise LiveKindHelmSmokeError(
            f"expected exactly one {component} Job for Helm revision {revision}"
        )
    job = items[0]
    metadata = job.get("metadata") if isinstance(job, Mapping) else None
    status = job.get("status") if isinstance(job, Mapping) else None
    job_name = metadata.get("name") if isinstance(metadata, Mapping) else None
    labels = metadata.get("labels") if isinstance(metadata, Mapping) else None
    expected_name = f"{RELEASE_NAME}-{component}-{revision}"
    if (
        job_name != expected_name
        or not isinstance(labels, Mapping)
        or labels.get("app.kubernetes.io/component") != component
        or labels.get("hallu-defense.openai.com/release-revision") != str(revision)
    ):
        raise LiveKindHelmSmokeError(
            f"{component} Job did not carry exact Helm revision {revision} identity"
        )
    if status is None:
        conditions: object = []
    elif isinstance(status, Mapping):
        conditions = status.get("conditions", [])
    else:
        raise LiveKindHelmSmokeError(
            f"{component} Job for Helm revision {revision} had invalid status"
        )
    if not isinstance(conditions, list) or any(
        not isinstance(condition, Mapping) for condition in conditions
    ):
        raise LiveKindHelmSmokeError(
            f"{component} Job for Helm revision {revision} had invalid conditions"
        )
    condition_states: dict[str, str] = {}
    for condition in conditions:
        condition_type = condition.get("type")
        condition_status = condition.get("status")
        if condition_type in {"Complete", "Failed"}:
            if condition_status not in {"True", "False", "Unknown"}:
                raise LiveKindHelmSmokeError(
                    f"{component} Job for Helm revision {revision} had invalid "
                    f"{condition_type} condition"
                )
            condition_states[str(condition_type)] = str(condition_status)
    if condition_states.get("Failed") == "True":
        raise LiveKindHelmSmokeError(
            f"{component} Job for Helm revision {revision} reported Failed=True"
        )
    if condition_states.get("Complete") != "True":
        return None
    return {"complete": True, "job": job_name, "revision": revision}


def _wait_for_fixture_pod_ready(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    revision: int,
    attempts: int = 150,
    interval_seconds: float = 1.0,
) -> dict[str, object]:
    selector = _job_selector(component="sandbox-fixture", revision=revision)
    for _ in range(attempts):
        inventory = execute(
            [*kubectl, "get", "pods", f"--selector={selector}", "--output=json"],
            timeout_seconds=30,
        )
        try:
            payload = json.loads(inventory.stdout)
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                "sandbox fixture Pod inventory did not return JSON"
            ) from exc
        items = payload.get("items") if isinstance(payload, Mapping) else None
        if not isinstance(items, list):
            raise LiveKindHelmSmokeError("sandbox fixture Pod inventory lacked items")
        if len(items) > 1:
            raise LiveKindHelmSmokeError(
                f"expected at most one sandbox fixture Pod for Helm revision {revision}"
            )
        if not items:
            time.sleep(interval_seconds)
            continue
        pod = items[0]
        metadata = pod.get("metadata") if isinstance(pod, Mapping) else None
        pod_spec = pod.get("spec") if isinstance(pod, Mapping) else None
        status = pod.get("status") if isinstance(pod, Mapping) else None
        name = metadata.get("name") if isinstance(metadata, Mapping) else None
        owners = (
            metadata.get("ownerReferences") if isinstance(metadata, Mapping) else None
        )
        labels = metadata.get("labels") if isinstance(metadata, Mapping) else None
        conditions = status.get("conditions") if isinstance(status, Mapping) else None
        containers = (
            status.get("containerStatuses") if isinstance(status, Mapping) else None
        )
        spec_containers = (
            pod_spec.get("containers") if isinstance(pod_spec, Mapping) else None
        )
        ready_condition = isinstance(conditions, list) and any(
            isinstance(condition, Mapping)
            and condition.get("type") == "Ready"
            and condition.get("status") == "True"
            for condition in conditions
        )
        ready_containers = (
            isinstance(containers, list)
            and bool(containers)
            and all(
                isinstance(container, Mapping)
                and container.get("ready") is True
                and container.get("restartCount") == 0
                for container in containers
            )
        )
        job_owners = (
            [
                owner
                for owner in owners
                if isinstance(owner, Mapping)
                and owner.get("kind") == "Job"
                and owner.get("controller") is True
            ]
            if isinstance(owners, list)
            else []
        )
        fixture_specs = (
            [
                container
                for container in spec_containers
                if isinstance(container, Mapping)
                and container.get("name") == "prepare-sandbox-fixture"
            ]
            if isinstance(spec_containers, list)
            else []
        )
        readiness_probe = (
            fixture_specs[0].get("readinessProbe") if len(fixture_specs) == 1 else None
        )
        probe_exec = (
            readiness_probe.get("exec")
            if isinstance(readiness_probe, Mapping)
            else None
        )
        probe_command = (
            probe_exec.get("command") if isinstance(probe_exec, Mapping) else None
        )
        exact_job_name = f"{RELEASE_NAME}-sandbox-fixture-{revision}"
        if (
            isinstance(name, str)
            and isinstance(labels, Mapping)
            and labels.get("hallu-defense.openai.com/release-revision") == str(revision)
            and isinstance(status, Mapping)
            and status.get("phase") == "Running"
            and ready_condition
            and ready_containers
            and len(job_owners) == 1
            and job_owners[0].get("name") == exact_job_name
            and isinstance(readiness_probe, Mapping)
            and readiness_probe.get("initialDelaySeconds") == 1
            and readiness_probe.get("periodSeconds") == 1
            and readiness_probe.get("timeoutSeconds") == 5
            and isinstance(probe_command, list)
            and "HALLU_FIXTURE_READY_MARKER"
            in " ".join(str(part) for part in probe_command)
        ):
            return {
                "job": exact_job_name,
                "pod": name,
                "ready": True,
                "revision": revision,
                "restarts": 0,
            }
        if isinstance(status, Mapping) and status.get("phase") in {
            "Failed",
            "Succeeded",
        }:
            break
        time.sleep(interval_seconds)
    raise LiveKindHelmSmokeError(
        f"sandbox fixture Pod for Helm revision {revision} was never observed Ready"
    )


def _wait_for_rollouts(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> None:
    for resource in (
        f"deployment/{RELEASE_NAME}-api",
        f"deployment/{RELEASE_NAME}-console",
        f"deployment/{RELEASE_NAME}-worker",
        f"deployment/{RELEASE_NAME}-vault",
        f"deployment/{RELEASE_NAME}-redis",
        f"statefulset/{RELEASE_NAME}-pgvector",
        f"statefulset/{RELEASE_NAME}-opensearch",
    ):
        execute(
            [
                *kubectl,
                "rollout",
                "status",
                resource,
                f"--timeout={ROLLOUT_WAIT_TIMEOUT_SECONDS}s",
            ],
            timeout_seconds=ROLLOUT_WAIT_TIMEOUT_SECONDS + 30,
        )


def _verify_helm_history(
    execute: CommandExecutor,
    *,
    namespace: str,
    context: str,
    kubeconfig: Path,
) -> list[dict[str, object]]:
    history_result = execute(
        [
            "helm",
            "history",
            RELEASE_NAME,
            "--namespace",
            namespace,
            "--max",
            "2",
            "--output",
            "json",
            "--kubeconfig",
            str(kubeconfig),
            "--kube-context",
            context,
        ],
        timeout_seconds=60,
    )
    try:
        history = json.loads(history_result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError("Helm history did not return JSON") from exc
    if not isinstance(history, list) or len(history) != 2:
        raise LiveKindHelmSmokeError("Helm history must contain exactly two revisions")
    normalized: list[dict[str, object]] = []
    for entry in history:
        revision = entry.get("revision") if isinstance(entry, Mapping) else None
        status = entry.get("status") if isinstance(entry, Mapping) else None
        if type(revision) is not int:
            raise LiveKindHelmSmokeError("Helm history revision was invalid")
        revision_number = revision
        if not isinstance(status, str):
            raise LiveKindHelmSmokeError("Helm history status was invalid")
        normalized.append({"revision": revision_number, "status": status.lower()})
    if normalized != [
        {"revision": 1, "status": "superseded"},
        {"revision": 2, "status": "deployed"},
    ]:
        raise LiveKindHelmSmokeError(
            f"Helm history did not prove a deployed second upgrade: {normalized!r}"
        )
    return normalized


def _verify_helm_release_secret_boundary(
    execute: CommandExecutor,
    *,
    context: str,
    namespace: str,
    kubeconfig: Path,
) -> dict[str, object]:
    forbidden_keys = {
        "keycloakJwks",
        "vaultToken",
        "postgresDsn",
        "migrationsPostgresDsn",
        "postgresUser",
        "postgresPassword",
        "postgresDatabase",
        "rootToken",
        "kindVaultCaCertificate",
        "kindVaultTlsCertificate",
        "kindVaultTlsPrivateKey",
        "kindRedisCaCertificate",
        "kindRedisTlsCertificate",
        "kindRedisTlsPrivateKey",
    }

    def inspect_release_value(
        value: object,
        path: str,
        leaked_fields: list[str],
    ) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}"
                if key_text in forbidden_keys:
                    leaked_fields.append(child_path)
                inspect_release_value(nested, child_path, leaked_fields)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for index, nested in enumerate(value):
                inspect_release_value(nested, f"{path}[{index}]", leaked_fields)
            return
        if isinstance(value, str) and (
            value.startswith(("postgresql://", "postgres://"))
            or ("-----BEGIN " + "PRIVATE KEY-----") in value
            or ("-----BEGIN RSA " + "PRIVATE KEY-----") in value
        ):
            leaked_fields.append(path)

    expected_names = {
        "runtime": f"{RELEASE_NAME}-runtime",
        "bootstrap": f"{RELEASE_NAME}-bootstrap",
        "migrations": f"{RELEASE_NAME}-migrations",
        "kindPostgres": f"{RELEASE_NAME}-postgres",
        "kindVault": f"{RELEASE_NAME}-kind-vault",
        "kindRedisTls": f"{RELEASE_NAME}-kind-redis-tls",
    }
    revision_names: dict[int, dict[str, str]] = {}
    for revision in (1, 2):
        revision_args = ["--revision", str(revision)]
        manifest_result = execute(
            [
                "helm",
                "get",
                "manifest",
                RELEASE_NAME,
                *revision_args,
                "--namespace",
                namespace,
                "--kube-context",
                context,
                "--kubeconfig",
                str(kubeconfig),
            ],
            timeout_seconds=60,
        )
        if re.search(r"(?m)^kind:\s*Secret\s*$", manifest_result.stdout):
            raise LiveKindHelmSmokeError(
                f"Helm release revision {revision} unexpectedly retained a Secret object"
            )
        values_result = execute(
            [
                "helm",
                "get",
                "values",
                RELEASE_NAME,
                *revision_args,
                "--all",
                "--output",
                "json",
                "--namespace",
                namespace,
                "--kube-context",
                context,
                "--kubeconfig",
                str(kubeconfig),
            ],
            timeout_seconds=60,
        )
        try:
            values = json.loads(values_result.stdout)
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                f"Helm release revision {revision} values did not return JSON"
            ) from exc
        if not isinstance(values, Mapping):
            raise LiveKindHelmSmokeError("Helm release values must be an object")
        secret_refs = values.get("secrets")
        if not isinstance(secret_refs, Mapping):
            raise LiveKindHelmSmokeError(
                "Helm release values are missing Secret references"
            )
        leaked_fields: list[str] = []
        inspect_release_value(values, "values", leaked_fields)
        if leaked_fields:
            raise LiveKindHelmSmokeError(
                f"Helm release revision {revision} retained a sensitive Secret field"
            )
        actual_names: dict[str, str] = {}
        for section, expected_name in expected_names.items():
            reference = secret_refs.get(section)
            name = reference.get("name") if isinstance(reference, Mapping) else None
            if name != expected_name:
                raise LiveKindHelmSmokeError(
                    f"Helm release revision {revision} Secret reference {section} was not exact"
                )
            actual_names[section] = expected_name
        if len(set(actual_names.values())) != len(actual_names):
            raise LiveKindHelmSmokeError(
                f"Helm release revision {revision} Secret references were not distinct"
            )
        revision_names[revision] = actual_names
    if revision_names[1] != revision_names[2]:
        raise LiveKindHelmSmokeError(
            "Helm release Secret references changed across revisions"
        )
    return {
        "manifest_secret_objects": 0,
        "revisions_checked": [1, 2],
        "sensitive_value_fields": 0,
        "precreated_secret_references": revision_names[2],
    }


def _workload_evidence(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, object]:
    pods_result = execute(
        [
            *kubectl,
            "get",
            "pods",
            "--selector",
            f"app.kubernetes.io/instance={RELEASE_NAME}",
            "--output=json",
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(pods_result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "workload pod inventory did not return JSON"
        ) from exc
    items = payload.get("items") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise LiveKindHelmSmokeError("workload pod inventory is missing items")
    evidence: dict[str, object] = {}
    for component in EXPECTED_WORKLOAD_COMPONENTS:
        matches: list[Mapping[str, object]] = []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            metadata = item.get("metadata")
            labels = metadata.get("labels") if isinstance(metadata, Mapping) else None
            if (
                isinstance(labels, Mapping)
                and labels.get("app.kubernetes.io/component") == component
            ):
                matches.append(item)
        if len(matches) != 1:
            raise LiveKindHelmSmokeError(
                f"expected exactly one running {component} Pod, found {len(matches)}"
            )
        pod = matches[0]
        metadata = pod.get("metadata")
        status = pod.get("status")
        if not isinstance(metadata, Mapping) or not isinstance(status, Mapping):
            raise LiveKindHelmSmokeError(f"{component} Pod is missing metadata/status")
        if status.get("phase") != "Running":
            raise LiveKindHelmSmokeError(f"{component} Pod is not Running")
        container_statuses = status.get("containerStatuses")
        if not isinstance(container_statuses, list) or not container_statuses:
            raise LiveKindHelmSmokeError(
                f"{component} Pod has no container status evidence"
            )
        if not all(
            isinstance(container, Mapping) and container.get("ready") is True
            for container in container_statuses
        ):
            raise LiveKindHelmSmokeError(
                f"{component} Pod containers are not all Ready"
            )
        all_statuses = [*container_statuses]
        init_statuses = status.get("initContainerStatuses", [])
        if isinstance(init_statuses, list):
            all_statuses.extend(init_statuses)
        restarts = sum(
            int(container.get("restartCount", 0))
            for container in all_statuses
            if isinstance(container, Mapping)
        )
        if restarts != 0:
            raise LiveKindHelmSmokeError(
                f"{component} Pod has {restarts} container restarts"
            )
        evidence[component] = {
            "pod": str(metadata.get("name", "")),
            "phase": "Running",
            "containers": len(container_statuses),
            "ready_containers": len(container_statuses),
            "restarts": restarts,
        }
    return evidence


def _verify_projected_runtime_secret_reads(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    revision: int = 1,
    migration_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    expected_runtime = {
        "postgres_dsn_file_read": True,
        "raw_secret_env_absent": True,
        "vault_token_file_read": True,
    }
    evidence: dict[str, object] = {}
    for component in ("api", "worker"):
        result = execute(
            [
                *kubectl,
                "exec",
                f"deployment/{RELEASE_NAME}-{component}",
                "--",
                "python",
                "-c",
                PROJECTED_RUNTIME_SECRET_READ_SCRIPT,
            ],
            timeout_seconds=30,
        )
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                f"{component} projected runtime secret probe did not return JSON"
            ) from exc
        if payload != expected_runtime:
            raise LiveKindHelmSmokeError(
                f"{component} projected runtime secret reads were not proven"
            )
        evidence[component] = expected_runtime.copy()

    captured_migration = (
        _verify_migration_projected_secret_read(
            execute,
            kubectl=kubectl,
            revision=revision,
        )
        if migration_evidence is None
        else dict(migration_evidence)
    )
    expected_migration_keys = {
        "newly_applied_migrations",
        "postgres_dsn_file_read",
        "raw_secret_env_absent",
        "revision",
        "restarts",
    }
    if (
        set(captured_migration) != expected_migration_keys
        or captured_migration.get("revision") != revision
        or captured_migration.get("postgres_dsn_file_read") is not True
        or captured_migration.get("raw_secret_env_absent") is not True
        or captured_migration.get("restarts") != 0
    ):
        raise LiveKindHelmSmokeError(
            "captured migration projected-secret evidence was invalid"
        )
    evidence["migrations"] = captured_migration
    return evidence


def _verify_migration_projected_secret_read(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    revision: int,
) -> dict[str, object]:
    migration_pods_result = execute(
        [
            *kubectl,
            "get",
            "pods",
            f"--selector={_job_selector(component='migrations', revision=revision)}",
            "--output=json",
        ],
        timeout_seconds=30,
    )
    try:
        migration_pods_payload = json.loads(migration_pods_result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "migration Pod restart evidence did not return JSON"
        ) from exc
    migration_pods = (
        migration_pods_payload.get("items")
        if isinstance(migration_pods_payload, Mapping)
        else None
    )
    if not isinstance(migration_pods, list) or len(migration_pods) != 1:
        raise LiveKindHelmSmokeError(
            f"expected exactly one completed migration Pod for Helm revision {revision}"
        )
    migration_pod = migration_pods[0]
    migration_status = (
        migration_pod.get("status") if isinstance(migration_pod, Mapping) else None
    )
    if (
        not isinstance(migration_status, Mapping)
        or migration_status.get("phase") != "Succeeded"
    ):
        raise LiveKindHelmSmokeError("migration Pod did not reach Succeeded")
    migration_container_statuses: list[Mapping[str, object]] = []
    for status_field in ("initContainerStatuses", "containerStatuses"):
        statuses = migration_status.get(status_field, [])
        if not isinstance(statuses, list):
            raise LiveKindHelmSmokeError(
                "migration Pod container status evidence was invalid"
            )
        migration_container_statuses.extend(
            status for status in statuses if isinstance(status, Mapping)
        )
    if not migration_container_statuses or not any(
        status.get("name") == "migrations" for status in migration_container_statuses
    ):
        raise LiveKindHelmSmokeError(
            "migration Pod main container status was unavailable"
        )
    migration_restarts = sum(
        int(status.get("restartCount", 0)) for status in migration_container_statuses
    )
    if migration_restarts != 0:
        raise LiveKindHelmSmokeError(
            f"migration Pod has {migration_restarts} container restarts"
        )

    migration_logs = execute(
        [
            *kubectl,
            "logs",
            f"--selector={_job_selector(component='migrations', revision=revision)}",
            "--container=migrations",
            "--prefix=false",
            "--tail=20",
        ],
        timeout_seconds=30,
    )
    migration_payloads: list[Mapping[str, object]] = []
    for line in migration_logs.stdout.splitlines():
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, Mapping) and candidate.get("status") in {
            "ok",
            "error",
        }:
            migration_payloads.append(candidate)
    if len(migration_payloads) != 1 or migration_payloads[0].get("status") != "ok":
        raise LiveKindHelmSmokeError(
            "migration Job did not prove successful projected PostgreSQL DSN consumption"
        )
    applied = migration_payloads[0].get("applied")
    expected_newly_applied = EXPECTED_MIGRATION_VERSIONS if revision == 1 else ()
    if not isinstance(applied, list) or tuple(applied) != expected_newly_applied:
        raise LiveKindHelmSmokeError(
            "migration Job projected DSN proof reported an unexpected newly-applied "
            f"inventory for Helm revision {revision}"
        )
    return {
        "newly_applied_migrations": len(applied),
        "postgres_dsn_file_read": True,
        "raw_secret_env_absent": True,
        "revision": revision,
        "restarts": 0,
    }


def _verify_runtime_secret_rotation(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    secret_manifests: Sequence[Mapping[str, object]],
    attempts: int = 90,
    interval_seconds: float = 1.0,
) -> dict[str, object]:
    runtime_matches: list[Mapping[str, object]] = []
    for manifest in secret_manifests:
        metadata = manifest.get("metadata")
        if (
            isinstance(metadata, Mapping)
            and metadata.get("name") == f"{RELEASE_NAME}-runtime"
        ):
            runtime_matches.append(manifest)
    if len(runtime_matches) != 1:
        raise LiveKindHelmSmokeError(
            "runtime Secret rotation requires exactly one precreated runtime manifest"
        )
    original_manifest = copy.deepcopy(runtime_matches[0])
    string_data = original_manifest.get("stringData")
    if not isinstance(string_data, Mapping):
        raise LiveKindHelmSmokeError(
            "runtime Secret rotation manifest is missing stringData"
        )
    original_credential = string_data.get("vault-token")
    if not isinstance(original_credential, str) or not original_credential:
        raise LiveKindHelmSmokeError("runtime Secret rotation token is unavailable")
    original_fingerprint = hashlib.sha256(
        original_credential.encode("utf-8")
    ).hexdigest()
    _wait_for_vault_manager_fingerprint(
        execute,
        kubectl=kubectl,
        expected_fingerprint=original_fingerprint,
        attempts=1,
        interval_seconds=0,
    )

    rotated_credential = secret_generator.token_urlsafe(32)
    while rotated_credential == original_credential:
        rotated_credential = secret_generator.token_urlsafe(32)
    rotated_fingerprint = hashlib.sha256(rotated_credential.encode("utf-8")).hexdigest()
    rotated_manifest = copy.deepcopy(original_manifest)
    rotated_data = rotated_manifest.get("stringData")
    if not isinstance(rotated_data, dict):
        raise LiveKindHelmSmokeError("runtime Secret rotation data is not mutable")
    rotated_data["vault-token"] = rotated_credential

    primary_error: Exception | None = None
    observed_rotated = False
    restored = False
    try:
        _apply_secret_manifest(execute, kubectl=kubectl, manifest=rotated_manifest)
        _wait_for_vault_manager_fingerprint(
            execute,
            kubectl=kubectl,
            expected_fingerprint=rotated_fingerprint,
            attempts=attempts,
            interval_seconds=interval_seconds,
        )
        observed_rotated = True
    except Exception as exc:
        primary_error = exc

    try:
        _apply_secret_manifest(execute, kubectl=kubectl, manifest=original_manifest)
        _wait_for_vault_manager_fingerprint(
            execute,
            kubectl=kubectl,
            expected_fingerprint=original_fingerprint,
            attempts=attempts,
            interval_seconds=interval_seconds,
        )
        restored = True
    except Exception as restore_exc:
        if primary_error is not None:
            raise LiveKindHelmSmokeError(
                "runtime Secret rotation failed and the original token could not be restored"
            ) from primary_error
        raise restore_exc
    if primary_error is not None:
        raise primary_error
    for component in ("api", "worker"):
        execute(
            [
                *kubectl,
                "wait",
                "--for=condition=Ready",
                "--timeout=90s",
                "pod",
                f"--selector=app.kubernetes.io/component={component}",
            ],
            timeout_seconds=105,
        )
    return {
        "runtime_components_recovered": ["api", "worker"],
        "fingerprint_changed": observed_rotated,
        "lexical_path_preserved": True,
        "manager_type": "VaultSecretManager",
        "original_restored": restored,
    }


def _apply_secret_manifest(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    manifest: Mapping[str, object],
) -> None:
    execute(
        [
            *kubectl,
            "apply",
            "--server-side",
            "--field-manager=hallu-defense-live-smoke",
            "--filename",
            "-",
        ],
        input_text=json.dumps(manifest, separators=(",", ":")),
        timeout_seconds=30,
    )


def _wait_for_vault_manager_fingerprint(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    expected_fingerprint: str,
    attempts: int,
    interval_seconds: float,
) -> None:
    if attempts < 1 or interval_seconds < 0:
        raise LiveKindHelmSmokeError(
            "runtime Secret rotation polling bounds are invalid"
        )
    for component in ("api", "worker"):
        for attempt in range(attempts):
            result = execute(
                [
                    *kubectl,
                    "exec",
                    f"deployment/{RELEASE_NAME}-{component}",
                    "--",
                    "python",
                    "-c",
                    VAULT_MANAGER_ROTATION_PROBE_SCRIPT,
                ],
                check=False,
                timeout_seconds=30,
            )
            if result.returncode == 0:
                try:
                    payload = json.loads(result.stdout.strip())
                except json.JSONDecodeError:
                    payload = None
                if payload == {
                    "lexical_path_preserved": True,
                    "manager_type": "VaultSecretManager",
                    "token_sha256": expected_fingerprint,
                }:
                    break
            if attempt + 1 < attempts:
                time.sleep(interval_seconds)
        else:
            raise LiveKindHelmSmokeError(
                f"{component} VaultSecretManager did not observe the expected "
                "projected-token revision"
            )


def _verify_console_oidc_runtime(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, object]:
    result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-console",
            "--",
            "node",
            "-e",
            CONSOLE_OIDC_RUNTIME_PROBE_SCRIPT,
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "Console OIDC runtime probe did not return JSON"
        ) from exc
    expected: dict[str, object] = {
        "api_audience": "hallu-defense-api",
        "api_origin": "https://api.kind.invalid",
        "auth_mode": "oidc",
        "environment": "production",
        "forbidden_env_absent": True,
        "http_status": 200,
        "issuer": "https://auth.kind.invalid/realms/hallu-defense",
        "public_origin": "https://console.kind.invalid",
        "required_roles": (
            "verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator"
        ),
        "roles_claim": "roles",
        "tenant_claim": "tenant_id",
    }
    if payload != expected:
        raise LiveKindHelmSmokeError(
            "Console runtime did not prove the exact production OIDC contract"
        )
    return expected


def _verify_worker_hybrid_readiness(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, bool]:
    execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-worker",
            "--",
            "python",
            "-m",
            "hallu_defense.worker",
            "--check-ready",
        ],
        timeout_seconds=30,
    )
    unavailable_script = """
from hallu_defense.services.rag_index import OpenSearchRagIndexBackend

backend = OpenSearchRagIndexBackend(
    endpoint="http://127.0.0.1:1",
    index_name="hallu_evidence",
    timeout_seconds=0.5,
)
backend.health_check()
"""
    unavailable = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-worker",
            "--",
            "python",
            "-c",
            unavailable_script,
        ],
        check=False,
        timeout_seconds=15,
    )
    if unavailable.returncode == 0:
        raise LiveKindHelmSmokeError(
            "worker OpenSearch health checker accepted an unreachable loopback endpoint"
        )
    return {
        "real_dependencies_ready": True,
        "unreachable_opensearch_rejected": True,
    }


def _verify_worker_metrics(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, object]:
    script = r"""
import json
import urllib.error
import urllib.request

from hallu_defense.config import RUNTIME_ROLE_WORKER, load_settings
from hallu_defense.services.secrets import create_secret_manager

worker_metrics_authenticated_probe = True
endpoint = "http://127.0.0.1:9090/metrics"
try:
    urllib.request.urlopen(endpoint, timeout=5)
except urllib.error.HTTPError as exc:
    unauthorized_status = exc.code
else:
    raise SystemExit("worker metrics accepted a request without Bearer auth")

settings = load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)
secret_name = settings.metrics_bearer_token_secret_name
if not secret_name:
    raise SystemExit("worker metrics token secret name is missing")
token = create_secret_manager(settings).get_secret(secret_name).reveal()
request = urllib.request.Request(
    endpoint,
    headers={"Authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    payload = response.read(1024 * 1024 + 1)
    status = response.status
    cache_control = response.headers.get("Cache-Control")
if len(payload) > 1024 * 1024 or b"hallu_ingestion_jobs_total" not in payload:
    raise SystemExit("worker metrics response is missing bounded ingestion metrics")
print(json.dumps({
    "authenticated_status": status,
    "cache_control": cache_control,
    "ingestion_metric_present": True,
    "unauthenticated_status": unauthorized_status,
}, sort_keys=True))
"""
    result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-worker",
            "--",
            "python",
            "-c",
            script,
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "worker metrics probe did not return JSON"
        ) from exc
    expected: dict[str, object] = {
        "authenticated_status": 200,
        "cache_control": "no-store",
        "ingestion_metric_present": True,
        "unauthenticated_status": 401,
    }
    if payload != expected:
        raise LiveKindHelmSmokeError(
            "worker metrics did not prove Bearer auth, no-store, and ingestion output"
        )
    return expected


def _verify_hybrid_lifecycle_tombstone(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, object]:
    result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            HYBRID_LIFECYCLE_TOMBSTONE_PROBE_SCRIPT,
        ],
        timeout_seconds=90,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "hybrid lifecycle tombstone probe did not return JSON"
        ) from exc
    expected: dict[str, object] = {
        "audit_parity": True,
        "backend": "hybrid",
        "external_deleted_count": 1,
        "journal_completed": True,
        "opensearch_after_delete": 0,
        "opensearch_after_reingest": 0,
        "pgvector_after_delete": 0,
        "pgvector_after_reingest": 0,
        "reingest_rejected": True,
        "tombstone_persisted": True,
    }
    if payload != expected:
        raise LiveKindHelmSmokeError(
            "hybrid lifecycle did not prove deletion parity, durable tombstone, "
            "and no-reingestion"
        )
    return expected


def _verify_opensearch_schema(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, object]:
    result = execute(
        [
            *kubectl,
            "logs",
            f"deployment/{RELEASE_NAME}-api",
            "--container",
            "bootstrap-opensearch-schema",
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "OpenSearch schema bootstrap did not return JSON"
        ) from exc
    expected_bootstrap = {
        "template_name": "hallu_evidence_template",
        "index_name": "hallu_evidence",
        "installed": True,
        "acknowledged": True,
        "schema_version": EXPECTED_OPENSEARCH_SCHEMA_VERSION,
        "schema_ready": True,
        "dry_run": False,
    }
    if not isinstance(payload, Mapping) or any(
        payload.get(key) != value for key, value in expected_bootstrap.items()
    ):
        raise LiveKindHelmSmokeError(
            "OpenSearch schema v3 provisioning/readback failed"
        )
    index_state = payload.get("index_state")
    if index_state not in {"absent", "compatible"}:
        raise LiveKindHelmSmokeError(
            "OpenSearch schema v3 index compatibility check failed"
        )

    health_result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            OPENSEARCH_SCHEMA_HEALTH_SCRIPT,
        ],
        timeout_seconds=30,
    )
    try:
        health_payload = json.loads(health_result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "OpenSearch schema/health readback did not return JSON"
        ) from exc
    if not isinstance(health_payload, Mapping):
        raise LiveKindHelmSmokeError("OpenSearch schema/health readback was invalid")
    if health_payload.get("template_replicas") != EXPECTED_OPENSEARCH_TEMPLATE_REPLICAS:
        raise LiveKindHelmSmokeError(
            "OpenSearch schema v3 template replica readback failed"
        )
    cluster_status = health_payload.get("cluster_status")
    cluster_timed_out = health_payload.get("cluster_timed_out")
    data_nodes = health_payload.get("data_nodes")
    if (
        cluster_status not in {"green", "yellow"}
        or cluster_timed_out is not False
        or not isinstance(data_nodes, int)
        or isinstance(data_nodes, bool)
        or data_nodes < 1
    ):
        raise LiveKindHelmSmokeError(
            "OpenSearch Kind cluster health requires green/yellow, no timeout, and >=1 data node"
        )
    transport_listeners = _verify_opensearch_transport_loopback(
        execute,
        kubectl=kubectl,
    )
    return {
        **expected_bootstrap,
        "index_state": index_state,
        "template_replicas": EXPECTED_OPENSEARCH_TEMPLATE_REPLICAS,
        "cluster_status": cluster_status,
        "cluster_timed_out": False,
        "data_nodes": data_nodes,
        "transport_9300_listeners": transport_listeners,
    }


def _verify_opensearch_transport_loopback(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> list[str]:
    script = r"""
import json
import ipaddress
import socket

opensearch_transport_loopback = True
listeners = []
for path in ("/proc/net/tcp", "/proc/net/tcp6"):
    with open(path, encoding="ascii") as stream:
        rows = stream.read().splitlines()[1:]
    for row in rows:
        fields = row.split()
        local_address, state = fields[1], fields[3]
        address_hex, port_hex = local_address.rsplit(":", maxsplit=1)
        if state != "0A" or int(port_hex, 16) != 9300:
            continue
        if path.endswith("tcp"):
            listeners.append(socket.inet_ntoa(bytes.fromhex(address_hex)[::-1]))
        else:
            packed = b"".join(
                bytes.fromhex(address_hex[index:index + 8])[::-1]
                for index in range(0, 32, 8)
            )
            listeners.append(str(ipaddress.IPv6Address(packed)))
print(json.dumps({"listeners": sorted(listeners)}, sort_keys=True))
"""
    result = execute(
        [
            *kubectl,
            "exec",
            f"statefulset/{RELEASE_NAME}-opensearch",
            "--",
            "python3",
            "-c",
            script,
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "OpenSearch transport listener readback did not return JSON"
        ) from exc
    raw_listeners = payload.get("listeners") if isinstance(payload, Mapping) else None
    if not isinstance(raw_listeners, list) or not raw_listeners:
        raise LiveKindHelmSmokeError(
            "OpenSearch transport port 9300 did not expose bounded listener evidence"
        )
    normalized: set[str] = set()
    for listener in raw_listeners:
        if not isinstance(listener, str):
            raise LiveKindHelmSmokeError(
                "OpenSearch transport port 9300 returned an invalid listener"
            )
        try:
            address = ipaddress.ip_address(listener)
        except ValueError:
            raise LiveKindHelmSmokeError(
                "OpenSearch transport port 9300 returned an invalid listener"
            ) from None
        if (
            isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
        ):
            address = address.ipv4_mapped
        if not address.is_loopback:
            raise LiveKindHelmSmokeError(
                "OpenSearch transport port 9300 must listen only on loopback"
            )
        normalized.add(str(address))
    return sorted(normalized)


def _verify_application_egress(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    probe_image: str = API_IMAGE,
    kubernetes_api_peers: Sequence[
        Mapping[str, object]
    ] = DEFAULT_KIND_KUBERNETES_API_PEERS,
) -> dict[str, object]:
    policy_result = execute(
        [*kubectl, "get", "networkpolicy", "--output=json"],
        timeout_seconds=30,
    )
    try:
        policy_payload = json.loads(policy_result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "NetworkPolicy inventory did not return JSON"
        ) from exc
    raw_items = (
        policy_payload.get("items") if isinstance(policy_payload, Mapping) else None
    )
    if not isinstance(raw_items, list):
        raise LiveKindHelmSmokeError("NetworkPolicy inventory did not contain items")
    policies_by_name = {
        str(metadata["name"]): item
        for item in raw_items
        if isinstance(item, Mapping)
        and isinstance((metadata := item.get("metadata")), Mapping)
        and isinstance(metadata.get("name"), str)
    }
    default_deny = policies_by_name.get(f"{RELEASE_NAME}-default-deny-ingress")
    default_deny_spec = (
        default_deny.get("spec") if isinstance(default_deny, Mapping) else None
    )
    # The Kubernetes API omits an explicitly empty ``ingress: []`` field when it
    # serializes NetworkPolicy objects.  Missing and empty are the same
    # default-deny semantic, but no additional spec fields are permitted here.
    if (
        not isinstance(default_deny_spec, Mapping)
        or set(default_deny_spec) - {"podSelector", "policyTypes", "ingress"}
        or default_deny_spec.get("podSelector") != {}
        or default_deny_spec.get("policyTypes") != ["Ingress"]
        or default_deny_spec.get("ingress", []) != []
    ):
        raise LiveKindHelmSmokeError(
            "application namespace default-deny ingress policy is missing or inexact"
        )
    policy_names = {
        "api": f"{RELEASE_NAME}-api-egress",
        "worker": f"{RELEASE_NAME}-worker-egress",
        "console": f"{RELEASE_NAME}-console-egress",
        "migrations": f"{RELEASE_NAME}-migrations-egress",
        "vault-bootstrap": f"{RELEASE_NAME}-vault-bootstrap-egress",
        "pgvector": f"{RELEASE_NAME}-pgvector-egress",
        "opensearch": f"{RELEASE_NAME}-opensearch-egress",
        "vault": f"{RELEASE_NAME}-vault-egress",
        "redis": f"{RELEASE_NAME}-redis",
    }
    expected_ingress = {
        "pgvector": (("api", "worker", "migrations"), 5432),
        "opensearch": (("api", "worker"), 9200),
        "vault": (("api", "worker", "vault-bootstrap", "redis"), 8200),
        "redis": (("api",), 6379),
    }
    try:
        application_namespace = kubectl[kubectl.index("--namespace") + 1]
    except (ValueError, IndexError) as exc:
        raise LiveKindHelmSmokeError(
            "kubectl command is missing its namespace"
        ) from exc
    expected_external_ingress = {
        "api": (
            (
                ("hallu-defense.openai.com/network-client", "api"),
                ("hallu-defense.openai.com/network-client", "metrics"),
            ),
            8000,
        ),
        "console": (
            (
                ("hallu-defense.openai.com/network-client", "console"),
                ("hallu-defense.openai.com/network-client", "metrics"),
            ),
            3000,
        ),
        "worker": (
            (("hallu-defense.openai.com/network-client", "metrics"),),
            9090,
        ),
    }
    policy_evidence: dict[str, object] = {
        "default-deny-ingress": {
            "name": f"{RELEASE_NAME}-default-deny-ingress",
            "ingress_rule_count": 0,
        }
    }
    for component, policy_name in policy_names.items():
        policy = policies_by_name.get(policy_name)
        if not isinstance(policy, Mapping):
            raise LiveKindHelmSmokeError(
                f"missing egress NetworkPolicy {policy_name} for {component}"
            )
        spec = policy.get("spec")
        if not isinstance(spec, Mapping):
            raise LiveKindHelmSmokeError(f"NetworkPolicy {policy_name} has no spec")
        expected_selector = {
            "matchLabels": {
                "app.kubernetes.io/name": RELEASE_NAME,
                "app.kubernetes.io/instance": RELEASE_NAME,
                "app.kubernetes.io/component": component,
            }
        }
        if spec.get("podSelector") != expected_selector:
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} does not select only {component}"
            )
        policy_types = spec.get("policyTypes")
        if not isinstance(policy_types, list) or "Egress" not in policy_types:
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} does not isolate egress"
            )
        ingress_sources: tuple[str, ...] = ()
        if component in expected_external_ingress:
            external_sources, ingress_port = expected_external_ingress[component]
            expected_ingress_rules = [
                {
                    "from": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": application_namespace
                                }
                            },
                            "podSelector": {"matchLabels": {label_key: label_value}},
                        }
                    ],
                    "ports": [{"protocol": "TCP", "port": ingress_port}],
                }
                for label_key, label_value in external_sources
            ]
            ingress_sources = tuple(
                f"{label_key}={label_value}"
                for label_key, label_value in external_sources
            )
            if (
                "Ingress" not in policy_types
                or spec.get("ingress") != expected_ingress_rules
            ):
                raise LiveKindHelmSmokeError(
                    f"NetworkPolicy {policy_name} external ingress allowlist is not exact"
                )
        elif component in expected_ingress:
            ingress_sources, ingress_port = expected_ingress[component]
            expected_ingress_rules = [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    "app.kubernetes.io/name": RELEASE_NAME,
                                    "app.kubernetes.io/instance": RELEASE_NAME,
                                    "app.kubernetes.io/component": source,
                                }
                            }
                        }
                        for source in ingress_sources
                    ],
                    "ports": [{"protocol": "TCP", "port": ingress_port}],
                }
            ]
            if (
                "Ingress" not in policy_types
                or spec.get("ingress") != expected_ingress_rules
            ):
                raise LiveKindHelmSmokeError(
                    f"NetworkPolicy {policy_name} ingress allowlist is not exact"
                )
        elif "Ingress" in policy_types or "ingress" in spec:
            raise LiveKindHelmSmokeError(
                f"egress-only NetworkPolicy {policy_name} must not alter ingress"
            )
        # Kubernetes omits an explicitly empty egress list in JSON.  With the
        # Egress policyType present, an omitted list is the canonical deny-all
        # representation and is equivalent to ``egress: []``.
        egress_rules = spec.get("egress", [])
        if not isinstance(egress_rules, list):
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} has invalid egress rules"
            )
        expected_console_egress = [
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "kube-system"
                            }
                        },
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }
                ],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            }
        ]
        if component == "console" and egress_rules != expected_console_egress:
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} must allow only cluster DNS in Kind"
            )
        if component in {"pgvector", "opensearch", "vault"} and egress_rules:
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} must deny all egress"
            )
        if component == "api":
            expected_api_egress = [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": "kube-system"
                                }
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                },
                *[
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {
                                        "app.kubernetes.io/name": RELEASE_NAME,
                                        "app.kubernetes.io/instance": RELEASE_NAME,
                                        "app.kubernetes.io/component": dependency,
                                    }
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": port}],
                    }
                    for dependency, port in (
                        ("pgvector", 5432),
                        ("vault", 8200),
                        ("redis", 6379),
                        ("opensearch", 9200),
                    )
                ],
                *[
                    {
                        "to": [{"ipBlock": {"cidr": str(peer["cidr"])}}],
                        "ports": [{"protocol": "TCP", "port": int(str(peer["port"]))}],
                    }
                    for peer in kubernetes_api_peers
                ],
            ]
            if egress_rules != expected_api_egress:
                raise LiveKindHelmSmokeError(
                    f"NetworkPolicy {policy_name} API egress allowlist is not exact"
                )
        if component == "worker" and any(
            isinstance(destination, Mapping) and "ipBlock" in destination
            for rule in egress_rules
            if isinstance(rule, Mapping)
            for destination in (
                rule.get("to") if isinstance(rule.get("to"), list) else []
            )
        ):
            raise LiveKindHelmSmokeError(
                f"NetworkPolicy {policy_name} must not allow Kubernetes API IP blocks"
            )
        policy_evidence[component] = {
            "name": policy_name,
            "egress_rule_count": len(egress_rules),
            "ingress_sources": list(ingress_sources),
        }

    python_script = """
import json
import os
import socket

network_policy_socket_probe = True

def connected(host, port):
    try:
        connection = socket.create_connection((host, port), timeout=2)
    except OSError:
        return False
    connection.close()
    return True

print(json.dumps({
    "internet_1_1_1_1": connected("1.1.1.1", 443),
    "kubernetes_api": connected(
        os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc"),
        int(os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")),
    ),
}, sort_keys=True))
"""
    probes: dict[str, object] = {}
    expected = {
        "api": {"internet_1_1_1_1": False, "kubernetes_api": True},
        "worker": {"internet_1_1_1_1": False, "kubernetes_api": False},
    }
    for component in ("api", "worker"):
        result = execute(
            [
                *kubectl,
                "exec",
                f"deployment/{RELEASE_NAME}-{component}",
                "--",
                "python",
                "-c",
                python_script,
            ],
            timeout_seconds=15,
        )
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                f"{component} application egress probe did not return JSON"
            ) from exc
        if payload != expected[component]:
            raise LiveKindHelmSmokeError(
                f"{component} application egress policy returned unexpected "
                f"bounded evidence: {json.dumps(payload, sort_keys=True)}"
            )
        probes[component] = payload

    console_script = """
const net = require("node:net");
const console_network_policy_socket_probe = true;

function connected(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(2000, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

(async () => {
  console.log(JSON.stringify({
    internet_1_1_1_1: await connected("1.1.1.1", 443),
  }));
})().catch(() => {
  process.exitCode = 1;
});
"""
    console_result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-console",
            "--",
            "node",
            "-e",
            console_script,
        ],
        timeout_seconds=15,
    )
    try:
        console_payload = json.loads(console_result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "console egress probe did not return JSON"
        ) from exc
    if console_payload != {"internet_1_1_1_1": False}:
        raise LiveKindHelmSmokeError(
            "Console OIDC egress allowlist permitted an unauthorized destination"
        )
    probes["console"] = console_payload
    probes["unauthorized_dependency_ingress"] = _verify_dependency_ingress_denial(
        execute,
        kubectl=kubectl,
        probe_image=probe_image,
    )
    return {"policies": policy_evidence, "probes": probes}


def _verify_dependency_ingress_denial(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    probe_image: str = API_IMAGE,
) -> dict[str, object]:
    pod_name = "hallu-network-ingress-probe"
    probe_names = [pod_name]
    opensearch_pod_ip = _selected_opensearch_pod_ip(execute, kubectl=kubectl)
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app.kubernetes.io/name": RELEASE_NAME,
                "app.kubernetes.io/instance": RELEASE_NAME,
                "app.kubernetes.io/component": "unauthorized-probe",
            },
        },
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "runAsGroup": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "probe",
                    "image": probe_image,
                    "imagePullPolicy": "Never",
                    "command": ["python", "-c", "import time; time.sleep(120)"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits": {"cpu": "100m", "memory": "64Mi"},
                    },
                }
            ],
        },
    }
    probe_error: Exception | None = None
    evidence: dict[str, object] | None = None
    try:
        execute(
            [*kubectl, "apply", "--filename", "-"],
            timeout_seconds=30,
            input_text=json.dumps(manifest, separators=(",", ":")),
        )
        execute(
            [
                *kubectl,
                "wait",
                "--for=condition=Ready",
                "--timeout=60s",
                f"pod/{pod_name}",
            ],
            timeout_seconds=75,
        )
        script = """
import json
import socket

unauthorized_dependency_ingress_probe = True

def connected(host, port):
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        return False
    connection.close()
    return True

print(json.dumps({
    "api": connected("hallu-defense-api", 8000),
    "console": connected("hallu-defense-console", 3000),
    "worker": connected("hallu-defense-worker", 9090),
    "pgvector": connected("hallu-defense-pgvector", 5432),
    "opensearch": connected("hallu-defense-opensearch", 9200),
    "opensearch_transport_pod_ip_9300": connected(__OPENSEARCH_POD_IP__, 9300),
    "vault": connected("hallu-defense-vault", 8200),
}, sort_keys=True))
""".replace("__OPENSEARCH_POD_IP__", json.dumps(opensearch_pod_ip))
        result = execute(
            [*kubectl, "exec", f"pod/{pod_name}", "--", "python", "-c", script],
            timeout_seconds=15,
        )
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            raise LiveKindHelmSmokeError(
                "unauthorized dependency ingress probe did not return JSON"
            ) from exc
        expected = {
            "api": False,
            "console": False,
            "worker": False,
            "opensearch": False,
            "opensearch_transport_pod_ip_9300": False,
            "pgvector": False,
            "vault": False,
        }
        if payload != expected:
            raise LiveKindHelmSmokeError(
                "an application workload accepted ingress from an unauthorized peer"
            )
        evidence = dict(expected)
        allowlist_script = """
import json
import socket
import time

application_ingress_allowlist_probe = True
expected = json.loads(__EXPECTED__)

def connected(host, port):
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        return False
    connection.close()
    return True

def snapshot():
    return {
        "api": connected("hallu-defense-api", 8000),
        "console": connected("hallu-defense-console", 3000),
        "worker": connected("hallu-defense-worker", 9090),
    }

for _ in range(15):
    actual = snapshot()
    if actual == expected:
        print(json.dumps(actual, sort_keys=True))
        break
    time.sleep(0.25)
else:
    raise SystemExit(
        "application ingress allowlist did not converge: "
        + json.dumps(actual, sort_keys=True)
    )
"""
        explicit_allowlists: dict[str, dict[str, bool]] = {}
        for label_value, expected_connections in (
            ("api", {"api": True, "console": False, "worker": False}),
            ("console", {"api": False, "console": True, "worker": False}),
            ("metrics", {"api": True, "console": True, "worker": True}),
        ):
            identity_pod_name = f"{pod_name}-{label_value}"
            identity_manifest = copy.deepcopy(manifest)
            identity_manifest["metadata"]["name"] = identity_pod_name
            identity_manifest["metadata"]["labels"][
                "hallu-defense.openai.com/network-client"
            ] = label_value
            probe_names.append(identity_pod_name)
            execute(
                [
                    *kubectl,
                    "apply",
                    "--filename",
                    "-",
                ],
                timeout_seconds=30,
                input_text=json.dumps(identity_manifest, separators=(",", ":")),
            )
            execute(
                [
                    *kubectl,
                    "wait",
                    "--for=condition=Ready",
                    "--timeout=60s",
                    f"pod/{identity_pod_name}",
                ],
                timeout_seconds=75,
            )
            allow_result = execute(
                [
                    *kubectl,
                    "exec",
                    f"pod/{identity_pod_name}",
                    "--",
                    "python",
                    "-c",
                    allowlist_script.replace(
                        "__EXPECTED__",
                        json.dumps(json.dumps(expected_connections, sort_keys=True)),
                    ),
                ],
                timeout_seconds=45,
            )
            try:
                allow_payload = json.loads(allow_result.stdout.strip())
            except json.JSONDecodeError as exc:
                raise LiveKindHelmSmokeError(
                    f"{label_value} ingress allowlist probe did not return JSON"
                ) from exc
            if allow_payload != expected_connections:
                raise LiveKindHelmSmokeError(
                    f"{label_value} ingress allowlist returned unexpected evidence"
                )
            explicit_allowlists[label_value] = expected_connections
        evidence["explicit_application_allowlists"] = explicit_allowlists
    except Exception as exc:
        probe_error = exc
    finally:
        delete_result = execute(
            [
                *kubectl,
                "delete",
                "pod",
                *probe_names,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=60s",
            ],
            check=False,
            timeout_seconds=75,
        )
        cleanup_error = None
        if delete_result.returncode != 0:
            cleanup_error = delete_result.stderr.strip() or "probe Pod delete failed"
        else:
            for deleted_probe_name in probe_names:
                absence_result = execute(
                    [*kubectl, "get", "pod", deleted_probe_name, "--output=name"],
                    check=False,
                    timeout_seconds=15,
                )
                if absence_result.returncode == 0:
                    cleanup_error = (
                        f"ingress probe Pod {deleted_probe_name} remained after delete"
                    )
                    break
        if cleanup_error is not None:
            if probe_error is None:
                raise LiveKindHelmSmokeError(cleanup_error)
            print(
                f"dependency ingress probe cleanup failed: {cleanup_error[:1000]}",
                file=sys.stderr,
            )
    if probe_error is not None:
        raise probe_error
    if evidence is None:
        raise LiveKindHelmSmokeError("dependency ingress probe produced no evidence")
    evidence["probe_pod_deleted"] = True
    return evidence


def _selected_opensearch_pod_ip(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> str:
    result = execute(
        [
            *kubectl,
            "get",
            "pods",
            "--selector",
            "app.kubernetes.io/component=opensearch",
            "--output=json",
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "OpenSearch Pod IP inventory did not return JSON"
        ) from exc
    items = payload.get("items") if isinstance(payload, Mapping) else None
    if (
        not isinstance(items, list)
        or len(items) != 1
        or not isinstance(items[0], Mapping)
    ):
        raise LiveKindHelmSmokeError(
            "OpenSearch Pod IP inventory must contain exactly one Pod"
        )
    status = items[0].get("status")
    pod_ip = status.get("podIP") if isinstance(status, Mapping) else None
    try:
        parsed = ipaddress.ip_address(pod_ip) if isinstance(pod_ip, str) else None
    except ValueError as exc:
        raise LiveKindHelmSmokeError("OpenSearch Pod IP was invalid") from exc
    if parsed is None or parsed.version != 4:
        raise LiveKindHelmSmokeError("OpenSearch Pod IP must be one valid IPv4 address")
    return str(parsed)


def _preflight_admission_policy(
    execute: CommandExecutor,
    *,
    context: str,
    namespace: str,
    kubeconfig: Path,
) -> None:
    rendered = execute(
        [
            "helm",
            "template",
            RELEASE_NAME,
            str(CHART_DIR),
            "--namespace",
            namespace,
            "--values",
            str(KIND_VALUES_PATH),
            "--show-only",
            "templates/sandbox-validating-admission-policy.yaml",
        ],
        timeout_seconds=120,
    )
    if "kind: ValidatingAdmissionPolicy" not in rendered.stdout:
        raise LiveKindHelmSmokeError(
            "admission preflight render did not contain the sandbox policy"
        )
    execute(
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "--context",
            context,
            "--namespace",
            namespace,
            "apply",
            "--server-side",
            "--dry-run=server",
            "--filename",
            "-",
        ],
        input_text=rendered.stdout,
        timeout_seconds=60,
    )


def _kind_secret_manifests(
    *,
    namespace: str,
    oidc_jwks: object,
) -> list[dict[str, object]]:
    vault_tls = _new_kind_vault_tls_material(namespace=namespace)
    redis_tls = _new_kind_redis_tls_material(namespace=namespace)
    runtime_postgres_dsn = (
        f"postgresql://prod_user:prod_pass@{RELEASE_NAME}-pgvector:5432/prod_db"
        "?sslmode=disable&gssencmode=disable"
    )
    vault_token = secret_generator.token_urlsafe(32)
    secret_data = (
        (
            f"{RELEASE_NAME}-runtime",
            {
                "keycloak-jwks.json": json.dumps(oidc_jwks, separators=(",", ":")),
                "vault-token": vault_token,
                "postgres-dsn": runtime_postgres_dsn,
            },
        ),
        (
            f"{RELEASE_NAME}-bootstrap",
            {"vault-token": vault_token},
        ),
        (
            f"{RELEASE_NAME}-migrations",
            {"migrations-postgres-dsn": runtime_postgres_dsn},
        ),
        (
            f"{RELEASE_NAME}-postgres",
            {
                "POSTGRES_USER": "prod_user",
                "POSTGRES_PASSWORD": "prod_pass",
                "POSTGRES_DB": "prod_db",
            },
        ),
        (
            f"{RELEASE_NAME}-kind-vault",
            {
                "root-token": vault_token,
                "ca.crt": vault_tls["ca_certificate"],
                "tls.crt": vault_tls["tls_certificate"],
                "tls.key": vault_tls["tls_private_key"],
            },
        ),
        (
            f"{RELEASE_NAME}-kind-redis-tls",
            {
                "ca.crt": redis_tls["ca_certificate"],
                "tls.crt": redis_tls["tls_certificate"],
                "tls.key": redis_tls["tls_private_key"],
            },
        ),
    )
    return [
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {"hallu-defense.openai.com/live-fixture": "true"},
            },
            "type": "Opaque",
            "stringData": string_data,
        }
        for name, string_data in secret_data
    ]


def _new_kind_oidc_material() -> dict[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    key_id = f"kind-{secret_generator.token_hex(8)}"
    jwks: dict[str, object] = {
        "keys": [
            {
                "kty": "RSA",
                "kid": key_id,
                "use": "sig",
                "alg": "RS256",
                "n": _base64url_uint(public_numbers.n),
                "e": _base64url_uint(public_numbers.e),
            }
        ]
    }
    now = int(datetime.now(timezone.utc).timestamp())
    header = _base64url_json({"alg": "RS256", "kid": key_id, "typ": "JWT"})
    claims = _base64url_json(
        {
            "iss": OIDC_ISSUER,
            "aud": OIDC_AUDIENCE,
            "sub": "kind-sandbox-runner",
            "tenant_id": "kind-smoke-tenant",
            "roles": ["sandbox_runner"],
            "iat": now,
            "nbf": now - 5,
            "exp": now + 900,
        }
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = private_key.sign(
        signing_input,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256(),
    )
    return {
        "jwks": jwks,
        "token": f"{header}.{claims}.{_base64url_bytes(signature)}",
    }


def _new_kind_vault_tls_material(*, namespace: str) -> dict[str, str]:
    return _new_kind_service_tls_material(
        namespace=namespace,
        service_name=f"{RELEASE_NAME}-vault",
        ca_common_name="hallu-kind-vault-ca",
    )


def _new_kind_redis_tls_material(*, namespace: str) -> dict[str, str]:
    return _new_kind_service_tls_material(
        namespace=namespace,
        service_name=f"{RELEASE_NAME}-redis",
        ca_common_name="hallu-kind-redis-ca",
    )


def _new_kind_service_tls_material(
    *,
    namespace: str,
    service_name: str,
    ca_common_name: str,
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service_name)])
    dns_names = (
        service_name,
        f"{service_name}.{namespace}",
        f"{service_name}.{namespace}.svc",
        f"{service_name}.{namespace}.svc.cluster.local",
    )
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return {
        "ca_certificate": ca_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii"),
        "tls_certificate": server_certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii"),
        "tls_private_key": server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    }


def _base64url_uint(value: int) -> str:
    payload = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return _base64url_bytes(payload)


def _base64url_json(value: Mapping[str, object]) -> str:
    return _base64url_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _base64url_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _verify_kind_redis(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> dict[str, bool]:
    script = """import json
import os
import socket

from redis import Redis
from redis.exceptions import AuthenticationError, ResponseError

from hallu_defense.api.dependencies import tool_validation_rate_limiter
from hallu_defense.services.rate_limit import RATE_LIMIT_KEY_PREFIX

tool_validation_rate_limiter.health_check()
rate_limit_eval_allowed = tool_validation_rate_limiter.allow(
    tenant_id="kind-redis-acl",
    subject_id="smoke-subject",
    tool_name="smoke-tool",
)
redis_client = tool_validation_rate_limiter._client
ca_path = os.environ["HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH"]
invalid_url = (
    "rediss://hallu-rate-limiter:" + ("0" * 64) + "@hallu-defense-redis:6379/0"
)
invalid_client = Redis.from_url(
    invalid_url,
    ssl_ca_certs=ca_path,
    ssl_cert_reqs="required",
    socket_connect_timeout=3,
    socket_timeout=3,
)
invalid_auth_rejected = False
try:
    invalid_client.ping()
except AuthenticationError:
    invalid_auth_rejected = True
finally:
    invalid_client.close()

acl_prefix_rejected = False
try:
    redis_client.eval(
        "return redis.call('INCR', KEYS[1])",
        1,
        "outside-rate-limit-prefix",
    )
except ResponseError:
    acl_prefix_rejected = True

acl_command_rejected = False
try:
    redis_client.set(RATE_LIMIT_KEY_PREFIX + "forbidden-set", "1")
except ResponseError:
    acl_command_rejected = True

plaintext_rejected = False
connection = socket.create_connection(("hallu-defense-redis", 6379), timeout=3)
try:
    connection.settimeout(3)
    connection.sendall(b"*1\\r\\n$4\\r\\nPING\\r\\n")
    try:
        plaintext_rejected = b"+PONG" not in connection.recv(128)
    except OSError:
        plaintext_rejected = True
finally:
    connection.close()

print(json.dumps({
    "acl_command_rejected": acl_command_rejected,
    "acl_prefix_rejected": acl_prefix_rejected,
    "invalid_auth_rejected": invalid_auth_rejected,
    "plaintext_rejected": plaintext_rejected,
    "rate_limit_eval_allowed": rate_limit_eval_allowed,
    "tls_ca_vault_health": True,
}, sort_keys=True))
"""
    result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            script,
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "kind Redis verification did not return JSON"
        ) from exc
    expected = {
        "acl_command_rejected": True,
        "acl_prefix_rejected": True,
        "invalid_auth_rejected": True,
        "plaintext_rejected": True,
        "rate_limit_eval_allowed": True,
        "tls_ca_vault_health": True,
    }
    if payload != expected:
        raise LiveKindHelmSmokeError("kind Redis TLS/AUTH/Vault verification failed")
    return expected


def _verify_api_sandbox_rbac(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    application_namespace: str,
    sandbox_namespace: str,
) -> dict[str, object]:
    command_prefix = list(kubectl)
    try:
        namespace_index = command_prefix.index("--namespace")
    except ValueError as exc:
        raise LiveKindHelmSmokeError(
            "kubectl command is missing its namespace"
        ) from exc
    del command_prefix[namespace_index : namespace_index + 2]
    service_account = (
        f"system:serviceaccount:{application_namespace}:{RELEASE_NAME}-api"
    )

    def can_i(
        namespace: str,
        verb: str,
        resource: str,
        subresource: str | None = None,
    ) -> bool:
        subresource_args = (
            [f"--subresource={subresource}"] if subresource is not None else []
        )
        result = execute(
            [
                *command_prefix,
                "--namespace",
                namespace,
                "auth",
                "can-i",
                verb,
                resource,
                *subresource_args,
                "--as",
                service_account,
            ],
            check=False,
            timeout_seconds=30,
        )
        answer = result.stdout.strip().lower()
        if answer not in {"yes", "no"}:
            raise LiveKindHelmSmokeError(
                "kubectl auth can-i returned invalid evidence for "
                f"{verb} {resource}{f'/{subresource}' if subresource else ''}"
            )
        if (answer == "yes") != (result.returncode == 0):
            raise LiveKindHelmSmokeError(
                "kubectl auth can-i exit status disagreed for "
                f"{verb} {resource}{f'/{subresource}' if subresource else ''}"
            )
        return answer == "yes"

    application_denials = {
        f"{verb}:{resource}{f'/{subresource}' if subresource else ''}": can_i(
            application_namespace, verb, resource, subresource
        )
        for verb, resource, subresource in (
            ("list", "pods", None),
            ("get", "pods", "log"),
            ("delete", "jobs.batch", None),
        )
    }
    if any(application_denials.values()):
        raise LiveKindHelmSmokeError(
            "API ServiceAccount unexpectedly has workload access in the application namespace"
        )
    sandbox_grants = {
        f"{verb}:{resource}{f'/{subresource}' if subresource else ''}": can_i(
            sandbox_namespace, verb, resource, subresource
        )
        for verb, resource, subresource in (
            ("create", "jobs.batch", None),
            ("get", "jobs.batch", None),
            ("delete", "jobs.batch", None),
            ("list", "pods", None),
            ("get", "pods", "log"),
            ("list", "networkpolicies.networking.k8s.io", None),
        )
    }
    if not all(sandbox_grants.values()):
        missing = sorted(
            name for name, allowed in sandbox_grants.items() if not allowed
        )
        raise LiveKindHelmSmokeError(
            "API ServiceAccount lacks expected sandbox namespace operations: "
            + json.dumps(missing)
        )
    return {
        "application_namespace_denied": {
            name: not allowed for name, allowed in application_denials.items()
        },
        "sandbox_namespace_allowed": sandbox_grants,
    }


def _verify_api_workspace_read_only(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
) -> bool:
    script = """
from pathlib import Path

api_workspace_read_only = True
target = Path("/workspace/smoke-repo/api-write-probe")
try:
    target.write_text("must-not-write", encoding="utf-8")
except OSError:
    print("api-workspace-read-only")
else:
    target.unlink(missing_ok=True)
    raise SystemExit("API workspace mount unexpectedly accepted a write")
"""
    result = execute(
        [
            *kubectl,
            "exec",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            script,
        ],
        timeout_seconds=30,
    )
    if result.stdout.strip() != "api-workspace-read-only":
        raise LiveKindHelmSmokeError(
            "API workspace read-only probe did not return deterministic evidence"
        )
    return True


def _verify_kubernetes_sandbox(
    execute: CommandExecutor,
    *,
    application_kubectl: Sequence[str],
    sandbox_kubectl: Sequence[str],
    application_namespace: str,
    sandbox_namespace: str,
    bearer_token: str,
    sandbox_image: str = SANDBOX_IMAGE,
) -> dict[str, object]:
    admission = _assert_admission_rejects_malicious_job(
        execute,
        kubectl=sandbox_kubectl,
        application_namespace=application_namespace,
        sandbox_image=sandbox_image,
    )
    rbac = _verify_api_sandbox_rbac(
        execute,
        kubectl=application_kubectl,
        application_namespace=application_namespace,
        sandbox_namespace=sandbox_namespace,
    )
    api_workspace_read_only = _verify_api_workspace_read_only(
        execute,
        kubectl=application_kubectl,
    )

    successful_run = _repo_checks_request(
        execute,
        kubectl=application_kubectl,
        bearer_token=bearer_token,
        payload={
            "repo_ref": "smoke-repo",
            "commands": [
                "python probe.py",
                "python -c \"print('sandbox-second')\"",
            ],
            "network_policy": "deny",
        },
        expected_status=200,
    )
    if successful_run.get("exit_codes") != [7, 0]:
        raise LiveKindHelmSmokeError(
            "sandbox smoke did not preserve both batched command exit codes: "
            + json.dumps(successful_run.get("exit_codes"))
        )
    stdout = successful_run.get("stdout")
    stderr = successful_run.get("stderr")
    artifacts = successful_run.get("artifacts")
    if (
        not isinstance(stdout, list)
        or not stdout
        or "sandbox-stdout" not in str(stdout[0])
        or len(stdout) != 2
        or "sandbox-second" not in str(stdout[1])
    ):
        raise LiveKindHelmSmokeError("sandbox smoke did not capture stdout")
    if (
        not isinstance(stderr, list)
        or not stderr
        or "sandbox-stderr" not in str(stderr[0])
    ):
        raise LiveKindHelmSmokeError("sandbox smoke did not capture stderr")
    if (
        not isinstance(artifacts, list)
        or "artifacts/sandbox-smoke.txt" not in artifacts
    ):
        raise LiveKindHelmSmokeError(
            "sandbox smoke did not report its generated artifact"
        )
    evidence = successful_run.get("evidence")
    if not isinstance(evidence, list):
        raise LiveKindHelmSmokeError("sandbox smoke did not return inspection evidence")
    inspection = next(
        (
            item.get("structured_content")
            for item in evidence
            if isinstance(item, Mapping)
            and item.get("source_ref") == "sandbox://inspection"
        ),
        None,
    )
    git_report = inspection.get("git") if isinstance(inspection, Mapping) else None
    if (
        not isinstance(git_report, Mapping)
        or git_report.get("is_repository") is not True
    ):
        raise LiveKindHelmSmokeError(
            "sandbox fixture was not inspected as a real Git repository"
        )
    if git_report.get("errors") != []:
        raise LiveKindHelmSmokeError(
            "API runtime Git inspection reported errors: "
            + json.dumps(git_report.get("errors"), sort_keys=True)[:1000]
        )

    escaped = _repo_checks_request(
        execute,
        kubectl=application_kubectl,
        bearer_token=bearer_token,
        payload={
            "repo_ref": "../",
            "commands": ["python probe.py"],
            "network_policy": "deny",
        },
        expected_status=400,
    )
    if (
        set(escaped) != {"trace_id", "error", "message", "details"}
        or not isinstance(escaped.get("trace_id"), str)
        or not escaped["trace_id"]
        or escaped.get("error") != "http_400"
        or escaped.get("details") != {}
        or "escapes the configured workspace"
        not in str(escaped.get("message", ""))
    ):
        raise LiveKindHelmSmokeError(
            "sandbox path escape was not rejected by the workspace guard"
        )

    timeout_run, cleanup_evidence = _repo_checks_request_with_cleanup_evidence(
        execute,
        kubectl=application_kubectl,
        bearer_token=bearer_token,
        payload={
            "repo_ref": "smoke-repo",
            "commands": ["python timeout.py"],
            "network_policy": "deny",
        },
        sandbox_namespace=sandbox_namespace,
        expected_status=200,
    )
    if timeout_run.get("exit_codes") != [SANDBOX_TIMEOUT_RETURN_CODE]:
        raise LiveKindHelmSmokeError(
            "sandbox timeout did not return the bounded timeout code"
        )
    timeout_stderr = timeout_run.get("stderr")
    if (
        not isinstance(timeout_stderr, list)
        or not timeout_stderr
        or "timed out" not in str(timeout_stderr[0])
    ):
        raise LiveKindHelmSmokeError("sandbox timeout did not return timeout evidence")

    egress_run = _repo_checks_request(
        execute,
        kubectl=application_kubectl,
        bearer_token=bearer_token,
        payload={
            "repo_ref": "smoke-repo",
            "commands": ["python egress.py"],
            "network_policy": "deny",
        },
        expected_status=200,
    )
    egress_stdout = egress_run.get("stdout")
    egress_stderr = egress_run.get("stderr")
    if isinstance(egress_stderr, list) and any(
        "egress-unexpectedly-allowed" in str(item) for item in egress_stderr
    ):
        raise LiveKindHelmSmokeError(
            "sandbox egress unexpectedly reached the external endpoint"
        )
    if egress_run.get("exit_codes") != [0] or (
        not isinstance(egress_stdout, list)
        or not egress_stdout
        or "egress-blocked" not in str(egress_stdout[0])
    ):
        raise LiveKindHelmSmokeError(
            "kindnet did not produce real failed egress evidence: "
            + json.dumps(
                {
                    "exit_codes": egress_run.get("exit_codes"),
                    "stdout": egress_stdout,
                    "stderr": egress_stderr,
                },
                sort_keys=True,
            )[:1000]
        )

    residual_jobs = _assert_empty_sandbox_workload_inventory(
        execute,
        kubectl=sandbox_kubectl,
        resource="jobs",
    )
    residual_pods = _assert_empty_sandbox_workload_inventory(
        execute,
        kubectl=sandbox_kubectl,
        resource="pods",
    )

    return {
        "admission": admission,
        "rbac": rbac,
        "api_workspace_read_only": api_workspace_read_only,
        "admission_rejected_malicious_job": True,
        "admission_accepted_backend_job": True,
        "admission_accepted_equivalent_quantities": True,
        "exit_code": 7,
        "batched_commands": 2,
        "stdout": "sandbox-stdout",
        "stderr": "sandbox-stderr",
        "artifact": "artifacts/sandbox-smoke.txt",
        "path_escape_rejected": True,
        "timeout_exit_code": SANDBOX_TIMEOUT_RETURN_CODE,
        "cleanup": cleanup_evidence,
        "egress_blocked_by_kindnet": True,
        "residual_jobs": residual_jobs,
        "residual_pods": residual_pods,
    }


def _assert_empty_sandbox_workload_inventory(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    resource: str,
) -> int:
    if resource not in {"jobs", "pods"}:
        raise ValueError("sandbox inventory resource must be jobs or pods")
    result = execute(
        [
            *kubectl,
            "get",
            resource,
            "--selector",
            SANDBOX_JOB_LABEL,
            "--output=json",
        ],
        timeout_seconds=30,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            f"sandbox residual {resource} check did not return JSON"
        ) from exc
    items = payload.get("items") if isinstance(payload, Mapping) else None
    if not isinstance(items, list):
        raise LiveKindHelmSmokeError(
            f"sandbox residual {resource} inventory did not contain an items list"
        )
    if items:
        raise LiveKindHelmSmokeError(
            f"sandbox execution left residual Kubernetes {resource}"
        )
    return 0


def _assert_admission_rejects_malicious_job(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    application_namespace: str,
    sandbox_image: str = SANDBOX_IMAGE,
) -> dict[str, object]:
    try:
        namespace = kubectl[kubectl.index("--namespace") + 1]
    except (ValueError, IndexError) as exc:
        raise LiveKindHelmSmokeError(
            "kubectl command is missing its namespace"
        ) from exc
    service_account = (
        f"system:serviceaccount:{application_namespace}:{RELEASE_NAME}-api"
    )
    policy_name = _sandbox_admission_policy_name(
        application_namespace,
        namespace,
    )
    activation = _wait_for_sandbox_admission_policy(
        execute,
        kubectl=kubectl,
        namespace=namespace,
        service_account=service_account,
        policy_name=policy_name,
        sandbox_image=sandbox_image,
    )
    valid_manifest = _sandbox_admission_valid_manifest(
        namespace,
        name="hallu-sandbox-admission-valid",
        image=sandbox_image,
    )
    valid_result = execute(
        [
            *kubectl,
            "--as",
            service_account,
            "create",
            "--dry-run=server",
            "--output=name",
            "--filename",
            "-",
        ],
        check=False,
        timeout_seconds=30,
        input_text=json.dumps(valid_manifest, separators=(",", ":")),
    )
    if valid_result.returncode != 0:
        denial = f"{valid_result.stdout}\n{valid_result.stderr}".strip()
        denial = JWT_PATTERN.sub("<redacted-jwt>", denial)[:4_000]
        raise LiveKindHelmSmokeError(
            "ValidatingAdmissionPolicy rejected the exact KubernetesJobBackend manifest"
            + (f": {denial}" if denial else "")
        )
    equivalent_manifest = _sandbox_admission_equivalent_quantity_manifest(
        namespace,
        image=sandbox_image,
    )
    equivalent_result = execute(
        [
            *kubectl,
            "--as",
            service_account,
            "create",
            "--dry-run=server",
            "--output=name",
            "--filename",
            "-",
        ],
        check=False,
        timeout_seconds=30,
        input_text=json.dumps(equivalent_manifest, separators=(",", ":")),
    )
    if equivalent_result.returncode != 0:
        denial = f"{equivalent_result.stdout}\n{equivalent_result.stderr}".strip()
        denial = JWT_PATTERN.sub("<redacted-jwt>", denial)[:4_000]
        raise LiveKindHelmSmokeError(
            "ValidatingAdmissionPolicy rejected semantically equivalent quantities"
            + (f": {denial}" if denial else "")
        )
    probes = _sandbox_admission_probe_manifests(namespace, image=sandbox_image)
    for job_name, manifest in probes:
        result = execute(
            [
                *kubectl,
                "--as",
                service_account,
                "create",
                "--dry-run=server",
                "--output=name",
                "--filename",
                "-",
            ],
            check=False,
            timeout_seconds=30,
            input_text=json.dumps(manifest, separators=(",", ":")),
        )
        if result.returncode == 0:
            raise LiveKindHelmSmokeError(
                f"ValidatingAdmissionPolicy allowed malicious sandbox Job {job_name}"
            )
        denial = f"{result.stdout}\n{result.stderr}"
        if policy_name not in denial:
            denial = JWT_PATTERN.sub("<redacted-jwt>", denial).strip()[:4_000]
            raise LiveKindHelmSmokeError(
                f"malicious Job {job_name} was rejected without evidence from the "
                "sandbox admission policy" + (f": {denial}" if denial else "")
            )
    return {
        **activation,
        "exact_backend_manifest_accepted": True,
        "equivalent_quantities_accepted": True,
        "malicious_jobs_denied": len(probes),
    }


def _wait_for_sandbox_admission_policy(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    namespace: str,
    service_account: str,
    policy_name: str,
    sandbox_image: str = SANDBOX_IMAGE,
) -> dict[str, object]:
    activation_manifest = dict(
        _sandbox_admission_probe_manifests(namespace, image=sandbox_image)
    )["hallu-sandbox-admission-finalizer"]
    last_detail = ""
    for _ in range(ADMISSION_POLICY_ACTIVATION_ATTEMPTS):
        policy_result = execute(
            [
                *kubectl,
                "get",
                "validatingadmissionpolicy",
                policy_name,
                "--output=json",
            ],
            check=False,
            timeout_seconds=30,
        )
        if policy_result.returncode == 0:
            try:
                policy = json.loads(policy_result.stdout)
            except json.JSONDecodeError:
                policy = {}
            metadata = policy.get("metadata") if isinstance(policy, Mapping) else None
            status = policy.get("status") if isinstance(policy, Mapping) else None
            generation = (
                metadata.get("generation") if isinstance(metadata, Mapping) else None
            )
            observed = (
                status.get("observedGeneration")
                if isinstance(status, Mapping)
                else None
            )
            if (
                isinstance(generation, int)
                and generation > 0
                and observed == generation
            ):
                activation_result = execute(
                    [
                        *kubectl,
                        "--as",
                        service_account,
                        "create",
                        "--dry-run=server",
                        "--output=name",
                        "--filename",
                        "-",
                    ],
                    check=False,
                    timeout_seconds=30,
                    input_text=json.dumps(activation_manifest, separators=(",", ":")),
                )
                denial = f"{activation_result.stdout}\n{activation_result.stderr}"
                if activation_result.returncode != 0 and policy_name in denial:
                    return {
                        "policy": policy_name,
                        "generation": generation,
                        "observed_generation": observed,
                    }
                last_detail = denial.strip()
            else:
                last_detail = (
                    f"generation={generation!r}, observedGeneration={observed!r}"
                )
        else:
            last_detail = f"{policy_result.stdout}\n{policy_result.stderr}".strip()
        time.sleep(ADMISSION_POLICY_ACTIVATION_INTERVAL_SECONDS)
    last_detail = JWT_PATTERN.sub("<redacted-jwt>", last_detail)[:4_000]
    raise LiveKindHelmSmokeError(
        "sandbox ValidatingAdmissionPolicy generation did not become active"
        + (f": {last_detail}" if last_detail else "")
    )


def _sandbox_admission_probe_manifests(
    namespace: str,
    *,
    image: str = SANDBOX_IMAGE,
) -> list[tuple[str, dict[str, object]]]:
    base = _sandbox_admission_valid_manifest(
        namespace,
        name="hallu-sandbox-admission-base",
        image=image,
    )
    probes: list[tuple[str, dict[str, object]]] = []

    privileged = _named_probe(base, "hallu-sandbox-admission-privileged")
    privileged_pod = _probe_pod_spec(privileged)
    privileged_runner = _probe_containers(privileged_pod)[0]
    privileged_security = cast(dict[str, object], privileged_runner["securityContext"])
    privileged_security["privileged"] = True
    privileged_security["allowPrivilegeEscalation"] = True
    privileged_runner["image"] = "busybox:latest"
    cast(list[dict[str, object]], privileged_pod["volumes"]).append(
        {"name": "host", "hostPath": {"path": "/"}}
    )
    cast(list[dict[str, object]], privileged_runner["volumeMounts"]).append(
        {"name": "host", "mountPath": "/host"}
    )
    probes.append(("hallu-sandbox-admission-privileged", privileged))

    secret_env = _named_probe(base, "hallu-sandbox-admission-secret-env")
    _probe_containers(_probe_pod_spec(secret_env))[0]["envFrom"] = [
        {"secretRef": {"name": "forbidden-secret"}}
    ]
    probes.append(("hallu-sandbox-admission-secret-env", secret_env))

    workspace_root = _named_probe(base, "hallu-sandbox-admission-workspace-root")
    workspace_runner = _probe_containers(_probe_pod_spec(workspace_root))[0]
    cast(list[dict[str, object]], workspace_runner["volumeMounts"]).append(
        {"name": "workspace", "mountPath": "/workspace-root"}
    )
    probes.append(("hallu-sandbox-admission-workspace-root", workspace_root))

    writable_source = _named_probe(base, "hallu-sandbox-admission-source-rw")
    writable_runner = _probe_containers(_probe_pod_spec(writable_source))[0]
    source_mount = next(
        mount
        for mount in cast(list[dict[str, object]], writable_runner["volumeMounts"])
        if mount["name"] == "source"
    )
    source_mount["readOnly"] = False
    probes.append(("hallu-sandbox-admission-source-rw", writable_source))

    unbounded = _named_probe(base, "hallu-sandbox-admission-unbounded")
    unbounded_runner = _probe_containers(_probe_pod_spec(unbounded))[0]
    resources = cast(dict[str, object], unbounded_runner["resources"])
    limits = cast(dict[str, object], resources["limits"])
    limits.update({"cpu": "1001m", "memory": "513Mi"})
    unbounded_volumes = cast(
        list[dict[str, object]], _probe_pod_spec(unbounded)["volumes"]
    )
    results_volume = next(
        volume for volume in unbounded_volumes if volume["name"] == "results"
    )
    cast(dict[str, object], results_volume["emptyDir"])["sizeLimit"] = "1024Mi"
    probes.append(("hallu-sandbox-admission-unbounded", unbounded))

    unmasked = _named_probe(base, "hallu-sandbox-admission-unmasked")
    unmasked_pod = _probe_pod_spec(unmasked)
    unmasked_pod["hostUsers"] = False
    unmasked_runner = _probe_containers(unmasked_pod)[0]
    cast(dict[str, object], unmasked_runner["securityContext"])["procMount"] = (
        "Unmasked"
    )
    probes.append(("hallu-sandbox-admission-unmasked", unmasked))

    controls = _named_probe(base, "hallu-sandbox-admission-controls")
    controls_metadata = cast(dict[str, object], controls["metadata"])
    cast(dict[str, object], controls_metadata["annotations"])["unexpected"] = "true"
    controls_spec = cast(dict[str, object], controls["spec"])
    controls_spec["suspend"] = True
    controls_runner = _probe_containers(_probe_pod_spec(controls))[0]
    controls_runner["ports"] = [{"containerPort": 9000, "hostPort": 9000}]
    probes.append(("hallu-sandbox-admission-controls", controls))

    entrypoint = _named_probe(base, "hallu-sandbox-admission-entrypoint")
    entrypoint_runner = _probe_containers(_probe_pod_spec(entrypoint))[0]
    entrypoint_runner["command"] = ["python", "-c"]
    entrypoint_runner["args"] = ["print('bypass')"]
    entrypoint_runner["stdin"] = True
    probes.append(("hallu-sandbox-admission-entrypoint", entrypoint))

    lifecycle = _named_probe(base, "hallu-sandbox-admission-lifecycle")
    lifecycle_runner = _probe_containers(_probe_pod_spec(lifecycle))[0]
    lifecycle_runner["lifecycle"] = {
        "postStart": {"exec": {"command": ["python", "-c", "print('bypass')"]}}
    }
    probes.append(("hallu-sandbox-admission-lifecycle", lifecycle))

    for probe_field in ("startupProbe", "livenessProbe", "readinessProbe"):
        probe_name = probe_field.removesuffix("Probe").lower()
        manifest_name = f"hallu-sandbox-admission-{probe_name}-probe"
        probe_manifest = _named_probe(base, manifest_name)
        probe_runner = _probe_containers(_probe_pod_spec(probe_manifest))[0]
        probe_runner[probe_field] = {
            "exec": {"command": ["python", "-c", "print('bypass')"]},
            "periodSeconds": 1,
        }
        probes.append((manifest_name, probe_manifest))

    supplemental = _named_probe(base, "hallu-sandbox-admission-groups")
    supplemental_pod = _probe_pod_spec(supplemental)
    cast(dict[str, object], supplemental_pod["securityContext"])[
        "supplementalGroups"
    ] = [0]
    probes.append(("hallu-sandbox-admission-groups", supplemental))

    selector = _named_probe(base, "hallu-sandbox-admission-selector")
    selector_spec = cast(dict[str, object], selector["spec"])
    selector_spec["manualSelector"] = True
    selector_spec["selector"] = {
        "matchLabels": {"hallu-defense.openai.com/sandbox": "true"}
    }
    probes.append(("hallu-sandbox-admission-selector", selector))

    finalizer = _named_probe(base, "hallu-sandbox-admission-finalizer")
    finalizer_metadata = cast(dict[str, object], finalizer["metadata"])
    finalizer_metadata["finalizers"] = ["hallu-defense.openai.com/stuck"]
    finalizer_metadata["generateName"] = "hallu-sandbox-attacker-"
    probes.append(("hallu-sandbox-admission-finalizer", finalizer))

    return probes


def _sandbox_admission_valid_manifest(
    namespace: str,
    *,
    name: str,
    image: str = SANDBOX_IMAGE,
) -> dict[str, object]:
    from hallu_defense.services.sandbox_kubernetes import (
        KubernetesApiTransport,
        KubernetesJobBackend,
    )

    with tempfile.TemporaryDirectory(prefix="hallu-admission-probe-") as temp_dir:
        workspace = Path(temp_dir)
        backend = KubernetesJobBackend(
            image=image,
            namespace=namespace,
            pvc_name=f"{RELEASE_NAME}-sandbox-workspace",
            workspace_root=workspace,
            workspace_mount_path="/workspace",
            network_policy_name=f"{RELEASE_NAME}-sandbox-deny-egress",
            memory_mb=512,
            cpus=1,
            pids_limit=256,
            poll_interval_seconds=0.25,
            job_ttl_seconds=60,
            api_request_timeout_seconds=5,
            setup_grace_seconds=15,
            timeout_grace_seconds=2,
            transport=cast(KubernetesApiTransport, None),
        )
        base = backend.build_job_manifest(
            job_name=name,
            argv=["python", "probe.py"],
            workspace_sub_path="smoke-repo",
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=12_000,
        )
    return base


def _sandbox_admission_equivalent_quantity_manifest(
    namespace: str,
    *,
    image: str = SANDBOX_IMAGE,
) -> dict[str, object]:
    manifest = _sandbox_admission_valid_manifest(
        namespace,
        name="hallu-sandbox-admission-equivalent-quantities",
        image=image,
    )
    pod_spec = _probe_pod_spec(manifest)
    for container in _probe_containers(pod_spec):
        resources = cast(dict[str, object], container["resources"])
        requests = cast(dict[str, object], resources["requests"])
        limits = cast(dict[str, object], resources["limits"])
        if container["name"] == "runner":
            requests.update({"cpu": "1000m", "memory": "524288Ki"})
            limits.update({"cpu": "1000m", "memory": "524288Ki"})
        else:
            requests.update({"cpu": "0.01", "memory": "16384Ki"})
            limits.update({"cpu": "0.1", "memory": "65536Ki"})
    volumes = cast(list[dict[str, object]], pod_spec["volumes"])
    for volume in volumes:
        if volume["name"] == "results":
            cast(dict[str, object], volume["emptyDir"])["sizeLimit"] = "1024Ki"
        elif volume["name"] == "workspace":
            cast(dict[str, object], volume["emptyDir"])["sizeLimit"] = "524288Ki"
        elif volume["name"] == "tmp":
            cast(dict[str, object], volume["emptyDir"])["sizeLimit"] = "65536Ki"
    return manifest


def _named_probe(
    manifest: Mapping[str, object],
    name: str,
) -> dict[str, object]:
    probe = cast(dict[str, object], copy.deepcopy(manifest))
    cast(dict[str, object], probe["metadata"])["name"] = name
    return probe


def _probe_pod_spec(manifest: Mapping[str, object]) -> dict[str, object]:
    spec = cast(dict[str, object], manifest["spec"])
    template = cast(dict[str, object], spec["template"])
    return cast(dict[str, object], template["spec"])


def _probe_containers(pod_spec: Mapping[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], pod_spec["containers"])


def _sandbox_admission_policy_name(
    application_namespace: str,
    sandbox_namespace: str,
) -> str:
    identity = f"{application_namespace}/{sandbox_namespace}"
    namespace_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
    prefix = RELEASE_NAME[:40].rstrip("-")
    return f"{prefix}-sandbox-jobs-{namespace_hash}"[:63].rstrip("-")


def _sandbox_payload_command_count(payload: Mapping[str, object]) -> int:
    commands = payload.get("commands")
    if (
        not isinstance(commands, Sequence)
        or isinstance(commands, (str, bytes))
        or not all(isinstance(command, str) and command for command in commands)
    ):
        raise LiveKindHelmSmokeError(
            "sandbox request commands must be a non-empty sequence of strings"
        )
    command_count = len(commands)
    _sandbox_supported_request_path_seconds(
        command_count,
        SANDBOX_CLEANUP_GRACE_SECONDS,
    )
    return command_count


def _repo_checks_request(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    bearer_token: str,
    payload: Mapping[str, object],
    expected_status: int,
) -> Mapping[str, object]:
    command_count = _sandbox_payload_command_count(payload)
    request_timeout_seconds = _sandbox_request_timeout_seconds(
        command_count,
        SANDBOX_CLEANUP_GRACE_SECONDS,
    )
    request_input = json.dumps(
        {"token": bearer_token, "body": payload},
        separators=(",", ":"),
    )
    script = Template(
        """import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

request_input = json.loads(sys.stdin.read())
request = Request(
    "http://127.0.0.1:8000/repo/checks/run",
    data=json.dumps(request_input["body"]).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + request_input["token"],
        "Content-Type": "application/json",
    },
    method="POST",
)
try:
    with urlopen(request, timeout=$request_timeout_seconds) as response:
        status = response.status
        body = response.read().decode("utf-8")
except HTTPError as exc:
    status = exc.code
    body = exc.read().decode("utf-8")
print(json.dumps({"status": status, "body": body}, separators=(",", ":")))
"""
    ).substitute(request_timeout_seconds=request_timeout_seconds)
    result = execute(
        [
            *kubectl,
            "exec",
            "--stdin",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            script,
        ],
        timeout_seconds=_sandbox_request_exec_timeout_seconds(
            command_count,
            SANDBOX_CLEANUP_GRACE_SECONDS,
        ),
        input_text=request_input,
    )
    envelope = _decode_repo_checks_envelope(
        result.stdout, expected_status=expected_status
    )
    return _decode_repo_checks_body(envelope)


SANDBOX_CLEANUP_UID_PROBE_TEMPLATE = Template(
    r"""import json
import os
import ssl
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

request_input = json.loads(sys.stdin.read())
namespace = request_input["sandbox_namespace"]
cleanup_grace_seconds = request_input["cleanup_grace_seconds"]
if (
    not isinstance(namespace, str)
    or not namespace
    or isinstance(cleanup_grace_seconds, bool)
    or not isinstance(cleanup_grace_seconds, int)
    or not $cleanup_grace_min_seconds <= cleanup_grace_seconds <= $cleanup_grace_max_seconds
):
    raise RuntimeError("sandbox cleanup probe input was invalid")

service_host = os.environ["KUBERNETES_SERVICE_HOST"]
service_port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
if ":" in service_host and not service_host.startswith("["):
    service_host = "[" + service_host + "]"
api_root = "https://" + service_host + ":" + service_port
service_account_root = "/run/hallu-defense/kubernetes"
with open(service_account_root + "/token", encoding="utf-8") as token_file:
    service_account_token = token_file.read().strip()
if not service_account_token:
    raise RuntimeError("sandbox cleanup probe service account token was empty")
tls_context = ssl.create_default_context(cafile=service_account_root + "/ca.crt")


def kube_json(
    path,
    *,
    allow_not_found=False,
    timeout_seconds=$kube_api_request_timeout_seconds,
):
    request = Request(
        api_root + path,
        headers={"Authorization": "Bearer " + service_account_token},
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout_seconds, context=tls_context) as response:
            if response.status != 200:
                raise RuntimeError("Kubernetes cleanup observation returned non-200")
            payload = json.load(response)
    except HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        raise RuntimeError("Kubernetes cleanup observation failed") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Kubernetes cleanup observation was not an object")
    return payload


def pod_inventory(*, timeout_seconds=$kube_api_request_timeout_seconds):
    payload = kube_json(
        "/api/v1/namespaces/" + quote(namespace, safe="") + "/pods",
        timeout_seconds=timeout_seconds,
    )
    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Kubernetes Pod inventory did not contain an items list")
    inventory = []
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError("Kubernetes Pod inventory contained a non-object")
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            raise RuntimeError("Kubernetes Pod metadata was invalid")
        pod_uid = metadata.get("uid")
        pod_name = metadata.get("name")
        labels = metadata.get("labels", {})
        owners = metadata.get("ownerReferences", [])
        if (
            not isinstance(pod_uid, str)
            or not pod_uid
            or not isinstance(pod_name, str)
            or not pod_name
            or not isinstance(labels, dict)
            or not isinstance(owners, list)
            or any(not isinstance(owner, dict) for owner in owners)
        ):
            raise RuntimeError("Kubernetes Pod identity was invalid")
        inventory.append(
            {
                "uid": pod_uid,
                "name": pod_name,
                "labels": labels,
                "owners": owners,
            }
        )
    return inventory


before_uids = {
    pod["uid"]
    for pod in pod_inventory(
        timeout_seconds=$initial_inventory_allowance_seconds
    )
}
response_state = {}
request_done = threading.Event()


def send_repo_request():
    request = Request(
        "http://127.0.0.1:8000/repo/checks/run",
        data=json.dumps(request_input["body"]).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + request_input["token"],
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=$request_timeout_seconds) as response:
            response_state["status"] = response.status
            response_state["body"] = response.read().decode("utf-8")
    except HTTPError as exc:
        response_state["status"] = exc.code
        response_state["body"] = exc.read().decode("utf-8")
    except BaseException as exc:
        response_state["error"] = type(exc).__name__
    finally:
        request_done.set()


request_thread = threading.Thread(target=send_repo_request, name="sandbox-cleanup-probe")
request_thread.start()
target_job_name = None
target_job_uid = None
capture_deadline = time.monotonic() + $job_capture_allowance_seconds
try:
    while target_job_uid is None:
        capture_remaining = capture_deadline - time.monotonic()
        if capture_remaining <= 0:
            raise RuntimeError("sandbox Job UID capture deadline expired")
        candidates = set()
        for pod in pod_inventory(
            timeout_seconds=min(
                $kube_api_request_timeout_seconds,
                capture_remaining,
            )
        ):
            if pod["uid"] in before_uids:
                continue
            if pod["labels"].get("hallu-defense.openai.com/sandbox") != "true":
                continue
            controller_owners = [
                owner
                for owner in pod["owners"]
                if owner.get("kind") == "Job" and owner.get("controller") is True
            ]
            if len(controller_owners) != 1:
                raise RuntimeError("new sandbox Pod did not have one controller Job owner")
            owner_name = controller_owners[0].get("name")
            owner_uid = controller_owners[0].get("uid")
            if not isinstance(owner_name, str) or not owner_name or not isinstance(owner_uid, str) or not owner_uid:
                raise RuntimeError("new sandbox Pod owner identity was invalid")
            candidates.add((owner_name, owner_uid))
        if len(candidates) > 1:
            raise RuntimeError("cleanup probe observed multiple new sandbox Jobs")
        if len(candidates) == 1:
            target_job_name, target_job_uid = next(iter(candidates))
            capture_remaining = capture_deadline - time.monotonic()
            if capture_remaining <= 0:
                raise RuntimeError("sandbox Job UID capture deadline expired")
            target_job = kube_json(
                "/apis/batch/v1/namespaces/"
                + quote(namespace, safe="")
                + "/jobs/"
                + quote(target_job_name, safe=""),
                timeout_seconds=min(
                    $kube_api_request_timeout_seconds,
                    capture_remaining,
                ),
            )
            metadata = target_job.get("metadata")
            labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
            if (
                not isinstance(metadata, dict)
                or metadata.get("name") != target_job_name
                or metadata.get("uid") != target_job_uid
                or not isinstance(labels, dict)
                or labels.get("hallu-defense.openai.com/sandbox") != "true"
            ):
                raise RuntimeError("observed sandbox Job identity did not match its Pod owner")
            break
        if request_done.is_set():
            raise RuntimeError("sandbox request completed before Job UID capture")
        if time.monotonic() >= capture_deadline:
            raise RuntimeError("sandbox Job UID capture deadline expired")
        time.sleep($job_capture_poll_interval_seconds)
finally:
    request_thread.join(timeout=$request_join_timeout_seconds)
if request_thread.is_alive():
    raise RuntimeError("authenticated sandbox request thread did not terminate")

if "error" in response_state:
    raise RuntimeError("authenticated sandbox request failed inside cleanup probe")
if not isinstance(response_state.get("status"), int) or not isinstance(response_state.get("body"), str):
    raise RuntimeError("authenticated sandbox request did not return a complete response")

cleanup_deadline = time.monotonic() + cleanup_grace_seconds
poll_attempts = 0
clean_observations = 0
while True:
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("sandbox Job and owned Pod cleanup deadline expired")
    observation_timeout = min($kube_api_request_timeout_seconds, remaining)
    target_job = kube_json(
        "/apis/batch/v1/namespaces/"
        + quote(namespace, safe="")
        + "/jobs/"
        + quote(target_job_name, safe=""),
        allow_not_found=True,
        timeout_seconds=observation_timeout,
    )
    if target_job is not None:
        metadata = target_job.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("uid") != target_job_uid:
            raise RuntimeError("sandbox Job name was rebound to a different UID")
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("sandbox Job and owned Pod cleanup deadline expired")
    pods = pod_inventory(
        timeout_seconds=min($kube_api_request_timeout_seconds, remaining)
    )
    owned_pods = [
        pod
        for pod in pods
        if any(
            owner.get("kind") == "Job" and owner.get("uid") == target_job_uid
            for owner in pod["owners"]
        )
    ]
    poll_attempts += 1
    if target_job is None and not owned_pods:
        clean_observations += 1
        if clean_observations >= 2:
            break
    else:
        clean_observations = 0
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("sandbox Job and owned Pod cleanup deadline expired")
    time.sleep(min($cleanup_poll_interval_seconds, remaining))

envelope = {
    "status": response_state["status"],
    "body": response_state["body"],
    "cleanup": {
        "probe": "sandbox_cleanup_uid_probe",
        "target_job_name": target_job_name,
        "target_job_uid": target_job_uid,
        "target_job_absent": True,
        "target_owned_pods": 0,
        "poll_attempts": poll_attempts,
    },
}
print(json.dumps(envelope, separators=(",", ":")))
"""
)


def _sandbox_cleanup_uid_probe_script(
    command_count: int,
    cleanup_grace_seconds: int,
) -> str:
    request_timeout_seconds = _sandbox_request_timeout_seconds(
        command_count,
        cleanup_grace_seconds,
    )
    return SANDBOX_CLEANUP_UID_PROBE_TEMPLATE.substitute(
        cleanup_grace_min_seconds=SANDBOX_CLEANUP_GRACE_MIN_SECONDS,
        cleanup_grace_max_seconds=SANDBOX_CLEANUP_GRACE_MAX_SECONDS,
        request_timeout_seconds=request_timeout_seconds,
        request_join_timeout_seconds=(
            request_timeout_seconds + SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS
        ),
        kube_api_request_timeout_seconds=SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS,
        initial_inventory_allowance_seconds=(
            SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS
        ),
        job_capture_allowance_seconds=SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS,
        job_capture_poll_interval_seconds=SANDBOX_JOB_CAPTURE_POLL_INTERVAL_SECONDS,
        cleanup_poll_interval_seconds=SANDBOX_CLEANUP_POLL_INTERVAL_SECONDS,
    )


SANDBOX_CLEANUP_UID_PROBE_SCRIPT = _sandbox_cleanup_uid_probe_script(
    1,
    SANDBOX_CLEANUP_GRACE_SECONDS,
)


def _sandbox_cleanup_exec_timeout_seconds(
    command_count: int,
    cleanup_grace_seconds: int,
) -> int:
    """Outer `kubectl exec` timeout for the embedded cleanup probe.

    Must never expire before the probe's own supported cleanup path can
    finish: the initial Pod inventory, the Job-UID capture poll, the bounded
    request-thread join, and the cleanup-grace convergence loop it runs
    internally. A distinct positive outer margin guarantees that the
    `kubectl exec` timeout strictly exceeds every substituted inner phase.
    """
    inner_budget_seconds = (
        SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS
        + SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS
        + _sandbox_request_exec_timeout_seconds(
            command_count,
            cleanup_grace_seconds,
        )
        + cleanup_grace_seconds
    )
    exec_timeout_seconds = (
        inner_budget_seconds + SANDBOX_CLEANUP_OUTER_SAFETY_MARGIN_SECONDS
    )
    if exec_timeout_seconds <= inner_budget_seconds:
        raise LiveKindHelmSmokeError(
            "sandbox cleanup exec timeout must exceed the embedded probe's own "
            "supported cleanup path"
        )
    return exec_timeout_seconds


def _repo_checks_request_with_cleanup_evidence(
    execute: CommandExecutor,
    *,
    kubectl: Sequence[str],
    bearer_token: str,
    payload: Mapping[str, object],
    sandbox_namespace: str,
    expected_status: int,
    cleanup_grace_seconds: int = SANDBOX_CLEANUP_GRACE_SECONDS,
) -> tuple[Mapping[str, object], dict[str, object]]:
    command_count = _sandbox_payload_command_count(payload)
    _sandbox_supported_request_path_seconds(command_count, cleanup_grace_seconds)
    request_input = json.dumps(
        {
            "token": bearer_token,
            "body": payload,
            "sandbox_namespace": sandbox_namespace,
            "cleanup_grace_seconds": cleanup_grace_seconds,
        },
        separators=(",", ":"),
    )
    result = execute(
        [
            *kubectl,
            "exec",
            "--stdin",
            f"deployment/{RELEASE_NAME}-api",
            "--",
            "python",
            "-c",
            _sandbox_cleanup_uid_probe_script(
                command_count,
                cleanup_grace_seconds,
            ),
        ],
        timeout_seconds=_sandbox_cleanup_exec_timeout_seconds(
            command_count,
            cleanup_grace_seconds,
        ),
        input_text=request_input,
    )
    envelope = _decode_repo_checks_envelope(
        result.stdout, expected_status=expected_status
    )
    cleanup = _validate_sandbox_cleanup_evidence(envelope.get("cleanup"))
    return _decode_repo_checks_body(envelope), cleanup


def _decode_repo_checks_envelope(
    stdout: str,
    *,
    expected_status: int,
) -> Mapping[str, object]:
    try:
        envelope = json.loads(stdout.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "authenticated sandbox request returned invalid JSON"
        ) from exc
    if not isinstance(envelope, Mapping) or envelope.get("status") != expected_status:
        raise LiveKindHelmSmokeError(
            f"authenticated sandbox request expected HTTP {expected_status}"
        )
    return envelope


def _decode_repo_checks_body(envelope: Mapping[str, object]) -> Mapping[str, object]:
    body = envelope.get("body")
    if not isinstance(body, str):
        raise LiveKindHelmSmokeError("authenticated sandbox response body was not text")
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError(
            "authenticated sandbox response body was not JSON"
        ) from exc
    if not isinstance(decoded, Mapping):
        raise LiveKindHelmSmokeError("authenticated sandbox response was not an object")
    return decoded


def _validate_sandbox_cleanup_evidence(raw: object) -> dict[str, object]:
    if not isinstance(raw, Mapping) or set(raw) != {
        "probe",
        "target_job_name",
        "target_job_uid",
        "target_job_absent",
        "target_owned_pods",
        "poll_attempts",
    }:
        raise LiveKindHelmSmokeError(
            "sandbox cleanup UID evidence was missing or malformed"
        )
    job_name = raw.get("target_job_name")
    job_uid = raw.get("target_job_uid")
    attempts = raw.get("poll_attempts")
    if (
        raw.get("probe") != "sandbox_cleanup_uid_probe"
        or not isinstance(job_name, str)
        or len(job_name) > 63
        or DNS_LABEL_PATTERN.fullmatch(job_name) is None
        or not isinstance(job_uid, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_uid) is None
        or raw.get("target_job_absent") is not True
        or isinstance(raw.get("target_owned_pods"), bool)
        or raw.get("target_owned_pods") != 0
        or isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= 10_000
    ):
        raise LiveKindHelmSmokeError(
            "sandbox cleanup did not prove exact Job and owner-UID Pod absence"
        )
    return dict(raw)


def _emit_diagnostics(
    execute: CommandExecutor,
    *,
    context: str,
    namespace: str,
    sandbox_namespace: str,
    kubeconfig: Path,
) -> None:
    application_kubectl = [
        "kubectl",
        "--kubeconfig",
        str(kubeconfig),
        "--context",
        context,
        "--namespace",
        namespace,
    ]
    sandbox_kubectl = [
        "kubectl",
        "--kubeconfig",
        str(kubeconfig),
        "--context",
        context,
        "--namespace",
        sandbox_namespace,
    ]
    for label, command in (
        ("resources", [*application_kubectl, "get", "all,pvc", "--output=wide"]),
        ("events", [*application_kubectl, "get", "events", "--sort-by=.lastTimestamp"]),
        (
            "pod-logs",
            [
                *application_kubectl,
                "logs",
                "--selector=app.kubernetes.io/instance=hallu-defense",
                "--all-containers",
                "--tail=200",
            ],
        ),
        ("sandbox-resources", [*sandbox_kubectl, "get", "all,pvc", "--output=wide"]),
        (
            "sandbox-events",
            [*sandbox_kubectl, "get", "events", "--sort-by=.lastTimestamp"],
        ),
        (
            "sandbox-pod-logs",
            [
                *sandbox_kubectl,
                "logs",
                "--selector=app.kubernetes.io/instance=hallu-defense",
                "--all-containers",
                "--tail=200",
            ],
        ),
    ):
        try:
            result = execute(command, check=False, timeout_seconds=60)
        except Exception as exc:
            print(
                f"[kind-smoke:{label}] unavailable: {type(exc).__name__}",
                file=sys.stderr,
            )
            continue
        output = _redact_sensitive_output(
            result.stdout.strip() or result.stderr.strip()
        )[:20_000]
        if output:
            print(f"[kind-smoke:{label}]\n{output}", file=sys.stderr)


def _run(
    command: Sequence[str],
    *,
    check: bool = True,
    timeout_seconds: float = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            input=input_text,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        message = f"{_command_display(command)} timed out after {timeout_seconds:g}s"
        if check:
            raise LiveKindHelmSmokeError(message) from exc
        return subprocess.CompletedProcess(
            list(command),
            124,
            _coerce_output(exc.stdout),
            _coerce_output(exc.stderr) or message,
        )
    if check and result.returncode != 0:
        detail = _redact_sensitive_output(
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit {result.returncode}"
        )[:4000]
        raise LiveKindHelmSmokeError(f"{_command_display(command)} failed: {detail}")
    return result


def _health_payload(raw: str) -> dict[str, str]:
    try:
        payload = json.loads(raw.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError("API /health did not return JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("status") != "ok":
        raise LiveKindHelmSmokeError("API /health did not report status=ok")
    environment = payload.get("environment")
    if environment != "production":
        raise LiveKindHelmSmokeError(
            "API /health did not report the production environment"
        )
    return {"status": "ok", "environment": "production"}


def _ready_payload(raw: str) -> dict[str, str]:
    try:
        payload = json.loads(raw.strip())
    except json.JSONDecodeError as exc:
        raise LiveKindHelmSmokeError("API /ready did not return JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("status") != "ready":
        raise LiveKindHelmSmokeError("API /ready did not report status=ready")
    return {"status": "ready"}


def _validated_dns_label(value: str, env_name: str) -> str:
    if len(value) > 63 or DNS_LABEL_PATTERN.fullmatch(value) is None:
        raise LiveKindHelmSmokeError(f"{env_name} must be a valid DNS label")
    return value


def _validated_run_id(value: str) -> str:
    if len(value) > 32 or RUN_ID_PATTERN.fullmatch(value) is None:
        raise LiveKindHelmSmokeError(
            f"{RUN_ID_ENV} must be a lowercase DNS-safe identifier of at most 32 characters"
        )
    return value


def _validated_kind_node_image(env: Mapping[str, str]) -> str:
    configured = _optional(env, KIND_NODE_IMAGE_ENV)
    if configured is not None and configured != KIND_NODE_IMAGE:
        raise LiveKindHelmSmokeError(
            f"{KIND_NODE_IMAGE_ENV} must equal the digest-pinned image {KIND_NODE_IMAGE}"
        )
    return KIND_NODE_IMAGE


def _command_display(command: Sequence[str]) -> str:
    return JWT_PATTERN.sub("<redacted-jwt>", " ".join(command))


def _redact_sensitive_output(value: str) -> str:
    redacted = JWT_PATTERN.sub("<redacted-jwt>", value)
    redacted = BASIC_AUTH_URI_PATTERN.sub(
        lambda match: f"{match.group(1)}://<redacted>@",
        redacted,
    )
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>",
        redacted,
    )
    return PRIVATE_KEY_PATTERN.sub("<redacted-private-key>", redacted)


def _coerce_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def main(
    argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None
) -> int:
    _ = argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        print(_json_result({"status": "failed", "error": str(exc)}))
        return 1
    print(_json_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
