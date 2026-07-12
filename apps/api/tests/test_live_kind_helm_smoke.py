from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import re
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID

from scripts.dev import live_kind_helm_smoke as smoke


class RecordingExecutor:
    def __init__(
        self,
        *,
        migration_count: int = smoke.EXPECTED_MIGRATION_COUNT,
        migration_checksums_valid: bool = True,
        fail_prefix: tuple[str, ...] | None = None,
        missing_network_policy: str | None = None,
        docker_architecture: str = "amd64",
        opensearch_replica_count: int = 1,
        opensearch_cluster_status: str = "yellow",
        opensearch_cluster_timed_out: bool = False,
        opensearch_data_nodes: int = 1,
        opensearch_transport_listeners: tuple[str, ...] = ("127.0.0.1",),
        projected_secret_reads_valid: bool = True,
        migration_secret_read_valid: bool = True,
        migration_restart_count: int = 0,
        console_oidc_runtime_valid: bool = True,
        runtime_secret_rotation_visible: bool = True,
        hybrid_lifecycle_valid: bool = True,
        existing_clusters: tuple[str, ...] = (),
        existing_images: tuple[str, ...] = (),
        fixture_ready: bool = True,
        fixture_probe_valid: bool = True,
        fixture_owner_valid: bool = True,
        cleanup_job_absent: bool = True,
        cleanup_owned_pods: int = 0,
        cleanup_evidence_override: object | None = None,
        residual_sandbox_jobs: int = 0,
        residual_sandbox_pods: int = 0,
        helm_history_override: object | None = None,
    ) -> None:
        self.commands: list[list[str]] = []
        self.command_timeouts: list[float] = []
        self.bearer_tokens: list[str] = []
        self.secret_manifests: list[dict[str, object]] = []
        self.kind_config_text: str | None = None
        self.migration_count = migration_count
        self.migration_checksums_valid = migration_checksums_valid
        self.fail_prefix = fail_prefix
        self.missing_network_policy = missing_network_policy
        self.docker_architecture = docker_architecture
        self.opensearch_replica_count = opensearch_replica_count
        self.opensearch_cluster_status = opensearch_cluster_status
        self.opensearch_cluster_timed_out = opensearch_cluster_timed_out
        self.opensearch_data_nodes = opensearch_data_nodes
        self.opensearch_transport_listeners = opensearch_transport_listeners
        self.projected_secret_reads_valid = projected_secret_reads_valid
        self.migration_secret_read_valid = migration_secret_read_valid
        self.migration_restart_count = migration_restart_count
        self.console_oidc_runtime_valid = console_oidc_runtime_valid
        self.runtime_secret_rotation_visible = runtime_secret_rotation_visible
        self.hybrid_lifecycle_valid = hybrid_lifecycle_valid
        self.initial_runtime_vault_token: str | None = None
        self.current_runtime_vault_token: str | None = None
        self.network_client_label: str | None = None
        self.kind_clusters = set(existing_clusters)
        self.docker_images = set(existing_images)
        self.fixture_ready = fixture_ready
        self.fixture_probe_valid = fixture_probe_valid
        self.fixture_owner_valid = fixture_owner_valid
        self.cleanup_job_absent = cleanup_job_absent
        self.cleanup_owned_pods = cleanup_owned_pods
        self.cleanup_evidence_override = cleanup_evidence_override
        self.residual_sandbox_jobs = residual_sandbox_jobs
        self.residual_sandbox_pods = residual_sandbox_pods
        self.helm_history_override = helm_history_override

    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        self.commands.append(argv)
        self.command_timeouts.append(timeout_seconds)
        if input_text is not None:
            try:
                input_payload = json.loads(input_text)
            except json.JSONDecodeError:
                input_payload = None
            if isinstance(input_payload, dict) and input_payload.get("kind") == "Secret":
                self.secret_manifests.append(input_payload)
                metadata = input_payload.get("metadata")
                string_data = input_payload.get("stringData")
                if (
                    isinstance(metadata, dict)
                    and metadata.get("name") == "hallu-defense-runtime"
                    and isinstance(string_data, dict)
                    and isinstance(string_data.get("vault-token"), str)
                ):
                    supplied = str(string_data["vault-token"])
                    if self.initial_runtime_vault_token is None:
                        self.initial_runtime_vault_token = supplied
                        self.current_runtime_vault_token = supplied
                    elif self.runtime_secret_rotation_visible:
                        self.current_runtime_vault_token = supplied
        if (
            self.fail_prefix is not None
            and tuple(argv[: len(self.fail_prefix)]) == self.fail_prefix
        ):
            if check:
                raise smoke.LiveKindHelmSmokeError("injected command failure")
            return subprocess.CompletedProcess(argv, 1, "", "injected command failure")
        if argv[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                f"{self.docker_architecture}\n",
                "",
            )
        if argv[:3] == ["docker", "image", "inspect"]:
            image = argv[3]
            if image in self.docker_images:
                return subprocess.CompletedProcess(argv, 0, "sha256:test\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "No such image")
        if argv[:3] == ["docker", "image", "rm"]:
            self.docker_images.discard(argv[3])
            return subprocess.CompletedProcess(argv, 0, f"Untagged: {argv[3]}\n", "")
        if argv[:2] == ["docker", "build"]:
            self.docker_images.add(argv[argv.index("--tag") + 1])
        if argv[:4] == ["kind", "create", "cluster", "--name"]:
            config_path = Path(argv[argv.index("--config") + 1])
            self.kind_config_text = config_path.read_text(encoding="utf-8")
            self.kind_clusters.add(argv[4])
        if argv[:3] == ["kind", "delete", "cluster"]:
            self.kind_clusters.discard(argv[argv.index("--name") + 1])
            return subprocess.CompletedProcess(argv, 0, "Deleted cluster\n", "")
        if argv[:3] == ["kind", "get", "clusters"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                "\n".join(sorted(self.kind_clusters)) + ("\n" if self.kind_clusters else ""),
                "",
            )
        if argv[:2] in (["helm", "lint"], ["helm", "template"], ["helm", "upgrade"]):
            if "--show-only" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "apiVersion: admissionregistration.k8s.io/v1\n"
                    "kind: ValidatingAdmissionPolicy\n",
                    "",
                )
        if argv[:3] == ["helm", "get", "manifest"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: hallu-defense-api\n",
                "",
            )
        if argv[:3] == ["helm", "get", "values"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "secrets": {
                            "runtime": {"name": "hallu-defense-runtime"},
                            "bootstrap": {"name": "hallu-defense-bootstrap"},
                            "migrations": {"name": "hallu-defense-migrations"},
                            "kindPostgres": {"name": "hallu-defense-postgres"},
                            "kindVault": {"name": "hallu-defense-kind-vault"},
                            "kindRedisTls": {"name": "hallu-defense-kind-redis-tls"},
                        }
                    }
                )
                + "\n",
                "",
            )
        if argv[:2] == ["helm", "history"]:
            history = (
                self.helm_history_override
                if self.helm_history_override is not None
                else [
                    {"revision": 1, "status": "superseded"},
                    {"revision": 2, "status": "deployed"},
                ]
            )
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(history) + "\n",
                "",
            )
        if "schema_migrations ORDER BY version;" in " ".join(argv):
            ledger = list(smoke.EXPECTED_MIGRATION_LEDGER[: self.migration_count])
            if ledger and not self.migration_checksums_valid:
                ledger[0] = (ledger[0][0], "0" * 64)
            rows = [f"{version}|{checksum}" for version, checksum in ledger]
            return subprocess.CompletedProcess(argv, 0, "\n".join(rows) + "\n", "")
        if "http://127.0.0.1:8000/health" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                '{"status":"ok","environment":"production"}\n',
                "",
            )
        if "http://127.0.0.1:8000/ready" in " ".join(argv):
            return subprocess.CompletedProcess(argv, 0, '{"status":"ready"}\n', "")
        if "console_oidc_runtime_probe" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "api_audience": "hallu-defense-api",
                        "api_origin": "https://api.kind.invalid",
                        "auth_mode": (
                            "oidc" if self.console_oidc_runtime_valid else "unsigned-local"
                        ),
                        "environment": "production",
                        "forbidden_env_absent": True,
                        "http_status": 200,
                        "issuer": "https://auth.kind.invalid/realms/hallu-defense",
                        "public_origin": "https://console.kind.invalid",
                        "required_roles": (
                            "verifier,approval_reviewer,policy_evaluator,"
                            "sandbox_runner,tool_operator"
                        ),
                        "roles_claim": "roles",
                        "tenant_claim": "tenant_id",
                    }
                )
                + "\n",
                "",
            )
        if "projected_runtime_secret_probe" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "postgres_dsn_file_read": self.projected_secret_reads_valid,
                        "raw_secret_env_absent": True,
                        "vault_token_file_read": True,
                    }
                )
                + "\n",
                "",
            )
        if "vault_manager_projected_rotation_probe" in " ".join(argv):
            if self.current_runtime_vault_token is None:
                return subprocess.CompletedProcess(argv, 1, "", "runtime token unavailable")
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "lexical_path_preserved": True,
                        "manager_type": "VaultSecretManager",
                        "token_sha256": hashlib.sha256(
                            self.current_runtime_vault_token.encode("utf-8")
                        ).hexdigest(),
                    }
                )
                + "\n",
                "",
            )
        if "hybrid_lifecycle_tombstone_probe" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "audit_parity": True,
                        "backend": "hybrid",
                        "external_deleted_count": 1,
                        "journal_completed": True,
                        "opensearch_after_delete": 0,
                        "opensearch_after_reingest": 0,
                        "pgvector_after_delete": 0,
                        "pgvector_after_reingest": 0,
                        "reingest_rejected": self.hybrid_lifecycle_valid,
                        "tombstone_persisted": True,
                    }
                )
                + "\n",
                "",
            )
        if "worker_metrics_authenticated_probe" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "authenticated_status": 200,
                        "cache_control": "no-store",
                        "ingestion_metric_present": True,
                        "unauthenticated_status": 401,
                    }
                )
                + "\n",
                "",
            )
        if (
            "logs" in argv
            and any(
                item.startswith("--selector=app.kubernetes.io/component=migrations,")
                for item in argv
            )
            and "--container=migrations" in argv
        ):
            selector = next(item for item in argv if item.startswith("--selector="))
            applied = (
                []
                if "release-revision=2" in selector
                else list(smoke.EXPECTED_MIGRATION_VERSIONS)
            )
            payload = (
                {
                    "status": "ok",
                    "applied": applied,
                }
                if self.migration_secret_read_valid
                else {"status": "error", "reason": "projected DSN rejected"}
            )
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload) + "\n", "")
        if '"tls_ca_vault_health": True' in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "acl_command_rejected": True,
                        "acl_prefix_rejected": True,
                        "invalid_auth_rejected": True,
                        "plaintext_rejected": True,
                        "rate_limit_eval_allowed": True,
                        "tls_ca_vault_health": True,
                    }
                )
                + "\n",
                "",
            )
        if (
            "logs" in argv
            and "deployment/hallu-defense-api" in argv
            and "bootstrap-opensearch-schema" in argv
        ):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "template_name": "hallu_evidence_template",
                        "index_name": "hallu_evidence",
                        "installed": True,
                        "acknowledged": True,
                        "schema_version": smoke.EXPECTED_OPENSEARCH_SCHEMA_VERSION,
                        "index_state": "absent",
                        "schema_ready": True,
                        "dry_run": False,
                    }
                )
                + "\n",
                "",
            )
        if "kind_opensearch_schema_health" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "template_replicas": self.opensearch_replica_count,
                        "cluster_status": self.opensearch_cluster_status,
                        "cluster_timed_out": self.opensearch_cluster_timed_out,
                        "data_nodes": self.opensearch_data_nodes,
                    }
                )
                + "\n",
                "",
            )
        if "opensearch_transport_loopback" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"listeners": list(self.opensearch_transport_listeners)}) + "\n",
                "",
            )
        if "127.0.0.1:1" in " ".join(argv):
            return subprocess.CompletedProcess(argv, 1, "", "OpenSearch unavailable")
        if "unauthorized_dependency_ingress_probe" in " ".join(argv):
            return subprocess.CompletedProcess(
                argv,
                0,
                (
                    '{"api":false,"console":false,"worker":false,"opensearch":false,'
                    '"opensearch_transport_pod_ip_9300":false,'
                    '"pgvector":false,"vault":false}\n'
                ),
                "",
            )
        if "label" in argv and "hallu-network-ingress-probe" in argv:
            label_arg = next(
                item for item in argv if item.startswith("hallu-defense.openai.com/network-client=")
            )
            self.network_client_label = label_arg.rsplit("=", 1)[-1]
            return subprocess.CompletedProcess(
                argv, 0, "pod/hallu-network-ingress-probe labeled\n", ""
            )
        if "application_ingress_allowlist_probe" in " ".join(argv):
            expected = {
                "api": self.network_client_label in {"api", "metrics"},
                "console": self.network_client_label == "console",
                "worker": self.network_client_label == "metrics",
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(expected) + "\n", "")
        if "api_workspace_read_only" in " ".join(argv):
            return subprocess.CompletedProcess(argv, 0, "api-workspace-read-only\n", "")
        if "auth" in argv and "can-i" in argv:
            namespace = argv[argv.index("--namespace") + 1]
            allowed = namespace == smoke.DEFAULT_SANDBOX_NAMESPACE
            return subprocess.CompletedProcess(
                argv,
                0 if allowed else 1,
                "yes\n" if allowed else "no\n",
                "",
            )
        if "network_policy_socket_probe" in " ".join(argv):
            if "deployment/hallu-defense-console" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    '{"internet_1_1_1_1":false}\n',
                    "",
                )
            component = "api" if "deployment/hallu-defense-api" in argv else "worker"
            payload = {
                "internet_1_1_1_1": False,
                "kubernetes_api": component == "api",
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload) + "\n", "")
        if "--as" in argv and "--dry-run=server" in argv:
            assert input_text is not None
            manifest = json.loads(input_text)
            metadata = manifest["metadata"]
            if metadata["name"] not in {
                "hallu-sandbox-admission-valid",
                "hallu-sandbox-admission-equivalent-quantities",
            }:
                service_account = argv[argv.index("--as") + 1]
                application_namespace = service_account.split(":")[2]
                sandbox_namespace = argv[argv.index("--namespace") + 1]
                return subprocess.CompletedProcess(
                    argv,
                    1,
                    "",
                    "ValidatingAdmissionPolicy "
                    f"{smoke._sandbox_admission_policy_name(application_namespace, sandbox_namespace)} denied request",
                )
            return subprocess.CompletedProcess(
                argv,
                0,
                "job.batch/hallu-sandbox-admission-valid\n",
                "",
            )
        if "validatingadmissionpolicy" in argv and "--output=json" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "metadata": {"generation": 1},
                        "status": {"observedGeneration": 1},
                    }
                ),
                "",
            )
        if "http://127.0.0.1:8000/repo/checks/run" in " ".join(argv):
            assert input_text is not None
            request = json.loads(input_text)
            self.bearer_tokens.append(str(request["token"]))
            body = request["body"]
            command = body["commands"][0]
            if body["repo_ref"] == "../":
                status = 400
                response = {"detail": "repo_ref escapes the configured workspace"}
            elif command == "python probe.py":
                status = 200
                batched = len(body["commands"]) == 2
                response = {
                    "exit_codes": [7, 0] if batched else [7],
                    "stdout": (
                        ["sandbox-stdout\n", "sandbox-second\n"]
                        if batched
                        else ["sandbox-stdout\n"]
                    ),
                    "stderr": ["sandbox-stderr\n", ""] if batched else ["sandbox-stderr\n"],
                    "artifacts": ["artifacts/sandbox-smoke.txt"],
                    "evidence": [
                        {
                            "source_ref": "sandbox://inspection",
                            "structured_content": {"git": {"is_repository": True, "errors": []}},
                        }
                    ],
                }
            elif command == "python timeout.py":
                status = 200
                response = {
                    "exit_codes": [smoke.SANDBOX_TIMEOUT_RETURN_CODE],
                    "stdout": [""],
                    "stderr": ["kubernetes sandbox command timed out\n"],
                    "artifacts": [],
                }
            else:
                assert command == "python egress.py"
                status = 200
                response = {
                    "exit_codes": [0],
                    "stdout": ["egress-blocked\n"],
                    "stderr": [""],
                    "artifacts": [],
                }
            envelope: dict[str, object] = {
                "status": status,
                "body": json.dumps(response),
            }
            if "sandbox_cleanup_uid_probe" in " ".join(argv):
                envelope["cleanup"] = (
                    self.cleanup_evidence_override
                    if self.cleanup_evidence_override is not None
                    else {
                        "probe": "sandbox_cleanup_uid_probe",
                        "target_job_name": "hallu-sandbox-timeout",
                        "target_job_uid": "11111111-1111-4111-8111-111111111111",
                        "target_job_absent": self.cleanup_job_absent,
                        "target_owned_pods": self.cleanup_owned_pods,
                        "poll_attempts": 2,
                    }
                )
            return subprocess.CompletedProcess(argv, 0, json.dumps(envelope) + "\n", "")
        if "get" in argv and "jobs" in argv and "--output=json" in argv:
            selectors = [item for item in argv if item.startswith("--selector=")]
            selector = selectors[0] if selectors else ""
            components = [
                component
                for component in ("migrations", "vault-bootstrap", "sandbox-fixture")
                if f"app.kubernetes.io/component={component}" in selector
            ]
            revisions = re.findall(
                r"hallu-defense\.openai\.com/release-revision=([0-9]+)",
                selector,
            )
            if len(components) == 1 and len(revisions) == 1:
                component = components[0]
                revision = revisions[0]
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        {
                            "items": [
                                {
                                    "metadata": {
                                        "name": f"hallu-defense-{component}-{revision}",
                                        "labels": {
                                            "app.kubernetes.io/component": component,
                                            "hallu-defense.openai.com/release-revision": revision
                                        },
                                    },
                                    "status": {
                                        "conditions": [
                                            {"type": "Complete", "status": "True"}
                                        ]
                                    },
                                }
                            ]
                        }
                    )
                    + "\n",
                    "",
                )
            if smoke.SANDBOX_JOB_LABEL in argv:
                items = [
                    {"metadata": {"name": f"residual-sandbox-job-{index}"}}
                    for index in range(self.residual_sandbox_jobs)
                ]
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps({"items": items}) + "\n",
                    "",
                )
            return subprocess.CompletedProcess(argv, 0, '{"items":[]}\n', "")
        if "get" in argv and "networkpolicy" in argv and "--output=json" in argv:
            policies = []
            if self.missing_network_policy != "default-deny-ingress":
                policies.append(
                    {
                        "metadata": {"name": "hallu-defense-default-deny-ingress"},
                        "spec": {
                            "podSelector": {},
                            "policyTypes": ["Ingress"],
                            "ingress": [],
                        },
                    }
                )
            ingress_allowlists = {
                "pgvector": (("api", "worker", "migrations"), 5432),
                "opensearch": (("api", "worker"), 9200),
                "vault": (("api", "worker", "vault-bootstrap", "redis"), 8200),
                "redis": (("api",), 6379),
            }
            external_ingress_allowlists = {
                "api": (("api", "metrics"), 8000),
                "console": (("console",), 3000),
                "worker": (("metrics",), 9090),
            }
            for component in (
                "api",
                "worker",
                "console",
                "migrations",
                "vault-bootstrap",
                "pgvector",
                "opensearch",
                "vault",
                "redis",
            ):
                if component == self.missing_network_policy:
                    continue
                policy_name = (
                    "hallu-defense-redis"
                    if component == "redis"
                    else f"hallu-defense-{component}-egress"
                )
                empty_egress = component in {"pgvector", "opensearch", "vault"}
                ingress = None
                if component in external_ingress_allowlists:
                    sources, port = external_ingress_allowlists[component]
                    ingress = [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": smoke.DEFAULT_NAMESPACE
                                        }
                                    },
                                    "podSelector": {
                                        "matchLabels": {
                                            "hallu-defense.openai.com/network-client": source
                                        }
                                    },
                                }
                            ],
                            "ports": [{"protocol": "TCP", "port": port}],
                        }
                        for source in sources
                    ]
                elif component in ingress_allowlists:
                    sources, port = ingress_allowlists[component]
                    ingress = [
                        {
                            "from": [
                                {
                                    "podSelector": {
                                        "matchLabels": {
                                            "app.kubernetes.io/name": "hallu-defense",
                                            "app.kubernetes.io/instance": "hallu-defense",
                                            "app.kubernetes.io/component": source,
                                        }
                                    }
                                }
                                for source in sources
                            ],
                            "ports": [{"protocol": "TCP", "port": port}],
                        }
                    ]
                console_dns_egress = [
                    {
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
                ]
                policy_spec = {
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "hallu-defense",
                            "app.kubernetes.io/instance": "hallu-defense",
                            "app.kubernetes.io/component": component,
                        }
                    },
                    "policyTypes": (
                        ["Ingress", "Egress"]
                        if component in ingress_allowlists
                        or component in external_ingress_allowlists
                        else ["Egress"]
                    ),
                    "egress": (
                        []
                        if empty_egress
                        else console_dns_egress
                        if component == "console"
                        else [{"to": []}]
                    ),
                }
                if ingress is not None:
                    policy_spec["ingress"] = ingress
                policies.append(
                    {
                        "metadata": {"name": policy_name},
                        "spec": policy_spec,
                    }
                )
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"items": policies}) + "\n",
                "",
            )
        if argv[-4:-1] == ["get", "pod", "hallu-network-ingress-probe"]:
            return subprocess.CompletedProcess(argv, 1, "", "NotFound")
        if (
            "get" in argv
            and "pods" in argv
            and any(
                item.startswith("--selector=app.kubernetes.io/component=sandbox-fixture,")
                for item in argv
            )
            and "--output=json" in argv
        ):
            selector = next(item for item in argv if item.startswith("--selector="))
            revision = re.search(r"release-revision=([0-9]+)", selector)
            assert revision is not None
            revision_value = revision.group(1)
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {
                                    "name": "hallu-defense-sandbox-fixture-pod",
                                    "labels": {
                                        "hallu-defense.openai.com/release-revision": revision_value
                                    },
                                    "ownerReferences": [
                                        {
                                            "kind": "Job",
                                            "name": (
                                                f"hallu-defense-sandbox-fixture-{revision_value}"
                                                if self.fixture_owner_valid
                                                else "attacker-job"
                                            ),
                                            "controller": True,
                                        }
                                    ],
                                },
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "prepare-sandbox-fixture",
                                            **(
                                                {
                                                    "readinessProbe": {
                                                        "exec": {
                                                            "command": [
                                                                "python",
                                                                "-c",
                                                                "HALLU_FIXTURE_READY_MARKER",
                                                            ]
                                                        },
                                                        "initialDelaySeconds": 1,
                                                        "periodSeconds": 1,
                                                        "timeoutSeconds": 1,
                                                    }
                                                }
                                                if self.fixture_probe_valid
                                                else {}
                                            ),
                                        }
                                    ]
                                },
                                "status": {
                                    "phase": "Running",
                                    "conditions": [
                                        {
                                            "type": "Ready",
                                            "status": "True" if self.fixture_ready else "False",
                                        }
                                    ],
                                    "containerStatuses": [
                                        {
                                            "name": "prepare-sandbox-fixture",
                                            "ready": self.fixture_ready,
                                            "restartCount": 0,
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                )
                + "\n",
                "",
            )
        if (
            "get" in argv
            and "pods" in argv
            and any(
                item.startswith("--selector=app.kubernetes.io/component=migrations,")
                for item in argv
            )
            and "--output=json" in argv
        ):
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "hallu-defense-migrations-pod"},
                                "status": {
                                    "phase": "Succeeded",
                                    "initContainerStatuses": [
                                        {
                                            "name": "wait-for-postgres",
                                            "restartCount": 0,
                                        }
                                    ],
                                    "containerStatuses": [
                                        {
                                            "name": "migrations",
                                            "restartCount": self.migration_restart_count,
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                )
                + "\n",
                "",
            )
        if (
            "get" in argv
            and "pods" in argv
            and "app.kubernetes.io/component=opensearch" in argv
            and "--output=json" in argv
        ):
            return subprocess.CompletedProcess(
                argv,
                0,
                '{"items":[{"status":{"podIP":"192.168.0.16"}}]}\n',
                "",
            )
        if "get" in argv and "pods" in argv and "--output=json" in argv:
            if smoke.SANDBOX_JOB_LABEL in argv:
                items = [
                    {"metadata": {"name": f"residual-sandbox-pod-{index}"}}
                    for index in range(self.residual_sandbox_pods)
                ]
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps({"items": items}) + "\n",
                    "",
                )
            items = []
            for component in smoke.EXPECTED_WORKLOAD_COMPONENTS:
                items.append(
                    {
                        "metadata": {
                            "name": f"hallu-defense-{component}-pod",
                            "labels": {"app.kubernetes.io/component": component},
                        },
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [
                                {
                                    "name": component,
                                    "ready": True,
                                    "restartCount": 0,
                                }
                            ],
                            "initContainerStatuses": [
                                {
                                    "name": "bootstrap",
                                    "ready": False,
                                    "restartCount": 0,
                                }
                            ],
                        },
                    }
                )
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"items": items}) + "\n",
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")


class RevisionJobPollingExecutor:
    def __init__(
        self,
        states: dict[str, list[str]],
    ) -> None:
        self.states = {component: list(sequence) for component, sequence in states.items()}
        self.commands: list[list[str]] = []
        self.calls: dict[str, int] = {component: 0 for component in states}

    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del check, timeout_seconds, input_text
        argv = list(command)
        self.commands.append(argv)
        selector = next(item for item in argv if item.startswith("--selector="))
        component_match = re.search(r"app\.kubernetes\.io/component=([^,]+)", selector)
        revision_match = re.search(r"release-revision=([0-9]+)", selector)
        assert component_match is not None
        assert revision_match is not None
        component = component_match.group(1)
        revision = revision_match.group(1)
        self.calls[component] = self.calls.get(component, 0) + 1
        sequence = self.states.setdefault(component, ["missing"])
        state = sequence.pop(0) if sequence else "missing"
        if state == "missing":
            items: list[dict[str, object]] = []
        else:
            labels = {
                "app.kubernetes.io/component": component,
                "hallu-defense.openai.com/release-revision": (
                    "999" if state == "wrong-revision" else revision
                ),
            }
            conditions = []
            if state == "complete":
                conditions = [{"type": "Complete", "status": "True"}]
            elif state == "failed":
                conditions = [{"type": "Failed", "status": "True"}]
            item = {
                "metadata": {
                    "name": f"hallu-defense-{component}-{revision}",
                    "labels": labels,
                },
                "status": {"conditions": conditions},
            }
            items = [item, item] if state == "duplicate" else [item]
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps({"items": items}) + "\n",
            "",
        )


class CleanupFailingExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if argv[:3] == ["kind", "delete", "cluster"]:
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "injected cleanup failure")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class ConcurrentClusterExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )
        if list(command)[:3] == ["kind", "delete", "cluster"]:
            self.kind_clusters.add("unrelated-concurrent-cluster")
        return result


class DockerInspectFailingExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if list(command)[:3] == ["docker", "image", "inspect"]:
            argv = list(command)
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 125, "", "daemon unavailable")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class DockerRemoveFailingExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if list(command)[:3] == ["docker", "image", "rm"]:
            argv = list(command)
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 125, "", "daemon unavailable")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class SelectiveDockerRemoveFailingExecutor(RecordingExecutor):
    def __init__(self, *, failing_image: str, existing_images: tuple[str, ...]) -> None:
        super().__init__(existing_images=existing_images)
        self.failing_image = failing_image

    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if argv[:3] == ["docker", "image", "rm"] and argv[3] == self.failing_image:
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 125, "", "daemon removal error")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class ProbeCleanupFailingExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if "delete" in argv and "hallu-network-ingress-probe" in argv:
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "injected probe cleanup failure")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class OverprivilegedRbacExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if "auth" in argv and "can-i" in argv:
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, "yes\n", "")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class WritableWorkspaceExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if "api_workspace_read_only" in " ".join(argv):
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, "write-succeeded\n", "")
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


class HelmSecretLeakingExecutor(RecordingExecutor):
    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        if argv[:3] == ["helm", "get", "manifest"]:
            self.commands.append(argv)
            return subprocess.CompletedProcess(
                argv,
                0,
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: leaked\n",
                "",
            )
        return super().__call__(
            command,
            check=check,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
        )


def _all_tools(_tool: str) -> str:
    return "/usr/local/bin/tool"


def test_live_kind_helm_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert result["required_tools"] == ["docker", "kind", "kubectl", "helm"]


def test_enabled_smoke_fails_closed_when_tools_are_missing() -> None:
    with pytest.raises(smoke.LiveKindHelmSmokeError, match="kind, helm"):
        smoke.run_from_env(
            {smoke.ENABLED_ENV: "true"},
            tool_locator=lambda tool: None if tool in {"kind", "helm"} else tool,
        )


def test_kind_node_image_override_accepts_only_the_exact_pinned_image() -> None:
    assert (
        smoke._validated_kind_node_image({smoke.KIND_NODE_IMAGE_ENV: smoke.KIND_NODE_IMAGE})
        == smoke.KIND_NODE_IMAGE
    )


@pytest.mark.parametrize(
    "override",
    (
        "kindest/node:v1.36.1",
        "kindest/node:v1.36.1@sha256:" + "0" * 64,
        "kindest/node:latest",
    ),
)
def test_kind_node_image_override_rejects_tags_and_other_digests(
    override: str,
) -> None:
    with pytest.raises(smoke.LiveKindHelmSmokeError, match="must equal the digest-pinned image"):
        smoke.run_from_env(
            {
                smoke.ENABLED_ENV: "true",
                smoke.KIND_NODE_IMAGE_ENV: override,
            },
            tool_locator=_all_tools,
            executor=RecordingExecutor(),
        )


def test_enabled_smoke_rejects_non_amd64_docker_server() -> None:
    executor = RecordingExecutor(docker_architecture="arm64")

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="amd64 Docker server"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    assert not any(command[:2] == ["kind", "create"] for command in executor.commands)


def test_application_egress_fails_when_any_workload_policy_is_missing() -> None:
    executor = RecordingExecutor(missing_network_policy="console")

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="console-egress"):
        smoke._verify_application_egress(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_application_ingress_fails_without_namespace_default_deny() -> None:
    executor = RecordingExecutor(missing_network_policy="default-deny-ingress")

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="default-deny ingress"):
        smoke._verify_application_egress(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_api_rbac_probe_rejects_application_namespace_privilege() -> None:
    executor = OverprivilegedRbacExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="application namespace"):
        smoke._verify_api_sandbox_rbac(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
            application_namespace=smoke.DEFAULT_NAMESPACE,
            sandbox_namespace=smoke.DEFAULT_SANDBOX_NAMESPACE,
        )


def test_api_workspace_probe_rejects_writable_mount() -> None:
    executor = WritableWorkspaceExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="read-only probe"):
        smoke._verify_api_workspace_read_only(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_helm_release_boundary_rejects_secret_manifest() -> None:
    executor = HelmSecretLeakingExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="retained a Secret"):
        smoke._verify_helm_release_secret_boundary(
            executor,
            context="kind-test",
            namespace=smoke.DEFAULT_NAMESPACE,
            kubeconfig=Path("scratch-kubeconfig"),
        )


def test_projected_runtime_secret_probe_fails_closed_on_unproven_read() -> None:
    executor = RecordingExecutor(projected_secret_reads_valid=False)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="api projected runtime secret reads were not proven",
    ):
        smoke._verify_projected_runtime_secret_reads(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_projected_runtime_secret_probe_script_compiles() -> None:
    compile(
        smoke.PROJECTED_RUNTIME_SECRET_READ_SCRIPT,
        "<projected-runtime-secret-read>",
        "exec",
    )


def test_runtime_secret_rotation_fails_when_manager_keeps_stale_revision() -> None:
    executor = RecordingExecutor(runtime_secret_rotation_visible=False)
    manifests = smoke._kind_secret_manifests(
        namespace=smoke.DEFAULT_NAMESPACE,
        oidc_jwks={"keys": []},
    )
    for manifest in manifests:
        executor(
            ["kubectl", "apply", "--filename", "-"],
            input_text=json.dumps(manifest),
        )

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="did not observe the expected projected-token revision",
    ):
        smoke._verify_runtime_secret_rotation(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
            secret_manifests=manifests,
            attempts=1,
            interval_seconds=0,
        )


def test_hybrid_lifecycle_tombstone_probe_script_compiles() -> None:
    compile(
        smoke.HYBRID_LIFECYCLE_TOMBSTONE_PROBE_SCRIPT,
        "<hybrid-lifecycle-tombstone>",
        "exec",
    )


def test_hybrid_lifecycle_tombstone_probe_fails_closed_on_reingestion() -> None:
    executor = RecordingExecutor(hybrid_lifecycle_valid=False)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="deletion parity, durable tombstone, and no-reingestion",
    ):
        smoke._verify_hybrid_lifecycle_tombstone(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_console_oidc_runtime_probe_fails_closed_on_contract_drift() -> None:
    executor = RecordingExecutor(console_oidc_runtime_valid=False)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="exact production OIDC contract",
    ):
        smoke._verify_console_oidc_runtime(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_projected_migration_dsn_probe_requires_successful_job_evidence() -> None:
    executor = RecordingExecutor(migration_secret_read_valid=False)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="successful projected PostgreSQL DSN consumption",
    ):
        smoke._verify_projected_runtime_secret_reads(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_projected_migration_dsn_probe_rejects_container_restart() -> None:
    executor = RecordingExecutor(migration_restart_count=1)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="migration Pod has 1 container restarts",
    ):
        smoke._verify_projected_runtime_secret_reads(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_dependency_ingress_probe_fails_closed_on_cleanup_error() -> None:
    executor = ProbeCleanupFailingExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="probe cleanup failure"):
        smoke._verify_dependency_ingress_denial(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_revision_jobs_are_polled_together_and_completed_jobs_are_not_requeried() -> None:
    executor = RevisionJobPollingExecutor(
        {
            "migrations": ["pending", "complete"],
            "vault-bootstrap": ["complete"],
            "sandbox-fixture": ["complete"],
        }
    )
    callbacks: list[str] = []

    result = smoke._wait_for_revision_jobs(
        executor,
        component_kubectls={
            "migrations": ["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
            "vault-bootstrap": ["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
            "sandbox-fixture": [
                "kubectl",
                "--namespace",
                smoke.DEFAULT_SANDBOX_NAMESPACE,
            ],
        },
        revision=7,
        on_complete={"migrations": lambda: callbacks.append("migrations")},
        attempts=3,
        interval_seconds=0,
    )

    assert set(result) == {"migrations", "vault-bootstrap", "sandbox-fixture"}
    assert executor.calls == {
        "migrations": 2,
        "vault-bootstrap": 1,
        "sandbox-fixture": 1,
    }
    assert callbacks == ["migrations"]
    assert all("release-revision=7" in " ".join(command) for command in executor.commands)


def test_revision_job_poll_fails_immediately_on_failed_condition() -> None:
    executor = RevisionJobPollingExecutor({"migrations": ["failed"]})

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="reported Failed=True"):
        smoke._wait_for_revision_jobs(
            executor,
            component_kubectls={"migrations": ["kubectl"]},
            revision=2,
            attempts=1,
            interval_seconds=0,
        )


@pytest.mark.parametrize(
    ("state", "match"),
    [
        ("wrong-revision", "exact Helm revision"),
        ("duplicate", "expected exactly one"),
    ],
)
def test_revision_job_poll_fails_closed_on_identity_drift(
    state: str,
    match: str,
) -> None:
    executor = RevisionJobPollingExecutor({"migrations": [state]})

    with pytest.raises(smoke.LiveKindHelmSmokeError, match=match):
        smoke._wait_for_revision_jobs(
            executor,
            component_kubectls={"migrations": ["kubectl"]},
            revision=2,
            attempts=1,
            interval_seconds=0,
        )


def test_revision_job_poll_fails_bounded_when_job_never_appears() -> None:
    executor = RevisionJobPollingExecutor({"migrations": ["missing", "missing"]})

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="after 2 polls"):
        smoke._wait_for_revision_jobs(
            executor,
            component_kubectls={"migrations": ["kubectl"]},
            revision=2,
            attempts=2,
            interval_seconds=0,
        )

    assert executor.calls == {"migrations": 2}


def test_revision_job_completion_after_deadline_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = RevisionJobPollingExecutor({"migrations": ["complete"]})
    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(smoke.time, "monotonic", lambda: next(clock))
    monkeypatch.setitem(smoke.JOB_WAIT_TIMEOUT_SECONDS, "migrations", 1)

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="bounded wait"):
        smoke._wait_for_revision_jobs(
            executor,
            component_kubectls={"migrations": ["kubectl"]},
            revision=2,
            attempts=1,
            interval_seconds=0,
        )


@pytest.mark.parametrize(
    "history",
    [
        [
            {"revision": 1, "status": "deployed"},
            {"revision": 2, "status": "superseded"},
        ],
        [
            {"revision": 2, "status": "deployed"},
            {"revision": 1, "status": "superseded"},
        ],
    ],
    ids=["status-drift", "revision-order-drift"],
)
def test_helm_history_inspection_fails_closed_on_revision_drift(
    history: list[dict[str, object]],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(helm_history_override=history)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="did not prove a deployed second upgrade",
    ):
        smoke._verify_helm_history(
            executor,
            namespace=smoke.DEFAULT_NAMESPACE,
            context="kind-test",
            kubeconfig=tmp_path / "kubeconfig",
        )


@pytest.mark.parametrize("malformed_revision", [True, 2.9, "2", "02"])
def test_helm_history_rejects_non_integer_revision_types(
    malformed_revision: object,
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(
        helm_history_override=[
            {"revision": 1, "status": "superseded"},
            {"revision": malformed_revision, "status": "deployed"},
        ]
    )

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="revision was invalid"):
        smoke._verify_helm_history(
            executor,
            namespace=smoke.DEFAULT_NAMESPACE,
            context="kind-test",
            kubeconfig=tmp_path / "kubeconfig",
        )


def _verify_sandbox_with_executor(executor: RecordingExecutor) -> dict[str, object]:
    return smoke._verify_kubernetes_sandbox(
        executor,
        application_kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        sandbox_kubectl=[
            "kubectl",
            "--namespace",
            smoke.DEFAULT_SANDBOX_NAMESPACE,
        ],
        application_namespace=smoke.DEFAULT_NAMESPACE,
        sandbox_namespace=smoke.DEFAULT_SANDBOX_NAMESPACE,
        bearer_token="test-bearer-token",
    )


def test_sandbox_request_timeout_budgets_are_derived_not_magic() -> None:
    source = Path(smoke.__file__).read_text(encoding="utf-8")

    assert "timeout=45" not in source
    assert "timeout_seconds=2.0" not in source
    assert "min(2.0, remaining)" not in source
    assert "timeout=$request_timeout_seconds" in source
    assert smoke.SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS == 5
    assert smoke.SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS == (
        smoke.SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS
        * smoke.SANDBOX_KUBE_API_POLL_REQUESTS
    )
    assert smoke.SANDBOX_REQUEST_TIMEOUT_SECONDS == (
        smoke.SANDBOX_SETUP_BUDGET_SECONDS
        + smoke.SANDBOX_COMMAND_BUDGET_SECONDS
        + smoke.SANDBOX_CLEANUP_GRACE_SECONDS
        + smoke.SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS
    )
    assert smoke.SANDBOX_REQUEST_EXEC_TIMEOUT_SECONDS == (
        smoke.SANDBOX_REQUEST_TIMEOUT_SECONDS
        + smoke.SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS
    )
    assert smoke.SANDBOX_CLEANUP_GRACE_MIN_SECONDS == 15
    assert smoke.SANDBOX_CLEANUP_GRACE_MAX_SECONDS == 30
    assert smoke.SANDBOX_CLEANUP_GRACE_SECONDS == 20
    assert smoke.SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS == (
        smoke.SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS
    )
    assert smoke.SANDBOX_CLEANUP_OUTER_SAFETY_MARGIN_SECONDS > 0


@pytest.mark.parametrize("command_count", [1, 2])
@pytest.mark.parametrize("cleanup_grace_seconds", [15, 20, 30])
def test_sandbox_cleanup_exec_timeout_never_precedes_supported_cleanup_path(
    command_count: int,
    cleanup_grace_seconds: int,
) -> None:
    supported_path_seconds = (
        smoke.SANDBOX_SETUP_BUDGET_SECONDS
        + smoke.SANDBOX_COMMAND_BUDGET_SECONDS * command_count
        + cleanup_grace_seconds
    )
    request_timeout_seconds = (
        supported_path_seconds + smoke.SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS
    )
    request_join_timeout_seconds = (
        request_timeout_seconds + smoke.SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS
    )
    inner_budget_seconds = (
        smoke.SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS
        + smoke.SANDBOX_KUBE_API_POLL_ALLOWANCE_SECONDS
        + request_join_timeout_seconds
        + cleanup_grace_seconds
    )

    exec_timeout_seconds = smoke._sandbox_cleanup_exec_timeout_seconds(
        command_count,
        cleanup_grace_seconds
    )

    assert smoke._sandbox_supported_request_path_seconds(
        command_count,
        cleanup_grace_seconds,
    ) == supported_path_seconds
    assert smoke._sandbox_request_timeout_seconds(
        command_count,
        cleanup_grace_seconds,
    ) == request_timeout_seconds
    assert exec_timeout_seconds > inner_budget_seconds
    assert exec_timeout_seconds == (
        inner_budget_seconds + smoke.SANDBOX_CLEANUP_OUTER_SAFETY_MARGIN_SECONDS
    )
    script = smoke._sandbox_cleanup_uid_probe_script(
        command_count,
        cleanup_grace_seconds,
    )
    assert f"urlopen(request, timeout={request_timeout_seconds})" in script
    assert (
        "request_thread.join(timeout="
        f"{request_join_timeout_seconds})"
        in script
    )
    assert (
        "timeout_seconds="
        f"{smoke.SANDBOX_CLEANUP_INITIAL_INVENTORY_ALLOWANCE_SECONDS}"
        in script
    )
    assert "capture_remaining = capture_deadline - time.monotonic()" in script
    assert "timeout_seconds=min(\n                5,\n                capture_remaining" in script


@pytest.mark.parametrize(
    "commands",
    [
        ["python probe.py"],
        ["python probe.py", "python -c \"print('sandbox-second')\""],
    ],
    ids=["one-command", "two-commands"],
)
def test_repo_request_timeout_tracks_payload_command_count(
    commands: list[str],
) -> None:
    executor = RecordingExecutor()

    smoke._repo_checks_request(
        executor,
        kubectl=["kubectl"],
        bearer_token="test-bearer-token",
        payload={
            "repo_ref": "smoke-repo",
            "commands": commands,
            "network_policy": "deny",
        },
        expected_status=200,
    )

    command_count = len(commands)
    request_timeout_seconds = smoke._sandbox_request_timeout_seconds(
        command_count,
        smoke.SANDBOX_CLEANUP_GRACE_SECONDS,
    )
    assert executor.command_timeouts[-1] == smoke._sandbox_request_exec_timeout_seconds(
        command_count,
        smoke.SANDBOX_CLEANUP_GRACE_SECONDS,
    )
    assert f"urlopen(request, timeout={request_timeout_seconds})" in executor.commands[-1][-1]


def test_sandbox_cleanup_probe_is_foreground_uid_scoped_and_bounded() -> None:
    script = smoke.SANDBOX_CLEANUP_UID_PROBE_SCRIPT

    ast.parse(script)
    assert "request_thread.join(timeout=" in script
    assert "request_thread.is_alive()" in script
    assert 'owner.get("uid") == target_job_uid' in script
    assert "target_job is None and not owned_pods" in script
    assert "sandbox request completed before Job UID capture" in script
    assert "sandbox Job name was rebound to a different UID" in script
    assert '"target_owned_pods": 0' in script
    assert "cleanup_grace_seconds <= 30" in script


def _execute_embedded_cleanup_probe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    capture_target: bool = True,
    cleanup_job_state: str = "absent",
    cleanup_pod_uids: Sequence[str | None] = (None, None),
    request_error: bool = False,
) -> tuple[dict[str, object], dict[str, int]]:
    target_job_name = "hallu-sandbox-timeout"
    target_job_uid = "11111111-1111-4111-8111-111111111111"
    state = {"job_gets": 0, "pod_lists": 0}
    pod_cleanup_sequence = list(cleanup_pod_uids)
    clock = {"now": 0.0}
    urlopen_timeouts: list[tuple[str, float]] = []
    join_timeouts: list[float | None] = []
    fake_threads: list[FakeThread] = []

    class FakeEvent:
        def __init__(self) -> None:
            self._set = False

        def set(self) -> None:
            self._set = True

        def is_set(self) -> bool:
            return self._set

    class FakeThread:
        def __init__(self, *, target: Callable[[], None], name: str) -> None:
            self._target = target
            self.name = name
            self._started = False
            self._finished = False
            fake_threads.append(self)

        def start(self) -> None:
            self._started = True

        def run_pending(self) -> None:
            if self._started and not self._finished:
                self._target()
                self._finished = True

        def join(self, timeout: float | None = None) -> None:
            join_timeouts.append(timeout)
            self.run_pending()

        def is_alive(self) -> bool:
            return self._started and not self._finished

    class FakeResponse(io.BytesIO):
        def __init__(self, payload: object, *, status: int = 200) -> None:
            super().__init__(json.dumps(payload).encode("utf-8"))
            self.status = status

    def target_job(*, uid: str = target_job_uid) -> dict[str, object]:
        return {
            "metadata": {
                "name": target_job_name,
                "uid": uid,
                "labels": {"hallu-defense.openai.com/sandbox": "true"},
            }
        }

    def pod_owned_by(owner_uid: str) -> dict[str, object]:
        return {
            "metadata": {
                "name": "hallu-sandbox-timeout-pod",
                "uid": "22222222-2222-4222-8222-222222222222",
                "labels": {"hallu-defense.openai.com/sandbox": "true"},
                "ownerReferences": [
                    {
                        "kind": "Job",
                        "name": target_job_name,
                        "uid": owner_uid,
                        "controller": True,
                    }
                ],
            }
        }

    def fake_urlopen(
        request: urllib.request.Request,
        timeout: float,
        context: object | None = None,
    ) -> FakeResponse:
        del context
        url = request.full_url
        urlopen_timeouts.append((url, timeout))
        if url == "http://127.0.0.1:8000/repo/checks/run":
            if request_error:
                raise OSError("injected request failure")
            return FakeResponse(
                {
                    "exit_codes": [smoke.SANDBOX_TIMEOUT_RETURN_CODE],
                    "stdout": [""],
                    "stderr": ["kubernetes sandbox command timed out\n"],
                    "artifacts": [],
                }
            )
        if url.endswith("/pods"):
            state["pod_lists"] += 1
            if state["pod_lists"] == 1:
                return FakeResponse({"items": []})
            if state["pod_lists"] == 2:
                assert len(fake_threads) == 1
                fake_threads[0].run_pending()
                items = [pod_owned_by(target_job_uid)] if capture_target else []
                return FakeResponse({"items": items})
            owner_uid = (
                pod_cleanup_sequence.pop(0)
                if pod_cleanup_sequence
                else cleanup_pod_uids[-1]
                if cleanup_pod_uids
                else None
            )
            return FakeResponse(
                {"items": [] if owner_uid is None else [pod_owned_by(owner_uid)]}
            )
        if "/jobs/" in url:
            state["job_gets"] += 1
            if state["job_gets"] == 1:
                return FakeResponse(target_job())
            if cleanup_job_state == "present":
                return FakeResponse(target_job())
            if cleanup_job_state == "rebound":
                return FakeResponse(target_job(uid="33333333-3333-4333-8333-333333333333"))
            assert cleanup_job_state == "absent"
            raise urllib.error.HTTPError(
                url,
                404,
                "Not Found",
                hdrs=None,
                fp=io.BytesIO(b"{}"),
            )
        raise AssertionError(f"unexpected probe URL: {url}")

    def fake_open(path: str, *, encoding: str) -> io.StringIO:
        assert path.endswith("/token")
        assert encoding == "utf-8"
        return io.StringIO("service-account-token")

    def fake_monotonic() -> float:
        clock["now"] += 0.01
        return clock["now"]

    def fake_sleep(seconds: float) -> None:
        clock["now"] += seconds

    request_input = {
        "token": "signed-test-jwt",
        "body": {
            "repo_ref": "smoke-repo",
            "commands": ["python timeout.py"],
            "network_policy": "deny",
        },
        "sandbox_namespace": smoke.DEFAULT_SANDBOX_NAMESPACE,
        "cleanup_grace_seconds": 20,
    }
    stdout = io.StringIO()
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: object())
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(threading, "Event", FakeEvent)
    monkeypatch.setattr(threading, "Thread", FakeThread)
    monkeypatch.setattr(smoke.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(smoke.time, "sleep", fake_sleep)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request_input)))
    monkeypatch.setattr(sys, "stdout", stdout)

    try:
        exec(smoke.SANDBOX_CLEANUP_UID_PROBE_SCRIPT, {"__name__": "__main__"})
    finally:
        assert all(not thread.is_alive() for thread in fake_threads)
    envelope = json.loads(stdout.getvalue())
    assert isinstance(envelope, dict)
    assert "signed-test-jwt" not in stdout.getvalue()
    assert "service-account-token" not in stdout.getvalue()
    assert join_timeouts == [
        smoke.SANDBOX_REQUEST_TIMEOUT_SECONDS
        + smoke.SANDBOX_REQUEST_SAFETY_MARGIN_SECONDS
    ]
    repo_timeouts = [
        timeout
        for url, timeout in urlopen_timeouts
        if url == "http://127.0.0.1:8000/repo/checks/run"
    ]
    kube_timeouts = [
        timeout
        for url, timeout in urlopen_timeouts
        if url != "http://127.0.0.1:8000/repo/checks/run"
    ]
    assert repo_timeouts == [smoke.SANDBOX_REQUEST_TIMEOUT_SECONDS]
    assert kube_timeouts
    assert all(
        0 < timeout <= smoke.SANDBOX_KUBE_API_REQUEST_TIMEOUT_SECONDS
        for timeout in kube_timeouts
    )
    return envelope, state


def test_embedded_cleanup_probe_requires_two_consecutive_clean_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope, state = _execute_embedded_cleanup_probe(
        monkeypatch,
        cleanup_pod_uids=(
            None,
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        ),
    )

    assert envelope["cleanup"]["target_job_absent"] is True
    assert envelope["cleanup"]["target_owned_pods"] == 0
    assert envelope["cleanup"]["poll_attempts"] == 4
    assert state == {"job_gets": 5, "pod_lists": 6}


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"cleanup_job_state": "present"}, "cleanup deadline expired"),
        (
            {
                "cleanup_pod_uids": (
                    "11111111-1111-4111-8111-111111111111",
                )
            },
            "cleanup deadline expired",
        ),
        ({"cleanup_job_state": "rebound"}, "rebound to a different UID"),
        ({"capture_target": False}, "completed before Job UID capture"),
        ({"request_error": True}, "request failed inside cleanup probe"),
    ],
    ids=[
        "job-persists",
        "target-owner-pod-persists",
        "job-name-rebound",
        "capture-absent",
        "request-thread-error",
    ],
)
def test_embedded_cleanup_probe_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(RuntimeError, match=match):
        _execute_embedded_cleanup_probe(monkeypatch, **kwargs)


def test_embedded_cleanup_probe_ignores_pod_owned_by_different_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope, _ = _execute_embedded_cleanup_probe(
        monkeypatch,
        cleanup_pod_uids=(
            "99999999-9999-4999-8999-999999999999",
            "99999999-9999-4999-8999-999999999999",
        ),
    )

    assert envelope["cleanup"]["target_owned_pods"] == 0
    assert envelope["cleanup"]["poll_attempts"] == 2


def test_cleanup_probe_executor_timeout_covers_maximum_schema_grace() -> None:
    executor = RecordingExecutor()

    body, evidence = smoke._repo_checks_request_with_cleanup_evidence(
        executor,
        kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        bearer_token="test-bearer-token",
        payload={
            "repo_ref": "smoke-repo",
            "commands": ["python timeout.py"],
            "network_policy": "deny",
        },
        sandbox_namespace=smoke.DEFAULT_SANDBOX_NAMESPACE,
        expected_status=200,
        cleanup_grace_seconds=30,
    )

    assert body["exit_codes"] == [smoke.SANDBOX_TIMEOUT_RETURN_CODE]
    assert evidence["target_owned_pods"] == 0
    assert executor.command_timeouts[-1] == 150


@pytest.mark.parametrize(
    "invalid_grace",
    [True, 14, 31, 15.5, float("nan"), float("inf")],
)
def test_cleanup_probe_rejects_out_of_contract_grace(
    invalid_grace: int | bool | float,
) -> None:
    executor = RecordingExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="integer between 15 and 30"):
        smoke._repo_checks_request_with_cleanup_evidence(
            executor,
            kubectl=["kubectl"],
            bearer_token="test-bearer-token",
            payload={"commands": ["python timeout.py"]},
            sandbox_namespace=smoke.DEFAULT_SANDBOX_NAMESPACE,
            expected_status=200,
            cleanup_grace_seconds=invalid_grace,
        )
    assert executor.commands == []


@pytest.mark.parametrize(
    "executor",
    [
        RecordingExecutor(cleanup_job_absent=False),
        RecordingExecutor(cleanup_owned_pods=1),
    ],
    ids=["target-job-remains", "target-owner-uid-pod-remains"],
)
def test_sandbox_cleanup_evidence_fails_closed_on_target_residuals(
    executor: RecordingExecutor,
) -> None:
    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="did not prove exact Job and owner-UID Pod absence",
    ):
        _verify_sandbox_with_executor(executor)


@pytest.mark.parametrize(
    "evidence",
    [
        {},
        [],
        {
            "probe": "sandbox_cleanup_uid_probe",
            "target_job_name": "hallu-sandbox-timeout",
            "target_job_uid": "invalid uid",
            "target_job_absent": True,
            "target_owned_pods": 0,
            "poll_attempts": 1,
        },
    ],
    ids=["missing", "non-object", "invalid-uid"],
)
def test_sandbox_cleanup_evidence_rejects_malformed_identity(evidence: object) -> None:
    executor = RecordingExecutor(cleanup_evidence_override=evidence)

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="cleanup UID evidence|did not prove"):
        _verify_sandbox_with_executor(executor)


def test_sandbox_global_inventory_rejects_owner_pod_after_jobs_are_absent() -> None:
    executor = RecordingExecutor(
        residual_sandbox_jobs=0,
        residual_sandbox_pods=1,
    )

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match="left residual Kubernetes pods",
    ):
        _verify_sandbox_with_executor(executor)

    command_text = [" ".join(command) for command in executor.commands]
    assert any(
        "get jobs --selector hallu-defense.openai.com/sandbox=true" in command
        for command in command_text
    )
    assert any(
        "get pods --selector hallu-defense.openai.com/sandbox=true" in command
        for command in command_text
    )


def test_live_kind_helm_smoke_runs_install_and_runtime_checks() -> None:
    executor = RecordingExecutor()

    result = smoke.run_from_env(
        {smoke.ENABLED_ENV: "true"},
        tool_locator=_all_tools,
        executor=executor,
    )

    command_text = [" ".join(command) for command in executor.commands]
    assert result["status"] == "passed"
    assert result["network_policy_engine"] == {
        "provider": "kindnet",
        "node_image": smoke.KIND_NODE_IMAGE,
        "platform": "linux/amd64",
        "native": True,
        "default_cni_enabled": True,
        "runtime_denials_verified": True,
    }
    assert result["migration_count"] == smoke.EXPECTED_MIGRATION_COUNT
    assert result["bootstrap_jobs"] == {
        "revision_1": {
            "migrations": {
                "complete": True,
                "job": "hallu-defense-migrations-1",
                "revision": 1,
            },
            "sandbox-fixture": {
                "complete": True,
                "job": "hallu-defense-sandbox-fixture-1",
                "revision": 1,
            },
            "vault-bootstrap": {
                "complete": True,
                "job": "hallu-defense-vault-bootstrap-1",
                "revision": 1,
            },
        },
        "revision_2": {
            "migrations": {
                "complete": True,
                "job": "hallu-defense-migrations-2",
                "revision": 2,
            },
            "vault-bootstrap": {
                "complete": True,
                "job": "hallu-defense-vault-bootstrap-2",
                "revision": 2,
            },
        },
    }
    assert result["fixture_readiness"] == {
        "job": "hallu-defense-sandbox-fixture-1",
        "pod": "hallu-defense-sandbox-fixture-pod",
        "ready": True,
        "revision": 1,
        "restarts": 0,
    }
    assert result["helm_history"] == [
        {"revision": 1, "status": "superseded"},
        {"revision": 2, "status": "deployed"},
    ]
    assert result["sandbox_namespace"] == smoke.DEFAULT_SANDBOX_NAMESPACE
    assert result["helm_secret_boundary"] == {
        "manifest_secret_objects": 0,
        "revisions_checked": [1, 2],
        "sensitive_value_fields": 0,
        "precreated_secret_references": {
            "runtime": "hallu-defense-runtime",
            "bootstrap": "hallu-defense-bootstrap",
            "migrations": "hallu-defense-migrations",
            "kindPostgres": "hallu-defense-postgres",
            "kindVault": "hallu-defense-kind-vault",
            "kindRedisTls": "hallu-defense-kind-redis-tls",
        },
    }
    assert any("docker build --file infra/docker/api.Dockerfile" in item for item in command_text)
    assert any(
        "docker build --file infra/docker/console.Dockerfile" in item for item in command_text
    )
    assert any(
        "docker build --file infra/docker/sandbox.Dockerfile" in item for item in command_text
    )
    assert any(
        "docker build --file infra/docker/pgvector.Dockerfile" in item for item in command_text
    )
    assert any(
        "docker build --file infra/docker/opensearch.Dockerfile" in item for item in command_text
    )
    assert any("kind load docker-image" in item for item in command_text)
    run_ids = {str(image).split(":kind-", maxsplit=1)[1] for image in result["images"]}
    assert len(run_ids) == 1
    assert result["images"] == [
        f"{repository}:kind-{next(iter(run_ids))}"
        for repository in smoke.SCRATCH_IMAGE_REPOSITORIES.values()
    ]
    assert str(result["cluster"]).startswith(f"{smoke.DEFAULT_CLUSTER}-")
    create_index = next(
        index for index, item in enumerate(command_text) if item.startswith("kind create")
    )
    node_ready_index = next(
        index
        for index, item in enumerate(command_text)
        if "wait nodes --all --for=condition=Ready" in item
    )
    helm_index = next(
        index for index, item in enumerate(command_text) if item.startswith("helm lint")
    )
    assert create_index < node_ready_index < helm_index
    assert "--wait" not in executor.commands[create_index]
    assert "--image" in executor.commands[create_index]
    assert smoke.KIND_NODE_IMAGE in executor.commands[create_index]
    assert executor.kind_config_text is not None
    assert "disableDefaultCNI" not in executor.kind_config_text
    assert f"podSubnet: {smoke.KIND_POD_SUBNET}" in executor.kind_config_text
    assert any(item.startswith("helm lint") for item in command_text)
    assert any(item.startswith("helm template") for item in command_text)
    assert any(item.startswith("helm upgrade --install") for item in command_text)
    assert sum(item.startswith("helm upgrade") for item in command_text) == 2
    assert any(
        item.startswith("helm upgrade hallu-defense")
        and "sandbox.fixture.enabled=false" in item
        for item in command_text
    )
    assert all("--rollback-on-failure" not in item for item in command_text)
    assert all("--wait-for-jobs" not in item for item in command_text)
    upgrade_timeouts = [
        timeout
        for argv, timeout in zip(
            executor.commands, executor.command_timeouts, strict=True
        )
        if argv[:2] == ["helm", "upgrade"]
    ]
    assert upgrade_timeouts == [
        smoke.HELM_EXECUTOR_TIMEOUT_SECONDS,
        smoke.HELM_EXECUTOR_TIMEOUT_SECONDS,
    ]
    assert any("--timeout=660s" in argv for argv in executor.commands)
    assert all("--atomic" not in item for item in command_text)
    preflight_index = next(
        index
        for index, item in enumerate(command_text)
        if "--show-only templates/sandbox-validating-admission-policy.yaml" in item
    )
    preflight_apply_index = next(
        index
        for index, item in enumerate(command_text)
        if "apply --server-side --dry-run=server" in item
    )
    image_load_index = next(
        index
        for index, item in enumerate(command_text)
        if item.startswith("kind load docker-image")
    )
    assert preflight_index < preflight_apply_index < image_load_index
    assert not any("wait --for=condition=complete" in item for item in command_text)
    fixture_ready_index = next(
        index
        for index, item in enumerate(command_text)
        if "get pods --selector=app.kubernetes.io/component=sandbox-fixture," in item
        and "release-revision=1" in item
    )
    revision_one_job_indices = [
        index
        for index, item in enumerate(command_text)
        if "get jobs --selector=app.kubernetes.io/component=" in item
        and "release-revision=1" in item
    ]
    assert len(revision_one_job_indices) == 3
    assert fixture_ready_index < min(revision_one_job_indices)
    second_upgrade_index = next(
        index
        for index, item in enumerate(command_text)
        if item.startswith("helm upgrade hallu-defense")
        and "--install" not in item
    )
    revision_two_migration_job_index = next(
        index
        for index, item in enumerate(command_text)
        if "get jobs --selector=app.kubernetes.io/component=migrations," in item
        and "release-revision=2" in item
    )
    revision_two_migration_pod_index = next(
        index
        for index, item in enumerate(command_text)
        if "get pods --selector=app.kubernetes.io/component=migrations," in item
        and "release-revision=2" in item
    )
    revision_two_migration_log_index = next(
        index
        for index, item in enumerate(command_text)
        if "logs --selector=app.kubernetes.io/component=migrations," in item
        and "release-revision=2" in item
    )
    second_rollout_index = next(
        index
        for index, item in enumerate(command_text)
        if index > second_upgrade_index and "rollout status" in item
    )
    assert (
        second_upgrade_index
        < revision_two_migration_job_index
        < revision_two_migration_pod_index
        < revision_two_migration_log_index
        < second_rollout_index
    )
    assert any("rollout status deployment/hallu-defense-worker" in item for item in command_text)
    assert any("rollout status deployment/hallu-defense-vault" in item for item in command_text)
    assert any("rollout status deployment/hallu-defense-redis" in item for item in command_text)
    assert any("app.kubernetes.io/component=vault-bootstrap" in item for item in command_text)
    assert any(
        "COALESCE(checksum_sha256, '<NULL>')" in item for item in command_text
    )
    assert result["migration_checksums"] == smoke.EXPECTED_MIGRATION_CHECKSUMS
    assert (
        result["migration_checksum_aggregate"]
        == smoke.EXPECTED_MIGRATION_CHECKSUM_AGGREGATE
    )
    assert any("http://127.0.0.1:8000/health" in item for item in command_text)
    assert any("http://127.0.0.1:8000/ready" in item for item in command_text)
    assert any(
        "logs deployment/hallu-defense-api --container bootstrap-opensearch-schema" in item
        for item in command_text
    )
    assert not any(
        "/app/scripts/dev/bootstrap_opensearch_template.py" in item for item in command_text
    )
    assert result["readiness"] == {"status": "ready"}
    assert result["console_oidc"] == {
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
    assert sum("console_oidc_runtime_probe" in item for item in command_text) == 1
    assert result["redis"] == {
        "acl_command_rejected": True,
        "acl_prefix_rejected": True,
        "invalid_auth_rejected": True,
        "plaintext_rejected": True,
        "rate_limit_eval_allowed": True,
        "tls_ca_vault_health": True,
    }
    redis_verification_script = next(
        argv[-1]
        for argv in executor.commands
        if argv[-2:-1] == ["-c"] and '"tls_ca_vault_health": True' in argv[-1]
    )
    compile(redis_verification_script, "<kind-redis-verification>", "exec")
    assert 'b"*1\\r\\n$4\\r\\nPING\\r\\n"' in redis_verification_script
    assert result["sandbox"]["admission_rejected_malicious_job"] is True
    assert result["sandbox"]["admission_accepted_backend_job"] is True
    assert result["sandbox"]["admission_accepted_equivalent_quantities"] is True
    assert result["sandbox"]["admission"] == {
        "policy": smoke._sandbox_admission_policy_name(
            smoke.DEFAULT_NAMESPACE,
            smoke.DEFAULT_SANDBOX_NAMESPACE,
        ),
        "generation": 1,
        "observed_generation": 1,
        "exact_backend_manifest_accepted": True,
        "equivalent_quantities_accepted": True,
        "malicious_jobs_denied": 15,
    }
    assert result["sandbox"]["egress_blocked_by_kindnet"] is True
    assert result["sandbox"]["batched_commands"] == 2
    assert result["sandbox"]["residual_jobs"] == 0
    assert result["sandbox"]["residual_pods"] == 0
    assert result["sandbox"]["cleanup"] == {
        "probe": "sandbox_cleanup_uid_probe",
        "target_job_name": "hallu-sandbox-timeout",
        "target_job_uid": "11111111-1111-4111-8111-111111111111",
        "target_job_absent": True,
        "target_owned_pods": 0,
        "poll_attempts": 2,
    }
    assert result["sandbox"]["api_workspace_read_only"] is True
    assert result["sandbox"]["rbac"] == {
        "application_namespace_denied": {
            "delete:jobs.batch": True,
            "get:pods/log": True,
            "list:pods": True,
        },
        "sandbox_namespace_allowed": {
            "create:jobs.batch": True,
            "delete:jobs.batch": True,
            "get:jobs.batch": True,
            "get:pods/log": True,
            "list:networkpolicies.networking.k8s.io": True,
            "list:pods": True,
        },
    }
    assert result["opensearch_schema"] == {
        "template_name": "hallu_evidence_template",
        "index_name": "hallu_evidence",
        "installed": True,
        "acknowledged": True,
        "schema_version": smoke.EXPECTED_OPENSEARCH_SCHEMA_VERSION,
        "schema_ready": True,
        "dry_run": False,
        "index_state": "absent",
        "template_replicas": 1,
        "cluster_status": "yellow",
        "cluster_timed_out": False,
        "data_nodes": 1,
        "transport_9300_listeners": ["127.0.0.1"],
    }
    assert result["worker_readiness"] == {
        "real_dependencies_ready": True,
        "unreachable_opensearch_rejected": True,
    }
    assert result["worker_metrics"] == {
        "authenticated_status": 200,
        "cache_control": "no-store",
        "ingestion_metric_present": True,
        "unauthenticated_status": 401,
    }
    assert result["projected_secret_reads"] == {
        "api": {
            "postgres_dsn_file_read": True,
            "raw_secret_env_absent": True,
            "vault_token_file_read": True,
        },
        "worker": {
            "postgres_dsn_file_read": True,
            "raw_secret_env_absent": True,
            "vault_token_file_read": True,
        },
        "migrations": {
            "newly_applied_migrations": 0,
            "postgres_dsn_file_read": True,
            "raw_secret_env_absent": True,
            "revision": 2,
            "restarts": 0,
        },
    }
    assert sum("projected_runtime_secret_probe" in item for item in command_text) == 2
    assert result["runtime_secret_rotation"] == {
        "api_restarts": 0,
        "fingerprint_changed": True,
        "lexical_path_preserved": True,
        "manager_type": "VaultSecretManager",
        "original_restored": True,
    }
    assert sum("vault_manager_projected_rotation_probe" in item for item in command_text) >= 3
    assert result["hybrid_lifecycle_tombstone"] == {
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
    assert sum("hybrid_lifecycle_tombstone_probe" in item for item in command_text) == 1
    assert any(
        "--selector=app.kubernetes.io/component=migrations," in item
        and "release-revision=2" in item
        and "--container=migrations" in item
        for item in command_text
    )
    application_egress = result["application_egress"]
    assert application_egress["probes"] == {
        "api": {"internet_1_1_1_1": False, "kubernetes_api": True},
        "worker": {"internet_1_1_1_1": False, "kubernetes_api": False},
        "console": {"internet_1_1_1_1": False},
        "unauthorized_dependency_ingress": {
            "api": False,
            "console": False,
            "worker": False,
            "explicit_application_allowlists": {
                "api": {"api": True, "console": False, "worker": False},
                "console": {"api": False, "console": True, "worker": False},
                "metrics": {"api": True, "console": False, "worker": True},
            },
            "opensearch": False,
            "opensearch_transport_pod_ip_9300": False,
            "pgvector": False,
            "vault": False,
            "probe_pod_deleted": True,
        },
    }
    allowlist_scripts = [
        argv[-1]
        for argv in executor.commands
        if argv[-2:-1] == ["-c"] and "application_ingress_allowlist_probe" in argv[-1]
    ]
    assert len(allowlist_scripts) == 3
    decoded_allowlists: list[dict[str, bool]] = []
    for script in allowlist_scripts:
        tree = ast.parse(script)
        expected_assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "expected"
                for target in node.targets
            )
        )
        assert isinstance(expected_assignment.value, ast.Call)
        assert isinstance(expected_assignment.value.func, ast.Attribute)
        assert expected_assignment.value.func.attr == "loads"
        assert isinstance(expected_assignment.value.func.value, ast.Name)
        assert expected_assignment.value.func.value.id == "json"
        assert len(expected_assignment.value.args) == 1
        encoded = ast.literal_eval(expected_assignment.value.args[0])
        decoded = json.loads(encoded)
        assert isinstance(decoded, dict)
        decoded_allowlists.append(decoded)
    assert decoded_allowlists == [
        {"api": True, "console": False, "worker": False},
        {"api": False, "console": True, "worker": False},
        {"api": True, "console": False, "worker": True},
    ]
    assert set(application_egress["policies"]) == {
        "api",
        "worker",
        "console",
        "migrations",
        "vault-bootstrap",
        "pgvector",
        "opensearch",
        "vault",
        "redis",
        "default-deny-ingress",
    }
    assert application_egress["policies"]["console"]["egress_rule_count"] == 1
    for component in ("pgvector", "opensearch", "vault"):
        assert application_egress["policies"][component]["egress_rule_count"] == 0
    assert application_egress["policies"]["pgvector"]["ingress_sources"] == [
        "api",
        "worker",
        "migrations",
    ]
    assert application_egress["policies"]["opensearch"]["ingress_sources"] == [
        "api",
        "worker",
    ]
    assert application_egress["policies"]["vault"]["ingress_sources"] == [
        "api",
        "worker",
        "vault-bootstrap",
        "redis",
    ]
    assert any("delete pod hallu-network-ingress-probe" in item for item in command_text)
    assert set(result["workloads"]) == set(smoke.EXPECTED_WORKLOAD_COMPONENTS)
    assert all(item["restarts"] == 0 for item in result["workloads"].values())
    assert result["cleanup"] == {
        "baseline_clusters_before": [],
        "cluster_deleted": True,
        "scratch_images_deleted": result["images"],
        "scratch_images_verified_absent": True,
        "unrelated_clusters_after": [],
        "verified_absent": True,
    }
    assert any(
        "--as system:serviceaccount:hallu-defense:hallu-defense-api" in item
        for item in command_text
    )
    admission_commands = [
        argv for argv in executor.commands if "--as" in argv and "--dry-run=server" in argv
    ]
    assert admission_commands
    assert all("--dry-run=server" in argv for argv in admission_commands)
    assert any("hallu-defense.openai.com/sandbox=true" in item for item in command_text)
    assert any(
        item == f"kind delete cluster --name {result['cluster']}" for item in command_text
    )
    assert all(
        "--kubeconfig" in argv for argv in executor.commands if argv[:1] == ["kubectl"]
    )
    assert not executor.docker_images
    assert not executor.kind_clusters
    secrets_by_name = {
        str(manifest["metadata"]["name"]): manifest["stringData"]
        for manifest in executor.secret_manifests
    }
    assert set(secrets_by_name) == {
        "hallu-defense-runtime",
        "hallu-defense-bootstrap",
        "hallu-defense-migrations",
        "hallu-defense-postgres",
        "hallu-defense-kind-vault",
        "hallu-defense-kind-redis-tls",
    }
    assert result["precreated_secrets"] == list(secrets_by_name)
    runtime_secrets = secrets_by_name["hallu-defense-runtime"]
    bootstrap_secrets = secrets_by_name["hallu-defense-bootstrap"]
    migrations_secrets = secrets_by_name["hallu-defense-migrations"]
    assert runtime_secrets["postgres-dsn"] == (
        "postgresql://prod_user:prod_pass@hallu-defense-pgvector:5432/prod_db"
        "?sslmode=disable&gssencmode=disable"
    )
    assert migrations_secrets["migrations-postgres-dsn"] == runtime_secrets["postgres-dsn"]
    assert set(bootstrap_secrets) == {"vault-token"}
    assert bootstrap_secrets["vault-token"] == runtime_secrets["vault-token"]
    jwks = json.loads(str(runtime_secrets["keycloak-jwks.json"]))
    assert isinstance(jwks, dict)
    keys = jwks["keys"]
    assert isinstance(keys, list) and len(keys) == 1
    jwk = keys[0]
    assert jwk["alg"] == "RS256"
    modulus = _decode_base64url_uint(str(jwk["n"]))
    assert modulus.bit_length() == 2048
    assert _decode_base64url_uint(str(jwk["e"])) == 65537
    assert executor.bearer_tokens
    signed_jwt = executor.bearer_tokens[0]
    header_segment, claims_segment, signature_segment = signed_jwt.split(".")
    header = json.loads(_decode_base64url(header_segment))
    claims = json.loads(_decode_base64url(claims_segment))
    assert header["kid"] == jwk["kid"]
    assert claims["iss"] == smoke.OIDC_ISSUER
    assert claims["aud"] == smoke.OIDC_AUDIENCE
    assert claims["roles"] == ["sandbox_runner"]
    public_key = rsa.RSAPublicNumbers(
        _decode_base64url_uint(str(jwk["e"])),
        _decode_base64url_uint(str(jwk["n"])),
    ).public_key()
    public_key.verify(
        _decode_base64url(signature_segment),
        f"{header_segment}.{claims_segment}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert all(signed_jwt not in item for item in command_text)
    vault_secrets = secrets_by_name["hallu-defense-kind-vault"]
    ca_certificate = x509.load_pem_x509_certificate(str(vault_secrets["ca.crt"]).encode("ascii"))
    tls_certificate = x509.load_pem_x509_certificate(str(vault_secrets["tls.crt"]).encode("ascii"))
    tls_private_key = serialization.load_pem_private_key(
        str(vault_secrets["tls.key"]).encode("ascii"),
        password=None,
    )
    assert tls_certificate.issuer == ca_certificate.subject
    assert (
        tls_certificate.public_key().public_numbers()
        == tls_private_key.public_key().public_numbers()
    )
    san = tls_certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value
    assert "hallu-defense-vault" in san.get_values_for_type(x509.DNSName)
    redis_secrets = secrets_by_name["hallu-defense-kind-redis-tls"]
    redis_ca_certificate = x509.load_pem_x509_certificate(
        str(redis_secrets["ca.crt"]).encode("ascii")
    )
    redis_tls_certificate = x509.load_pem_x509_certificate(
        str(redis_secrets["tls.crt"]).encode("ascii")
    )
    redis_tls_private_key = serialization.load_pem_private_key(
        str(redis_secrets["tls.key"]).encode("ascii"),
        password=None,
    )
    assert redis_tls_certificate.issuer == redis_ca_certificate.subject
    assert (
        redis_tls_certificate.public_key().public_numbers()
        == redis_tls_private_key.public_key().public_numbers()
    )
    redis_san = redis_tls_certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value
    assert "hallu-defense-redis" in redis_san.get_values_for_type(x509.DNSName)
    serialized_secrets = json.dumps(executor.secret_manifests)
    assert "kindProviderApiKey" not in serialized_secrets
    assert "kindMetricsBearerToken" not in serialized_secrets
    assert "metricsBearerToken" not in serialized_secrets
    assert "opensearchInitialAdminPassword" not in serialized_secrets


def test_sandbox_admission_probes_cover_known_escalations() -> None:
    probes = dict(smoke._sandbox_admission_probe_manifests(smoke.DEFAULT_NAMESPACE))

    assert set(probes) == {
        "hallu-sandbox-admission-privileged",
        "hallu-sandbox-admission-secret-env",
        "hallu-sandbox-admission-workspace-root",
        "hallu-sandbox-admission-source-rw",
        "hallu-sandbox-admission-unbounded",
        "hallu-sandbox-admission-unmasked",
        "hallu-sandbox-admission-controls",
        "hallu-sandbox-admission-entrypoint",
        "hallu-sandbox-admission-lifecycle",
        "hallu-sandbox-admission-startup-probe",
        "hallu-sandbox-admission-liveness-probe",
        "hallu-sandbox-admission-readiness-probe",
        "hallu-sandbox-admission-groups",
        "hallu-sandbox-admission-selector",
        "hallu-sandbox-admission-finalizer",
    }
    serialized = {name: json.dumps(manifest) for name, manifest in probes.items()}
    assert "hostPath" in serialized["hallu-sandbox-admission-privileged"]
    assert '"allowPrivilegeEscalation": true' in serialized["hallu-sandbox-admission-privileged"]
    assert "secretRef" in serialized["hallu-sandbox-admission-secret-env"]
    assert "workspace-root" in serialized["hallu-sandbox-admission-workspace-root"]
    assert (
        '"name": "source", "mountPath": "/hallu-source", "readOnly": false'
        in (serialized["hallu-sandbox-admission-source-rw"])
    )
    assert "1001m" in serialized["hallu-sandbox-admission-unbounded"]
    assert "513Mi" in serialized["hallu-sandbox-admission-unbounded"]
    assert "1024Mi" in serialized["hallu-sandbox-admission-unbounded"]
    assert "Unmasked" in serialized["hallu-sandbox-admission-unmasked"]
    assert '"hostUsers": false' in serialized["hallu-sandbox-admission-unmasked"]
    assert "hostPort" in serialized["hallu-sandbox-admission-controls"]
    assert "bypass" in serialized["hallu-sandbox-admission-entrypoint"]
    assert "postStart" in serialized["hallu-sandbox-admission-lifecycle"]
    assert "startupProbe" in serialized["hallu-sandbox-admission-startup-probe"]
    assert "livenessProbe" in serialized["hallu-sandbox-admission-liveness-probe"]
    assert "readinessProbe" in serialized["hallu-sandbox-admission-readiness-probe"]
    assert "supplementalGroups" in serialized["hallu-sandbox-admission-groups"]
    assert "manualSelector" in serialized["hallu-sandbox-admission-selector"]
    assert "finalizers" in serialized["hallu-sandbox-admission-finalizer"]


def test_valid_admission_probe_is_exact_backend_manifest() -> None:
    manifest = smoke._sandbox_admission_valid_manifest(
        smoke.DEFAULT_NAMESPACE,
        name="hallu-sandbox-admission-valid",
    )
    spec = manifest["spec"]
    assert isinstance(spec, dict)
    assert spec["suspend"] is False
    template = spec["template"]
    assert isinstance(template, dict)
    pod_spec = template["spec"]
    assert isinstance(pod_spec, dict)
    containers = pod_spec["containers"]
    assert isinstance(containers, list)
    runner = containers[0]
    assert isinstance(runner, dict)
    assert runner["command"] == ["python", "/opt/hallu-defense/sandbox_runner.py"]
    assert runner["args"][:4] == ["256", "50000", "536870912", "python"]
    mounts = {mount["name"]: mount for mount in runner["volumeMounts"]}
    assert mounts["source"] == {
        "name": "source",
        "mountPath": "/hallu-source",
        "readOnly": True,
        "subPath": "smoke-repo",
    }
    assert mounts["workspace"] == {"name": "workspace", "mountPath": "/workspace"}
    volumes = {volume["name"]: volume for volume in pod_spec["volumes"]}
    assert volumes["source"] == {
        "name": "source",
        "persistentVolumeClaim": {"claimName": "hallu-defense-sandbox-workspace"},
    }
    assert volumes["workspace"] == {
        "name": "workspace",
        "emptyDir": {"sizeLimit": "512Mi"},
    }


def test_equivalent_quantity_probe_preserves_semantic_limits() -> None:
    manifest = smoke._sandbox_admission_equivalent_quantity_manifest(smoke.DEFAULT_NAMESPACE)
    pod_spec = manifest["spec"]["template"]["spec"]
    runner = pod_spec["containers"][0]
    assert runner["resources"]["limits"] == {
        "cpu": "1000m",
        "memory": "524288Ki",
    }
    volumes = {volume["name"]: volume for volume in pod_spec["volumes"]}
    assert volumes["workspace"]["emptyDir"]["sizeLimit"] == "524288Ki"
    assert volumes["results"]["emptyDir"]["sizeLimit"] == "1024Ki"
    assert volumes["tmp"]["emptyDir"]["sizeLimit"] == "65536Ki"


def test_sandbox_admission_policy_name_is_namespace_scoped() -> None:
    first = smoke._sandbox_admission_policy_name("tenant-a", smoke.DEFAULT_SANDBOX_NAMESPACE)
    second = smoke._sandbox_admission_policy_name("tenant-b", smoke.DEFAULT_SANDBOX_NAMESPACE)

    assert first != second
    assert len(first) <= 63
    assert len(second) <= 63


def test_command_display_redacts_signed_jwt() -> None:
    signed_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzbW9rZSJ9.signaturevalue"

    display = smoke._command_display(["command", signed_jwt])

    assert signed_jwt not in display
    assert "<redacted-jwt>" in display


def test_live_command_output_replaces_invalid_utf8() -> None:
    result = smoke._run(
        [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'\\xff')"],
    )

    assert result.stdout == "\ufffd"


@pytest.mark.parametrize(
    ("executor", "message"),
    [
        (
            RecordingExecutor(opensearch_replica_count=0),
            "template replica readback failed",
        ),
        (
            RecordingExecutor(opensearch_cluster_status="red"),
            "Kind cluster health requires",
        ),
        (
            RecordingExecutor(opensearch_cluster_timed_out=True),
            "Kind cluster health requires",
        ),
        (
            RecordingExecutor(opensearch_data_nodes=0),
            "Kind cluster health requires",
        ),
        (
            RecordingExecutor(opensearch_transport_listeners=("0.0.0.0",)),
            "port 9300 must listen only on IPv4 loopback",
        ),
    ],
)
def test_opensearch_schema_health_readback_fails_closed(
    executor: RecordingExecutor,
    message: str,
) -> None:
    with pytest.raises(smoke.LiveKindHelmSmokeError, match=message):
        smoke._verify_opensearch_schema(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_NAMESPACE],
        )


def test_opensearch_schema_health_script_reads_canonical_nested_settings(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    responses = {
        "/_index_template/hallu_evidence_template": {
            "index_templates": [
                {
                    "name": "hallu_evidence_template",
                    "index_template": {
                        "template": {"settings": {"index": {"number_of_replicas": "1"}}}
                    },
                }
            ]
        },
        "/_cluster/health": {
            "status": "yellow",
            "timed_out": False,
            "number_of_data_nodes": 1,
        },
    }

    def fake_urlopen(url: str, *, timeout: int) -> io.BytesIO:
        assert timeout == 5
        path = url.removeprefix("http://opensearch:9200")
        return io.BytesIO(json.dumps(responses[path]).encode("utf-8"))

    monkeypatch.setenv("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://opensearch:9200")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    exec(smoke.OPENSEARCH_SCHEMA_HEALTH_SCRIPT, {})

    assert json.loads(capsys.readouterr().out) == {
        "cluster_status": "yellow",
        "cluster_timed_out": False,
        "data_nodes": 1,
        "template_replicas": 1,
    }


def test_opensearch_schema_health_script_rejects_noncanonical_replica_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_response = {
        "index_templates": [
            {
                "name": "hallu_evidence_template",
                "index_template": {"template": {"settings": {"number_of_replicas": 1}}},
            }
        ]
    }

    def fake_urlopen(_url: str, *, timeout: int) -> io.BytesIO:
        assert timeout == 5
        return io.BytesIO(json.dumps(template_response).encode("utf-8"))

    monkeypatch.setenv("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "http://opensearch:9200")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="replica count was invalid"):
        exec(smoke.OPENSEARCH_SCHEMA_HEALTH_SCRIPT, {})


def test_live_kind_helm_smoke_rejects_incomplete_migrations_and_cleans_up() -> None:
    executor = RecordingExecutor(migration_count=smoke.EXPECTED_MIGRATION_COUNT - 1)

    with pytest.raises(
        smoke.LiveKindHelmSmokeError,
        match=f"expected {smoke.EXPECTED_MIGRATION_COUNT} applied migrations",
    ):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    assert ["kind", "delete", "cluster", "--name", smoke.DEFAULT_CLUSTER] in executor.commands
    assert ["kind", "get", "clusters"] in executor.commands
    assert not executor.docker_images
    assert not executor.kind_clusters


def test_live_kind_helm_smoke_collects_diagnostics_and_cleans_up_on_install_failure() -> None:
    executor = RecordingExecutor(fail_prefix=("helm", "upgrade"))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="injected command failure"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    command_text = [" ".join(command) for command in executor.commands]
    assert any("get all,pvc --output=wide" in item for item in command_text)
    assert "kind delete cluster --name hallu-defense-smoke" in command_text
    assert "kind get clusters" in command_text
    assert not executor.docker_images
    assert not executor.kind_clusters


def test_live_kind_helm_smoke_fails_when_successful_body_cannot_clean_up() -> None:
    executor = CleanupFailingExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="cleanup failed after successful"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )


def test_live_kind_helm_smoke_preserves_primary_failure_when_cleanup_also_fails() -> None:
    executor = CleanupFailingExecutor(fail_prefix=("helm", "upgrade"))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="injected command failure"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )


def test_temporary_directory_cleanup_never_masks_primary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_factory = smoke.tempfile.TemporaryDirectory

    class CleanupErrorDirectory:
        def __init__(self, *, prefix: str) -> None:
            self._delegate = original_factory(prefix=prefix)
            self.name = self._delegate.name

        def cleanup(self) -> None:
            self._delegate.cleanup()
            raise PermissionError("injected temporary cleanup failure")

    def temporary_directory(*, prefix: str):  # type: ignore[no-untyped-def]
        if prefix == "hallu-kind-bootstrap-":
            return CleanupErrorDirectory(prefix=prefix)
        return original_factory(prefix=prefix)

    monkeypatch.setattr(smoke.tempfile, "TemporaryDirectory", temporary_directory)
    executor = RecordingExecutor(fail_prefix=("helm", "upgrade"))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="injected command failure"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )


def test_kind_create_failure_never_deletes_an_unowned_cluster() -> None:
    executor = RecordingExecutor(fail_prefix=("kind", "create", "cluster"))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="injected command failure"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    assert not any(argv[:3] == ["kind", "delete", "cluster"] for argv in executor.commands)
    assert not any(argv[:3] == ["docker", "image", "rm"] for argv in executor.commands)


def test_cleanup_ignores_unrelated_concurrent_cluster_creation() -> None:
    executor = ConcurrentClusterExecutor(existing_clusters=("baseline-cluster",))

    result = smoke.run_smoke(
        cluster=smoke.DEFAULT_CLUSTER,
        namespace=smoke.DEFAULT_NAMESPACE,
        executor=executor,
    )

    assert result["cleanup"]["baseline_clusters_before"] == ["baseline-cluster"]
    assert result["cleanup"]["unrelated_clusters_after"] == [
        "baseline-cluster",
        "unrelated-concurrent-cluster",
    ]
    assert smoke.DEFAULT_CLUSTER not in executor.kind_clusters


def test_live_smoke_refuses_to_overwrite_existing_scratch_image() -> None:
    images = smoke._scratch_image_references("collision")
    protected_image = images["api"]
    executor = RecordingExecutor(existing_images=(protected_image,))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="refusing to overwrite"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            images=images,
            executor=executor,
        )

    assert protected_image in executor.docker_images
    assert not any(argv[:3] == ["docker", "image", "rm"] for argv in executor.commands)


def test_scratch_image_preflight_fails_closed_on_daemon_error() -> None:
    executor = DockerInspectFailingExecutor()

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="could not prove.*absent"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    assert not any(argv[:3] == ["kind", "create", "cluster"] for argv in executor.commands)


def test_scratch_image_cleanup_fails_closed_on_remove_error() -> None:
    image = "hallu-defense-api:kind-cleanup-error"
    executor = DockerRemoveFailingExecutor(existing_images=(image,))

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="image cleanup failed"):
        smoke._remove_scratch_images(executor, [image])


def test_scratch_image_cleanup_attempts_every_exact_tag_after_one_failure() -> None:
    first = "hallu-defense-api:kind-cleanup-many"
    second = "hallu-defense-console:kind-cleanup-many"
    executor = SelectiveDockerRemoveFailingExecutor(
        failing_image=first,
        existing_images=(first, second),
    )

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="image cleanup failed"):
        smoke._remove_scratch_images(executor, [first, second])

    removals = [argv[3] for argv in executor.commands if argv[:3] == ["docker", "image", "rm"]]
    inspections = [
        argv[3] for argv in executor.commands if argv[:3] == ["docker", "image", "inspect"]
    ]
    assert removals == [first, second]
    assert inspections == [first, second]
    assert first in executor.docker_images
    assert second not in executor.docker_images


def test_live_smoke_rejects_checksum_drift_with_complete_migration_count() -> None:
    executor = RecordingExecutor(migration_checksums_valid=False)

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="exact checksums"):
        smoke.run_smoke(
            cluster=smoke.DEFAULT_CLUSTER,
            namespace=smoke.DEFAULT_NAMESPACE,
            executor=executor,
        )

    assert not executor.docker_images
    assert not executor.kind_clusters


def test_fixture_readiness_must_be_observed_before_completion() -> None:
    executor = RecordingExecutor(fixture_ready=False)

    with pytest.raises(smoke.LiveKindHelmSmokeError, match="never observed Ready"):
        smoke._wait_for_fixture_pod_ready(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_SANDBOX_NAMESPACE],
            revision=1,
            attempts=1,
            interval_seconds=0,
        )


@pytest.mark.parametrize(
    "executor",
    [
        RecordingExecutor(fixture_probe_valid=False),
        RecordingExecutor(fixture_owner_valid=False),
    ],
)
def test_fixture_readiness_requires_exact_probe_and_owner(
    executor: RecordingExecutor,
) -> None:
    with pytest.raises(smoke.LiveKindHelmSmokeError, match="never observed Ready"):
        smoke._wait_for_fixture_pod_ready(
            executor,
            kubectl=["kubectl", "--namespace", smoke.DEFAULT_SANDBOX_NAMESPACE],
            revision=1,
            attempts=1,
            interval_seconds=0,
        )


def test_run_id_contract_produces_concurrent_safe_names() -> None:
    first = smoke._scratch_image_references("a1b2c3")
    second = smoke._scratch_image_references("d4e5f6")

    assert set(first.values()).isdisjoint(second.values())
    assert all(":kind-a1b2c3" in image for image in first.values())
    with pytest.raises(smoke.LiveKindHelmSmokeError, match="lowercase DNS-safe"):
        smoke._validated_run_id("INVALID_RUN")


def test_live_kind_helm_smoke_rejects_invalid_cluster_name() -> None:
    with pytest.raises(smoke.LiveKindHelmSmokeError, match="valid DNS label"):
        smoke.run_from_env(
            {
                smoke.ENABLED_ENV: "true",
                smoke.CLUSTER_ENV: "INVALID_CLUSTER",
            },
            tool_locator=_all_tools,
            executor=RecordingExecutor(),
        )


def test_live_kind_helm_smoke_skip_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"


def test_live_kind_helm_smoke_failure_prints_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_env: object) -> dict[str, object]:
        raise smoke.LiveKindHelmSmokeError("fail closed")

    monkeypatch.setattr(smoke, "run_from_env", fail)

    assert smoke.main(env={smoke.ENABLED_ENV: "true"}) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"error": "fail closed", "status": "failed"}


def _decode_base64url_uint(value: str) -> int:
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


def _decode_base64url(value: str) -> bytes:
    padding_text = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding_text)
