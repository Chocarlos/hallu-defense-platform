from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
from collections.abc import Sequence
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
    ) -> None:
        self.commands: list[list[str]] = []
        self.bearer_tokens: list[str] = []
        self.secret_manifests: list[dict[str, object]] = []
        self.kind_config_text: str | None = None
        self.migration_count = migration_count
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

    def __call__(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 120,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del timeout_seconds
        argv = list(command)
        self.commands.append(argv)
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
        if argv[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                f"{self.docker_architecture}\n",
                "",
            )
        if argv[:4] == ["kind", "create", "cluster", "--name"]:
            config_path = Path(argv[argv.index("--config") + 1])
            self.kind_config_text = config_path.read_text(encoding="utf-8")
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
        if (
            self.fail_prefix is not None
            and tuple(argv[: len(self.fail_prefix)]) == self.fail_prefix
        ):
            if check:
                raise smoke.LiveKindHelmSmokeError("injected command failure")
            return subprocess.CompletedProcess(argv, 1, "", "injected command failure")
        if "SELECT version FROM schema_migrations ORDER BY version;" in argv:
            versions = smoke.EXPECTED_MIGRATION_VERSIONS[: self.migration_count]
            return subprocess.CompletedProcess(argv, 0, "\n".join(versions) + "\n", "")
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
            and "--selector=app.kubernetes.io/component=migrations" in argv
            and "--container=migrations" in argv
        ):
            payload = (
                {
                    "status": "ok",
                    "applied": list(smoke.EXPECTED_MIGRATION_VERSIONS),
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
            envelope = {"status": status, "body": json.dumps(response)}
            return subprocess.CompletedProcess(argv, 0, json.dumps(envelope) + "\n", "")
        if "get" in argv and "jobs" in argv and "--output=json" in argv:
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
            and "--selector=app.kubernetes.io/component=migrations" in argv
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
        "migrations": True,
        "sandbox-fixture": True,
        "vault-bootstrap": True,
    }
    assert result["sandbox_namespace"] == smoke.DEFAULT_SANDBOX_NAMESPACE
    assert result["helm_secret_boundary"] == {
        "manifest_secret_objects": 0,
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
    assert result["images"] == [
        smoke.API_IMAGE,
        smoke.CONSOLE_IMAGE,
        smoke.SANDBOX_IMAGE,
        smoke.PGVECTOR_IMAGE,
        smoke.OPENSEARCH_IMAGE,
    ]
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
    assert any("--rollback-on-failure" in item for item in command_text)
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
    assert any("wait --for=condition=complete" in item for item in command_text)
    assert any("rollout status deployment/hallu-defense-worker" in item for item in command_text)
    assert any("rollout status deployment/hallu-defense-vault" in item for item in command_text)
    assert any("rollout status deployment/hallu-defense-redis" in item for item in command_text)
    assert any("app.kubernetes.io/component=vault-bootstrap" in item for item in command_text)
    assert any(
        "SELECT version FROM schema_migrations ORDER BY version;" in item for item in command_text
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
        "malicious_jobs_denied": 11,
    }
    assert result["sandbox"]["egress_blocked_by_kindnet"] is True
    assert result["sandbox"]["batched_commands"] == 2
    assert result["sandbox"]["residual_jobs"] == 0
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
            "applied_migrations": smoke.EXPECTED_MIGRATION_COUNT,
            "postgres_dsn_file_read": True,
            "raw_secret_env_absent": True,
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
        "--selector=app.kubernetes.io/component=migrations --container=migrations" in item
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
    assert result["cleanup"] == {"cluster_deleted": True, "verified_absent": True}
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
    assert command_text[-2:] == [
        "kind delete cluster --name hallu-defense-smoke",
        "kind get clusters",
    ]
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

    assert executor.commands[-2] == [
        "kind",
        "delete",
        "cluster",
        "--name",
        smoke.DEFAULT_CLUSTER,
    ]
    assert executor.commands[-1] == ["kind", "get", "clusters"]


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
    assert command_text[-2:] == [
        "kind delete cluster --name hallu-defense-smoke",
        "kind get clusters",
    ]


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
