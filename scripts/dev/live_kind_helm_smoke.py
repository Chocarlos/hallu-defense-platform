"""Env-gated kind + Helm smoke scaffold for the hallu-defense chart."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = ROOT / "infra" / "k8s" / "helm" / "hallu-defense"

ENABLED_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED"
CLUSTER_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_CLUSTER"
NAMESPACE_ENV = "HALLU_DEFENSE_LIVE_KIND_HELM_NAMESPACE"
DEFAULT_CLUSTER = "hallu-defense-smoke"
DEFAULT_NAMESPACE = "hallu-defense"


class LiveKindHelmSmokeError(RuntimeError):
    pass


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the kind/Helm live smoke",
            "required_tools": ["kind", "kubectl", "helm"],
        }
    missing_tools = [tool for tool in ("kind", "kubectl", "helm") if shutil.which(tool) is None]
    if missing_tools:
        return {
            "status": "skipped",
            "reason": "required live tools are unavailable: " + ", ".join(missing_tools),
            "required_tools": ["kind", "kubectl", "helm"],
        }
    cluster = _optional(effective_env, CLUSTER_ENV) or DEFAULT_CLUSTER
    namespace = _optional(effective_env, NAMESPACE_ENV) or DEFAULT_NAMESPACE
    return run_smoke(cluster=cluster, namespace=namespace)


def run_smoke(*, cluster: str, namespace: str) -> dict[str, object]:
    created = False
    try:
        _run(["kind", "create", "cluster", "--name", cluster])
        created = True
        _run(["kubectl", "create", "namespace", namespace, "--context", f"kind-{cluster}"])
        _run(
            [
                "helm",
                "template",
                "hallu-defense",
                str(CHART_DIR),
                "--namespace",
                namespace,
                "--set",
                "worker.enabled=true",
                "--set-string",
                "secrets.keycloakJwks=jwks-placeholder",
                "--set-string",
                "secrets.vaultToken=prod-vault-token",
                "--set-string",
                "secrets.postgresDsn=postgresql://prod_user:prod_pass@pgvector:5432/prod_db",
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
            ]
        )
        return {
            "status": "passed",
            "cluster": cluster,
            "namespace": namespace,
            "checks": ["kind cluster create", "namespace create", "helm template"],
        }
    finally:
        if created:
            _run(["kind", "delete", "cluster", "--name", cluster], check=False)


def _run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise LiveKindHelmSmokeError(
            f"{' '.join(command)} failed: "
            + (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
        )
    return result


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
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
