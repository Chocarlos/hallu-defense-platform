from __future__ import annotations

import ast
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "live.yml"
IMAGE_INVENTORY = ROOT / "requirements" / "container-images.json"
COMPOSE_PATH = ROOT / "docker-compose.yml"
HELM_VALUES_PATH = ROOT / "infra" / "k8s" / "helm" / "hallu-defense" / "values.yaml"
KIND_SMOKE_PATH = ROOT / "scripts" / "dev" / "live_kind_helm_smoke.py"
DOCKERIGNORE_PATH = ROOT / ".dockerignore"
KEYCLOAK_ARTIFACTS_PATH = ROOT / "requirements" / "keycloak-artifacts.json"
SEAWEEDFS_LAUNCHER_PATH = ROOT / "infra" / "docker" / "seaweedfs_launcher.go"
OPENSEARCH_ENTRYPOINT_PATH = ROOT / "infra" / "docker" / "opensearch_entrypoint.sh"
OTEL_BUILDER_CONFIG_PATH = ROOT / "infra" / "docker" / "otel-collector-builder.yaml"
DOCKERFILES = {
    "api": ROOT / "infra" / "docker" / "api.Dockerfile",
    "console": ROOT / "infra" / "docker" / "console.Dockerfile",
    "sandbox": ROOT / "infra" / "docker" / "sandbox.Dockerfile",
    "pgvector": ROOT / "infra" / "docker" / "pgvector.Dockerfile",
    "keycloak": ROOT / "infra" / "docker" / "keycloak.Dockerfile",
    "grafana": ROOT / "infra" / "docker" / "grafana.Dockerfile",
    "opensearch": ROOT / "infra" / "docker" / "opensearch.Dockerfile",
    "seaweedfs": ROOT / "infra" / "docker" / "seaweedfs.Dockerfile",
    "otel-collector": ROOT / "infra" / "docker" / "otel-collector.Dockerfile",
    "vault": ROOT / "infra" / "docker" / "vault.Dockerfile",
}
IMAGE_REFS = {
    "api": "hallu-defense-api:ci",
    "console": "hallu-defense-console:ci",
    "sandbox": "hallu-defense-sandbox:ci",
    "pgvector": "hallu-defense-pgvector:ci",
    "keycloak": "hallu-defense-keycloak:ci",
    "grafana": "hallu-defense-grafana:ci",
    "opensearch": "hallu-defense-opensearch:ci",
    "seaweedfs": "hallu-defense-seaweedfs:ci",
    "otel-collector": "hallu-defense-otel-collector:ci",
    "vault": "hallu-defense-vault:ci",
}
TRIVY_ACTION = "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"
TRIVY_VERSION = "v0.72.0"
TRIVY_CONFIG_INPUT = "${{ runner.temp }}/hallu-trivy-policy/trivy.yaml"
TRIVY_IGNORE_INPUT = "${{ runner.temp }}/hallu-trivy-policy/empty.trivyignore"
TRIVY_POLICY_STEP_NAME = "Create empty external Trivy policy"
TRIVY_POLICY_RUN = " ".join(
    (
        "set -euo pipefail",
        'install -d -m 0755 "${RUNNER_TEMP}/hallu-trivy-policy"',
        "printf '{}\\n' > \"${RUNNER_TEMP}/hallu-trivy-policy/trivy.yaml\"",
        ': > "${RUNNER_TEMP}/hallu-trivy-policy/empty.trivyignore"',
        'chmod 0444 "${RUNNER_TEMP}/hallu-trivy-policy/trivy.yaml" \\',
        '"${RUNNER_TEMP}/hallu-trivy-policy/empty.trivyignore"',
    )
)
RUNNER_DISK_STEP_NAME = "Reclaim unused hosted runner SDKs"
RUNNER_DISK_RUN = " ".join(
    (
        "set -euo pipefail",
        "sudo rm -rf -- /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup",
        "docker builder prune --all --force",
        "available_kb=\"$(df --output=avail -k / | tail -n 1 | tr -d ' ')\"",
        'test "${available_kb}" -ge 20971520',
    )
)
KIND_NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
IMMUTABLE_IMAGE_RE = re.compile(r"^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$")
API_OPA_BUILDER_FROM = (
    "FROM golang:1.26.5-trixie@"
    "sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 "
    "AS opa-builder"
)
API_PYTHON_FROM = (
    "FROM python:3.12.13-alpine3.24@"
    "sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)


class ContainerScanConfigError(ValueError):
    pass


def validate_container_scan_config(
    *,
    workflow_text: str,
    dockerfile_texts: Mapping[str, str],
    dockerignore_text: str | None = None,
    seaweedfs_launcher_text: str | None = None,
    opensearch_entrypoint_text: str | None = None,
) -> None:
    errors: list[str] = []
    _validate_workflow(workflow_text, errors)
    for name, image_ref in IMAGE_REFS.items():
        dockerfile_text = dockerfile_texts.get(name)
        if dockerfile_text is None:
            errors.append(f"missing Dockerfile text for {name}")
            continue
        if image_ref != f"hallu-defense-{name}:ci":
            errors.append(f"first-party image ref for {name} must be name-derived")
        _validate_dockerfile(name, dockerfile_text, errors)
    _validate_external_image_inventory(workflow_text, errors)
    _validate_kind_ci_boundary(errors)
    _validate_dockerignore(
        DOCKERIGNORE_PATH.read_text(encoding="utf-8")
        if dockerignore_text is None
        else dockerignore_text,
        errors,
    )
    try:
        launcher_text = (
            SEAWEEDFS_LAUNCHER_PATH.read_text(encoding="utf-8")
            if seaweedfs_launcher_text is None
            else seaweedfs_launcher_text
        )
    except OSError as exc:
        errors.append(f"SeaweedFS launcher could not be read: {exc}")
    else:
        _validate_seaweedfs_launcher(launcher_text, errors)
    try:
        entrypoint_text = (
            OPENSEARCH_ENTRYPOINT_PATH.read_text(encoding="utf-8")
            if opensearch_entrypoint_text is None
            else opensearch_entrypoint_text
        )
    except OSError as exc:
        errors.append(f"OpenSearch entrypoint could not be read: {exc}")
    else:
        _validate_opensearch_entrypoint(entrypoint_text, errors)

    if errors:
        raise ContainerScanConfigError("\n".join(errors))


def _validate_workflow(workflow_text: str, errors: list[str]) -> None:
    if "continue-on-error: true" in workflow_text:
        errors.append("container scanning must not use continue-on-error")

    if "ignore-unfixed:" in workflow_text:
        errors.append("security workflow must not ignore unfixed vulnerabilities")
    if "915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2" in workflow_text:
        errors.append(
            "security workflow must not use the vulnerable Trivy action v0.28.0"
        )
    try:
        workflow = yaml.safe_load(workflow_text)
    except yaml.YAMLError as exc:
        errors.append(f"security workflow must be valid YAML: {exc}")
        return
    jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
    trivy_steps: list[Mapping[str, object]] = []
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            trivy_steps.extend(
                step
                for step in steps
                if isinstance(step, dict)
                and str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
            )
    if len(trivy_steps) != 2:
        errors.append(
            "security workflow must have one first-party matrix scan and one "
            "third-party matrix scan"
        )
    scan_refs: list[str] = []
    for step in trivy_steps:
        if step.get("uses") != TRIVY_ACTION:
            errors.append(f"Trivy scans must use the safe action commit {TRIVY_ACTION}")
        inputs = step.get("with", {})
        if not isinstance(inputs, dict):
            errors.append("every Trivy scan must define pinned inputs")
            continue
        scan_refs.append(str(inputs.get("image-ref", "")))
        expected = {
            "version": TRIVY_VERSION,
            "image-ref": (
                "hallu-defense-${{ matrix.name }}:ci"
                if "first-party" in str(step.get("name", "")).lower()
                else "${{ matrix.image }}"
            ),
            "format": "table",
            "exit-code": "1",
            "vuln-type": "os,library",
            "severity": "CRITICAL,HIGH",
            "trivy-config": TRIVY_CONFIG_INPUT,
            "trivyignores": TRIVY_IGNORE_INPUT,
        }
        if set(inputs) != set(expected):
            errors.append(
                "every Trivy scan must contain only the exact fail-closed input set"
            )
        for key, value in expected.items():
            if str(inputs.get(key, "")) != value:
                errors.append(f"every Trivy scan must set {key}: {value}")

    first_party_ref = "hallu-defense-${{ matrix.name }}:ci"
    third_party_ref = "${{ matrix.image }}"
    if scan_refs.count(first_party_ref) != 1:
        errors.append("security workflow must have exactly one first-party matrix scan")
    if scan_refs.count(third_party_ref) != 1:
        errors.append("security workflow must have exactly one matrix image-ref scan")
    if isinstance(jobs, Mapping):
        _validate_first_party_matrix(jobs.get("first-party-images"), errors)
        _validate_third_party_matrix(jobs.get("third-party-images"), errors)


def _validate_first_party_matrix(job: object, errors: list[str]) -> None:
    if not isinstance(job, Mapping):
        errors.append("security workflow first-party image matrix job is missing")
        return
    if set(job) != {"runs-on", "timeout-minutes", "strategy", "steps"}:
        errors.append("first-party image matrix job must have only its exact fields")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 45:
        errors.append(
            "first-party image matrix job must use its exact trusted runner limits"
        )
    strategy = job.get("strategy")
    if not isinstance(strategy, Mapping) or strategy.get("fail-fast") is not False:
        errors.append("first-party image matrix must set fail-fast: false")
        return
    if set(strategy) != {"fail-fast", "max-parallel", "matrix"}:
        errors.append("first-party image matrix strategy must have only exact fields")
    if strategy.get("max-parallel") != 1:
        errors.append(
            "first-party image matrix must serialize Docker work with max-parallel: 1"
        )
    matrix = strategy.get("matrix")
    if not isinstance(matrix, Mapping) or set(matrix) != {"include"}:
        errors.append(
            "first-party image matrix must contain only its exact include list"
        )
    include = matrix.get("include") if isinstance(matrix, Mapping) else None
    if not isinstance(include, list):
        errors.append("first-party image matrix include list is missing")
        return
    actual_rows: Counter[tuple[str, str]] = Counter()
    for row in include:
        if not isinstance(row, Mapping) or set(row) != {"name", "dockerfile"}:
            errors.append(
                "first-party matrix rows must contain only exact name and dockerfile fields"
            )
            continue
        actual_rows[(str(row["name"]), str(row["dockerfile"]))] += 1
    expected_rows = Counter(
        (name, f"infra/docker/{name}.Dockerfile") for name in IMAGE_REFS
    )
    if actual_rows != expected_rows:
        errors.append(
            "first-party matrix must cover every approved Dockerfile exactly once"
        )

    steps = job.get("steps")
    if not isinstance(steps, list):
        errors.append("first-party image matrix steps are missing")
        return
    if any(isinstance(step, Mapping) and "continue-on-error" in step for step in steps):
        errors.append("first-party image matrix steps must not weaken failures")
    _validate_external_trivy_policy_step(steps, errors, label="first-party")
    if len(steps) != 5:
        errors.append(
            "first-party matrix must contain exactly five ordered trusted steps"
        )
    else:
        reclaim = steps[1]
        checkout = steps[2]
        build = steps[3]
        scan = steps[4]
        if (
            not isinstance(reclaim, Mapping)
            or set(reclaim) != {"name", "shell", "run"}
            or reclaim.get("name") != RUNNER_DISK_STEP_NAME
            or reclaim.get("shell") != "bash"
            or " ".join(str(reclaim.get("run", "")).split()) != RUNNER_DISK_RUN
        ):
            errors.append("first-party matrix runner disk reclamation step is not exact")
        if not isinstance(checkout, Mapping) or dict(checkout) != {
            "uses": "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
            "with": {"persist-credentials": False},
        }:
            errors.append(
                "first-party matrix checkout step must be exact and credentialless"
            )
        if not isinstance(build, Mapping) or set(build) != {"name", "run"}:
            errors.append(
                "first-party matrix build step must contain only exact metadata"
            )
        _validate_exact_trivy_step(
            scan,
            expected_name="Scan current first-party image",
            expected_ref="hallu-defense-${{ matrix.name }}:ci",
            label="first-party",
            errors=errors,
        )
    run_step_names = [
        step.get("name")
        for step in steps
        if isinstance(step, Mapping) and isinstance(step.get("run"), str)
    ]
    if run_step_names != [
        TRIVY_POLICY_STEP_NAME,
        RUNNER_DISK_STEP_NAME,
        "Build current first-party image",
    ]:
        errors.append(
            "first-party matrix must contain only its exact policy, disk, and build commands"
        )
    build_commands = [
        " ".join(str(step["run"]).split())
        for step in steps
        if isinstance(step, Mapping)
        and step.get("name") == "Build current first-party image"
        and isinstance(step.get("run"), str)
    ]
    expected_build = (
        'docker build -f "${{ matrix.dockerfile }}" '
        '-t "hallu-defense-${{ matrix.name }}:ci" .'
    )
    if build_commands != [expected_build]:
        errors.append(
            "first-party matrix must contain only its exact current Dockerfile build "
            "and name-derived tag"
        )
    matrix_scans = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
    ]
    if len(matrix_scans) != 1 or not isinstance(matrix_scans[0].get("with"), Mapping):
        errors.append("first-party matrix must contain exactly one Trivy scan")
    elif matrix_scans[0]["with"].get("image-ref") != (
        "hallu-defense-${{ matrix.name }}:ci"
    ):
        errors.append("first-party matrix Trivy scan must use its name-derived image")


def _validate_third_party_matrix(job: object, errors: list[str]) -> None:
    if not isinstance(job, Mapping):
        errors.append("security workflow third-party image matrix job is missing")
        return
    if set(job) != {"runs-on", "timeout-minutes", "strategy", "steps"}:
        errors.append("third-party image matrix job must have only its exact fields")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 45:
        errors.append(
            "third-party image matrix job must use its exact trusted runner limits"
        )
    strategy = job.get("strategy")
    if not isinstance(strategy, Mapping) or strategy.get("fail-fast") is not False:
        errors.append("third-party image matrix must set fail-fast: false")
    if not isinstance(strategy, Mapping) or strategy.get("max-parallel") != 1:
        errors.append(
            "third-party image matrix must serialize scans with max-parallel: 1"
        )
    matrix = strategy.get("matrix") if isinstance(strategy, Mapping) else None
    if (
        not isinstance(strategy, Mapping)
        or set(strategy) != {"fail-fast", "max-parallel", "matrix"}
        or not isinstance(matrix, Mapping)
        or set(matrix) != {"image"}
    ):
        errors.append(
            "third-party image matrix must use only its exact immutable image list"
        )
    steps = job.get("steps")
    if not isinstance(steps, list):
        errors.append("third-party image matrix steps are missing")
        return
    if any(isinstance(step, Mapping) and "continue-on-error" in step for step in steps):
        errors.append("third-party image matrix steps must not weaken failures")
    _validate_external_trivy_policy_step(steps, errors, label="third-party")
    if len(steps) != 2:
        errors.append("third-party matrix must contain exactly policy then Trivy scan")
    else:
        _validate_exact_trivy_step(
            steps[1],
            expected_name="Scan immutable third-party image",
            expected_ref="${{ matrix.image }}",
            label="third-party",
            errors=errors,
        )
    run_step_names = [
        step.get("name")
        for step in steps
        if isinstance(step, Mapping) and isinstance(step.get("run"), str)
    ]
    if run_step_names != [TRIVY_POLICY_STEP_NAME]:
        errors.append("third-party matrix must contain only its exact policy command")
    matrix_scans = [
        step
        for step in steps
        if isinstance(step, Mapping)
        and str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
    ]
    if len(matrix_scans) != 1 or not isinstance(matrix_scans[0].get("with"), Mapping):
        errors.append("third-party matrix must contain exactly one Trivy scan")
    elif matrix_scans[0]["with"].get("image-ref") != "${{ matrix.image }}":
        errors.append(
            "third-party matrix Trivy scan must use its immutable matrix image"
        )


def _validate_exact_trivy_step(
    step: object,
    *,
    expected_name: str,
    expected_ref: str,
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(step, Mapping) or set(step) != {"name", "uses", "with"}:
        errors.append(f"{label} Trivy step must contain only exact trusted metadata")
        return
    expected_inputs = {
        "version": TRIVY_VERSION,
        "image-ref": expected_ref,
        "format": "table",
        "exit-code": "1",
        "vuln-type": "os,library",
        "severity": "CRITICAL,HIGH",
        "trivy-config": TRIVY_CONFIG_INPUT,
        "trivyignores": TRIVY_IGNORE_INPUT,
    }
    if (
        step.get("name") != expected_name
        or step.get("uses") != TRIVY_ACTION
        or step.get("with") != expected_inputs
    ):
        errors.append(f"{label} Trivy step must equal its exact fail-closed definition")


def _validate_external_trivy_policy_step(
    steps: list[object],
    errors: list[str],
    *,
    label: str,
) -> None:
    policy_steps = [
        step
        for step in steps
        if isinstance(step, Mapping) and step.get("name") == TRIVY_POLICY_STEP_NAME
    ]
    if len(policy_steps) != 1:
        errors.append(
            f"{label} scan must create exactly one external empty Trivy policy"
        )
        return
    step = policy_steps[0]
    if set(step) != {"name", "shell", "run"} or step.get("shell") != "bash":
        errors.append(
            f"{label} external Trivy policy step must contain only exact trusted metadata"
        )
    run = " ".join(str(step.get("run", "")).split())
    if run != TRIVY_POLICY_RUN:
        errors.append(
            f"{label} external Trivy policy must use the exact empty fail-closed command"
        )
    policy_index = steps.index(step)
    scan_indexes = [
        index
        for index, candidate in enumerate(steps)
        if isinstance(candidate, Mapping)
        and (
            str(candidate.get("uses", "")).startswith("aquasecurity/trivy-action@")
            or candidate.get("name") == "Build current first-party image"
        )
    ]
    if scan_indexes and policy_index >= min(scan_indexes):
        errors.append(f"{label} external Trivy policy must exist before build/scan")


def _validate_external_image_inventory(workflow_text: str, errors: list[str]) -> None:
    try:
        inventory = json.loads(IMAGE_INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"container image inventory is invalid: {exc}")
        return
    if inventory.get("schema_version") != "container-image-inventory.v1":
        errors.append("container image inventory schema is invalid")
    if inventory.get("scanner") != {
        "action": TRIVY_ACTION,
        "version": TRIVY_VERSION,
    }:
        errors.append("container image inventory scanner pin is invalid")
    entries = inventory.get("images", [])
    if not isinstance(entries, list):
        errors.append("container image inventory images must be a list")
        return
    expected_by_source: defaultdict[str, set[str]] = defaultdict(set)
    inventory_refs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("container image inventory entry must be an object")
            continue
        reference = entry.get("reference")
        sources = entry.get("sources")
        digest_kind = entry.get("digest_kind")
        if (
            not isinstance(reference, str)
            or IMMUTABLE_IMAGE_RE.fullmatch(reference) is None
        ):
            errors.append(f"inventory image reference must be tag@sha256: {reference}")
            continue
        if reference in inventory_refs:
            errors.append(f"duplicate image inventory reference: {reference}")
        inventory_refs.add(reference)
        if digest_kind not in {"manifest-list", "oci-index", "linux-amd64-manifest"}:
            errors.append(f"inventory image {reference} has invalid digest_kind")
        if not isinstance(sources, list) or not sources:
            errors.append(f"inventory image {reference} must declare sources")
            continue
        for source in sources:
            if isinstance(source, str):
                expected_by_source[source].add(reference)

    actual_by_source = _actual_external_images(errors)
    if set(expected_by_source) != set(actual_by_source):
        errors.append(
            "container inventory source set does not match Compose/Helm/scripts"
        )
    for source in sorted(set(expected_by_source) | set(actual_by_source)):
        if expected_by_source[source] != actual_by_source.get(source, set()):
            errors.append(f"container inventory drift for {source}")

    try:
        workflow = yaml.safe_load(workflow_text)
        raw_matrix_refs = workflow["jobs"]["third-party-images"]["strategy"]["matrix"][
            "image"
        ]
        if not isinstance(raw_matrix_refs, list):
            raise TypeError
        matrix_refs = Counter(str(reference) for reference in raw_matrix_refs)
    except (KeyError, TypeError, yaml.YAMLError):
        errors.append(
            "security workflow third-party image matrix is missing or invalid"
        )
        return
    expected_refs = Counter(inventory_refs)
    if matrix_refs != expected_refs:
        missing = sorted((expected_refs - matrix_refs).elements())
        extra = sorted((matrix_refs - expected_refs).elements())
        errors.append(
            f"security workflow image matrix drift; missing={missing}, extra={extra}"
        )


def _actual_external_images(errors: list[str]) -> dict[str, set[str]]:
    actual: defaultdict[str, set[str]] = defaultdict(set)
    try:
        compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
        services = compose["services"]
        # OTel Collector and Vault are rebuilt locally from pinned source and
        # belong to the first-party build/scan matrix.
        for service in ("prometheus", "redis"):
            actual[f"compose:{service}"].add(str(services[service]["image"]))
        helm = yaml.safe_load(HELM_VALUES_PATH.read_text(encoding="utf-8"))
        dependencies = helm["kindDependencies"]
        # OpenSearch and pgvector are locally built first-party derivatives and
        # are scanned by their dedicated image jobs, not this external matrix.
        for dependency in ("redis",):
            actual[f"helm:kindDependencies.{dependency}"].add(
                str(dependencies[dependency]["image"])
            )
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        errors.append(f"could not derive external image inventory: {exc}")
    return dict(actual)


def _validate_kind_ci_boundary(errors: list[str]) -> None:
    try:
        workflow_text = LIVE_WORKFLOW.read_text(encoding="utf-8")
        workflow = yaml.safe_load(workflow_text)
        job = workflow["jobs"]["kind-helm-live"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        errors.append(f"live Kind workflow is missing or invalid: {exc}")
        return
    if workflow.get("permissions") != {"contents": "read"}:
        errors.append("live workflow must use read-only contents permission")
    if (
        job.get("if")
        != "github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'"
    ):
        errors.append(
            "Kind live job must run only for trusted dispatch or schedule events"
        )
    if job.get("timeout-minutes") != 60:
        errors.append("Kind live job must keep its explicit 60 minute timeout")
    environment = job.get("env", {})
    if (
        not isinstance(environment, Mapping)
        or environment.get("HALLU_DEFENSE_LIVE_KIND_NODE_IMAGE") != KIND_NODE_IMAGE
    ):
        errors.append("Kind live job must pin the approved node image by exact digest")
    rendered_job = yaml.safe_dump(job, sort_keys=False)
    if "secrets." in rendered_job:
        errors.append(
            "Kind live job must not receive repository or environment secrets"
        )
    for marker in (
        "KIND_VERSION: v0.32.0",
        "KIND_SHA256: 50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54",
        "HELM_VERSION: v4.2.2",
        "HELM_SHA256: 9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6",
        "KUBECTL_VERSION: v1.36.1",
        "KUBECTL_SHA256: 629d3f410e09bf49b64ae7079f7f0bda1191efed311f7d37fdbab0ad5b0ec2b7",
        "persist-credentials: false",
        "if: always()",
    ):
        if marker not in workflow_text:
            errors.append(f"Kind live workflow is missing integrity marker `{marker}`")
    smoke_text = KIND_SMOKE_PATH.read_text(encoding="utf-8")
    try:
        smoke_node_image = _literal_assignment(KIND_SMOKE_PATH, "KIND_NODE_IMAGE")
    except (OSError, SyntaxError, ValueError) as exc:
        errors.append(f"Kind smoke node-image assignment is invalid: {exc}")
    else:
        if smoke_node_image != KIND_NODE_IMAGE:
            errors.append("Kind smoke must pin the approved node image by exact digest")
    for marker in (
        "HALLU_DEFENSE_LIVE_KIND_NODE_IMAGE",
        '"--image",',
        "KIND_NODE_IMAGE",
        'KIND_NETWORK_POLICY_PROVIDER = "kindnet"',
        '"default_cni_enabled": True',
        '"runtime_denials_verified": True',
        '"egress_blocked_by_kindnet": True',
    ):
        if marker not in smoke_text:
            errors.append(
                f"Kind smoke is missing approved CI boundary marker `{marker}`"
            )
    for forbidden_marker in (
        "disableDefaultCNI:",
        "raw.githubusercontent.com/project",
        "quay.io/",
    ):
        if forbidden_marker in smoke_text:
            errors.append(
                "Kind smoke must use its built-in network-policy provider; "
                f"found forbidden marker `{forbidden_marker}`"
            )


def _literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Name) and target.id == name for target in targets
            ):
                if node.value is None:
                    continue
                return ast.literal_eval(node.value)
    raise ValueError(f"{path.name} does not define literal {name}")


def _validate_dockerfile(
    name: str,
    dockerfile_text: str,
    errors: list[str],
) -> None:
    dockerfile_path = f"infra/docker/{name}.Dockerfile"
    from_lines = [
        line
        for line in dockerfile_text.splitlines()
        if line.strip().startswith("FROM ")
    ]
    if not from_lines:
        errors.append(f"{dockerfile_path} must declare a base image")
    for line in from_lines:
        if ":latest" in line:
            errors.append(f"{dockerfile_path} must not use latest base images")

    user_lines = re.findall(r"(?im)^USER\s+(\S+)\s*$", dockerfile_text)
    if user_lines and user_lines[-1].lower() in {"root", "0"}:
        errors.append(f"{dockerfile_path} must not end with root user")
    elif not user_lines:
        errors.append(f"{dockerfile_path} must set a non-root USER")

    if re.search(r"(?im)\bchmod\b[^\n]*(?:0?777|a\+w|o\+w)", dockerfile_text):
        errors.append(f"{dockerfile_path} must not create world-writable runtime paths")

    if name not in {"sandbox", "keycloak"} and re.search(
        r"(?im)^ADD\s+(?:--checksum=\S+\s+)?https?://",
        dockerfile_text,
    ):
        errors.append(f"{dockerfile_path} must not ADD remote URLs")

    if name == "api":
        if "pip install --no-cache-dir" not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} must install Python dependencies without pip cache"
            )
        if API_OPA_BUILDER_FROM not in from_lines:
            errors.append(
                f"{dockerfile_path} must pin the Go 1.26.5 OPA builder stage by digest"
            )
        if API_PYTHON_FROM not in from_lines:
            errors.append(f"{dockerfile_path} must pin the Python 3.12 base by digest")
        for line in from_lines:
            if "@sha256:" not in line:
                errors.append(f"{dockerfile_path} base stages must be pinned by digest")
        for snippet in (
            "ARG OPA_TAG=v1.18.2",
            "ARG OPA_COMMIT=e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297",
            'rev-parse "refs/tags/${OPA_TAG}^{commit}"',
            "COPY infra/docker/opa-no-oci.patch /tmp/opa-no-oci.patch",
            "git -C /src/opa apply --check /tmp/opa-no-oci.patch",
            "git -C /src/opa apply /tmp/opa-no-oci.patch",
            "-require=golang.org/x/crypto@v0.52.0",
            "-require=golang.org/x/net@v0.55.0",
            "-require=golang.org/x/sys@v0.45.0",
            "go mod verify",
            "CGO_ENABLED=0 go build -tags=opa_no_oci -mod=readonly -trimpath -buildvcs=false",
            '! go version -m /out/opa | grep -F "oras.land/oras-go"',
            "Go Version: go1.26.5",
            "COPY infra/opa/policies /app/infra/opa/policies",
            "COPY --from=opa-builder /out/opa /usr/local/bin/opa",
            "/usr/local/bin/opa version",
            "/usr/local/bin/opa check --strict /app/infra/opa/policies",
            "adduser -D -u 10001",
            "find /app -type d -exec chmod 0555",
            "find /app -type f -exec chmod 0444",
        ):
            if snippet not in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} missing OPA runtime marker `{snippet}`"
                )
        if "-require=oras.land/oras-go" in dockerfile_text:
            errors.append(
                f"{dockerfile_path} must not force an OCI client into the OPA build"
            )
        if re.search(r"(?m)^COPY\s+infra/opa(?:\s|/tests(?:\s|/))", dockerfile_text):
            errors.append(f"{dockerfile_path} must copy only infra/opa/policies")
        if re.search(r"chown\s+-R\s+\S+\s+/app", dockerfile_text):
            errors.append(
                f"{dockerfile_path} must keep application and policy files root-owned"
            )
    if name == "console":
        if "npm ci" not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} must use npm ci for reproducible installs"
            )
        for snippet in (
            "COPY .npmrc /app/.npmrc",
            'test "$(node --version)" = "v24.18.0"',
            'test "$(npm --version)" = "11.16.0"',
            "find /app -type d -exec chmod 0555",
            "find /app -type f -exec chmod 0444",
        ):
            if snippet not in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} must enforce npm policy and keep runtime code "
                    f"root-owned/read-only; missing `{snippet}`"
                )
        for forbidden in ("--ignore-scripts", "--dangerously-allow-all-scripts"):
            if forbidden in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} must not bypass npm install-script policy"
                )
        if "--chown=node:node" in dockerfile_text:
            errors.append(
                f"{dockerfile_path} must not make runtime code writable by node"
            )
    if name == "sandbox":
        for snippet in (
            "sandbox-linux-py312.lock",
            "--require-hashes",
            "--no-index",
            "verify_sandbox_npm_archive.mjs",
            "sandbox-npm.lock.json /tmp/sandbox-npm.lock.json",
            "find /opt/hallu-defense -type d -exec chmod 0555",
            "find /opt/hallu-defense -type f -exec chmod 0444",
            "apk add --no-cache git=2.54.0-r0",
        ):
            if snippet not in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} missing sandbox integrity marker `{snippet}`"
                )
        if "--chown=10001:10001" in dockerfile_text or re.search(
            r"chown\s+-R\s+10001:10001\s+/opt", dockerfile_text
        ):
            errors.append(
                f"{dockerfile_path} must keep runner code root-owned/read-only"
            )
        if (
            "node:" not in dockerfile_text
            or "/usr/local/bin/node" not in dockerfile_text
        ):
            errors.append(
                f"{dockerfile_path} must include pinned Node/npm runtime support"
            )
        if "USER 10001" not in dockerfile_text:
            errors.append(f"{dockerfile_path} must run as non-root UID 10001")
        for snippet in (
            "COPY infra/docker/sandbox_runner.py /opt/hallu-defense/sandbox_runner.py",
            "COPY infra/docker/sandbox_stream_exporter.py /opt/hallu-defense/sandbox_stream_exporter.py",
            "COPY infra/docker/sandbox_git_inspector.py /opt/hallu-defense/sandbox_git_inspector.py",
            "python -m py_compile /opt/hallu-defense/sandbox_runner.py",
        ):
            if snippet not in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} missing image-baked runner marker `{snippet}`"
                )
    if name == "pgvector":
        for snippet in (
            "postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
            "ARG PGVECTOR_TAG=v0.8.5",
            "ARG PGVECTOR_COMMIT=159b79aaad5983fb7459c1e3df2897fbb2d11788",
            'rev-parse "refs/tags/${PGVECTOR_TAG}^{commit}"',
            'make OPTFLAGS=""',
            "make install DESTDIR=/opt/pgvector",
            "rm -f /usr/local/bin/gosu",
            "test ! -e /usr/local/bin/gosu",
            'test "$(postgres --version)" = "postgres (PostgreSQL) 16.14"',
            "USER postgres",
        ):
            if snippet not in dockerfile_text:
                errors.append(
                    f"{dockerfile_path} missing pgvector integrity marker `{snippet}`"
                )
        if dockerfile_text.count("FROM postgres:16.14-alpine3.24@sha256:") != 2:
            errors.append(f"{dockerfile_path} must use the exact Postgres base twice")
        if "COPY --from=pgvector-builder" not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} must keep compiler tooling out of runtime"
            )
    if name == "keycloak":
        _validate_keycloak_dockerfile(dockerfile_text, dockerfile_path, errors)
    if name == "grafana":
        _validate_grafana_dockerfile(dockerfile_text, dockerfile_path, errors)
    if name == "opensearch":
        _validate_opensearch_dockerfile(dockerfile_text, dockerfile_path, errors)
    if name == "seaweedfs":
        _validate_seaweedfs_dockerfile(dockerfile_text, dockerfile_path, errors)
    if name == "otel-collector":
        _validate_otel_collector_dockerfile(dockerfile_text, dockerfile_path, errors)
    if name == "vault":
        _validate_vault_dockerfile(dockerfile_text, dockerfile_path, errors)


def _validate_otel_collector_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    markers = (
        "golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113",
        "ARG OCB_VERSION=0.156.0",
        "COPY infra/docker/otel-collector-builder.yaml /src/builder.yaml",
        '"go.opentelemetry.io/collector/cmd/builder@v${OCB_VERSION}"',
        "/go/bin/builder --config /src/builder.yaml",
        "f2de43b6617e9c5c88da5265733bd14a937545f766d8a1ab00ddec156390765e",
        "otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108",
        "FROM scratch",
        "USER 10001:10001",
        'ENTRYPOINT ["/otelcol-contrib"]',
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing reproducible OTel marker `{marker}`"
            )
    expected_components = {
        "exporters": [
            {"gomod": "go.opentelemetry.io/collector/exporter/debugexporter v0.156.0"},
            {
                "gomod": "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter v0.156.0"
            },
        ],
        "processors": [
            {"gomod": "go.opentelemetry.io/collector/processor/batchprocessor v0.156.0"}
        ],
        "receivers": [
            {"gomod": "go.opentelemetry.io/collector/receiver/otlpreceiver v0.156.0"}
        ],
        "providers": [
            {"gomod": "go.opentelemetry.io/collector/confmap/provider/envprovider v1.62.0"},
            {"gomod": "go.opentelemetry.io/collector/confmap/provider/fileprovider v1.62.0"},
            {"gomod": "go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.62.0"},
        ],
    }
    try:
        builder_config = yaml.safe_load(OTEL_BUILDER_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        errors.append(f"OTel builder config is missing or invalid: {exc}")
        return
    if not isinstance(builder_config, Mapping):
        errors.append("OTel builder config must be a YAML object")
        return
    if set(builder_config) != {"dist", *expected_components}:
        errors.append("OTel builder config must contain only the approved sections")
    dist = builder_config.get("dist")
    if not isinstance(dist, Mapping) or dist.get("version") != "0.156.0":
        errors.append("OTel builder config must pin distribution version 0.156.0")
    for section, expected in expected_components.items():
        if builder_config.get(section) != expected:
            errors.append(f"OTel builder config {section} set is not exact")


def _validate_vault_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    markers = (
        "golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc",
        "node:20-alpine3.23@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293",
        "hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
        "ARG VAULT_COMMIT=7193f9a48ff6093ca61b3b627a8671e770428ba6",
        "ARG VAULT_SOURCE_SHA256=7a12e6300ea17de23b1d533ff6452ed18802b9efa5b075dd1135ea1ded7b307b",
        "pnpm install --frozen-lockfile",
        "pnpm run build",
        "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local",
        "go build -trimpath -buildvcs=false -tags=ui",
        "FROM scratch",
        "COPY --from=patched / /",
        "USER vault",
        'ENTRYPOINT ["docker-entrypoint.sh"]',
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing reproducible Vault marker `{marker}`"
            )


def _validate_seaweedfs_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    markers = (
        "golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2",
        "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "ARG SEAWEEDFS_VERSION=4.29",
        "ARG SEAWEEDFS_COMMIT=1355c7a102194d6c461baf090eff50367b575afb",
        "ARG SEAWEEDFS_SOURCE_SHA256=d4ec97a7eda952296913fbfdcb3aefc62546fb80da7ad06f8e0c85f59474c6ed",
        "https://codeload.github.com/seaweedfs/seaweedfs/tar.gz/${SEAWEEDFS_COMMIT}",
        "sha256sum -c -",
        "weed/command/admin.go",
        'addr := fmt.Sprintf("127.0.0.1:%d", *options.port)',
        "weed/admin/dash/worker_grpc_server.go",
        'net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))',
        "go mod edit -dropreplace=github.com/apache/thrift",
        "github.com/apache/thrift@v0.23.0",
        "golang.org/x/net@v0.55.0",
        "go mod verify",
        "go build -mod=readonly -trimpath -buildvcs=false",
        "cmp /out/weed.first /out/weed.second",
        "COPY infra/docker/seaweedfs_launcher.go /launcher/seaweedfs_launcher.go",
        "cmp /out/seaweedfs-launcher.first /out/seaweedfs-launcher.second",
        "go version -m /out/weed",
        "COPY --from=seaweedfs-builder --chmod=0555 /out/weed /usr/local/bin/weed",
        "COPY --from=seaweedfs-builder --chmod=0555 /out/seaweedfs-launcher /usr/local/bin/seaweedfs-launcher",
        "USER 10001:10001",
        'ENTRYPOINT ["/usr/local/bin/seaweedfs-launcher"]',
        'CMD ["mini", "-dir=/data", "-s3.port=9000", "-bucket=hallu-backups,hallu-primary,hallu-backup-replica"]',
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing SeaweedFS integrity marker `{marker}`"
            )
    for forbidden in (
        "chrislusf/seaweedfs:",
        "minio/minio:",
        ":latest",
        "USER root",
    ):
        if forbidden in dockerfile_text:
            errors.append(
                f"{dockerfile_path} contains forbidden SeaweedFS marker `{forbidden}`"
            )
    if re.search(
        r"(?im)\bchown\b[^\n]*\b10001(?::10001)?\b[^\n]*/usr/local/bin",
        dockerfile_text,
    ):
        errors.append(f"{dockerfile_path} must keep the SeaweedFS binary root-owned")


def _validate_seaweedfs_launcher(launcher_text: str, errors: list[str]) -> None:
    markers = (
        'publicAddress  = "0.0.0.0:9000"',
        'privateAddress = "127.0.0.1:8333"',
        '"-ip=127.0.0.1"',
        '"-ip.bind=127.0.0.1"',
        '"-s3.port=8333"',
        '"-s3.port.iceberg=0"',
        '"-s3.iam=false"',
        'net.Listen("tcp4", publicAddress)',
        'exec.Command("/usr/local/bin/weed", privateArguments...)',
        'net.DialTimeout("tcp4", privateAddress, 5*time.Second)',
        "if !equalArguments(arguments, publicArguments)",
    )
    for marker in markers:
        if marker not in launcher_text:
            errors.append(f"SeaweedFS launcher missing isolation marker `{marker}`")
    for forbidden in (
        '"0.0.0.0:8888"',
        '"0.0.0.0:7333"',
        '"0.0.0.0:9333"',
        '"0.0.0.0:9340"',
        '"0.0.0.0:23646"',
        'exec.Command("sh"',
        'exec.Command("/bin/sh"',
    ):
        if forbidden in launcher_text:
            errors.append(f"SeaweedFS launcher contains forbidden marker `{forbidden}`")


def _validate_grafana_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    markers = (
        "golang:1.26.5-trixie@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43",
        "ARG GRAFANA_COMMIT=b309c9bb3b81a748c3a75289236a27309ed2566a",
        "ARG TEMPO_COMMIT=4aeafc237b8d9a8d62e45735131e8a89eb741a00",
        "git -C /src/grafana apply --check",
        "grafana-tempo-2.10.3.patch",
        "make build-go OS=linux ARCH=amd64 CGO_ENABLED=0",
        "9e7b41aa84cfc2e735f7482d51103e5ffcc6989525b6be7dad7b43c7b724c2f9",
        "github.com/grafana/tempo",
        "v2.10.3+incompatible",
        "golang.org/x/net",
        "v0.55.0",
        "google.golang.org/grpc",
        "v1.81.1",
        "grafana/grafana:13.1.0@sha256:121a7a9ece6dc10b969f1f96eed64b4f07dfac0d0b8abc070f7cb83bbde86f63",
        "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "/usr/share/grafana/public /usr/share/grafana/public",
        "/usr/share/grafana/conf /usr/share/grafana/conf",
        "chown -R root:root /etc/grafana /usr/share/grafana",
        "chmod -R a-w /etc/grafana /usr/share/grafana",
        "stat -c '%u:%g:%a' /usr/share/grafana/bin/grafana",
        '"0:0:555"',
        "addgroup -S -g 472 grafana",
        "chown -R 472:472 /var/lib/grafana /var/log/grafana",
        "USER 472:472",
        'ENTRYPOINT ["/usr/share/grafana/bin/grafana"]',
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing Grafana integrity marker `{marker}`"
            )
    for forbidden in (
        "COPY --from=upstream-assets /usr/share/grafana /usr/share/grafana",
        "plugins-bundled",
        "USER root",
        "--chown=472",
        "chown -R 472:0 /usr/share/grafana",
    ):
        if forbidden in dockerfile_text:
            errors.append(
                f"{dockerfile_path} contains forbidden Grafana marker `{forbidden}`"
            )
    if re.search(
        r"(?im)\bchown\b[^\n]*\b472(?::(?:472|0))?\b[^\n]*"
        r"(?:/etc/grafana|/usr/share/grafana)",
        dockerfile_text,
    ):
        errors.append(f"{dockerfile_path} must keep Grafana code and config root-owned")


def _validate_opensearch_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    markers = (
        "opensearchproject/opensearch:3.7.0@sha256:123e6591a47b1d54686890551bdb35739c85193ecded381219fc9e059e18128f",
        "ARG AMAZON_LINUX_RELEASEVER=2023.12.20260706",
        '--releasever="${AMAZON_LINUX_RELEASEVER}" upgrade',
        'openssl-libs)" = "3.5.5-1.amzn2023.0.5',
        'expat)" = "2.6.3-1.amzn2023.0.6',
        "/usr/share/opensearch/plugins/*",
        "/usr/share/opensearch/modules/ingest-geoip",
        'test -z "$(ls -A /usr/share/opensearch/plugins)"',
        "chown -R root:root /usr/share/opensearch",
        "chmod -R a-w /usr/share/opensearch",
        "cp -a /usr/share/opensearch/config /opt/hallu-defense/opensearch-config",
        "COPY --chown=0:0 --chmod=0555 infra/docker/opensearch_entrypoint.sh",
        'ENTRYPOINT ["/usr/local/bin/hallu-opensearch-entrypoint"]',
        "stat -c '%u:%g:%a' /usr/share/opensearch/bin/opensearch",
        '"0:0:555"',
        '"1000:1000:700"',
        "USER 1000",
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing OpenSearch integrity marker `{marker}`"
            )
    for forbidden in (
        "opensearch-plugin install",
        ":latest",
    ):
        if forbidden in dockerfile_text:
            errors.append(
                f"{dockerfile_path} contains forbidden OpenSearch marker `{forbidden}`"
            )
    allowed_runtime_chown = re.compile(
        r"^\s*&&\s+chown\s+-R\s+1000:1000\s+"
        r"/usr/share/opensearch/data\s+/usr/share/opensearch/logs\s+\\\s*$"
    )
    for line in dockerfile_text.splitlines():
        if (
            re.search(r"\bchown\b[^\n]*\b1000(?::1000)?\b", line)
            and "/usr/share/opensearch" in line
            and allowed_runtime_chown.fullmatch(line) is None
        ):
            errors.append(
                f"{dockerfile_path} must keep OpenSearch code and config root-owned"
            )
            break


def _validate_opensearch_entrypoint(
    entrypoint_text: str,
    errors: list[str],
) -> None:
    markers = (
        'if [[ "$(id -u)" == "0" ]]',
        '! -w "${runtime_dir}"',
        "shopt -s dotglob globstar nullglob",
        'if [[ -L "${template_entry}" ]]',
        'rm -rf -- "${runtime_entries[@]}"',
        "cp -R --no-preserve=ownership,mode,timestamps",
        'chmod -R u+rwX,go-rwx -- "${copied_entries[@]}"',
        'exec /usr/share/opensearch/opensearch-docker-entrypoint.sh "$@"',
    )
    for marker in markers:
        if marker not in entrypoint_text:
            errors.append(
                "infra/docker/opensearch_entrypoint.sh missing fail-closed marker "
                f"`{marker}`"
            )
    for forbidden in (
        "cp -a",
        'chmod -R u+rwX,go-rwx "${runtime_dir}"',
    ):
        if forbidden in entrypoint_text:
            errors.append(
                "infra/docker/opensearch_entrypoint.sh contains fsGroup-unsafe marker "
                f"`{forbidden}`"
            )


def _validate_keycloak_dockerfile(
    dockerfile_text: str,
    dockerfile_path: str,
    errors: list[str],
) -> None:
    keycloak = {
        "version": "26.7.0",
        "url": "https://github.com/keycloak/keycloak/releases/download/26.7.0/keycloak-26.7.0.tar.gz",
        "sha256": "f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a",
    }
    jackson = {
        "version": "2.21.4",
        "url": "https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.21.4/jackson-databind-2.21.4.jar",
        "sha256": "3888e9e69ab66fbacaacc9aea0e9ffbf15368288e4aca468b024dba11c09fbf9",
    }
    expected_lock: dict[str, object] = {
        "schema_version": "keycloak-artifacts.v1",
        "keycloak": keycloak,
        "jackson_databind": jackson,
        "builder_image": (
            "eclipse-temurin:21.0.11_10-jre-alpine-3.23@sha256:"
            "3f08b13888f595cc49edabea7250ba69499ba25602b267da591720769400e08c"
        ),
        "runtime_image": (
            "alpine:3.24@sha256:"
            "28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
        ),
    }
    try:
        artifact_lock = json.loads(KEYCLOAK_ARTIFACTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"Keycloak artifact lock is invalid: {exc}")
        return
    if artifact_lock != expected_lock:
        errors.append("Keycloak artifact lock must equal the approved release inputs")
    markers = (
        f"FROM {expected_lock['builder_image']} AS keycloak-builder",
        f"FROM {expected_lock['runtime_image']}",
        f"ADD --checksum=sha256:{keycloak['sha256']} {keycloak['url']}",
        f"ADD --checksum=sha256:{jackson['sha256']} {jackson['url']}",
        "KC_DB=postgres",
        "KC_HEALTH_ENABLED=true",
        "KC_METRICS_ENABLED=true",
        "/opt/keycloak/bin/kc.sh build",
        "COPY scripts/ci/patch_keycloak_metadata.py",
        "python /tmp/patch_keycloak_metadata.py",
        "com.fasterxml.jackson.core.jackson-databind-2.21.4.jar",
        "rm -rf /opt/keycloak/bin/client",
        "com.microsoft.sqlserver.mssql-jdbc-13.2.1.jre11.jar",
        "org.postgresql.postgresql-42.7.11.jar",
        "find /opt/keycloak -type d -exec chmod 0555",
        "find /opt/keycloak -type f -exec chmod 0444",
        "USER 10001:10001",
        'CMD ["start", "--optimized"]',
    )
    for marker in markers:
        if marker not in dockerfile_text:
            errors.append(
                f"{dockerfile_path} missing Keycloak integrity marker `{marker}`"
            )
    for forbidden in (
        "quay.io/keycloak/keycloak:",
        "start-dev",
        "USER root",
        "--chown=10001:10001",
    ):
        if forbidden in dockerfile_text:
            errors.append(
                f"{dockerfile_path} contains forbidden Keycloak marker `{forbidden}`"
            )
    if re.search(
        r"(?im)\bchown\b[^\n]*\b10001(?::10001)?\b[^\n]*/opt/keycloak",
        dockerfile_text,
    ):
        errors.append(f"{dockerfile_path} must keep Keycloak runtime files root-owned")


def _validate_dockerignore(dockerignore_text: str, errors: list[str]) -> None:
    patterns = {
        line.strip()
        for line in dockerignore_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required = {
        ".git",
        ".env",
        ".env.*",
        ".codex",
        ".codex-leader-worktrees",
        ".claude",
        "node_modules",
        "**/node_modules",
        "**/__pycache__",
        "**/.pytest_cache",
        "**/.mypy_cache",
        "**/.ruff_cache",
        "var",
        "*.log",
    }
    missing = sorted(required - patterns)
    if missing:
        errors.append(
            f".dockerignore missing sensitive/build-state patterns: {missing}"
        )


def load_current_config() -> tuple[str, dict[str, str]]:
    workflow_text = SECURITY_WORKFLOW.read_text(encoding="utf-8")
    dockerfile_texts = {
        name: path.read_text(encoding="utf-8") for name, path in DOCKERFILES.items()
    }
    return workflow_text, dockerfile_texts


def main() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    validate_container_scan_config(
        workflow_text=workflow_text,
        dockerfile_texts=dockerfile_texts,
    )
    print(
        "Validated container scan config for "
        f"{len(IMAGE_REFS)} first-party image(s) and the immutable external inventory."
    )


if __name__ == "__main__":
    main()
