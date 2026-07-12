from __future__ import annotations

from collections.abc import Callable

import pytest

from scripts.ci.check_container_scan_config import (
    ContainerScanConfigError,
    IMAGE_REFS,
    OPENSEARCH_ENTRYPOINT_PATH,
    SEAWEEDFS_LAUNCHER_PATH,
    load_current_config,
    validate_container_scan_config,
)


@pytest.mark.parametrize(
    "unsafe_marker",
    [
        "cp -a",
        'chmod -R u+rwX,go-rwx "${runtime_dir}"',
    ],
)
def test_container_scan_config_rejects_fsgroup_unsafe_opensearch_wrapper(
    unsafe_marker: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    entrypoint_text = OPENSEARCH_ENTRYPOINT_PATH.read_text(encoding="utf-8")

    with pytest.raises(ContainerScanConfigError, match="fsGroup-unsafe"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=dockerfile_texts,
            opensearch_entrypoint_text=f"{entrypoint_text}\n{unsafe_marker}\n",
        )


def test_container_scan_config_validates_required_images() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    validate_container_scan_config(
        workflow_text=workflow_text,
        dockerfile_texts=dockerfile_texts,
    )
    for name in IMAGE_REFS:
        assert f"infra/docker/{name}.Dockerfile" in workflow_text
    assert "fail-fast: false" in workflow_text
    assert workflow_text.count("max-parallel: 1") == 2
    assert "image-ref: hallu-defense-${{ matrix.name }}:ci" in workflow_text
    assert (
        workflow_text.count("trivy-config: ${{ runner.temp }}/hallu-trivy-policy/trivy.yaml") == 2
    )
    assert (
        workflow_text.count("trivyignores: ${{ runner.temp }}/hallu-trivy-policy/empty.trivyignore")
        == 2
    )
    assert (
        "redis:7-alpine@sha256:"
        "6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99" in workflow_text
    )
    assert "sandbox" in dockerfile_texts


def test_container_scan_config_rejects_missing_trivy_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="matrix scan"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace(
                "aquasecurity/trivy-action@", "disabled-trivy-action@"
            ),
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_non_failing_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="exit-code"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace('exit-code: "1"', 'exit-code: "0"'),
            dockerfile_texts=dockerfile_texts,
        )


@pytest.mark.parametrize(
    "name",
    tuple(IMAGE_REFS),
)
def test_container_scan_config_rejects_missing_first_party_matrix_member(
    name: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    row = f"          - name: {name}\n            dockerfile: infra/docker/{name}.Dockerfile\n"
    insecure = workflow_text.replace(row, "", 1)
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="every approved Dockerfile"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_commented_scan_marker_and_duplicate_ref() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    expected = (
        "          - name: grafana\n            dockerfile: infra/docker/grafana.Dockerfile\n"
    )
    insecure = workflow_text.replace(
        expected,
        "          - name: api\n"
        "            dockerfile: infra/docker/api.Dockerfile\n"
        "          # - name: grafana\n"
        "          #   dockerfile: infra/docker/grafana.Dockerfile\n",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="every approved Dockerfile"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_wrong_dockerfile_with_commented_build() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "            dockerfile: infra/docker/grafana.Dockerfile",
        "            dockerfile: infra/docker/api.Dockerfile\n"
        "          # dockerfile: infra/docker/grafana.Dockerfile",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="every approved Dockerfile"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_requires_non_short_circuiting_first_party_matrix() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace("      fail-fast: false", "      fail-fast: true", 1)

    with pytest.raises(ContainerScanConfigError, match="first-party.*fail-fast: false"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


@pytest.mark.parametrize("occurrence", [1, 2])
def test_container_scan_config_requires_serial_docker_work(occurrence: int) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    marker = "      max-parallel: 1"
    offset = 0
    index = -1
    for _ in range(occurrence):
        index = workflow_text.find(marker, offset)
        assert index >= 0
        offset = index + len(marker)
    insecure = (
        workflow_text[:index] + marker.replace("1", "4") + workflow_text[index + len(marker) :]
    )

    with pytest.raises(ContainerScanConfigError, match="serialize"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_static_first_party_build() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        'docker build -f "${{ matrix.dockerfile }}"',
        "docker build -f infra/docker/api.Dockerfile",
        1,
    )

    with pytest.raises(ContainerScanConfigError, match="exact current Dockerfile"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_second_tag_overwrite_build() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "      - name: Scan current first-party image",
        "      - name: Overwrite scanned tag\n"
        "        run: >-\n"
        "          docker build -f infra/docker/api.Dockerfile\n"
        '          -t "hallu-defense-${{ matrix.name }}:ci" .\n'
        "      - name: Scan current first-party image",
        1,
    )

    with pytest.raises(ContainerScanConfigError, match="contain only its exact"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_requires_scan_inside_first_party_matrix() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "image-ref: hallu-defense-${{ matrix.name }}:ci",
        "image-ref: ${{ matrix.image }}",
        1,
    )

    with pytest.raises(ContainerScanConfigError, match="first-party matrix.*image"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_conditional_continue_on_error() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "      - name: Scan current first-party image",
        "      - name: Scan current first-party image\n        continue-on-error: ${{ always() }}",
        1,
    )

    with pytest.raises(ContainerScanConfigError, match="must not weaken failures"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


@pytest.mark.parametrize(
    ("image", "marker", "message"),
    [
        (
            "grafana",
            "ARG TEMPO_COMMIT=4aeafc237b8d9a8d62e45735131e8a89eb741a00",
            "Grafana integrity marker",
        ),
        (
            "grafana",
            "v2.10.3+incompatible",
            "Grafana integrity marker",
        ),
        (
            "grafana",
            "chown -R root:root /etc/grafana /usr/share/grafana",
            "Grafana integrity marker",
        ),
        (
            "grafana",
            "USER 472:472",
            "Grafana integrity marker",
        ),
        (
            "opensearch",
            "ARG AMAZON_LINUX_RELEASEVER=2023.12.20260706",
            "OpenSearch integrity marker",
        ),
        (
            "opensearch",
            "/usr/share/opensearch/plugins/*",
            "OpenSearch integrity marker",
        ),
        (
            "opensearch",
            "chown -R root:root /usr/share/opensearch",
            "OpenSearch integrity marker",
        ),
        (
            "opensearch",
            "COPY --chown=0:0 --chmod=0555 infra/docker/opensearch_entrypoint.sh",
            "OpenSearch integrity marker",
        ),
    ],
)
def test_container_scan_config_requires_hardened_service_integrity(
    image: str,
    marker: str,
    message: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure[image] = insecure[image].replace(marker, "removed-integrity-marker")

    with pytest.raises(ContainerScanConfigError, match=message):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    ("image", "path"),
    [
        ("grafana", "/usr/share/grafana"),
        ("opensearch", "/usr/share/opensearch"),
        ("seaweedfs", "/usr/local/bin"),
    ],
)
def test_container_scan_config_rejects_world_writable_runtime_paths(
    image: str,
    path: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure[image] = f"{insecure[image]}\nRUN chmod -R 0777 {path}\n"

    with pytest.raises(ContainerScanConfigError, match="world-writable"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


def test_container_scan_config_rejects_runtime_owned_opensearch_tree() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["opensearch"] = insecure["opensearch"].replace(
        "chown -R root:root /usr/share/opensearch",
        "chown -R 1000:1000 /usr/share/opensearch",
    )

    with pytest.raises(ContainerScanConfigError, match="code and config root-owned"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    ("image", "injected", "message"),
    [
        (
            "grafana",
            "RUN chown 472:472 /usr/share/grafana/bin/grafana",
            "Grafana code and config root-owned",
        ),
        (
            "opensearch",
            "RUN chown 1000:1000 /usr/share/opensearch/lib/opensearch-3.7.0.jar",
            "OpenSearch code and config root-owned",
        ),
        (
            "seaweedfs",
            "RUN chown 10001:10001 /usr/local/bin/weed",
            "SeaweedFS binary root-owned",
        ),
        (
            "keycloak",
            "RUN chown 10001:10001 /opt/keycloak/bin/kc.sh",
            "Keycloak runtime files root-owned",
        ),
    ],
)
def test_container_scan_config_rejects_point_runtime_code_chown(
    image: str,
    injected: str,
    message: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure[image] = f"{insecure[image]}\n{injected}\n"

    with pytest.raises(ContainerScanConfigError, match=message):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    "marker",
    (
        "golang:1.26.4-alpine3.24@sha256:3ad57304",
        "ARG SEAWEEDFS_COMMIT=1355c7a102194d6c461baf090eff50367b575afb",
        "ARG SEAWEEDFS_SOURCE_SHA256=d4ec97a7",
        'addr := fmt.Sprintf("127.0.0.1:%d", *options.port)',
        'net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))',
        "github.com/apache/thrift@v0.23.0",
        "golang.org/x/net@v0.55.0",
        "cmp /out/weed.first /out/weed.second",
        "cmp /out/seaweedfs-launcher.first /out/seaweedfs-launcher.second",
        'ENTRYPOINT ["/usr/local/bin/seaweedfs-launcher"]',
        "USER 10001:10001",
    ),
)
def test_container_scan_config_requires_hardened_seaweedfs(marker: str) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["seaweedfs"] = insecure["seaweedfs"].replace(
        marker,
        "removed-seaweedfs-marker",
    )

    with pytest.raises(ContainerScanConfigError, match="SeaweedFS integrity marker"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    "marker",
    (
        'privateAddress = "127.0.0.1:8333"',
        '"-ip=127.0.0.1"',
        '"-ip.bind=127.0.0.1"',
        '"-s3.port.iceberg=0"',
        '"-s3.iam=false"',
        "if !equalArguments(arguments, publicArguments)",
    ),
)
def test_container_scan_config_requires_isolated_seaweedfs_launcher(marker: str) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    launcher_text = SEAWEEDFS_LAUNCHER_PATH.read_text(encoding="utf-8")

    with pytest.raises(ContainerScanConfigError, match="launcher missing isolation marker"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=dockerfile_texts,
            seaweedfs_launcher_text=launcher_text.replace(
                marker,
                "removed-seaweedfs-launcher-marker",
            ),
        )


@pytest.mark.parametrize(
    "marker",
    (
        "ADD --checksum=sha256:f771df0a",
        "ADD --checksum=sha256:3888e9e6",
        "python /tmp/patch_keycloak_metadata.py",
        "rm -rf /opt/keycloak/bin/client",
        "USER 10001:10001",
    ),
)
def test_container_scan_config_requires_hardened_keycloak(marker: str) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["keycloak"] = insecure["keycloak"].replace(marker, "removed-keycloak-marker")

    with pytest.raises(ContainerScanConfigError, match="Keycloak integrity marker"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


def test_deployed_image_inventory_excludes_kind_ci_substrate() -> None:
    workflow_text, _dockerfile_texts = load_current_config()

    assert "kindest/node:" not in workflow_text
    assert "quay.io/calico/" not in workflow_text
    assert "minio/minio:" not in workflow_text
    assert "minio/mc:" not in workflow_text
    assert "chrislusf/seaweedfs:" not in workflow_text


def test_container_scan_config_rejects_missing_pinned_redis_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="image matrix drift"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace(
                "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
                "removed-redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
            ),
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_duplicate_third_party_matrix_row() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    reference = (
        "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    )
    insecure = workflow_text.replace(
        f"          - {reference}",
        f"          - {reference}\n          - {reference}",
        1,
    )

    with pytest.raises(ContainerScanConfigError, match="image matrix drift"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_vulnerable_action_and_ignored_findings() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "ed142fd0673e97e23eac54620cfb913e5ce36c25",
        "915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2",
    ).replace(
        "          vuln-type: os,library",
        "          ignore-unfixed: true\n          vuln-type: os,library",
        1,
    )

    with pytest.raises(
        ContainerScanConfigError,
        match="ignore unfixed|vulnerable Trivy action",
    ):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_requires_exact_trivy_binary_version() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="version: v0.72.0"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace("version: v0.72.0", "version: latest"),
            dockerfile_texts=dockerfile_texts,
        )


@pytest.mark.parametrize(
    ("trusted", "untrusted"),
    (
        (
            "trivy-config: ${{ runner.temp }}/hallu-trivy-policy/trivy.yaml",
            "trivy-config: trivy.yaml",
        ),
        (
            "trivyignores: ${{ runner.temp }}/hallu-trivy-policy/empty.trivyignore",
            "trivyignores: .trivyignore",
        ),
    ),
)
def test_container_scan_config_rejects_repository_authored_trivy_policy(
    trusted: str,
    untrusted: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(trusted, untrusted, 1)
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="every Trivy scan must set"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_missing_external_empty_trivy_policy() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "      - name: Create empty external Trivy policy",
        "      - name: Trust repository Trivy policy",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(
        ContainerScanConfigError,
        match="external empty Trivy policy|exact policy",
    ):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_refilling_external_trivy_ignore_file() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    marker = '          : > "${RUNNER_TEMP}/hallu-trivy-policy/empty.trivyignore"'
    insecure = workflow_text.replace(
        marker,
        marker
        + "\n"
        + "          printf 'CVE-2026-9999\\n' >> "
        + '"${RUNNER_TEMP}/hallu-trivy-policy/empty.trivyignore"',
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="exact empty fail-closed"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_trivy_policy_step_environment_override() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "      - name: Create empty external Trivy policy\n        shell: bash",
        "      - name: Create empty external Trivy policy\n"
        "        env:\n"
        "          TRIVY_CONFIG: .trivy.yaml\n"
        "        shell: bash",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="exact trusted metadata"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_additional_trivy_suppression_input() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = workflow_text.replace(
        "          vuln-type: os,library",
        "          skip-dirs: /usr/local/lib\n          vuln-type: os,library",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="only the exact fail-closed"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


@pytest.mark.parametrize(
    "injection",
    (
        "        if: ${{ false }}\n",
        '        env:\n          TRIVY_IGNORE_UNFIXED: "true"\n',
    ),
)
def test_container_scan_config_rejects_neutralized_third_party_scan(
    injection: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    marker = "      - name: Scan immutable third-party image\n"
    insecure = workflow_text.replace(marker, marker + injection, 1)
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="exact trusted metadata"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_third_party_matrix_exclusion() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    marker = "      matrix:\n        image:\n"
    insecure = workflow_text.replace(
        marker,
        "      matrix:\n"
        "        exclude:\n"
        "          - image: prom/prometheus:excluded\n"
        "        image:\n",
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="exact immutable image list"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_extra_action_before_third_party_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    marker = "      - name: Scan immutable third-party image\n"
    insecure = workflow_text.replace(
        marker,
        "      - name: Overwrite scanner policy\n        uses: ./attacker-action\n" + marker,
        1,
    )
    assert insecure != workflow_text

    with pytest.raises(ContainerScanConfigError, match="exactly policy then Trivy"):
        validate_container_scan_config(
            workflow_text=insecure,
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_requires_sensitive_dockerignore_patterns() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="dockerignore"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=dockerfile_texts,
            dockerignore_text=".git\n.env\nnode_modules\n",
        )


@pytest.mark.parametrize(
    ("image", "secure_marker", "insecure_marker"),
    [
        (
            "console",
            "COPY --from=builder /app/apps/console/.next/standalone ./",
            "COPY --from=builder --chown=node:node /app/apps/console/.next/standalone ./",
        ),
        (
            "sandbox",
            "COPY infra/docker/sandbox_runner.py /opt/hallu-defense/sandbox_runner.py",
            "COPY --chown=10001:10001 infra/docker/sandbox_runner.py /opt/hallu-defense/sandbox_runner.py",
        ),
    ],
)
def test_container_scan_config_rejects_runtime_owned_code(
    image: str,
    secure_marker: str,
    insecure_marker: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure[image] = insecure[image].replace(secure_marker, insecure_marker)

    with pytest.raises(ContainerScanConfigError, match="root-owned|writable"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


def test_container_scan_config_rejects_root_container_user() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["api"] = dockerfile_texts["api"].replace("USER appuser", "USER root")

    with pytest.raises(ContainerScanConfigError, match="root user"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda text: text.replace("COPY .npmrc /app/.npmrc", "COPY missing-npmrc /app/.npmrc"),
        lambda text: text.replace("npm ci", "npm ci --ignore-scripts"),
        lambda text: text.replace("npm ci", "npm ci --dangerously-allow-all-scripts"),
    ),
)
def test_container_scan_config_rejects_npm_policy_bypass(
    mutation: Callable[[str], str],
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["console"] = mutation(dockerfile_texts["console"])

    with pytest.raises(ContainerScanConfigError, match=r"npm.*policy"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


@pytest.mark.parametrize(
    ("marker", "message"),
    [
        ("golang:1.26.4-trixie@sha256:", "Go 1.26.4"),
        ("ARG OPA_TAG=v1.17.0", "OPA runtime marker"),
        (
            "ARG OPA_COMMIT=64a3625d33bc6ad8e7c40df03b76ce2fb3ab4d21",
            "OPA runtime marker",
        ),
        ("COPY infra/docker/opa-no-oci.patch", "OPA runtime marker"),
        ("git -C /src/opa apply --check", "OPA runtime marker"),
        ("-require=golang.org/x/crypto@v0.52.0", "OPA runtime marker"),
        ("-require=golang.org/x/net@v0.55.0", "OPA runtime marker"),
        ("go build -tags=opa_no_oci", "OPA runtime marker"),
        ("go version -m /out/opa", "OPA runtime marker"),
        ("python:3.12.13-alpine3.24@sha256:", "Python 3.12"),
        ("COPY infra/opa/policies /app/infra/opa/policies", "OPA runtime marker"),
        ("/usr/local/bin/opa check --strict", "OPA runtime marker"),
    ],
)
def test_container_scan_config_requires_pinned_opa_runtime(
    marker: str,
    message: str,
) -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["api"] = dockerfile_texts["api"].replace(marker, "removed-marker")

    with pytest.raises(ContainerScanConfigError, match=message):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )


def test_container_scan_config_rejects_writable_or_broad_opa_tree() -> None:
    workflow_text, dockerfile_texts = load_current_config()
    insecure = dict(dockerfile_texts)
    insecure["api"] = (
        dockerfile_texts["api"]
        .replace(
            "COPY infra/opa/policies /app/infra/opa/policies",
            "COPY infra/opa /app/infra/opa",
        )
        .replace(
            "find /app -type f -exec chmod 0444 {} +",
            "chown -R appuser:appuser /app",
        )
    )

    with pytest.raises(ContainerScanConfigError, match="copy only|root-owned"):
        validate_container_scan_config(
            workflow_text=workflow_text,
            dockerfile_texts=insecure,
        )
