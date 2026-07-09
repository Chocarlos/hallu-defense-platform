from __future__ import annotations

import pytest

from scripts.ci.check_container_scan_config import (
    ContainerScanConfigError,
    load_current_config,
    validate_container_scan_config,
)


def test_container_scan_config_validates_required_images() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    validate_container_scan_config(
        workflow_text=workflow_text,
        dockerfile_texts=dockerfile_texts,
    )
    assert "infra/docker/sandbox.Dockerfile" in workflow_text
    assert "hallu-defense-sandbox:ci" in workflow_text
    assert "sandbox" in dockerfile_texts


def test_container_scan_config_rejects_missing_trivy_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="aquasecurity/trivy-action"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace("aquasecurity/trivy-action@", "disabled-trivy-action@"),
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_non_failing_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="exit-code"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace('exit-code: "1"', 'exit-code: "0"'),
            dockerfile_texts=dockerfile_texts,
        )


def test_container_scan_config_rejects_missing_sandbox_scan() -> None:
    workflow_text, dockerfile_texts = load_current_config()

    with pytest.raises(ContainerScanConfigError, match="hallu-defense-sandbox:ci"):
        validate_container_scan_config(
            workflow_text=workflow_text.replace("image-ref: hallu-defense-sandbox:ci", ""),
            dockerfile_texts=dockerfile_texts,
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
