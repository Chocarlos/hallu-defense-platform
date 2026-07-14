from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.ci.check_marketing_compatibility_config import (
    MarketingCompatibilityConfigError,
    REPO_ROOT,
    validate,
)


REQUIRED_PATHS = (
    ".env.example",
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "infra/k8s/helm/hallu-defense/values.yaml",
    "infra/k8s/helm/hallu-defense/values.schema.json",
    "infra/k8s/helm/hallu-defense/templates/console-deployment.yaml",
    "infra/k8s/helm/hallu-defense/templates/application-egress-network-policies.yaml",
    "infra/docker/console.Dockerfile",
    "apps/console/package.json",
    "apps/console/playwright.marketing.config.ts",
    "apps/console/e2e-marketing/marketing.spec.ts",
    "apps/console/e2e-marketing/accessibility.spec.ts",
    "apps/console/scripts/run-browserstack-marketing.mjs",
    "Makefile",
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    "docs/deployment/marketing-launch.md",
    "README.md",
)


def test_current_marketing_compatibility_config_is_valid() -> None:
    validate(REPO_ROOT)


def test_gate_rejects_silent_browserstack_minimum_reduction(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/scripts/run-browserstack-marketing.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace("edge-111", "edge-latest"),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="edge-111"):
        validate(tmp_path)


def test_gate_rejects_enabled_local_intake_default(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        compose.read_text(encoding="utf-8").replace(
            'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"',
            'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="docker-compose.yml"):
        validate(tmp_path)


def _copy_fixture(destination: Path) -> None:
    for relative in REQUIRED_PATHS:
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
