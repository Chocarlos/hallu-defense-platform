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
    "infra/prometheus/demo-request-alerts.yml",
    "infra/prometheus/prometheus.yml",
    "infra/prometheus/prometheus.prod.yml",
    "infra/docker/console.Dockerfile",
    "apps/console/package.json",
    "apps/console/components/marketing/marketing.module.css",
    "apps/console/lib/demo-request/redis.ts",
    "apps/console/lib/demo-request/metrics.ts",
    "apps/console/playwright.marketing.config.ts",
    "apps/console/e2e-marketing/marketing.spec.ts",
    "apps/console/e2e-marketing/accessibility.spec.ts",
    "apps/console/e2e-marketing/csp.spec.ts",
    "apps/console/e2e-marketing/demo-request.spec.ts",
    "apps/console/e2e-marketing/disabled-intake.spec.ts",
    "apps/console/e2e-marketing/performance-lab.spec.ts",
    "apps/console/e2e-marketing/progressive-enhancement.spec.ts",
    "apps/console/e2e-marketing/run-marketing-suite.mjs",
    "apps/console/e2e-marketing/serve-standalone.mjs",
    "apps/console/scripts/run-browserstack-marketing.mjs",
    "Makefile",
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    "docs/deployment/marketing-launch.md",
    "README.md",
)


def test_current_marketing_compatibility_config_is_valid() -> None:
    validate(REPO_ROOT)


def test_gate_rejects_alert_without_console_metrics_scrape(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    prometheus = tmp_path / "infra/prometheus/prometheus.prod.yml"
    prometheus.write_text(
        prometheus.read_text(encoding="utf-8").replace(
            "job_name: hallu-defense-console",
            "job_name: removed-console-metrics",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        MarketingCompatibilityConfigError, match="hallu-defense-console"
    ):
        validate(tmp_path)


def test_gate_rejects_silent_browserstack_minimum_reduction(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/scripts/run-browserstack-marketing.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace("edge-111", "edge-latest"),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="edge-111"):
        validate(tmp_path)


def test_gate_rejects_browserstack_ios_catalog_shape_regression(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/scripts/run-browserstack-marketing.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace(
            "browser_version: null",
            'browser_version: "16.4"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="browser_version: null"):
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


def test_gate_rejects_reduced_playwright_viewport_matrix(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    config = tmp_path / "apps/console/playwright.marketing.config.ts"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            '{ name: "mobile-320", width: 320, height: 800 },',
            '{ name: "mobile-375", width: 375, height: 800 },',
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="exactly the 320"):
        validate(tmp_path)


def test_gate_rejects_disabled_axe_target_size_rule(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/accessibility.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            'rules: { "target-size": { enabled: true } }',
            'rules: { "target-size": { enabled: false } }',
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="target-size"):
        validate(tmp_path)


def test_gate_requires_axe_in_the_enabled_form_phase(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/accessibility.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "@form axe WCAG 2.2 AA enabled form states",
            "axe enabled form states",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="@form axe"):
        validate(tmp_path)


def test_gate_rejects_contrast_diluting_reveal_opacity(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    stylesheet = tmp_path / "apps/console/components/marketing/marketing.module.css"
    stylesheet.write_text(
        stylesheet.read_text(encoding="utf-8").replace(
            ".revealPending {\n  opacity: 1;",
            ".revealPending {\n  opacity: 0;",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="revealPending"):
        validate(tmp_path)


def test_gate_requires_redis_cluster_client_and_dispatch_alert(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    redis = tmp_path / "apps/console/lib/demo-request/redis.ts"
    redis.write_text(
        redis.read_text(encoding="utf-8").replace("createCluster", "removedCluster"),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="createCluster"):
        validate(tmp_path)


def test_gate_rejects_weakened_horizontal_scroll_probe(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/marketing.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "horizontalScrollProbe",
            "unusedScrollProbe",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="horizontalScrollProbe"):
        validate(tmp_path)


def test_gate_rejects_missing_csp_script_nonce_assertion(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/csp.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace("script.nonce", 'script.getAttribute("src")'),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="script.nonce"):
        validate(tmp_path)


def test_gate_rejects_missing_synthetic_secret_cleanup(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/e2e-marketing/run-marketing-suite.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace(
            "cleanupSyntheticRuntime(runtime.directory)",
            "void runtime.directory",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="cleanupSyntheticRuntime"):
        validate(tmp_path)


def test_gate_rejects_missing_malformed_202_regression(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/demo-request.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace("malformed 202", "unexpected response"),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="malformed 202"):
        validate(tmp_path)


def test_gate_rejects_relaxed_synthetic_lcp_budget(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/performance-lab.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "lcpMilliseconds: 2_500",
            "lcpMilliseconds: 3_000",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="2_500"):
        validate(tmp_path)


def test_gate_rejects_browserstack_remote_on_pull_requests(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "if: github.event_name == 'push'",
            "if: github.event_name == 'pull_request'",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="github.event_name"):
        validate(tmp_path)


@pytest.mark.parametrize(
    "marker",
    [
        "HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED: ${{ vars.HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED || 'false' }}",
        "BROWSERSTACK_WEBHOOK_STUB: ${{ vars.BROWSERSTACK_WEBHOOK_STUB || 'false' }}",
    ],
)
def test_gate_rejects_missing_browserstack_live_form_isolation_marker(
    tmp_path: Path,
    marker: str,
) -> None:
    _copy_fixture(tmp_path)
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(marker, "missing-live-form-marker"),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="missing"):
        validate(tmp_path)


def test_gate_rejects_next_start_for_production_marketing_e2e(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    config = tmp_path / "apps/console/playwright.marketing.config.ts"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "node ./e2e-marketing/serve-standalone.mjs --port",
            "npx next start --port",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="serve-standalone"):
        validate(tmp_path)


def test_gate_rejects_missing_standalone_static_copy(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    helper = tmp_path / "apps/console/e2e-marketing/serve-standalone.mjs"
    helper.write_text(
        helper.read_text(encoding="utf-8").replace(
            "cpSync(source, destination",
            "disabledCopy(source, destination",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="cpSync"):
        validate(tmp_path)


@pytest.mark.parametrize(
    "marker",
    [
        "request.headers()",
        "request.postData()",
        "expect(inputWasEnabled).toBe(false)",
        "expect(buttonWasEnabled).toBe(false)",
        "expect(leakingChannels).toEqual([])",
    ],
)
def test_gate_rejects_weakened_no_javascript_pii_boundary(
    tmp_path: Path,
    marker: str,
) -> None:
    _copy_fixture(tmp_path)
    spec = tmp_path / "apps/console/e2e-marketing/progressive-enhancement.spec.ts"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(marker, "missing-nojs-boundary-marker"),
        encoding="utf-8",
    )

    with pytest.raises(
        MarketingCompatibilityConfigError,
        match="progressive-enhancement",
    ):
        validate(tmp_path)


def test_gate_rejects_missing_live_browserstack_form_submission(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/scripts/run-browserstack-marketing.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace(
            "await completePlaywrightDemoRequest(",
            "await inspectPlaywrightDemoFormWithoutSubmitting(",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="completePlaywright"):
        validate(tmp_path)


def test_gate_rejects_missing_live_selenium_form_submission(tmp_path: Path) -> None:
    _copy_fixture(tmp_path)
    runner = tmp_path / "apps/console/scripts/run-browserstack-marketing.mjs"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace(
            "await completeSeleniumDemoRequest(",
            "await inspectSeleniumDemoFormWithoutSubmitting(",
        ),
        encoding="utf-8",
    )

    with pytest.raises(MarketingCompatibilityConfigError, match="completeSelenium"):
        validate(tmp_path)


def _copy_fixture(destination: Path) -> None:
    for relative in REQUIRED_PATHS:
        source = REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
