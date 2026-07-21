from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_ENVIRONMENT_NAMES = (
    "HALLU_DEFENSE_DEMO_REQUESTS_ENABLED",
    "HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL",
    "HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE",
    "HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE",
    "HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN",
    "HALLU_DEFENSE_DEMO_REDIS_URL_FILE",
    "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
    "HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE",
)


class MarketingCompatibilityConfigError(RuntimeError):
    """Raised when marketing deployment or compatibility wiring drifts."""


def validate(root: Path = REPO_ROOT) -> None:
    errors: list[str] = []
    texts = {
        path: _read(root / path, path, errors)
        for path in (
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
            "infra/docker/console.Dockerfile",
        )
    }

    for name in REQUIRED_ENVIRONMENT_NAMES:
        for path in (".env.example", "docker-compose.prod.yml"):
            _require(texts[path], name, path, errors)
    _require(
        texts["docker-compose.yml"],
        'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"',
        "docker-compose.yml",
        errors,
    )
    for marker in (
        "hallu_demo_webhook_url",
        "hallu_demo_webhook_hmac_secret",
        "hallu_demo_redis_url",
        "hallu_demo_redis_ca",
        "hallu_console_metrics_bearer",
        ":-/dev/null",
    ):
        _require(texts["docker-compose.prod.yml"], marker, "docker-compose.prod.yml", errors)

    for marker in (
        "demoRequests:",
        "enabled: false",
        "redisMode: cluster",
        "demoWebhook: []",
        "demoRedis: []",
        "secrets.demo.name",
        "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
        "HALLU_DEFENSE_DEMO_REDIS_MODE",
        "mountPath: /run/hallu-defense/demo",
        "path: /console",
    ):
        if marker in {"secrets.demo.name"}:
            corpus = texts[
                "infra/k8s/helm/hallu-defense/templates/console-deployment.yaml"
            ]
            path = "infra/k8s/helm/hallu-defense/templates/console-deployment.yaml"
        elif marker in {
            "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
            "HALLU_DEFENSE_DEMO_REDIS_MODE",
            "mountPath: /run/hallu-defense/demo",
            "path: /console",
        }:
            path = "infra/k8s/helm/hallu-defense/templates/console-deployment.yaml"
            corpus = texts[path]
        else:
            path = "infra/k8s/helm/hallu-defense/values.yaml"
            corpus = texts[path]
        _require(corpus, marker, path, errors)
    for marker in ("demoRequests.enabled", "demoWebhook", "demoRedis"):
        _require(
            texts[
                "infra/k8s/helm/hallu-defense/templates/application-egress-network-policies.yaml"
            ],
            marker,
            "infra/k8s/helm/hallu-defense/templates/application-egress-network-policies.yaml",
            errors,
        )

    package_label = "apps/console/package.json"
    package = _parse_json_object(texts[package_label], package_label, errors)
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    expected_scripts = {
        "test:e2e:marketing:list": (
            "node ./e2e-marketing/run-marketing-suite.mjs --list"
        ),
        "test:e2e:marketing": "node ./e2e-marketing/run-marketing-suite.mjs",
        "test:e2e:marketing:production": (
            "node ./e2e-marketing/run-marketing-suite.mjs --phase=production"
        ),
        "test:e2e:marketing:form": (
            "node ./e2e-marketing/run-marketing-suite.mjs --phase=form"
        ),
        "test:browserstack:config": (
            "node ./scripts/run-browserstack-marketing.mjs --check-config"
        ),
        "test:browserstack:marketing": (
            "node ./scripts/run-browserstack-marketing.mjs"
        ),
    }
    if not isinstance(scripts, dict):
        errors.append(f"{package_label} scripts must be an object")
    else:
        for name, expected in expected_scripts.items():
            if scripts.get(name) != expected:
                errors.append(f"{package_label} script `{name}` must be `{expected}`")

    playwright = texts["apps/console/playwright.marketing.config.ts"]
    _validate_playwright_matrix(playwright, errors)
    for marker in (
        'testDir: "./e2e-marketing"',
        'const baseURL = `http://127.0.0.1:${port}`',
        'mode === "form"',
        "npx next dev --hostname 127.0.0.1 --port",
        "npm run build && node ./e2e-marketing/serve-standalone.mjs --port",
        'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"',
        'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"',
        'HALLU_DEFENSE_DEMO_REDIS_MODE: "standalone"',
    ):
        _require(playwright, marker, "apps/console/playwright.marketing.config.ts", errors)

    standalone_label = "apps/console/e2e-marketing/serve-standalone.mjs"
    for marker in (
        "cpSync(source, destination",
        'path.join(consoleDirectory, ".next", "static")',
        'path.join(standaloneConsoleDirectory, ".next", "static")',
        'path.join(consoleDirectory, "public")',
        'path.join(standaloneConsoleDirectory, "public")',
        'path.join(standaloneConsoleDirectory, "server.js")',
        'process.env.HOSTNAME = "127.0.0.1"',
        "process.chdir(standaloneDirectory)",
    ):
        _require(texts[standalone_label], marker, standalone_label, errors)

    marketing_spec = texts["apps/console/e2e-marketing/marketing.spec.ts"]
    for marker in (
        'privacyPath: "/privacy"',
        'privacyPath: "/en/privacy"',
        'page.goto("/console")',
        "reducedMotion: \"reduce\"",
        "200% scale equivalence",
        "not browser UI zoom",
        "deviceScaleFactor: 2",
        "physicalWidth: window.innerWidth * window.devicePixelRatio",
        "assertNoHorizontalOverflow",
        "root.clientWidth",
        "body.clientWidth",
        "document.scrollingElement",
        "scroller?.scrollWidth",
        "minimumClientWidth",
        "maximumScrollWidth",
        "horizontalScrollProbe",
        "overflowingElements",
        "bodyMinimumWidth",
        "classic 15px scrollbar",
        'page.on("pageerror"',
        'message.type() === "error"',
        'getByRole("tab")',
        'page.keyboard.press("ArrowRight")',
        "waitForTimeout(6_750)",
    ):
        _require(marketing_spec, marker, "apps/console/e2e-marketing/marketing.spec.ts", errors)

    accessibility_label = "apps/console/e2e-marketing/accessibility.spec.ts"
    for marker in (
        "AxeBuilder",
        "@form axe WCAG 2.2 AA enabled form states",
        'data-demo-form-hydrated="true"',
        "await expectAxeWcag22Aa(page);",
        '"wcag22aa"',
        'rules: { "target-size": { enabled: true } }',
        'id === "target-size"',
    ):
        _require(texts[accessibility_label], marker, accessibility_label, errors)
    marketing_css_label = "apps/console/components/marketing/marketing.module.css"
    for marker in (
        ".revealPending {\n  opacity: 1;",
        "@keyframes reveal-in {\n  from {\n    opacity: 1;",
    ):
        _require(texts[marketing_css_label], marker, marketing_css_label, errors)

    redis_label = "apps/console/lib/demo-request/redis.ts"
    for marker in (
        "createCluster",
        'config.redisMode === "cluster"',
        "RedisClusterCommandClient",
        "maxCommandRedirections: 4",
        "return {'dispatching', state[2]}",
    ):
        _require(texts[redis_label], marker, redis_label, errors)
    metrics_label = "apps/console/lib/demo-request/metrics.ts"
    _require(
        texts[metrics_label],
        "hallu_demo_dispatching_guard_total",
        metrics_label,
        errors,
    )
    alert_label = "infra/prometheus/demo-request-alerts.yml"
    for marker in (
        "HalluDefenseDemoDispatchingGuardObserved",
        "increase(hallu_demo_dispatching_guard_total[15m]) > 0",
    ):
        _require(texts[alert_label], marker, alert_label, errors)
    _require(
        texts["infra/prometheus/prometheus.prod.yml"],
        "/etc/prometheus/demo-request-alerts.yml",
        "infra/prometheus/prometheus.prod.yml",
        errors,
    )
    for marker in (
        "job_name: hallu-defense-console",
        "credentials_file: /run/secrets/hallu_console_metrics_bearer",
        "- console:3000",
    ):
        _require(
            texts["infra/prometheus/prometheus.prod.yml"],
            marker,
            "infra/prometheus/prometheus.prod.yml",
            errors,
        )
    for marker in (
        "networkPolicy.ingress.console.metricsScrapers",
        ".Values.networkPolicy.ingress.console.metricsScrapers",
    ):
        _require(
            texts[
                "infra/k8s/helm/hallu-defense/templates/application-egress-network-policies.yaml"
            ],
            marker,
            "infra/k8s/helm/hallu-defense/templates/application-egress-network-policies.yaml",
            errors,
        )

    csp_label = "apps/console/e2e-marketing/csp.spec.ts"
    for marker in (
        '"content-security-policy"',
        "script-src",
        "'nonce-([^']+)'",
        'page.locator("script")',
        "script.nonce",
        "nonce !== responseNonce",
        '"application/ld+json"',
    ):
        _require(texts[csp_label], marker, csp_label, errors)

    form_label = "apps/console/e2e-marketing/demo-request.spec.ts"
    for marker in (
        "PUBLIC_REQUEST_ID",
        '"dr_AbCdEfGhIjKlMnOpQrStUvWx"',
        "[422, 503, 202]",
        "malformed 202",
        'request_id: "synthetic-browser-response"',
        "submission_id",
        "toBeFocused",
        "privacy.v1",
        "not.toContainText",
        'page.route("**/demo-request"',
    ):
        _require(texts[form_label], marker, form_label, errors)

    disabled_label = "apps/console/e2e-marketing/disabled-intake.spec.ts"
    for marker in ("@disabled", 'input[type="email"]', "demoRequests"):
        _require(texts[disabled_label], marker, disabled_label, errors)

    performance_label = "apps/console/e2e-marketing/performance-lab.spec.ts"
    for marker in (
        "@lab-performance",
        "chromium-desktop-1440",
        "lcpMilliseconds: 2_500",
        "syntheticInpMilliseconds: 200",
        "cls: 0.1",
        "largest-contentful-paint",
        "layout-shift",
        'type: "event"',
        "durationThreshold: 16",
        "hadRecentInput",
        "style.aspectRatio",
    ):
        _require(texts[performance_label], marker, performance_label, errors)

    progressive_label = "apps/console/e2e-marketing/progressive-enhancement.spec.ts"
    for marker in (
        "javaScriptEnabled: false",
        "hasNoTransparentContent",
        'element.querySelectorAll("*")',
        "getComputedStyle(current).opacity",
        "cannot transmit form PII without JavaScript",
        "inputWasEnabled",
        "buttonWasEnabled",
        "leakingChannels",
        "containsEncodedValue(request.url(), email)",
        "request.headers()",
        "request.postData()",
        "expect(inputWasEnabled).toBe(false)",
        "expect(buttonWasEnabled).toBe(false)",
        "expect(leakingChannels).toEqual([])",
        "new URL(page.url()).search",
    ):
        _require(texts[progressive_label], marker, progressive_label, errors)

    suite_runner_label = "apps/console/e2e-marketing/run-marketing-suite.mjs"
    for marker in (
        "mkdtempSync",
        "tmpdir()",
        'flag: "wx", mode: 0o600',
        "cleanupSyntheticRuntime",
        "finally",
        "if (runtime !== undefined) cleanupSyntheticRuntime(runtime.directory);",
        'phase === "form"',
        'phase === "form" ? ["--grep", "@form"]',
        'phase === "form" ? "true" : "false"',
        "Refusing to remove an unmanaged marketing E2E directory.",
        "createServer",
        'server.listen(0, "127.0.0.1"',
        "MARKETING_E2E_PORT: String(port)",
    ):
        _require(texts[suite_runner_label], marker, suite_runner_label, errors)

    browserstack = texts["apps/console/scripts/run-browserstack-marketing.mjs"]
    for marker in (
        "automate/browsers.json",
        "browserstack-smoke@example.invalid",
        "chrome-111",
        "edge-111",
        "firefox-111",
        "safari-16.4",
        "ios-safari-16.4",
        'key: "current-webkit"',
        'capabilityBrowser: "playwright-firefox"',
        'capabilityBrowser: "playwright-webkit"',
        "browser_version: null",
        "deviceName: entry.device",
        "osVersion: entry.osVersion",
        'Object.hasOwn(capabilities, "browser_version") === requirement.branded',
        "Remote BrowserStack smoke requires an HTTPS staging URL.",
        "BrowserStack credentials must be supplied together.",
        "MAX_CATALOG_BYTES",
        "REMOTE_CONNECT_TIMEOUT_MS",
        'action: "getSessionDetails"',
        "hashed_id",
        "recordDiagnostic",
        "runPlaywrightSmoke",
        "runSeleniumSmoke",
        "No compatibility result is claimed",
        "BROWSERSTACK_WEBHOOK_STUB",
        "HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED",
        "liveFormEnabled,",
        "webhookStub",
        "runtime.liveFormEnabled",
        "assertIsolatedWebhookStub",
        "await completePlaywrightDemoRequest(",
        'liveSmokeEmail("playwright", requirement.key)',
        "await completeSeleniumDemoRequest(",
        'liveSmokeEmail("selenium", requirement.key)',
        "response.status() !== 202",
        "responseStatus !== 202",
        "PUBLIC_REQUEST_ID_PATTERN",
        "liveSmokeEmail",
        'new Set(liveEmails).size === liveEmails.length',
        'email.endsWith("@example.invalid")',
    ):
        _require(browserstack, marker, "apps/console/scripts/run-browserstack-marketing.mjs", errors)

    makefile = texts["Makefile"]
    for marker in (
        "marketing-config:",
        "marketing-e2e:",
        "marketing-e2e-production:",
        "marketing-e2e-form:",
        "browserstack-marketing-config:",
        "check_marketing_compatibility_config.py",
    ):
        _require(makefile, marker, "Makefile", errors)
    ci = texts[".github/workflows/ci.yml"]
    for marker in (
        "check_marketing_compatibility_config.py",
        "playwright install --with-deps chromium firefox webkit",
        "test:e2e:marketing",
        "test:browserstack:marketing",
    ):
        _require(ci, marker, ".github/workflows/ci.yml", errors)
    _validate_browserstack_ci_isolation(ci, errors)
    security_label = ".github/workflows/security.yml"
    for marker in (
        "check_marketing_compatibility_config.py",
        "test:browserstack:config",
        "npm audit --audit-level=high",
        "npm audit --omit=dev --audit-level=high",
    ):
        _require(texts[security_label], marker, security_label, errors)
    for marker in (
        "90 days",
        "legal approval",
        "BrowserStack",
        "no compatibility claim",
        "hallu_demo_dispatching_guard_total",
        "HalluDefenseDemoDispatchingGuardObserved",
        "HALLU_DEFENSE_DEMO_REDIS_MODE=cluster",
    ):
        _require(
            texts["docs/deployment/marketing-launch.md"],
            marker,
            "docs/deployment/marketing-launch.md",
            errors,
        )
    _require(texts["README.md"], "/console", "README.md", errors)
    _require(texts["README.md"], "marketing-launch.md", "README.md", errors)

    public = root / "apps/console/public"
    if public.is_dir() and any(item.is_file() for item in public.rglob("*")):
        _require(
            texts["infra/docker/console.Dockerfile"],
            "/app/apps/console/public",
            "infra/docker/console.Dockerfile",
            errors,
        )

    if errors:
        raise MarketingCompatibilityConfigError("\n".join(errors))


def _read(path: Path, label: str, errors: list[str]) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{label} could not be read: {exc}")
        return ""


def _parse_json_object(corpus: str, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(corpus)
    except json.JSONDecodeError as exc:
        errors.append(f"{label} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must contain a JSON object")
        return {}
    return value


def _validate_playwright_matrix(corpus: str, errors: list[str]) -> None:
    label = "apps/console/playwright.marketing.config.ts"
    browser_match = re.search(r"const browsers = \[(.*?)\] as const;", corpus, re.DOTALL)
    browsers = (
        tuple(re.findall(r'"([^"\\]+)"', browser_match.group(1)))
        if browser_match is not None
        else ()
    )
    if browsers != ("chromium", "firefox", "webkit"):
        errors.append(f"{label} must define exactly chromium, firefox, and webkit")

    viewports = tuple(
        (name, int(width), int(height))
        for name, width, height in re.findall(
            r'\{ name: "([^"]+)", width: (\d+), height: (\d+) \}', corpus
        )
    )
    expected = (
        ("mobile-320", 320, 800),
        ("tablet-768", 768, 1024),
        ("desktop-1440", 1440, 1000),
    )
    if viewports != expected:
        errors.append(f"{label} must define exactly the 320, 768, and 1440 viewports")


def _validate_browserstack_ci_isolation(corpus: str, errors: list[str]) -> None:
    label = ".github/workflows/ci.yml"
    typescript_marker = "\n  typescript:"
    browserstack_marker = "\n  browserstack-marketing:"
    if typescript_marker not in corpus or browserstack_marker not in corpus:
        errors.append(f"{label} must define separate typescript and browserstack-marketing jobs")
        return
    typescript_job, browserstack_job = corpus.split(browserstack_marker, maxsplit=1)
    typescript_job = typescript_job.split(typescript_marker, maxsplit=1)[1]
    if "test:browserstack:marketing" in typescript_job:
        errors.append(f"{label} must not expose BrowserStack credentials in the PR job")
    for marker in (
        "if: github.event_name == 'push'",
        "needs: typescript",
        "test:browserstack:marketing",
        "BROWSERSTACK_USERNAME: ${{ secrets.BROWSERSTACK_USERNAME }}",
        "BROWSERSTACK_ACCESS_KEY: ${{ secrets.BROWSERSTACK_ACCESS_KEY }}",
        "BROWSERSTACK_BASE_URL: ${{ secrets.BROWSERSTACK_BASE_URL }}",
        "HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED: ${{ vars.HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED || 'false' }}",
        "BROWSERSTACK_WEBHOOK_STUB: ${{ vars.BROWSERSTACK_WEBHOOK_STUB || 'false' }}",
    ):
        _require(browserstack_job, marker, label, errors)
    for forbidden in ("BROWSERSTACK_LOCAL:", "BROWSERSTACK_LOCAL_IDENTIFIER:"):
        if forbidden in browserstack_job:
            errors.append(f"{label} push job must use an HTTPS staging URL, not BrowserStack Local")


def _require(corpus: str, marker: str, label: str, errors: list[str]) -> None:
    if marker not in corpus:
        errors.append(f"{label} missing `{marker}`")


def main() -> None:
    validate()
    print(
        "Validated disabled-by-default marketing infrastructure, web matrix, and BrowserStack wiring."
    )


if __name__ == "__main__":
    main()
