from __future__ import annotations

from pathlib import Path


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
        "demoWebhook: []",
        "demoRedis: []",
        "secrets.demo.name",
        "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
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

    package = texts["apps/console/package.json"]
    for marker in (
        '"test:e2e:marketing:list"',
        '"test:e2e:marketing"',
        '"test:browserstack:config"',
        '"test:browserstack:marketing"',
    ):
        _require(package, marker, "apps/console/package.json", errors)
    playwright = texts["apps/console/playwright.marketing.config.ts"]
    for marker in (
        '"chromium", "firefox", "webkit"',
        'name: "mobile-320", width: 320',
        'name: "tablet-768", width: 768',
        'name: "desktop-1440", width: 1440',
        'testDir: "./e2e-marketing"',
        'HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"',
    ):
        _require(playwright, marker, "apps/console/playwright.marketing.config.ts", errors)
    marketing_spec = texts["apps/console/e2e-marketing/marketing.spec.ts"]
    for marker in (
        'privacyPath: "/privacy"',
        'privacyPath: "/en/privacy"',
        'page.goto("/console")',
        "reducedMotion: \"reduce\"",
        "synthetic 200% zoom",
        "assertNoHorizontalOverflow",
        'getByRole("tab")',
    ):
        _require(marketing_spec, marker, "apps/console/e2e-marketing/marketing.spec.ts", errors)
    _require(
        texts["apps/console/e2e-marketing/accessibility.spec.ts"],
        "AxeBuilder",
        "apps/console/e2e-marketing/accessibility.spec.ts",
        errors,
    )

    browserstack = texts["apps/console/scripts/run-browserstack-marketing.mjs"]
    for marker in (
        "automate/browsers.json",
        "browserstack-smoke@example.invalid",
        "chrome-111",
        "edge-111",
        "firefox-111",
        "safari-16.4",
        "ios-safari-16.4",
        "runPlaywrightSmoke",
        "runSeleniumSmoke",
        "No compatibility result is claimed",
        "BROWSERSTACK_WEBHOOK_STUB",
    ):
        _require(browserstack, marker, "apps/console/scripts/run-browserstack-marketing.mjs", errors)

    makefile = texts["Makefile"]
    for marker in (
        "marketing-config:",
        "marketing-e2e:",
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
    _require(
        texts[".github/workflows/security.yml"],
        "check_marketing_compatibility_config.py",
        ".github/workflows/security.yml",
        errors,
    )
    for marker in (
        "90 days",
        "legal approval",
        "BrowserStack",
        "no compatibility claim",
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
