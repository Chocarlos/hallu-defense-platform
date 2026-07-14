# Marketing, demo intake, and web compatibility

The bilingual landing (`/`, `/en`) and privacy notices (`/privacy`,
`/en/privacy`) are public. The authenticated operational surface remains under
`/console`. Public rendering must not depend on OIDC or the authenticated API.

## Safe default and activation

`HALLU_DEFENSE_DEMO_REQUESTS_ENABLED=false` is the committed default in local,
Compose production, Helm, and browser tests. Disabled intake is a valid localized
state; it is not evidence that CRM delivery works.

Production activation requires all of the following before changing the flag:

1. legal approval of `privacy.v1`, Hallu Defense's controller identity, and the
   published `HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL`;
2. an exact public HTTPS origin and ingress/DNS configuration;
3. an exact HTTPS webhook origin and URL with redirects disabled by the runtime;
4. a file-backed HMAC secret of at least 32 bytes;
5. a `rediss://` URL, a trusted Redis CA file, and atomic rate-limit/idempotency
   behavior verified against the target service;
6. a file-backed Console metrics bearer of 32–256 bytes;
7. an isolated CRM/webhook stub proving signature bytes, timeout, error handling,
   idempotency, and absence of PII from logs, metrics, traces, and errors; and
8. an operator-confirmed CRM rule that deletes inactive leads after 90 days.

The file pointers consumed by the Next runtime are:

- `HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE`
- `HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE`
- `HALLU_DEFENSE_DEMO_REDIS_URL_FILE`
- `HALLU_DEFENSE_DEMO_REDIS_CA_PATH`
- `HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE`

Compose mounts five read-only secrets. Their `/dev/null` defaults intentionally
permit a disabled production landing; enabling intake without real content makes
runtime validation fail closed. Helm mounts a distinct, precreated
`secrets.demo.name` Secret only when `demoRequests.enabled=true`. Helm never
renders secret values into release history.

## Egress

The webhook allowlist is an exact HTTPS origin enforced by the runtime. Kubernetes
NetworkPolicy additionally requires explicit `/32` or `/128` peers under
`networkPolicy.console.demoWebhook` and `networkPolicy.console.demoRedis` before
enabled intake can render. Because standard NetworkPolicy cannot bind an FQDN to
an IP, operators should use stable egress-gateway addresses and verify that those
addresses resolve only to the approved webhook and Redis destinations. Compose
deployments require an equivalent host/firewall egress policy; Compose syntax by
itself is not an egress firewall.

## Browser gates

Marketing Playwright is separate from the Docker-backed operational Console E2E:

```text
make marketing-e2e-list
make marketing-e2e
make browserstack-marketing-config
make browserstack-marketing
```

The local marketing matrix collects Chromium, Firefox, and WebKit at 320, 768,
and 1440 px and includes axe, public routes, language, privacy noindex, keyboard
tour interaction, reduced motion, synthetic 200% zoom, overflow, disabled form,
and `/console` routing. Axe complements rather than replaces manual keyboard,
focus, contrast, zoom, motion, and screen-reader review.

The BrowserStack command is intentionally skip-safe when credentials are absent
and then makes no compatibility claim. With credentials it first queries the
account's real Automate catalog, refuses to silently omit Chrome 111, Edge 111,
Firefox 111, Safari 16.4, or iOS Safari 16.4, uses Playwright for current desktop
candidates, and Selenium for exact minimum-version smoke. Configure either an
externally managed BrowserStack Local tunnel and identifier or an isolated HTTPS
staging URL. Test contact data uses `browserstack-smoke@example.invalid`; enabled
form testing additionally requires `BROWSERSTACK_WEBHOOK_STUB=true` and an
isolated webhook stub. Store BrowserStack credentials only in CI secrets.

Record browser, version, OS, device, result, and remote session evidence in the
release record. Do not convert static configuration, local WebKit, or a newer
browser result into a claim about an unexecuted minimum version.
