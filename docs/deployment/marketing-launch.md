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
   published `HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL` (a valid address of at most
   254 characters);
2. an exact public HTTPS origin and ingress/DNS configuration;
3. an exact HTTPS webhook origin and URL with redirects disabled by the runtime;
4. a file-backed HMAC secret of at least 32 bytes;
5. a `rediss://` URL, a trusted Redis CA file, and atomic rate-limit/idempotency
   behavior verified against the target service;
6. a file-backed Console metrics bearer containing 32–256 printable ASCII
   characters of high-entropy material;
7. an isolated CRM/webhook stub proving signature bytes, timeout, error handling,
   idempotency, and absence of PII from logs, metrics, traces, and errors;
8. a CRM consumer that treats the `Idempotency-Key` header as a create-once
   boundary and returns success for an already accepted key; and
9. an operator-confirmed CRM rule that deletes inactive leads after 90 days.

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

## Public wire contract V1

The canonical source is
`apps/console/lib/demo-request/public-contract.ts`. The form builder, request
parser and response helpers import these V1 types; extra request fields are
rejected. Requests use `Content-Type: application/json`, are limited to 8 KiB,
and have this exact shape:

```json
{
  "submission_id": "123e4567-e89b-42d3-a456-426614174000",
  "locale": "es",
  "email": "person@example.invalid",
  "name": "Optional name",
  "company": "Optional company",
  "use_case": "rag_verification",
  "consent": true,
  "privacy_version": "privacy.v1",
  "website": ""
}
```

`submission_id` is a UUIDv4. `locale` is `es` or `en`; `use_case` is one of
`rag_verification`, `high_risk_tools`, `code_agents`, or
`enterprise_governance`. `name` and `company` are the only optional fields.
`website` is a required wire field and must be empty for a human submission; it
is the honeypot and is never forwarded to the CRM.

Acceptance is exactly HTTP 202 with a no-store JSON body:

```json
{"request_id":"dr_0123456789abcdefghijklmn"}
```

The identifier is `dr_` plus 24 URL-safe characters and is derived without
reflecting the email or submission ID. Public failures use only HTTP 400, 415,
422, 429, or 503 with `{"error":"<generic message>"}`; 429 may include a
numeric `Retry-After`. Responses never return raw form fields, payload hashes,
Redis keys, webhook details, or internal exceptions.

Before client hydration the server-rendered form is intentionally inert: it has
no action or method, the email control has no submission name, and both the
input and button are disabled with an accessible status message. This prevents
native Enter/click submission from transmitting PII before the consent step
when JavaScript is unavailable. The launch gate inspects URL, request headers,
and body for this boundary in both languages.

After origin/Fetch Metadata validation, every request consumes the Redis global
budget before its body is parsed: 60 requests per minute. Valid parsed requests
also consume an email-scoped budget of 3 per hour and a payload-bound,
submission-scoped idempotency record for 24 hours. Redis server time prevents
application-clock skew, and every Lua key shares the
`hallu-defense:{demo-request-v1}` Cluster hash tag.

Production additionally fixes `HALLU_DEFENSE_DEMO_REDIS_MODE=cluster`; the
runtime refuses standalone mode there and accepts only database 0 because Redis
Cluster does not support selecting another logical database. The Node client
uses cluster discovery and bounded `MOVED`/`ASK` redirection. Local browser and
scratch integration may select `standalone` explicitly.

Immediately before webhook delivery, the record enters `dispatching` for 24
hours. A lost final Redis acknowledgement therefore cannot cause local
redelivery after a successful webhook; explicit webhook failures release the
record for retry. The deliberate tradeoff is availability: a process crash
after `dispatching` but before confirmed delivery can suppress retries for the
TTL. Production must alert on this state and the CRM must honor
`Idempotency-Key`. Honeypot requests consume the same local boundaries and
public minimum response floor but never call the external webhook, so no claim
is made that they reproduce a real webhook outage exactly.

Each retry suppressed by this ambiguous state increments
`hallu_demo_dispatching_guard_total`. Import
`infra/prometheus/demo-request-alerts.yml` into the production Prometheus rule
loader and route `HalluDefenseDemoDispatchingGuardObserved` to the demo-intake
operator. The alert deliberately instructs operators to inspect CRM and Redis
before replaying, so recovery cannot manufacture a duplicate lead.

## Current local evidence

At historical code candidate `d6c15bda15dda7a5e901f913d1007fd04d3089c5`, a scratch-only
integration used WSL Redis 7.0.15 plus a loopback HTTPS webhook with a
self-signed CA trusted only by the test. It verified 202 acceptance, 503 pending
and Redis-down behavior, 422 payload conflict, email and global 429 boundaries,
approximately 24-hour idempotency TTL, exact-byte HMAC, concurrent/duplicate
suppression, protected metrics, and no PII in metrics. Five expected unique
webhook deliveries occurred. The measured public response floor was 308 ms for
a real request and 331 ms for the honeypot; scratch state was removed on exit.

The 2026-07-20/21 campaign based on
`98a6bd135e075ed5db48af28fe2b6d6fc01e3fda` additionally exercised the actual
`createCluster` adapter against six isolated Redis 7 nodes (three masters and
three replicas). A root node that did not own the demo hash slot produced a
real `MOVED`; the adapter then completed reserve, delivery CAS, finalization and
duplicate readback. After the owning master was stopped, the Cluster recovered
and the same operations passed through a surviving root. The exact six
containers, network and generated bundle were removed. This smoke used plain
Redis on an isolated Docker network, so production `rediss://` CA and hostname
verification remains a deployment gate.

This is deterministic local integration evidence, not proof of a production
Redis Cluster, CRM, ingress, egress policy, retention job, or legal approval.
Those checks must be repeated against the exact staging and production
configuration before activation.

## Egress

The webhook allowlist is an exact HTTPS origin enforced by the runtime. Kubernetes
NetworkPolicy additionally requires explicit `/32` or `/128` peers under
`networkPolicy.console.demoWebhook` and `networkPolicy.console.demoRedis` before
enabled intake can render. Because standard NetworkPolicy cannot bind an FQDN to
an IP, operators should use stable egress-gateway addresses and verify that those
addresses resolve only to the approved webhook and Redis destinations. Compose
deployments require an equivalent host/firewall egress policy; Compose syntax by
itself is not an egress firewall.

Standard Kubernetes NetworkPolicy is an L3/L4 control, not an origin or DNS
allowlist. A shared destination IP can still serve another origin, and permitted
DNS can carry traffic that an IP/port policy does not classify. The runtime's
exact-origin and no-redirect checks protect the intended request path, but do not
contain arbitrary code execution. Production should route demo traffic through
an isolated L7 egress gateway, or use a CNI with audited FQDN/DNS policy, and
retain the exact host-CIDR rules as defense in depth.

## Production activation runbook

Use a dedicated staging release and an isolated CRM/webhook stub first. Stop if
legal approval, the retention rule, an exact destination inventory, secret-file
metadata, or deterministic validation evidence is missing. Never promote a
disabled render or a static config check as proof that CRM delivery works.

### Compose on Linux

The `/dev/null` fallbacks exist only so the disabled landing can start. Before
enabling intake, provision exactly five regular non-symlink files in a versioned,
root-owned directory:

- `webhook-url`: the complete HTTPS URL whose origin exactly matches
  `HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN`;
- `webhook-hmac-secret`: at least 32 bytes of generated key material;
- `redis-url`: a `rediss://` URL with the exact production host and port;
- `redis-ca.pem`: the CA chain that authenticates that Redis endpoint; and
- `metrics-bearer`: 32–256 printable ASCII characters of generated,
  high-entropy bearer material suitable for an HTTP `Bearer` header.

The parent directory must be `root:root/0750`; every file must be
`root:10001/0440`. Compose file-backed secrets retain host metadata, so the
production Console receives supplemental group `10001`. Do not print, hash into
logs, or pass secret values on a command line. On the deployment host, adapt the
following metadata-only check to the versioned directory:

```sh
secret_dir=/run/hallu-defense-secrets/demo-v42
test "$(stat -Lc '%u:%g %a' -- "$secret_dir")" = "0:0 750"
for name in webhook-url webhook-hmac-secret redis-url redis-ca.pem metrics-bearer; do
  path="$secret_dir/$name"
  test -f "$path" && test ! -L "$path"
  test "$(stat -Lc '%u:%g %a' -- "$path")" = "0:10001 440"
done
```

The runtime POSIX reader accepts regular files with mode `0400`, `0440`, `0600`,
or `0640`, but this root-owned Compose layout deliberately selects `0440` so the
non-root process can read through group `10001`. Generate the metrics bearer
directly into its file without printing it, then reapply the required metadata
and perform a silent shape check:

```sh
umask 027
openssl rand -base64 48 | tr -d '\r\n' > "$secret_dir/metrics-bearer"
chown 0:10001 "$secret_dir/metrics-bearer"
chmod 0440 "$secret_dir/metrics-bearer"
LC_ALL=C grep -Eq '^[!-~]{32,256}$' "$secret_dir/metrics-bearer"
```

The managed Prometheus deployment must mount the exact same Console bearer
bytes at `/run/secrets/hallu_console_metrics_bearer` for its dedicated
`hallu-defense-console` scrape job. This is separate from the API metrics
bearer and must not be substituted with it. In Kubernetes, allow the scraper
explicitly through `networkPolicy.ingress.console.metricsScrapers`; in Compose,
the production overlay intentionally does not start Prometheus, so provisioning
and rotation remain an operator-owned control.
The committed local Prometheus profile deliberately does not load this alert:
local demo intake and Console metrics are disabled, so loading a rule with no
possible source series would create false confidence. The production file
loads the rule and defines the authenticated Console scrape together.

Map the five `*_HOST_PATH` variables to those files. Configure a host firewall
or an audited egress proxy for only the exact `/32` or `/128` webhook and Redis
destinations and their exact URL ports, plus the separately approved OIDC and
DNS paths. Compose does not implement an egress firewall; activation is blocked
until that external control has evidence.

Run the static gates before changing the flag:

```text
python scripts/ci/check_prod_profile_config.py
python scripts/ci/check_helm_chart.py
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
```

Then set the privacy contact, exact webhook origin, five host paths, and
`HALLU_DEFENSE_DEMO_REQUESTS_ENABLED=true`. Recreate the process because the
flag, webhook, Redis TLS configuration, and secret-file paths are cached at
runtime:

```text
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate console
```

Wait for the Compose healthcheck; `/console` must return exactly HTTP 200 without
a redirect. Against the isolated stub, verify Redis TLS/CA validation, signature
bytes, rate limiting, idempotent replay, timeout behavior, localized privacy
copy, and the absence of lead data in logs, metrics, traces, and errors. Only then
may the same versioned configuration be promoted.

### Helm

Create a versioned Secret outside Helm with exactly these data keys:
`webhook-url`, `webhook-hmac-secret`, `redis-url`, `redis-ca.pem`, and
`metrics-bearer`. Supply only its name through `secrets.demo.name`; never place
secret values in a values file, `--set`, a rendered manifest, or release history.
Confirm the external controller's metadata and key inventory without emitting
data. The runtime remains the authoritative content check and fails closed if the
URL, HMAC, `rediss://` URL, CA, or bearer is invalid.

Set `demoRequests.enabled=true`, the approved privacy contact and exact webhook
origin, keep `demoRequests.redisMode=cluster`, and configure at least one named
host peer in each of
`networkPolicy.console.demoWebhook` and `networkPolicy.console.demoRedis`. Every
peer must use the exact `/32` or `/128` destination and the port encoded by its
corresponding URL. Render and inspect both disabled and enabled profiles, then use
an atomic, waited upgrade. The Console deployment uses strategy `Recreate` to
avoid simultaneous revisions with different process-local state or secret
inodes; plan for a short Console interruption because it deliberately provides
no overlap.

After rollout, require both probes on `/console`, an exact HTTP 200 response, one
Console Pod, five `0440` Secret projections, and only the approved webhook and
Redis egress destinations. Preserve sanitized render, policy, stub, and health
evidence in the release record.

Kubernetes projects those five files with `defaultMode: 0440`; the Console Pod's
`runAsUser`, `runAsGroup`, and `fsGroup` are all `10001`, which is compatible with
the runtime reader's permitted `0400`/`0440`/`0600`/`0640` set without granting
world access.

## Abort criteria and rollback

Abort immediately on a redirect or non-200 `/console`, secret validation error,
Redis certificate/hostname failure, unexpected egress, signature mismatch,
duplicate CRM delivery, PII telemetry, or inability to prove the 90-day deletion
rule. For active exfiltration or credential compromise, first block demo egress
and revoke the webhook/HMAC, Redis credentials, and metrics bearer at their
services; otherwise begin by disabling intake.

For Compose, set `HALLU_DEFENSE_DEMO_REQUESTS_ENABLED=false` and run the same
`up -d --force-recreate console` command. Verify `/console` is exactly HTTP 200,
the public form is localized and disabled, POST intake fails closed, and no
further webhook or Redis connection occurs. Remove the demo-specific firewall
rules only after the recreated Console is healthy. Rotate all five files into a
new versioned directory, revoke the old remote credentials, and delete old files
only after no container references them.

For Helm, prefer a corrective atomic upgrade to a known disabled values set. An
external Secret is not versioned by Helm, so `helm rollback` alone cannot restore
or prove its content and an old revision could re-enable intake. Before using a
historical revision, inspect its values and rendered policy, bind it to an
explicit versioned Secret, and prove the resulting flag remains false. Database
migrations are forward-only; do not roll schema state backward as part of this
marketing rollback. Wait for the `Recreate` rollout, verify both `/console`
probes and disabled intake, then remove demo egress and retire the old Secret
after no Pod references it.

Finally, reconcile any leads already delivered to the CRM under the approved
retention/deletion procedure, preserve sanitized incident evidence, record the
credential rotations and remote revocations, and require a fresh activation
review before re-enabling intake.

## Browser gates

Marketing Playwright is separate from the Docker-backed operational Console E2E:

```text
make marketing-e2e-list
make marketing-e2e
make browserstack-marketing-config
make browserstack-marketing
```

The production phase serves the copied `.next/standalone` artifact and runs
Chromium, Firefox, and WebKit at 320, 768, and 1440 px. It covers CSP nonces,
axe WCAG 2.2 AA baseline, public routes/language/privacy, keyboard tour, reduced
motion, progressive enhancement, overflow, disabled intake, `/console`
routing, and desktop-Chromium synthetic LCP/interaction/CLS budgets. A separate
hydrated-form phase covers both languages, two-step keyboard/focus/consent/202,
422/503 retries with one submission ID, malformed 202 responses, no-JavaScript
PII boundaries, and the DOM-newer-than-React-state regression.

In the 2026-07-20/21 campaign, production ran 216 cases: 148 passed, 68
deliberate project-scope skips, 0 failed. The expanded form/Axe phase ran 117:
77 passed, 40 deliberate skips, 0 failed. It covers the initial enabled form,
step two and native-invalid state in both languages across the full
browser/viewport matrix. Its first run found eight contrast failures while a
reveal animation reduced effective FAQ text contrast; opacity was fixed and the
complete phase reran green. The skips keep single-engine or desktop-only labs from being
misrepresented as cross-matrix execution; they are not failures. The automated
"200%" check is explicitly Chromium `deviceScaleFactor: 2` equivalence at a
720 CSS-pixel viewport, not browser UI zoom. Native 200% zoom and manual focus,
contrast, motion, and screen-reader review remain release checks. Axe and
synthetic lab budgets complement rather than replace them or field Core Web
Vitals.

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
