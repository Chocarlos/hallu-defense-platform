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
origin, and at least one named host peer in each of
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
