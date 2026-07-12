# Console OIDC, session, and BFF boundary

The Console uses OIDC Authorization Code with PKCE S256 and a same-origin
backend-for-frontend (BFF). OAuth credentials remain inside the running Next
server. Browser JavaScript receives only tenant, subject, roles, expiry, and a
session-bound CSRF value; it never receives an access, ID, or refresh token.

The Next server reads runtime configuration for every dynamic request. No URL,
identity, credential, or issuer setting uses `NEXT_PUBLIC_*` or is embedded by
`next build`.

## Production configuration

| Variable | Contract |
| --- | --- |
| `HALLU_DEFENSE_ENV` | `production` or `staging` for a production-like deployment |
| `HALLU_DEFENSE_CONSOLE_AUTH_MODE` | `oidc` |
| `HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN` | Exact canonical HTTPS Console origin; no path, credentials, query, fragment, or trailing slash |
| `HALLU_DEFENSE_CONSOLE_API_ORIGIN` | Exact canonical HTTPS server-to-server API origin; this is not exposed to browser code |
| `HALLU_DEFENSE_CONSOLE_OIDC_ISSUER` | Exact canonical HTTPS realm issuer without trailing slash, credentials, query, fragment, or percent encoding |
| `HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID` | Public client identifier, normally `hallu-defense-console` |
| `HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE` | Required access-token audience, normally `hallu-defense-api` |
| `HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES` | Unique comma-separated roles required before session creation |

Optional bounded settings and defaults are:

```text
HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM=tenant_id
HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM=roles
HALLU_DEFENSE_CONSOLE_OIDC_CLOCK_SKEW_SECONDS=30
HALLU_DEFENSE_CONSOLE_OIDC_HTTP_TIMEOUT_MS=5000
HALLU_DEFENSE_CONSOLE_OIDC_DISCOVERY_CACHE_TTL_SECONDS=300
HALLU_DEFENSE_CONSOLE_OIDC_JWKS_CACHE_TTL_SECONDS=300
HALLU_DEFENSE_CONSOLE_OIDC_FAILURE_COOLDOWN_SECONDS=5
HALLU_DEFENSE_CONSOLE_OIDC_TRANSACTION_TTL_SECONDS=300
HALLU_DEFENSE_CONSOLE_SESSION_MAX_SECONDS=3600
HALLU_DEFENSE_CONSOLE_AUTH_RATE_LIMIT_WINDOW_SECONDS=60
HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX=20
HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX=30
HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS=0
```

Production and staging reject HTTP, unsigned identity, insecure-local mode, and
any request to enable the removed demo fixture. Explicit loopback tests may set
`HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP=true`. Unsigned-local mode also
requires `HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL=true` plus the local
tenant, subject, and roles variables. Even in that mode, identity is read by the
Next server and placed in an opaque server-side session; browser-provided
identity headers are ignored.

## Authorization and session lifecycle

`GET /auth/login` accepts only a top-level same-origin or user-entered browser
navigation. It creates independent 256-bit state, nonce, and verifier values,
derives an S256 challenge, and retains verifier and nonce in a bounded
server-side transaction. If an active OIDC session exists, its opaque ID is
captured in that same one-shot transaction; login does not allocate a second
session. This binding happens before provider discovery or any other await; a
failed login initiation deletes the unissued transaction. The `HttpOnly`,
`SameSite=Lax` state cookie contains only the opaque state. Cross-site
subresources cannot initiate login.

`GET /auth/callback` requires exactly one state and issuer, constant-time state
cookie equality, an unexpired one-time server transaction, the configured
authorization-response issuer, and a bounded authorization code. Invalid or
replayed state is rejected before it consumes callback quota or causes provider
traffic. The code exchange uses the exact callback and PKCE verifier without a
client secret.

Discovery must advertise code flow, PKCE S256, and an end-session endpoint. All
authorization, token, JWKS, and logout endpoints must stay below the configured
issuer path. ID and access JWTs must use RS256 and pass signature, issuer,
audience, authorized-party, time, nonce, subject, tenant, role, and cross-token
consistency checks. Discovery and JWKS reads are bounded, cached, single-flight,
and fail closed with a provider-failure cooldown.

The session cookie remains `SameSite=Strict`, so an IdP-initiated cross-site
callback is expected not to carry it. After every provider and token check
passes, the server atomically replaces the exact prior session captured by the
transaction with a random opaque session identifier and independent CSRF value.
It never infers the prior session from callback cookies. A failed callback
leaves the prior session intact; a replay cannot rotate the newly issued
session. If concurrent transactions were bound to the same prior session, the
replacement is a compare-and-swap: exactly one succeeds and every stale sibling
fails without allocating a session. Abandoned reauthentication transactions
consume transaction capacity only, not session capacity. At a full session
store, a valid rotation can replace its bound prior record without a temporary
extra slot.

The production cookie is
`__Host-hallu-console-session`, `Secure`, `HttpOnly`, `SameSite=Strict`, and
`Path=/`. `/auth/session` is `no-store`, varies on `Cookie`, and returns only
non-credential metadata. Expiry, upstream `401`, logout, or loss of the
server-side record invalidates the session.

`POST /auth/logout` requires the exact Console `Origin` and same-origin Fetch
Metadata. It deletes the local session and expires the cookie before discovering
or contacting the provider. In OIDC mode it then redirects with `303` to the
validated end-session endpoint using only `client_id` and the exact
`post_logout_redirect_uri`; no token or `id_token_hint` is placed in a browser
URL. Provider failure cannot restore the local session.

## Same-origin API BFF

Browser SDK calls target `/api/*` on the Console origin. The BFF accepts `POST`
only, rejects queries and unknown paths, and currently allowlists:

```text
/verification/run
/verification/replay
/verification/runs/list
/rag/corpus-grants/upsert
/rag/corpus-grants/list
/documents/ingest
/documents/ingest/status
/evals/reports/list
/approvals/list
/approvals/decide
/tools/validate-input
/policy/evaluate
/repo/checks/run
```

Every mutation requires the exact public `Origin`, compatible same-origin Fetch
Metadata, the opaque `HttpOnly` session cookie, and constant-time equality of
the session-bound `x-console-csrf` header. Requests must be JSON objects and are
limited to 1 MiB. Responses must be JSON and are limited to 4 MiB. Redirects are
rejected, normal requests have a 15-second timeout, and the explicitly
long-running sandbox endpoint has a 335-second ceiling.

The BFF constructs upstream headers from scratch. OIDC mode adds the retained
Bearer server-side; unsigned-local mode adds identity read from server
configuration. Browser `Authorization`, `x-tenant-id`, `x-subject-id`,
`x-roles`, cookies, and arbitrary forwarding headers never reach the API.
Upstream non-success bodies are discarded; `401`, `403`, `429`, timeout, and
`5xx` messages are status-specific but generic. An upstream `401` also deletes
the Console session. All BFF responses are `no-store`, `nosniff`, and vary on
`Cookie, Origin`; only a bounded numeric `Retry-After` may be copied.

The browser request coordinator uses per-channel epochs and `AbortController`.
Identical in-flight requests share one promise, a newer different request aborts
and supersedes the old one, and aborted results cannot overwrite current state.
Paginated runs, corpus grants, and eval reports are deduplicated by stable IDs;
the newest run/report and highest grant version win. The UI never retries `429`
automatically and never renders raw upstream error bodies.

## Deployment contracts outside this front

The API and ingress must satisfy these contracts; this Console change does not
modify the Python API, Helm, or persistent infrastructure:

- The API derives tenant, subject, and roles exclusively from a verified Bearer
  in OIDC deployments and rejects parallel or inconsistent identity headers.
- The API origin is reachable from the Console server or its service identity,
  not from arbitrary browsers. Browser CORS is unnecessary for the BFF path and
  should be disabled or restricted independently.
- The identity provider registers the exact callback and post-logout URI,
  permits public-client code flow with mandatory PKCE S256, publishes RS256
  signing keys, and exposes an issuer-bound end-session endpoint.
- A controlled ingress strips and reconstructs `X-Forwarded-For`. Set trusted
  proxy hops only to the exact controlled chain length. With the default zero,
  forged forwarding headers and all cookies are ignored and requests share a
  conservative unattributed process bucket.
- Multi-replica production requires an atomic shared transaction, session,
  provider-cache, and rate-limit store with the same TTL, one-time consume, and
  capacity semantics. The transaction-bound prior-session rotation must be one
  atomic compare-and-swap across replicas: verify the exact prior OIDC record,
  delete it, and insert one replacement without an intervening writer.
  Process-local maps are suitable only for one replica; affinity alone does not
  provide failover safety. Ingress/WAF distributed quotas must complement the
  in-process limiter.
- Logs, traces, analytics, reverse proxies, and error pages must redact
  authorization codes, state, nonce, CSRF values, cookies, and tokens.

## XSS, cache, and browser policy

React renders external strings as text; the Console uses no
`dangerouslySetInnerHTML`. Sensitive snippets are redacted before display. A
per-request nonce CSP restricts scripts and styles and sets `connect-src 'self'`,
`frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, and
`form-action 'self'`. Responses also set `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, a restrictive Permissions Policy, and
production HSTS. Auth, session, BFF, and logout responses are never cacheable.

## Reproducible gates

The production build checker scans deployable server and static artifacts and
fails on the retired `tr_demo`, `initialRun`, demo reset, demo run, or demo API
key payload markers.

```text
make console-check
make console-build-check
npm --workspace @hallu-defense/console run test:e2e-static
npm --workspace @hallu-defense/console run test:e2e:list
node scripts/dev/live_console_oidc_smoke.mjs
```

Playwright configuration requires `E2E_PYTHON_BIN` to be an existing absolute
interpreter path; it never falls back to a worktree `.venv` or a bare command.
CI uses the absolute `actions/setup-python` output. Local runs may explicitly
point at a trusted shared root venv. The API webServer sets `PYTHONPATH` to this
worktree's `apps/api/src` and runs the committed import-source preflight before
any Docker command. The committed `test:e2e:list` script collects the specs
without starting webServers, a browser, or Docker; full `test:e2e` remains a
Docker-backed live gate.

The last command safely reports a skip unless
`HALLU_DEFENSE_LIVE_CONSOLE_OIDC_SMOKE_ENABLED=true`. With the local Keycloak
and an OIDC Console on port 3100, `make console-oidc-live-smoke` proves state,
nonce, PKCE S256, opaque cookies, credential-free session JSON, same-origin
BFF/CSRF enforcement, server-only Bearer forwarding, absence of CORS, provider
logout invocation, and local invalidation. Its JSON output contains booleans
only and never prints authorization codes, CSRF values, cookies, or tokens.
