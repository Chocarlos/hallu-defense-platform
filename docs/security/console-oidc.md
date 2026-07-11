# Console OIDC and Runtime Configuration

The Console uses OIDC Authorization Code with PKCE S256. The running Next server
reads its configuration for every dynamic request; no Console URL or identity
setting uses `NEXT_PUBLIC_*` or is embedded by `next build`.

## Production contract

These variables are required in `oidc` mode:

| Variable | Contract |
| --- | --- |
| `HALLU_DEFENSE_ENV` | `production` or `staging` for a production-like deployment |
| `HALLU_DEFENSE_CONSOLE_AUTH_MODE` | `oidc` |
| `HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN` | Exact canonical HTTPS origin of the Console; no path, credentials, query, or fragment |
| `HALLU_DEFENSE_CONSOLE_API_ORIGIN` | Exact canonical HTTPS origin of the browser-facing API |
| `HALLU_DEFENSE_CONSOLE_OIDC_ISSUER` | Exact canonical HTTPS realm issuer; a realm path is expected, with no trailing slash, credentials, query, fragment, or percent encoding |
| `HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID` | Public client identifier, normally `hallu-defense-console` |
| `HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE` | Required access-token audience, normally `hallu-defense-api` |
| `HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES` | Unique comma-separated roles required before a Console session is created |

The production Compose profile fixes the tenant and roles claims to `tenant_id`
and `roles`. The optional tuning variables and defaults are:

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

Production and staging reject HTTP, unsigned identity, and all local fixture
flags. For an explicit loopback-only fixture, set both
`HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP=true` and, when using local
headers instead of OIDC, `HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL=true`.
Unsigned mode additionally requires `HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID`,
`HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID`, and
`HALLU_DEFENSE_CONSOLE_LOCAL_ROLES`.

## Authentication boundary

`/auth/login` creates random state, nonce, and verifier values with a five-minute
maximum lifetime. Only the opaque state is placed in a `SameSite=Lax`,
`HttpOnly` cookie; the verifier and nonce stay in a bounded process-memory
transaction. The callback consumes state once, requires the authorization
response issuer, exchanges the code without a client secret, and validates the
ID and access-token RS256 signatures against discovery JWKS.

Discovery and JWKS documents use separate bounded process caches. Concurrent
misses share one in-flight request, successful values have explicit TTLs, and a
failed provider read starts a cooldown during which requests fail closed without
calling the provider again. An unknown signing key can trigger at most one
single-flight JWKS refresh per cooldown; key identifiers and upstream failure
details are never returned to the browser.

Session creation requires exact issuer, client and API audiences, nonce,
authorized party, expiry, subject, tenant, roles, and configured required roles.
The browser keeps the validated access token only in component memory and gives
it directly to the SDK. When Bearer is present, the SDK omits `x-tenant-id`,
`x-subject-id`, and `x-roles`; request payload tenant values come from the
validated token claim. No refresh token is retained. Logout, token expiry, or a
server restart ends the session. The bounded transaction and session stores
reject new entries when all slots are live; they never evict a legitimate state
or active session to admit a new one.

`/auth/login` and `/auth/callback` have independent bounded fixed-window rate
limits. By default, untrusted forwarding headers are ignored and clients are
identified by a server-issued, HMAC-authenticated, `HttpOnly` key cookie; raw IPs
and cookie values are never stored as bucket keys. Requests without a valid key
share a fail-closed anonymous bucket. Set
`HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS` above zero only when every direct
connection comes from that exact number of controlled proxies and the nearest
proxy strips or appends `X-Forwarded-For`; malformed chains share one
unattributed bucket instead of bypassing the limit. These process-local controls
complement, rather than replace, ingress/WAF rate limits for a multi-replica
deployment.

The opaque session and authentication-client cookies are `Secure` and use the
`__Host-` prefix in production-like environments. A multi-replica deployment
must provide session affinity because the deliberately minimal metadata,
rate-limit, transaction, and session stores are process-local.

Every dynamic response receives a per-request nonce CSP, `frame-ancestors
'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, a
restrictive Permissions Policy, and production HSTS. The policy allows no
third-party scripts.

## Local Keycloak fixture

`infra/security/keycloak/realm-hallu-defense.json` defines the public
`hallu-defense-console` client with exact callbacks on ports 3000 and 3100,
PKCE S256, API audience, tenant, and realm-role mappers. The local-only user is
`console-reviewer` with password `console-reviewer-local-only` and tenant
`tenant-a`. This credential is a disposable development fixture and must never
be reused or imported into production.

Run the deterministic gates with:

```text
npm --workspace @hallu-defense/console test
npm --workspace @hallu-defense/console run typecheck
npm --workspace @hallu-defense/console run build
python scripts/ci/check_local_runtime_config.py
python scripts/ci/check_prod_profile_config.py
```

With the local Keycloak and a Console process on port 3100 running in OIDC mode,
the opt-in browser proof is:

```text
HALLU_DEFENSE_LIVE_CONSOLE_OIDC_SMOKE_ENABLED=true node scripts/dev/live_console_oidc_smoke.mjs
```

The smoke uses a loopback stub API and reports only boolean outcomes; it never
prints authorization codes or tokens.
