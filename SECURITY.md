# Security Policy

## Security Defaults

The platform is designed for strict enterprise defaults:

- Tenant-aware request context on every API call.
- In-process OIDC JWT/JWKS authentication path documented in
  `docs/security/auth-rbac.md`, with trusted gateway signed headers available
  for deployments that terminate OIDC before the API.
- RBAC/ABAC-ready authorization policy layer; `docs/security/auth-rbac.md` defines
  the current endpoint-to-role matrix.
- High-risk tool calls require human approval.
- Sandbox network access is denied by default.
- Repository paths are scoped to the configured workspace.
- Tool outputs are scanned for secret-like keys and common PII patterns
  (email addresses, US-style SSNs, and conservative phone formats) and sanitized.
- Audit events and verification runs carry trace identifiers.
- Audit persistence is documented in `docs/security/audit-ledger.md`; production and staging
  must use a persistent backend.
- Approval queue persistence is documented in `docs/security/approvals.md`; production and staging
  must use a persistent backend.
- Auth/RBAC production defaults are versioned in `infra/security/auth-policy.json` and
  checked in CI.
- Encryption policy is versioned in `infra/security/encryption-policy.json` and checked in CI.
- Vault-compatible secret manager configuration is versioned in `infra/security/secrets-policy.json`
  and checked in CI.
- Backup/restore and retention policy is versioned in
  `infra/security/backup-retention-policy.json` and checked in CI.
- Python dependencies are audited with `pip-audit`; Node dependencies are audited with `npm audit`.
- API and console container images are built and scanned with Trivy in the security workflow.
- External providers must be accessed through provider adapters; OpenAI-compatible credentials
  must be resolved through `SecretManager`.

## Sensitive Data Handling

- Do not commit secrets, access tokens, credentials, private keys, or production data.
- Do not log raw secrets or sensitive tenant payloads.
- Prefer metadata, hashes, redacted samples, and source references in logs.
- Use `.env.example` for configuration shape only.
- Production deployments must use the Vault-compatible secret manager backend documented in
  `docs/security/secrets.md`.
- Production deployments must satisfy `docs/security/encryption.md` for in-transit and at-rest encryption.

## Supported Versions

Hallu Defense Platform has not published a stable release. Security evidence applies only to the exact commits and workflow runs identified in the repository's QA and release records. Do not extrapolate historical acceptance to a later commit or an unverified deployment.

## Reporting a Vulnerability

Do not report vulnerabilities through a public issue, pull request, discussion, commit message, or public log.

1. Open the repository's **Security** page. When **Report a vulnerability** is available, use that private GitHub form.
2. If private vulnerability reporting is not yet available, contact the repository owner, `@Chocarlos`, through an available private out-of-band channel.
3. If no private contact channel is available, open a neutral public issue asking the owner to establish private contact. Do not include the affected component, exploit details, proof of concept, secrets, private logs, tenant data, or other vulnerability information in that issue.

A useful private report includes the affected commit or release, impact, prerequisites, a minimal safe reproduction, expected and observed behavior, and any suggested mitigation. Redact all credentials and real tenant data.

Repository administrators should enable GitHub private vulnerability reporting before broad promotion. The presence of this policy file alone does not prove that the private reporting feature is enabled.

## Coordinated Handling

Security reports should remain private while they are triaged and remediated. Public disclosure, release notes, CVE requests, and acknowledgements must be coordinated with the reporter and must not expose secrets, tenant data, or operational details that create avoidable risk.

## Current Security Gaps

These are tracked in `docs/TRACEABILITY_MATRIX.md` and must not be represented as complete:

- The live workflow proves the local realm through real Keycloak OIDC discovery/
  JWKS service and a separately deployed Uvicorn API. It checks unauthenticated
  rejection, reviewer authorization, least-privilege denial, JWT/header tenant
  mismatch rejection, and JWT-tenant audit propagation across actual HTTP.
- External identity-provider smoke remains opt-in through
  `scripts/ci/oidc_provider_smoke.py`; it covers direct JWKS URL, discovery, and
  refresh on unknown `kid` only when a provider URL and short-lived test JWT are
  supplied. The local Keycloak/Uvicorn result is not evidence for an external
  deployment.
- Tenant identity is JWT-derived in `oidc_jwt` mode; local and trusted-gateway
  modes still rely on boundary headers.
- Managed-scale performance, failover, and restore evidence for the implemented
  tenant-aware PostgreSQL, pgvector, and OpenSearch persistence layers.
- Runtime Vault connectivity tests against deployed infrastructure.
- Remote evidence for the CI-pinned OPA version and deployment-specific policy
  bundles; the repository's Python policy tests and executable Rego suite are active.
- Broader PII detection beyond deterministic common patterns, including non-US
  identifiers and domain-specific sensitive payloads.
- Runtime proof that Docker/Kubernetes services are using TLS and encrypted volumes.
- Runtime connectivity tests for configured model providers.
- Runtime backup job execution and restore drill artifacts for deployed infrastructure.
