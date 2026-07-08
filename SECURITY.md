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

## Reporting Issues

Until a private intake process exists, report security issues directly to the repository owner out of band. Do not open public issues containing exploit details, secrets, private logs, or tenant data.

## Current Security Gaps

These are tracked in `docs/TRACEABILITY_MATRIX.md` and must not be represented as complete:

- Deployed identity-provider smoke for the OIDC JWT/JWKS path is wired through
  `scripts/ci/oidc_provider_smoke.py`; local CI skips it unless provider URL and
  short-lived test JWT environment variables are supplied.
- Deployed identity-provider smoke tests cover direct JWKS URL, OIDC discovery,
  and refresh on unknown `kid` when the required provider environment variables
  are supplied.
- Tenant identity is JWT-derived in `oidc_jwt` mode; local and trusted-gateway
  modes still rely on boundary headers.
- Persistent tenant-aware database layer.
- Runtime Vault connectivity tests against deployed infrastructure.
- Full OPA/Rego policy test suite.
- Broader PII detection beyond deterministic common patterns, including non-US
  identifiers and domain-specific sensitive payloads.
- Runtime proof that Docker/Kubernetes services are using TLS and encrypted volumes.
- Runtime connectivity tests for configured model providers.
- Runtime backup job execution and restore drill artifacts for deployed infrastructure.
