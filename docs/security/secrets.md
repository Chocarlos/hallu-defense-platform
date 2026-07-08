# Vault-Compatible Secrets

## Runtime Model

The API uses a `SecretManager` abstraction instead of reading provider credentials directly
from business logic. Local development and tests may use the `env` backend, but production
and staging must use the `vault` backend.

Supported configuration:

- `HALLU_DEFENSE_SECRETS_BACKEND`: `env` for local/test/CI, `vault` for production.
- `HALLU_DEFENSE_ENV_SECRET_PREFIX`: prefix for local-only secret variables.
- `HALLU_DEFENSE_VAULT_ADDR`: base URL for the Vault-compatible service.
- `HALLU_DEFENSE_VAULT_MOUNT`: KV v2 mount name.
- `HALLU_DEFENSE_VAULT_NAMESPACE`: optional Vault namespace.
- `HALLU_DEFENSE_VAULT_TOKEN_ENV`: name of the environment variable that carries the token.
- `HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS`: HTTP timeout for secret reads.

The raw token variable, by default `HALLU_DEFENSE_VAULT_TOKEN`, must not be committed to
`.env.example`, docs, tests, or source. The code stores a `SecretValue` wrapper whose string
and repr forms are redacted; callers must explicitly call `reveal()` at the final integration
boundary that needs the credential.

## Local Development

For local-only secrets, use names derived from the logical secret path:

```text
HALLU_DEFENSE_SECRET_PROVIDERS_OPENAI_API_KEY=<local value outside git>
```

The logical lookup name is `providers/openai/api-key`. Secret names are relative paths and
path traversal segments are rejected.

## Validation

`infra/security/secrets-policy.json` declares the required production backend and runtime
controls. `scripts/ci/check_secrets_config.py` validates the policy, `.env.example`,
`SECURITY.md`, and this document.
