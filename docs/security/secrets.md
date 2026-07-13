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

## Local Vault

Docker Compose includes a local-only Vault 2.0.3 dev server rebuilt reproducibly
with Go 1.26.5 from the exact upstream commit. The original upstream image remains pinned
as a filesystem/config source, while the active binary and UI are rebuilt and scanned.
The local endpoint is `http://localhost:8200`. It is not a production Vault deployment: storage is
ephemeral, the dev root token is local-only, and it exists to exercise the same
KV v2 client path used by `services/secrets.py`.

Use `scripts/dev/bootstrap_local_vault.py` to seed the local KV v2 mount with:

- `observability/metrics-scrape-token`
- `auth/trusted-header-signing-key`
- `backup/encryption-key`
- `providers/openai/api-key`

The bootstrap script refuses non-loopback Vault addresses by default and prints
only the seeded secret names. The `auth/trusted-header-signing-key` secret is
already consumed by signed-header auth. The metrics scrape token is consumed by
authenticated `/metrics` scraping. The `backup/encryption-key` secret is consumed
by `scripts/dev/backup_restore_drill.py` for Fernet encryption of PostgreSQL
backup drills. `providers/openai/api-key` is consumed by the OpenAI-compatible
provider adapter; its local value is a deterministic fixture, never a production
credential.

`scripts/dev/live_vault_secrets_smoke.py` is skip-by-default. Set
`HALLU_DEFENSE_LIVE_VAULT_SECRETS_SMOKE_ENABLED=true` after starting `vault` and
running the bootstrap script to verify all four secrets through
`VaultSecretManager` / `create_secret_manager`.

## Provider Connectivity Smoke

`scripts/dev/live_provider_vault_smoke.py` turns the local manual
Vault -> OpenAI-compatible -> Ollama check into a repeatable, opt-in smoke. It
loads `providers/openai/api-key` through `create_secret_manager`, supplies that
credential only to the OpenAI-compatible adapter, and then exercises the direct
Ollama chat adapter with the same configured model.

Start and bootstrap local Vault, start an Ollama-compatible server, configure an
installed model in `HALLU_DEFENSE_LIVE_PROVIDER_MODEL`, then run:

```text
HALLU_DEFENSE_LIVE_PROVIDER_VAULT_SMOKE_ENABLED=true \
  make provider-vault-live-smoke
```

The smoke defaults to loopback Vault and provider endpoints. Non-loopback
execution requires `HALLU_DEFENSE_LIVE_PROVIDER_ALLOW_NONLOCAL=true` and HTTPS
for every remote endpoint. Enabled runs fail closed on missing model, missing
credential, invalid transport, malformed response, or empty completion.

Output is redacted by construction: it reports check names, provider adapter
names, and logical secret names, but never emits the Vault token, provider
credential, prompt, provider response, response metadata, endpoint, or model.
Unexpected exceptions are also mapped to a generic redacted error.

Both the provider HTTP transport and Vault HTTP reader cap response bodies at
1 MiB by reading at most one byte beyond the limit. Oversized bodies fail with
typed `ProviderResponseTooLargeError` or `SecretResponseTooLargeError` errors;
invalid UTF-8/JSON is likewise mapped to the typed provider/secret error family.

## Validation

`infra/security/secrets-policy.json` declares the required production backend and runtime
controls. `scripts/ci/check_secrets_config.py` validates the policy, `.env.example`,
local Vault Compose wiring, the bootstrap/smoke scripts, `SECURITY.md`, and this
document. The gate also requires the `provider-vault-live-smoke` Make target,
its opt-in configuration, redaction controls, both provider adapters, and the
bounded-response documentation above.
