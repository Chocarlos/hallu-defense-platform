# Provider Adapters

The API must not call external model providers directly from business logic. Provider access
goes through `ModelProvider` adapters in `hallu_defense.services.providers`.

Supported backends:

- `mock`: deterministic local/test backend. It is rejected in production-like environments.
- `openai-compatible`: calls `/chat/completions` on a configurable OpenAI-compatible base URL.
- `ollama`: calls local Ollama `/api/chat`.

Configuration:

- `HALLU_DEFENSE_PROVIDER_BACKEND`
- `HALLU_DEFENSE_PROVIDER_MODEL`
- `HALLU_DEFENSE_PROVIDER_TIMEOUT_SECONDS`
- `HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL`
- `HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME`
- `HALLU_DEFENSE_OLLAMA_BASE_URL`
- `HALLU_DEFENSE_MOCK_PROVIDER_RESPONSE`

The OpenAI-compatible adapter obtains its credential through `SecretManager` using the
configured logical secret name. The raw credential must not appear in source, docs, audit
events, telemetry attributes, or provider response metadata.

Tests use an injected JSON transport so CI proves payload shape, header construction,
timeout behavior, and parser behavior without network access or real provider credentials.

## Provider-Backed NLI

`HALLU_DEFENSE_PROVIDER_NLI_ENABLED` enables a strict JSON NLI adjudicator for document
and web evidence only. It is disabled by default. When enabled, it can only adjudicate
claims that already have evidence items with stable IDs, and it must return one of:

- `supported`
- `contradicted`
- `insufficient_evidence`

The verifier rejects malformed provider output, unknown evidence IDs, and support claims
without cited evidence. Provider NLI is not used for repository, test/build, tool-output,
policy, or sandbox claims, which continue to require deterministic evidence.
