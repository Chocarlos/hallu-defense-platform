# Hallu Defense MCP server

The MCP server is a newline-delimited JSON-RPC 2.0 stdio process. It proxies
the platform tools to the FastAPI verification plane and validates public
request and response contracts before data crosses either boundary.

## Production configuration

Production and staging are fail-closed. They require an HTTPS API origin and a
file-backed OIDC bearer token:

```text
HALLU_DEFENSE_ENV=production
HALLU_DEFENSE_API_BASE_URL=https://api.example.internal
HALLU_DEFENSE_MCP_API_TOKEN_FILE=/run/secrets/hallu-defense-mcp-token
HALLU_DEFENSE_MCP_OIDC_TENANT_CLAIM=tenant_id
HALLU_DEFENSE_MCP_REQUEST_TIMEOUT_MS=10000
HALLU_DEFENSE_MCP_MAX_INPUT_BYTES=1048576
```

The token path must be absolute, refer directly to a regular non-symlink file,
contain one UTF-8 line of at most 64 KiB, and have exact POSIX mode `0440`.
Provision it for the MCP process group; do not put the token in an environment
variable, command argument, image layer, or log. Rotate it by atomically
replacing the file with another `0440` regular file. The server reopens and
rereads the path for every tool call, so rotation does not require a restart.

With bearer authentication, the proxy sends `Authorization` and `x-trace-id`
only. It deliberately omits `x-tenant-id`, `x-subject-id`, and `x-roles`; the
API derives identity and authorization from the verified JWT. The MCP process
decodes the configured tenant claim only to reject payload tenant mismatches.
It never treats that unverified local decode as authentication: signature,
issuer, audience, expiry, roles, and tenant authorization remain enforced by
the API's OIDC verifier.

Local loopback development may omit the bearer token and use
`HALLU_DEFENSE_TENANT_ID`; this unsigned header mode is rejected in production
and staging.

## Protocol behavior

- The client must send `initialize`, receive the negotiated protocol version,
  and then send `notifications/initialized` before listing or calling tools.
- Supported versions match the pinned official TypeScript MCP SDK v1.29.0.
- `ping` is available during initialization.
- Valid notifications never receive JSON-RPC responses.
- JSON-RPC parse, request, method, parameter, and internal errors use the
  canonical standard codes.
- Every tool result includes text `content`, JSON `structuredContent`, and an
  explicit `isError`. Successful and failed results both require a generated
  `trace_id`; each tool advertises an `outputSchema` that covers both branches.
- Public tool failures never reflect an upstream `message`, `detail`, bearer,
  JWT, API key, password, response payload, or exception text. Authentication,
  HTTP-status, upstream-contract, and unexpected failures use bounded generic
  messages; local argument-validation errors contain schema locations only.
- Advertised schemas are the same bundled public contracts enforced at runtime.
  Tool-specific non-empty invariants reject empty claim, document, command, and
  verdict collections where the operation requires at least one item.
- A single input line is capped by `HALLU_DEFENSE_MCP_MAX_INPUT_BYTES`; the
  transport discards oversized lines without retaining an unbounded buffer.
  Fragmented lines are assembled in bounded slabs with one final concatenation,
  so processing remains linear in input size instead of repeatedly copying the
  accumulated prefix.

## Validation

From the repository root:

```text
npm --workspace @hallu-defense/mcp-server run typecheck
npm --workspace @hallu-defense/mcp-server run test
npx eslint packages/mcp-server/src packages/mcp-server/tests --max-warnings=0
npm --workspace @hallu-defense/mcp-server run build
```

The test suite includes a real stdio handshake, list, ping, schema compilation,
malformed calls, and a tool call using the pinned official MCP client. It also
starts local API doubles to prove bearer rotation, absence of spoofable identity
headers, upstream-error redaction, output validation, and trace propagation
without external network access.
