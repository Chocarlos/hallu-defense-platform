# Agent tool adapters

`@hallu-defense/agent-adapters` wraps a tool execution with the required
pre-execution and post-execution validation calls.

## Trusted definition boundary

`inputSchema`, `outputSchema`, `riskLevel`, and `approvalRequired` are required
wire assertions, not client-defined policy. The API compares them exactly with
an operator-provisioned, versioned tool definition and blocks unknown tools or
any mismatch. `callerContext` is correlation data only; it cannot establish
tenant, subject, approval, side effects, policy action, or command evidence.

The adapter sends the same canonical risk and approval assertions in both
phases. Output validation does not request a second human approval: phase is a
server-side policy fact. An approval ID and execution token can be exchanged only
for an internal single-use capability whose originating approval record/trace,
authenticated tenant and subject, tool/action, canonical arguments, and trusted
definition version/digest match the server-created grant.

## Output safety contract

- Every tool definition must provide an explicit closed `outputSchema` with
  `type: "object"`, declared `properties`, a `required` array, and
  `additionalProperties: false`. Nested objects must follow the same rule and
  arrays must declare `items`.
- Local validation intentionally supports the structural JSON Schema subset
  above plus scalar `type` checks. Unsupported validation keywords are rejected
  up front instead of being silently ignored.
- The tool's raw output exists only inside `executeAgentTool` long enough to be
  sent to `/tools/validate-output`. It is never included in the returned value
  or in a blocked-output error.
- A successful validation must return `sanitized_output`. Missing or malformed
  sanitized output fails closed with `ToolOutputValidationContractError`.
- The API revalidates redacted output against the trusted server definition. If a
  marker violates that schema, validation blocks with no output; adapters never
  fall back to the raw tool result.
- The sanitized output is copied into plain immutable JSON data and validated
  against the closed schema before it can be returned.
- `AgentToolCallResult` exposes only `output`, a safe final `verdict`, and a
  payload-free validation `trace`. It never exposes input/output envelopes,
  execution grants, raw output, or validator reasons.

Callers must consume `result.output`, not values captured inside their tool
executor. A `ToolOutputValidationBlockedError` means the tool already ran but
its output is unsafe and must not be used.
