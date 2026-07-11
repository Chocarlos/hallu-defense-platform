# Agent tool adapters

`@hallu-defense/agent-adapters` wraps a tool execution with the required
pre-execution and post-execution validation calls.

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
- The sanitized output is copied into plain immutable JSON data and validated
  against the closed schema before it can be returned.
- `AgentToolCallResult` exposes only `output`, a safe final `verdict`, and a
  payload-free validation `trace`. It never exposes input/output envelopes,
  execution grants, raw output, or validator reasons.

Callers must consume `result.output`, not values captured inside their tool
executor. A `ToolOutputValidationBlockedError` means the tool already ran but
its output is unsafe and must not be used.
