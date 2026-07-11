#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import path from "node:path";
import { stderr, stdin, stdout } from "node:process";
import { fileURLToPath } from "node:url";

import { HalluDefenseClient, HalluDefenseError } from "@hallu-defense/sdk";
import type {
  Claim,
  ClaimVerdict,
  DocumentIngestionRequest,
  DocumentIngestionResponse,
  DocumentIngestionStatusRequest,
  DocumentIngestionStatusResponse,
  DocumentInput,
  Evidence,
  EvidenceRetrievalRequest,
  EvidenceRetrievalResponse,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  RepoChecksRunRequest,
  SandboxRun,
  ToolCallEnvelope,
  ToolValidationResponse,
  VerificationRun,
  VerificationRunRequest
} from "@hallu-defense/contracts";

import {
  ContractValidationError,
  bundledContractSchema,
  validateContract,
  validateContractArray
} from "./schema-validation.js";
import {
  type McpRuntimeConfig,
  McpConfigurationError,
  loadMcpRuntimeConfig,
  readApiAuthContext
} from "./config.js";
import {
  JSON_RPC_ERROR,
  type McpCallToolResult,
  type McpToolDefinition,
  McpSession,
  RpcError,
  failedToolResult,
  successfulToolResult
} from "./protocol.js";
import { runBoundedStdioServer } from "./stdio.js";

const stringSchema = { type: "string", minLength: 1 } as const;
const traceIdSchema = {
  type: "string",
  pattern: "^tr_[A-Za-z0-9_-]+$"
} as const;
const errorOutputSchema = {
  type: "object",
  required: ["trace_id", "error"],
  properties: { trace_id: traceIdSchema, error: stringSchema },
  additionalProperties: false
} as const;

const toolInputSchemas = {
  ingest_documents: bundledContractSchema("document-ingestion-request"),
  get_ingestion_status: bundledContractSchema("document-ingestion-status-request"),
  verify_claims: requireNonEmptyArrayProperties(
    requireContractProperties(
      bundledContractSchema("claim-verification-request"),
      ["evidence"]
    ),
    ["claims"]
  ),
  retrieve_evidence: requireNonEmptyArrayProperties(
    bundledContractSchema("evidence-retrieval-request"),
    ["claims", "documents", "context_refs"]
  ),
  validate_tool_call: bundledContractSchema("tool-call-envelope"),
  validate_tool_output: bundledContractSchema("tool-call-envelope"),
  run_repo_checks: bundledContractSchema("repo-checks-run-request"),
  explain_policy: bundledContractSchema("policy-evaluation-request"),
  repair_response: requireNonEmptyArrayProperties(
    omitContractProperties(
      bundledContractSchema("verification-run-request"),
      ["tenant_id"]
    ),
    ["documents", "tool_outputs"]
  )
} as const;

const toolOutputSchemas = {
  ingest_documents: outputSchema(bundledContractSchema("document-ingestion-response")),
  get_ingestion_status: outputSchema(
    bundledContractSchema("document-ingestion-status-response")
  ),
  verify_claims: outputSchema(
    addTraceIdToContract(
      requireNonEmptyArrayProperties(
        bundledContractSchema("claim-verification-response"),
        ["verdicts"]
      )
    )
  ),
  retrieve_evidence: outputSchema(
    addTraceIdToContract(bundledContractSchema("evidence-retrieval-response"))
  ),
  validate_tool_call: outputSchema(
    addTraceIdToContract(bundledContractSchema("tool-validation-response"))
  ),
  validate_tool_output: outputSchema(
    addTraceIdToContract(bundledContractSchema("tool-validation-response"))
  ),
  run_repo_checks: outputSchema(
    addTraceIdToContract(bundledContractSchema("sandbox-run"))
  ),
  explain_policy: outputSchema(bundledContractSchema("policy-evaluation-response")),
  repair_response: outputSchema(repairResponseSuccessSchema())
} as const;

export const tools = [
  {
    name: "ingest_documents",
    description: "Ingest documents into the configured tenant-scoped RAG corpus.",
    inputSchema: toolInputSchemas.ingest_documents,
    outputSchema: toolOutputSchemas.ingest_documents
  },
  {
    name: "get_ingestion_status",
    description: "Fetch the tenant-scoped status for an async document ingestion job.",
    inputSchema: toolInputSchemas.get_ingestion_status,
    outputSchema: toolOutputSchemas.get_ingestion_status
  },
  {
    name: "verify_claims",
    description: "Verify atomic claims against supplied evidence.",
    inputSchema: toolInputSchemas.verify_claims,
    outputSchema: toolOutputSchemas.verify_claims
  },
  {
    name: "retrieve_evidence",
    description: "Retrieve candidate evidence for claims from supplied documents.",
    inputSchema: toolInputSchemas.retrieve_evidence,
    outputSchema: toolOutputSchemas.retrieve_evidence
  },
  {
    name: "validate_tool_call",
    description: "Validate a tool call before execution.",
    inputSchema: toolInputSchemas.validate_tool_call,
    outputSchema: toolOutputSchemas.validate_tool_call
  },
  {
    name: "validate_tool_output",
    description: "Validate and sanitize a tool output before exposure.",
    inputSchema: toolInputSchemas.validate_tool_output,
    outputSchema: toolOutputSchemas.validate_tool_output
  },
  {
    name: "run_repo_checks",
    description: "Run allowlisted repository checks in the configured sandbox.",
    inputSchema: toolInputSchemas.run_repo_checks,
    outputSchema: toolOutputSchemas.run_repo_checks
  },
  {
    name: "explain_policy",
    description: "Evaluate enterprise policy for an action.",
    inputSchema: toolInputSchemas.explain_policy,
    outputSchema: toolOutputSchemas.explain_policy
  },
  {
    name: "repair_response",
    description: "Run the full verification pipeline and return repaired text.",
    inputSchema: toolInputSchemas.repair_response,
    outputSchema: toolOutputSchemas.repair_response
  }
] as const satisfies readonly McpToolDefinition[];

export function createToolHandler(config: McpRuntimeConfig) {
  return async (name: string, args: unknown): Promise<McpCallToolResult> =>
    callTool(config, name, args);
}

async function callTool(
  config: McpRuntimeConfig,
  name: string,
  args: unknown
): Promise<McpCallToolResult> {
  const traceId = createTraceId();

  try {
    const auth = readApiAuthContext(config);
    const client = new HalluDefenseClient({
      baseUrl: config.apiBaseUrl,
      traceId,
      timeoutMs: config.requestTimeoutMs,
      ...(auth.token !== undefined ? { token: auth.token } : {}),
      ...(auth.token === undefined && auth.tenantId !== undefined
        ? { tenantId: auth.tenantId }
        : {})
    });
    switch (name) {
      case "ingest_documents": {
        const result = validateContract<DocumentIngestionResponse>(
          "document-ingestion-response",
          await client.ingestDocuments(requireDocumentIngestionArgs(args)),
          "ingest_documents output"
        );
        assertTraceMatches(result, traceId, "ingest_documents output");
        assertTenantMatches(result, auth.tenantId, "ingest_documents output");
        return successfulToolResult(
          traceId,
          result as unknown as Record<string, unknown>
        );
      }
      case "get_ingestion_status": {
        const result = validateContract<DocumentIngestionStatusResponse>(
          "document-ingestion-status-response",
          await client.getDocumentIngestionStatus(requireDocumentIngestionStatusArgs(args)),
          "get_ingestion_status output"
        );
        assertTraceMatches(result, traceId, "get_ingestion_status output");
        assertTenantMatches(result, auth.tenantId, "get_ingestion_status output");
        return successfulToolResult(
          traceId,
          result as unknown as Record<string, unknown>
        );
      }
      case "verify_claims": {
        const payload = requireClaimsVerificationArgs(args);
        const verdicts = validateContractArray<ClaimVerdict>(
          "verdict",
          await client.verifyClaims(payload.claims, payload.evidence),
          "verify_claims output.verdicts"
        );
        requireNonEmptyOutputArray(verdicts);
        return successfulToolResult(traceId, { verdicts });
      }
      case "retrieve_evidence": {
        const payload = requireEvidenceRetrievalArgs(args);
        const options = {
          ...(payload.context_refs !== undefined ? { context_refs: payload.context_refs } : {}),
          ...(payload.metadata_filter !== undefined
            ? { metadata_filter: payload.metadata_filter }
            : {}),
          ...(payload.max_evidence_per_claim !== undefined
            ? { max_evidence_per_claim: payload.max_evidence_per_claim }
            : {})
        } satisfies Omit<EvidenceRetrievalRequest, "claims" | "documents">;
        const result = validateContract<EvidenceRetrievalResponse>(
          "evidence-retrieval-response",
          await client.retrieveEvidence(payload.claims, payload.documents ?? [], options),
          "retrieve_evidence output"
        );
        return successfulToolResult(traceId, {
          evidence: result.evidence,
          claim_evidence_map: result.claim_evidence_map
        });
      }
      case "validate_tool_call": {
        const result = validateContract<ToolValidationResponse>(
          "tool-validation-response",
          await client.validateToolInput(requireToolEnvelope(args, auth.tenantId)),
          "validate_tool_call output"
        );
        return successfulToolResult(traceId, result as unknown as Record<string, unknown>);
      }
      case "validate_tool_output": {
        const result = validateContract<ToolValidationResponse>(
          "tool-validation-response",
          await client.validateToolOutput(requireToolEnvelope(args, auth.tenantId)),
          "validate_tool_output output"
        );
        return successfulToolResult(traceId, result as unknown as Record<string, unknown>);
      }
      case "run_repo_checks": {
        const run = validateContract<SandboxRun>(
          "sandbox-run",
          await client.runRepoChecks(requireRepoChecksArgs(args)),
          "run_repo_checks output"
        );
        return successfulToolResult(traceId, run as unknown as Record<string, unknown>);
      }
      case "explain_policy": {
        const result = validateContract<PolicyEvaluationResponse>(
          "policy-evaluation-response",
          await client.evaluatePolicy(requirePolicyArgs(args)),
          "explain_policy output"
        );
        assertTraceMatches(result, traceId, "explain_policy output");
        return successfulToolResult(
          traceId,
          result as unknown as Record<string, unknown>
        );
      }
      case "repair_response": {
        const run = validateContract<VerificationRun>(
          "verification-run",
          await client.runVerification(requireVerificationRunArgs(args)),
          "repair_response output.run"
        );
        assertTraceMatches(run, traceId, "repair_response output.run");
        assertTenantMatches(run, auth.tenantId, "repair_response output.run");
        return successfulToolResult(traceId, {
          final_text: run.final_text,
          run
        });
      }
      default:
        throw new RpcError(JSON_RPC_ERROR.invalidParams, "Unknown tool");
    }
  } catch (error) {
    if (error instanceof RpcError) {
      throw error;
    }
    return failedToolResult(traceId, publicToolErrorMessage(error));
  }
}

function requireDocumentIngestionArgs(args: unknown): DocumentIngestionRequest {
  const record = requireRecord(args, "ingest_documents arguments");
  assertAllowedKeys(record, ["documents", "corpus_id"], "ingest_documents arguments");
  const payload = validateInputContract<DocumentIngestionRequest>(
    "document-ingestion-request",
    record,
    "ingest_documents arguments"
  );
  return {
    ...payload,
    documents: validateInputContractArray<DocumentInput>(
      "document-input",
      payload.documents,
      "ingest_documents arguments.documents"
    )
  };
}

function requireDocumentIngestionStatusArgs(args: unknown): DocumentIngestionStatusRequest {
  const record = requireRecord(args, "get_ingestion_status arguments");
  assertAllowedKeys(record, ["job_id"], "get_ingestion_status arguments");
  return validateInputContract<DocumentIngestionStatusRequest>(
    "document-ingestion-status-request",
    record,
    "get_ingestion_status arguments"
  );
}

function createTraceId(): string {
  return `tr_mcp_${randomUUID().replaceAll("-", "")}`;
}

function requireRecord(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new McpToolInputError(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  context: string
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new McpToolInputError(`${context} contains an unsupported field`);
    }
  }
}

function requireString(
  record: Record<string, unknown>,
  key: string,
  context: string
): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new McpToolInputError(`${context}.${key} must be a non-empty string`);
  }
  return value;
}

function requireArray<T>(
  record: Record<string, unknown>,
  key: string,
  context: string
): readonly T[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new McpToolInputError(`${context}.${key} must be an array`);
  }
  return value as readonly T[];
}

function requireNonEmptyInputArray<T>(
  values: readonly T[],
  context: string
): readonly T[] {
  if (values.length === 0) {
    throw new McpToolInputError(`${context} must contain at least one item`);
  }
  return values;
}

function requireNonEmptyOutputArray(values: readonly unknown[]): void {
  if (values.length === 0) {
    throw new McpUpstreamContractError();
  }
}

function validateInputContract<T>(
  schemaName: Parameters<typeof validateContract>[0],
  value: unknown,
  context: string
): T {
  try {
    return validateContract<T>(schemaName, value, context);
  } catch (error) {
    if (error instanceof ContractValidationError) {
      throw new McpToolInputError(error.message);
    }
    throw error;
  }
}

function validateInputContractArray<T>(
  schemaName: Parameters<typeof validateContractArray>[0],
  values: readonly unknown[],
  context: string
): readonly T[] {
  try {
    return validateContractArray<T>(schemaName, values, context);
  } catch (error) {
    if (error instanceof ContractValidationError) {
      throw new McpToolInputError(error.message);
    }
    throw error;
  }
}

function requireClaimsVerificationArgs(args: unknown): {
  readonly claims: readonly Claim[];
  readonly evidence: readonly Evidence[];
} {
  const record = requireRecord(args, "verify_claims arguments");
  assertAllowedKeys(record, ["claims", "evidence"], "verify_claims arguments");
  const claims = requireNonEmptyInputArray(
    requireArray<unknown>(record, "claims", "verify_claims arguments"),
    "verify_claims arguments.claims"
  );
  const evidence = requireArray<unknown>(record, "evidence", "verify_claims arguments");
  return {
    claims: validateInputContractArray<Claim>("claim", claims, "verify_claims arguments.claims"),
    evidence: validateInputContractArray<Evidence>(
      "evidence",
      evidence,
      "verify_claims arguments.evidence"
    )
  };
}

function requireEvidenceRetrievalArgs(args: unknown): {
  readonly claims: readonly Claim[];
  readonly documents?: readonly DocumentInput[];
  readonly context_refs?: readonly string[];
  readonly metadata_filter?: Readonly<Record<string, unknown>>;
  readonly max_evidence_per_claim?: number;
} {
  const record = requireRecord(args, "retrieve_evidence arguments");
  assertAllowedKeys(
    record,
    ["claims", "documents", "context_refs", "metadata_filter", "max_evidence_per_claim"],
    "retrieve_evidence arguments"
  );
  const payload = validateInputContract<EvidenceRetrievalRequest>(
    "evidence-retrieval-request",
    record,
    "retrieve_evidence arguments"
  );
  const result: {
    claims: readonly Claim[];
    documents?: readonly DocumentInput[];
    context_refs?: readonly string[];
    metadata_filter?: Readonly<Record<string, unknown>>;
    max_evidence_per_claim?: number;
  } = {
    claims: validateInputContractArray<Claim>(
      "claim",
      requireNonEmptyInputArray(payload.claims, "retrieve_evidence arguments.claims"),
      "retrieve_evidence arguments.claims"
    )
  };
  if (payload.documents !== undefined) {
    result.documents = validateInputContractArray<DocumentInput>(
      "document-input",
      requireNonEmptyInputArray(
        payload.documents,
        "retrieve_evidence arguments.documents"
      ),
      "retrieve_evidence arguments.documents"
    );
  }
  if (payload.context_refs !== undefined) {
    result.context_refs = requireNonEmptyInputArray(
      payload.context_refs,
      "retrieve_evidence arguments.context_refs"
    );
  }
  if (payload.metadata_filter !== undefined) {
    result.metadata_filter = payload.metadata_filter;
  }
  if (payload.max_evidence_per_claim !== undefined) {
    result.max_evidence_per_claim = payload.max_evidence_per_claim;
  }
  return result;
}

function requireToolEnvelope(args: unknown, expectedTenantId: string | undefined): ToolCallEnvelope {
  const envelope = validateInputContract<ToolCallEnvelope>(
    "tool-call-envelope",
    args,
    "tool envelope"
  );
  if (expectedTenantId === undefined) {
    return envelope;
  }
  const callerContext = requireRecord(envelope.caller_context, "tool envelope.caller_context");
  const suppliedTenant = requireString(
    callerContext,
    "tenant_id",
    "tool envelope.caller_context"
  );
  if (suppliedTenant !== expectedTenantId) {
    throw new McpToolInputError(
      "tool envelope caller tenant does not match authenticated tenant"
    );
  }
  return envelope;
}

function requireRepoChecksArgs(args: unknown): RepoChecksRunRequest {
  return validateInputContract<RepoChecksRunRequest>(
    "repo-checks-run-request",
    args,
    "run_repo_checks arguments"
  );
}

function requirePolicyArgs(args: unknown): PolicyEvaluationRequest {
  return validateInputContract<PolicyEvaluationRequest>(
    "policy-evaluation-request",
    args,
    "explain_policy arguments"
  );
}

function requireVerificationRunArgs(args: unknown): VerificationRunRequest {
  const record = requireRecord(args, "repair_response arguments");
  assertAllowedKeys(
    record,
    ["message_text", "documents", "tool_outputs", "execution_artifacts", "task_type", "message_id"],
    "repair_response arguments"
  );
  const payload = validateInputContract<VerificationRunRequest>(
    "verification-run-request",
    record,
    "repair_response arguments"
  );
  if (payload.documents !== undefined) {
    requireNonEmptyInputArray(payload.documents, "repair_response arguments.documents");
  }
  if (payload.tool_outputs !== undefined) {
    requireNonEmptyInputArray(payload.tool_outputs, "repair_response arguments.tool_outputs");
  }
  return payload;
}

function outputSchema(
  successSchema: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> {
  const { $defs, ...successBranch } = successSchema;
  return {
    type: "object",
    anyOf: [successBranch, errorOutputSchema],
    ...(isPlainRecord($defs) ? { $defs } : {})
  };
}

function addTraceIdToContract(
  schema: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> {
  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  const properties = isPlainRecord(schema.properties) ? schema.properties : {};
  return {
    ...schema,
    required: ["trace_id", ...required.filter((item) => item !== "trace_id")],
    properties: { ...properties, trace_id: traceIdSchema }
  };
}

function requireContractProperties(
  schema: Readonly<Record<string, unknown>>,
  names: readonly string[]
): Readonly<Record<string, unknown>> {
  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  return {
    ...schema,
    required: [...new Set([...required, ...names])]
  };
}

function requireNonEmptyArrayProperties(
  schema: Readonly<Record<string, unknown>>,
  names: readonly string[]
): Readonly<Record<string, unknown>> {
  const properties = isPlainRecord(schema.properties) ? schema.properties : {};
  const tightenedProperties: Record<string, unknown> = { ...properties };
  for (const name of names) {
    const property = properties[name];
    if (!isPlainRecord(property) || property.type !== "array") {
      throw new Error(`Cannot require non-empty array for schema property ${name}`);
    }
    const existingMinimum =
      typeof property.minItems === "number" && Number.isSafeInteger(property.minItems)
        ? property.minItems
        : 0;
    tightenedProperties[name] = {
      ...property,
      minItems: Math.max(1, existingMinimum)
    };
  }
  return { ...schema, properties: tightenedProperties };
}

function omitContractProperties(
  schema: Readonly<Record<string, unknown>>,
  names: readonly string[]
): Readonly<Record<string, unknown>> {
  const omitted = new Set(names);
  const required = Array.isArray(schema.required)
    ? schema.required.filter(
        (item): item is string => typeof item === "string" && !omitted.has(item)
      )
    : [];
  const properties = isPlainRecord(schema.properties) ? schema.properties : {};
  return {
    ...schema,
    required,
    properties: Object.fromEntries(
      Object.entries(properties).filter(([name]) => !omitted.has(name))
    )
  };
}

function repairResponseSuccessSchema(): Readonly<Record<string, unknown>> {
  const bundledRun = bundledContractSchema("verification-run");
  const { $defs, ...runSchema } = bundledRun;
  const runDependencies = isPlainRecord($defs) ? $defs : {};
  return {
    type: "object",
    required: ["trace_id", "final_text", "run"],
    properties: {
      trace_id: traceIdSchema,
      final_text: { type: "string" },
      run: { $ref: "#/$defs/verification-run" }
    },
    additionalProperties: false,
    $defs: { ...runDependencies, "verification-run": runSchema }
  };
}

function assertTenantMatches(
  value: unknown,
  expectedTenantId: string | undefined,
  context: string
): void {
  if (expectedTenantId === undefined) {
    return;
  }
  const record = requireRecord(value, context);
  if (record.tenant_id !== expectedTenantId) {
    throw new Error(`${context} tenant does not match authenticated tenant`);
  }
}

function assertTraceMatches(
  value: unknown,
  expectedTraceId: string,
  context: string
): void {
  const record = requireRecord(value, context);
  if (record.trace_id !== expectedTraceId) {
    throw new Error(`${context} trace does not match the MCP request`);
  }
}

function publicToolErrorMessage(error: unknown): string {
  if (error instanceof McpToolInputError) {
    return error.message.slice(0, 2048);
  }
  if (error instanceof ContractValidationError || error instanceof McpUpstreamContractError) {
    return "Upstream API response failed contract validation.";
  }
  if (error instanceof HalluDefenseError) {
    return `Upstream API request failed with status ${String(error.status)}.`;
  }
  if (error instanceof McpConfigurationError) {
    return "MCP authentication material is unavailable.";
  }
  return "Tool call failed.";
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class McpToolInputError extends Error {
  readonly code = "MCP_TOOL_INPUT_ERROR" as const;

  constructor(message: string) {
    super(message);
    this.name = "McpToolInputError";
  }
}

class McpUpstreamContractError extends Error {
  readonly code = "MCP_UPSTREAM_CONTRACT_ERROR" as const;

  constructor() {
    super("Upstream API response failed contract validation");
    this.name = "McpUpstreamContractError";
  }
}

export async function runMcpServer(config = loadMcpRuntimeConfig()): Promise<void> {
  if (config.apiTokenFile !== undefined) {
    // Fail at startup and then re-read for every call so atomic secret rotation is observed.
    readApiAuthContext(config);
  }
  const session = new McpSession(tools, createToolHandler(config));
  await runBoundedStdioServer(session, stdin, stdout, config.maxInputBytes);
}

function isMainModule(): boolean {
  const entrypoint = process.argv[1];
  return entrypoint !== undefined && path.resolve(entrypoint) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  runMcpServer().catch((error: unknown) => {
    const message =
      error instanceof McpConfigurationError ? error.message : "MCP server terminated unexpectedly";
    stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
