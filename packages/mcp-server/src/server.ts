#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { randomUUID } from "node:crypto";

import { HalluDefenseClient } from "@hallu-defense/sdk";
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

import { validateContract, validateContractArray } from "./schema-validation.js";

type JsonRpcRequest = {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: unknown;
};

type JsonRpcResponse =
  | {
      readonly jsonrpc: "2.0";
      readonly id: string | number | null;
      readonly result: unknown;
    }
  | {
      readonly jsonrpc: "2.0";
      readonly id: string | number | null;
      readonly error: { readonly code: number; readonly message: string };
    };

const apiBaseUrl = process.env.HALLU_DEFENSE_API_BASE_URL ?? "http://127.0.0.1:8000";
const tenantId = process.env.HALLU_DEFENSE_TENANT_ID ?? "mcp";

function createClient(traceId: string): HalluDefenseClient {
  return new HalluDefenseClient({ baseUrl: apiBaseUrl, tenantId, traceId });
}

const tools = [
  {
    name: "ingest_documents",
    description: "Ingest documents into the configured tenant-scoped RAG corpus.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["documents"],
      properties: {
        documents: { type: "array" },
        corpus_id: { type: "string", minLength: 1 }
      }
    }
  },
  {
    name: "get_ingestion_status",
    description: "Fetch the tenant-scoped status for an async document ingestion job.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["job_id"],
      properties: {
        job_id: { type: "string", minLength: 1 }
      }
    }
  },
  {
    name: "verify_claims",
    description: "Verify atomic claims against supplied evidence.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["claims", "evidence"],
      properties: {
        claims: { type: "array" },
        evidence: { type: "array" }
      }
    }
  },
  {
    name: "retrieve_evidence",
    description: "Retrieve candidate evidence for claims from supplied documents.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["claims"],
      properties: {
        claims: { type: "array" },
        documents: { type: "array" },
        context_refs: { type: "array", items: { type: "string" } },
        metadata_filter: { type: "object" },
        max_evidence_per_claim: { type: "integer", minimum: 1, maximum: 10 }
      }
    }
  },
  {
    name: "validate_tool_call",
    description: "Validate a tool call before execution.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["tool_name", "input", "schema", "risk_level", "approval_required", "caller_context"],
      properties: {
        tool_name: { type: "string", minLength: 1 },
        input: { type: "object" },
        schema: { type: "object" },
        risk_level: { type: "string", enum: ["low", "medium", "high", "critical"] },
        approval_required: { type: "boolean" },
        caller_context: { type: "object" }
      }
    }
  },
  {
    name: "validate_tool_output",
    description: "Validate and sanitize a tool output before exposure.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["tool_name", "input", "schema", "risk_level", "approval_required", "caller_context"],
      properties: {
        tool_name: { type: "string", minLength: 1 },
        input: { type: "object" },
        schema: { type: "object" },
        risk_level: { type: "string", enum: ["low", "medium", "high", "critical"] },
        approval_required: { type: "boolean" },
        caller_context: { type: "object" }
      }
    }
  },
  {
    name: "run_repo_checks",
    description: "Run allowlisted repository checks in the configured sandbox.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["commands"],
      properties: {
        repo_ref: { type: "string" },
        commands: { type: "array", items: { type: "string", minLength: 1 } },
        network_policy: { type: "string", enum: ["deny", "allowlisted"] }
      }
    }
  },
  {
    name: "explain_policy",
    description: "Evaluate enterprise policy for an action.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["action"],
      properties: {
        subject: { type: "string" },
        action: { type: "string", minLength: 1 },
        resource: { type: "string" },
        risk_level: { type: "string", enum: ["low", "medium", "high", "critical"] },
        attributes: { type: "object" }
      }
    }
  },
  {
    name: "repair_response",
    description: "Run the full verification pipeline and return repaired text.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["message_text"],
      properties: {
        message_text: { type: "string", minLength: 1 },
        documents: { type: "array" },
        tool_outputs: { type: "array" },
        execution_artifacts: { type: "object" },
        task_type: { type: "string" },
        message_id: { type: "string" }
      }
    }
  }
] as const;

async function handle(request: JsonRpcRequest): Promise<unknown> {
  if (request.method === "initialize") {
    return {
      protocolVersion: "2024-11-05",
      serverInfo: { name: "hallu-defense-mcp", version: "0.1.0" },
      capabilities: { tools: {} }
    };
  }

  if (request.method === "tools/list") {
    return { tools };
  }

  if (request.method === "tools/call") {
    const params = requireRecord(request.params, "tools/call params");
    const name = requireString(params, "name", "tools/call params");
    return callTool(name, params.arguments);
  }

  throw new Error(`Unsupported method: ${request.method}`);
}

async function callTool(name: string, args: unknown): Promise<unknown> {
  const traceId = createTraceId();
  const client = createClient(traceId);

  switch (name) {
    case "ingest_documents": {
      const result = validateContract<DocumentIngestionResponse>(
        "document-ingestion-response",
        await client.ingestDocuments(requireDocumentIngestionArgs(args)),
        "ingest_documents output"
      );
      return { structuredContent: result };
    }
    case "get_ingestion_status": {
      const result = validateContract<DocumentIngestionStatusResponse>(
        "document-ingestion-status-response",
        await client.getDocumentIngestionStatus(requireDocumentIngestionStatusArgs(args)),
        "get_ingestion_status output"
      );
      return { structuredContent: result };
    }
    case "verify_claims": {
      const payload = requireClaimsVerificationArgs(args);
      const verdicts = validateContractArray<ClaimVerdict>(
        "verdict",
        await client.verifyClaims(payload.claims, payload.evidence),
        "verify_claims output.verdicts"
      );
      return { structuredContent: { trace_id: traceId, verdicts } };
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
      return {
        structuredContent: {
          trace_id: traceId,
          evidence: result.evidence,
          claim_evidence_map: result.claim_evidence_map
        }
      };
    }
    case "validate_tool_call": {
      const result = validateContract<ToolValidationResponse>(
        "tool-validation-response",
        await client.validateToolInput(requireToolEnvelope(args)),
        "validate_tool_call output"
      );
      return { structuredContent: { trace_id: traceId, ...result } };
    }
    case "validate_tool_output": {
      const result = validateContract<ToolValidationResponse>(
        "tool-validation-response",
        await client.validateToolOutput(requireToolEnvelope(args)),
        "validate_tool_output output"
      );
      return { structuredContent: { trace_id: traceId, ...result } };
    }
    case "run_repo_checks": {
      const run = validateContract<SandboxRun>(
        "sandbox-run",
        await client.runRepoChecks(requireRepoChecksArgs(args)),
        "run_repo_checks output"
      );
      return { structuredContent: { trace_id: traceId, ...run } };
    }
    case "explain_policy": {
      const result = validateContract<PolicyEvaluationResponse>(
        "policy-evaluation-response",
        await client.evaluatePolicy(requirePolicyArgs(args)),
        "explain_policy output"
      );
      return { structuredContent: result };
    }
    case "repair_response": {
      const run = validateContract<VerificationRun>(
        "verification-run",
        await client.runVerification(requireVerificationRunArgs(args)),
        "repair_response output.run"
      );
      return { structuredContent: { trace_id: run.trace_id, final_text: run.final_text, run } };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function requireDocumentIngestionArgs(args: unknown): DocumentIngestionRequest {
  const record = requireRecord(args, "ingest_documents arguments");
  assertAllowedKeys(record, ["documents", "corpus_id"], "ingest_documents arguments");
  const payload = validateContract<DocumentIngestionRequest>(
    "document-ingestion-request",
    record,
    "ingest_documents arguments"
  );
  return {
    ...payload,
    documents: validateContractArray<DocumentInput>(
      "document-input",
      payload.documents,
      "ingest_documents arguments.documents"
    )
  };
}

function requireDocumentIngestionStatusArgs(args: unknown): DocumentIngestionStatusRequest {
  const record = requireRecord(args, "get_ingestion_status arguments");
  assertAllowedKeys(record, ["job_id"], "get_ingestion_status arguments");
  return validateContract<DocumentIngestionStatusRequest>(
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
    throw new Error(`${context} must be an object`);
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
      throw new Error(`${context} contains unsupported field: ${key}`);
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
    throw new Error(`${context}.${key} must be a non-empty string`);
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
    throw new Error(`${context}.${key} must be an array`);
  }
  return value as readonly T[];
}

function requireClaimsVerificationArgs(args: unknown): {
  readonly claims: readonly Claim[];
  readonly evidence: readonly Evidence[];
} {
  const record = requireRecord(args, "verify_claims arguments");
  assertAllowedKeys(record, ["claims", "evidence"], "verify_claims arguments");
  const claims = requireArray<unknown>(record, "claims", "verify_claims arguments");
  const evidence = requireArray<unknown>(record, "evidence", "verify_claims arguments");
  return {
    claims: validateContractArray<Claim>("claim", claims, "verify_claims arguments.claims"),
    evidence: validateContractArray<Evidence>(
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
  const payload = validateContract<EvidenceRetrievalRequest>(
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
    claims: validateContractArray<Claim>(
      "claim",
      payload.claims,
      "retrieve_evidence arguments.claims"
    )
  };
  if (payload.documents !== undefined) {
    result.documents = validateContractArray<DocumentInput>(
      "document-input",
      payload.documents,
      "retrieve_evidence arguments.documents"
    );
  }
  if (payload.context_refs !== undefined) {
    result.context_refs = payload.context_refs;
  }
  if (payload.metadata_filter !== undefined) {
    result.metadata_filter = payload.metadata_filter;
  }
  if (payload.max_evidence_per_claim !== undefined) {
    result.max_evidence_per_claim = payload.max_evidence_per_claim;
  }
  return result;
}

function requireToolEnvelope(args: unknown): ToolCallEnvelope {
  return validateContract<ToolCallEnvelope>("tool-call-envelope", args, "tool envelope");
}

function requireRepoChecksArgs(args: unknown): RepoChecksRunRequest {
  return validateContract<RepoChecksRunRequest>(
    "repo-checks-run-request",
    args,
    "run_repo_checks arguments"
  );
}

function requirePolicyArgs(args: unknown): PolicyEvaluationRequest {
  return validateContract<PolicyEvaluationRequest>(
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
  return validateContract<VerificationRunRequest>(
    "verification-run-request",
    record,
    "repair_response arguments"
  );
}

function writeResponse(response: JsonRpcResponse): void {
  output.write(`${JSON.stringify(response)}\n`);
}

const rl = createInterface({ input });
for await (const line of rl) {
  if (line.trim().length === 0) {
    continue;
  }
  let request: JsonRpcRequest;
  try {
    request = JSON.parse(line) as JsonRpcRequest;
  } catch {
    writeResponse({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" }
    });
    continue;
  }

  try {
    const result = await handle(request);
    writeResponse({ jsonrpc: "2.0", id: request.id ?? null, result });
  } catch (error) {
    writeResponse({
      jsonrpc: "2.0",
      id: request.id ?? null,
      error: {
        code: -32000,
        message: error instanceof Error ? error.message : "Unknown server error"
      }
    });
  }
}
