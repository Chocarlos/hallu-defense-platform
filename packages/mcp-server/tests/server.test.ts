import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { createContractSchemaValidator } from "../src/schema-validation.js";
import { tools as toolDefinitions } from "../src/server.js";

type ApiServer = {
  readonly baseUrl: string;
  readonly stop: () => Promise<void>;
  readonly sandboxRepoRef: string;
};

type JsonRpcResponse = {
  readonly jsonrpc: "2.0";
  readonly id: number;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string };
};

type RpcClient = {
  readonly request: (method: string, params?: unknown) => Promise<JsonRpcResponse>;
  readonly notify: (method: string, params?: unknown) => void;
  readonly stop: () => Promise<void>;
};

const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(testDir, "..");
const repoRoot = path.resolve(packageRoot, "../..");
const tenantId = "mcp-contract";
const claimPayload = {
  claim_id: "clm_mcp_contract",
  text: "Full-time employees receive 15 days of paid vacation per year.",
  canonical_form: "full-time employees receive 15 days of paid vacation per year",
  type: "doc_grounded",
  risk_level: "medium",
  requires_evidence: true,
  source_span: null,
  metadata: {}
} as const;
const evidencePayload = {
  evidence_id: "ev_mcp_contract",
  kind: "document_chunk",
  source_ref: "hr-manual-v7",
  content: "Full-time employees receive 15 days of paid vacation per year.",
  structured_content: {},
  authority: "internal",
  freshness: {
    retrieved_at: "2026-07-07T00:00:00Z",
    published_at: null,
    staleness_class: "fresh"
  }
} as const;
const documentPayload = {
  source_ref: "hr-manual-v7",
  content: "Full-time employees receive 15 days of paid vacation per year.",
  authority: "internal"
} as const;
const toolEnvelope = {
  tool_name: "read_document",
  input: { document_id: "hr-manual-v7" },
  schema: {
    type: "object",
    properties: { document_id: { type: "string", minLength: 1 } },
    required: ["document_id"],
    additionalProperties: false
  },
  risk_level: "low",
  approval_required: false,
  caller_context: { tenant_id: tenantId }
} as const;

describe("hallu-defense MCP server API contract", () => {
  let apiServer: ApiServer | undefined;
  let rpcClient: RpcClient | undefined;

  beforeAll(async () => {
    apiServer = await startApiServer();
    rpcClient = startRpcClient(apiServer.baseUrl);
    const initialized = await rpcClient.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "hallu-defense-tests", version: "1.0.0" }
    });
    expect(initialized.error).toBeUndefined();
    rpcClient.notify("notifications/initialized");
  }, 25000);

  afterAll(async () => {
    await rpcClient?.stop();
    await apiServer?.stop();
  });

  it("exposes required tools", async () => {
    const rpc = requireRpcClient(rpcClient);
    const response = await rpc.request("tools/list");
    expect(response.error).toBeUndefined();

    const result = requireRecord(response.result, "tools/list result");
    const tools = requireArray<Record<string, unknown>>(result, "tools", "tools/list result");
    const names = tools.map((tool) => requireString(tool, "name", "tool"));

    expect(names).toEqual(
      expect.arrayContaining([
        "verify_claims",
        "ingest_documents",
        "get_ingestion_status",
        "retrieve_evidence",
        "validate_tool_call",
        "validate_tool_output",
        "run_repo_checks",
        "explain_policy",
        "repair_response"
      ])
    );
    for (const definition of toolDefinitions) {
      const validateOutput = createContractSchemaValidator().compile(definition.outputSchema);
      expect(
        validateOutput({ trace_id: "tr_safe_tool_failure", error: "safe tool failure" }),
        definition.name
      ).toBe(true);
      expect(validateOutput({ error: "missing trace" }), definition.name).toBe(false);
    }

    const validateToolOutput = toolDefinitions.find(
      (definition) => definition.name === "validate_tool_output"
    );
    if (validateToolOutput === undefined) {
      throw new Error("Missing validate_tool_output definition");
    }
    const validateBlockedOutput = createContractSchemaValidator().compile(
      validateToolOutput.outputSchema
    );
    const failClosed = {
      trace_id: "tr_schema_invalid_redaction",
      allowed: false,
      action: "block",
      reason: "Sanitized tool output does not conform to its trusted JSON Schema.",
      approval_required: false,
      approval_id: null,
      sanitized_output: null,
      policy_version: null,
      matched_rules: []
    };
    expect(validateBlockedOutput(failClosed), JSON.stringify(validateBlockedOutput.errors)).toBe(
      true
    );
    expect(JSON.stringify(failClosed)).not.toContain("person@example.com");
  });

  it("interoperates with the official MCP stdio client", async () => {
    const api = requireApiServer(apiServer);
    const serverEntrypoint = path.join(packageRoot, "dist", "server.js");
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [serverEntrypoint],
      cwd: packageRoot,
      env: {
        ...definedEnvironment(process.env),
        HALLU_DEFENSE_ENV: "test",
        HALLU_DEFENSE_API_BASE_URL: api.baseUrl,
        HALLU_DEFENSE_TENANT_ID: tenantId
      },
      stderr: "pipe"
    });
    const client = new Client({ name: "hallu-defense-official-client-test", version: "1.0.0" });

    try {
      await client.connect(transport);
      await client.ping();
      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name)).toContain("repair_response");
      expect(listed.tools.every((tool) => tool.outputSchema !== undefined)).toBe(true);
      const malformedInputs = [
        { name: "verify_claims", value: { claims: [{}], evidence: [{}] } },
        { name: "verify_claims", value: { claims: [], evidence: [] } },
        { name: "ingest_documents", value: { documents: [] } },
        {
          name: "retrieve_evidence",
          value: { claims: [], documents: [documentPayload] }
        },
        {
          name: "retrieve_evidence",
          value: { claims: [claimPayload], documents: [] }
        },
        { name: "run_repo_checks", value: { commands: [] } },
        {
          name: "repair_response",
          value: { message_text: "valid text", documents: ["not-a-document"] }
        },
        {
          name: "repair_response",
          value: { message_text: "valid text", documents: [] }
        },
        {
          name: "repair_response",
          value: { tenant_id: "spoofed", message_text: "valid text" }
        }
      ] as const;
      for (const malformed of malformedInputs) {
        const definition = listed.tools.find((tool) => tool.name === malformed.name);
        if (definition === undefined) {
          throw new Error(`Official client did not list ${malformed.name}`);
        }
        const validateInput = createContractSchemaValidator().compile(definition.inputSchema);
        expect(validateInput(malformed.value), malformed.name).toBe(false);
      }

      const malformedOutputs = [
        { name: "verify_claims", value: { trace_id: "tr_bad", verdicts: [{}] } },
        { name: "verify_claims", value: { trace_id: "tr_bad", verdicts: [] } },
        {
          name: "retrieve_evidence",
          value: { trace_id: "tr_bad", evidence: [{}], claim_evidence_map: {} }
        },
        { name: "run_repo_checks", value: { trace_id: "tr_bad" } },
        {
          name: "repair_response",
          value: { trace_id: "tr_bad", final_text: "", run: {} }
        }
      ] as const;
      for (const malformed of malformedOutputs) {
        const definition = listed.tools.find((tool) => tool.name === malformed.name);
        if (definition?.outputSchema === undefined) {
          throw new Error(`Official client did not expose ${malformed.name} outputSchema`);
        }
        const validateOutput = createContractSchemaValidator().compile(definition.outputSchema);
        expect(validateOutput(malformed.value), malformed.name).toBe(false);
      }

      const emptyClaimsResult = await client.callTool({
        name: "verify_claims",
        arguments: { claims: [], evidence: [] }
      });
      expect(emptyClaimsResult.isError).toBe(true);
      expect(requireRecord(emptyClaimsResult.structuredContent, "empty claims result")).toEqual(
        expect.objectContaining({ trace_id: expect.stringMatching(/^tr_mcp_/u) })
      );

      const result = await client.callTool({
        name: "repair_response",
        arguments: {
          message_text: "Full-time employees receive 15 days of paid vacation per year.",
          documents: [documentPayload]
        }
      });
      expect(result.isError).toBe(false);
      expect(result.content[0]).toEqual(expect.objectContaining({ type: "text" }));
      expect(requireRecord(result.structuredContent, "official client structuredContent")).toEqual(
        expect.objectContaining({ trace_id: expect.stringMatching(/^tr_mcp_/u) })
      );
    } finally {
      await client.close();
    }
  });

  it("returns trace IDs and preserves MCP tenant context through audit events", async () => {
    const rpc = requireRpcClient(rpcClient);
    const api = requireApiServer(apiServer);
    const response = await rpc.request("tools/call", {
      name: "repair_response",
      arguments: {
        message_text: "Full-time employees receive 15 days of paid vacation per year.",
        documents: [
          {
            source_ref: "hr-manual-v7",
            content: "Full-time employees receive 15 days of paid vacation per year.",
            authority: "internal"
          }
        ]
      }
    });

    expect(response.error).toBeUndefined();
    const result = requireRecord(response.result, "repair_response result");
    const structured = requireRecord(result.structuredContent, "repair_response structuredContent");
    const traceId = requireString(structured, "trace_id", "repair_response structuredContent");
    const run = requireRecord(structured.run, "repair_response run");

    expect(traceId.startsWith("tr_mcp_")).toBe(true);
    expect(run.trace_id).toBe(traceId);
    expect(run.tenant_id).toBe(tenantId);
    expect(requireArray(run, "claims", "repair_response run").length).toBeGreaterThan(0);

    const audit = await exportAudit(api.baseUrl, tenantId);
    const events = requireArray<Record<string, unknown>>(audit, "events", "audit export");
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          tenant_id: tenantId,
          trace_id: traceId,
          path: "/verification/run",
          outcome: "success"
        })
      ])
    );
  });

  it("calls every required MCP tool against the API with trace IDs and audit events", async () => {
    const rpc = requireRpcClient(rpcClient);
    const api = requireApiServer(apiServer);
    const calls = [
      {
        name: "ingest_documents",
        path: "/documents/ingest",
        arguments: { documents: [documentPayload], corpus_id: "hr" },
        assert: (structured: Record<string, unknown>) => {
          expect(structured.tenant_id).toBe(tenantId);
          expect(structured.backend).toBe("local");
          expect(structured.indexed_count).toBe(0);
          expect(requireArray(structured, "warnings", "ingest_documents output").length).toBe(1);
        }
      },
      {
        name: "verify_claims",
        path: "/claims/verify",
        arguments: { claims: [claimPayload], evidence: [evidencePayload] },
        assert: (structured: Record<string, unknown>) => {
          expect(requireArray(structured, "verdicts", "verify_claims output").length).toBe(1);
        }
      },
      {
        name: "retrieve_evidence",
        path: "/evidence/retrieve",
        arguments: { claims: [claimPayload], documents: [documentPayload] },
        assert: (structured: Record<string, unknown>) => {
          expect(requireArray(structured, "evidence", "retrieve_evidence output").length).toBe(1);
          expect(requireRecord(structured.claim_evidence_map, "retrieve_evidence map")).toHaveProperty(
            claimPayload.claim_id
          );
        }
      },
      {
        name: "validate_tool_call",
        path: "/tools/validate-input",
        arguments: toolEnvelope,
        assert: (structured: Record<string, unknown>) => {
          expect(structured.allowed).toBe(true);
        }
      },
      {
        name: "validate_tool_output",
        path: "/tools/validate-output",
        arguments: {
          ...toolEnvelope,
          input: { content: "api_key=test-value" },
          schema: {
            type: "object",
            properties: { content: { type: "string" } },
            required: ["content"],
            additionalProperties: false
          }
        },
        assert: (structured: Record<string, unknown>) => {
          const sanitized = requireRecord(
            structured.sanitized_output,
            "validate_tool_output sanitized output"
          );
          expect(sanitized.content).toBe("[REDACTED]");
        }
      },
      {
        name: "run_repo_checks",
        path: "/repo/checks/run",
        arguments: {
          repo_ref: api.sandboxRepoRef,
          commands: ["python --version"],
          network_policy: "deny"
        },
        assert: (structured: Record<string, unknown>) => {
          expect(requireArray(structured, "exit_codes", "run_repo_checks output")).toEqual([0]);
          expect(structured.network_policy).toBe("deny");
          const evidence = requireArray<Record<string, unknown>>(
            structured,
            "evidence",
            "run_repo_checks output"
          );
          expect(evidence.map((item) => item.evidence_id)).toEqual(
            expect.arrayContaining(["ev_sandbox_cmd_001", "ev_sandbox_inspection"])
          );
        }
      },
      {
        name: "explain_policy",
        path: "/policy/evaluate",
        arguments: { action: "read", risk_level: "low", attributes: {} },
        assert: (structured: Record<string, unknown>) => {
          expect(structured.allowed).toBe(true);
          expect(requireArray(structured, "matched_rules", "explain_policy output")).toContain(
            "default_allow_registered_action"
          );
        }
      },
      {
        name: "repair_response",
        path: "/verification/run",
        arguments: {
          message_text: "Full-time employees receive 15 days of paid vacation per year.",
          documents: [documentPayload]
        },
        assert: (structured: Record<string, unknown>) => {
          expect(requireRecord(structured.run, "repair_response run").tenant_id).toBe(tenantId);
        }
      }
    ] as const;
    const observedTraces: string[] = [];

    for (const call of calls) {
      const definition = toolDefinitions.find((tool) => tool.name === call.name);
      if (definition === undefined) {
        throw new Error(`Missing tool definition for ${call.name}`);
      }
      const validateInput = createContractSchemaValidator().compile(definition.inputSchema);
      expect(validateInput(call.arguments), JSON.stringify(validateInput.errors)).toBe(true);
      const response = await rpc.request("tools/call", {
        name: call.name,
        arguments: call.arguments
      });

      expect(response.error, call.name).toBeUndefined();
      const structured = structuredContent(response.result, call.name);
      const validateOutput = createContractSchemaValidator().compile(definition.outputSchema);
      expect(validateOutput(structured), JSON.stringify(validateOutput.errors)).toBe(true);
      const traceId = requireString(structured, "trace_id", `${call.name} output`);
      expect(traceId.startsWith("tr_mcp_"), call.name).toBe(true);
      observedTraces.push(traceId);
      call.assert(structured);
    }

    const audit = await exportAudit(api.baseUrl, tenantId);
    const events = requireArray<Record<string, unknown>>(audit, "events", "audit export");
    for (const [index, call] of calls.entries()) {
      expect(events).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            tenant_id: tenantId,
            trace_id: observedTraces[index],
            path: call.path,
            outcome: "success"
          })
        ])
      );
    }
  });

  it("rejects invalid nested public contract payloads before proxying", async () => {
    const rpc = requireRpcClient(rpcClient);
    const response = await rpc.request("tools/call", {
      name: "verify_claims",
      arguments: {
        claims: [
          {
            ...claimPayload,
            source_span: undefined
          }
        ],
        evidence: [evidencePayload]
      }
    });

    const failure = requireToolFailure(response, "verify_claims");
    expect(failure).toContain("claim schema validation");
    expect(failure).toContain("source_span");
  });

  it("rejects invalid request-only tool contracts before proxying", async () => {
    const rpc = requireRpcClient(rpcClient);
    const repoResponse = await rpc.request("tools/call", {
      name: "run_repo_checks",
      arguments: {
        repo_ref: requireApiServer(apiServer).sandboxRepoRef,
        commands: [],
        network_policy: "deny"
      }
    });
    const policyResponse = await rpc.request("tools/call", {
      name: "explain_policy",
      arguments: {
        risk_level: "low",
        attributes: {}
      }
    });
    const ingestResponse = await rpc.request("tools/call", {
      name: "ingest_documents",
      arguments: {
        documents: [],
        corpus_id: "hr"
      }
    });
    const claimsResponse = await rpc.request("tools/call", {
      name: "verify_claims",
      arguments: { claims: [], evidence: [] }
    });
    const retrievalResponse = await rpc.request("tools/call", {
      name: "retrieve_evidence",
      arguments: { claims: [claimPayload], documents: [] }
    });
    const repairResponse = await rpc.request("tools/call", {
      name: "repair_response",
      arguments: { message_text: "valid text", documents: [] }
    });

    expect(requireToolFailure(repoResponse, "run_repo_checks")).toContain(
      "repo-checks-run-request schema validation"
    );
    expect(requireToolFailure(repoResponse, "run_repo_checks")).toContain(
      "must NOT have fewer than 1 items"
    );
    expect(requireToolFailure(policyResponse, "explain_policy")).toContain(
      "policy-evaluation-request schema validation"
    );
    expect(requireToolFailure(policyResponse, "explain_policy")).toContain("action");
    expect(requireToolFailure(ingestResponse, "ingest_documents")).toContain(
      "document-ingestion-request schema validation"
    );
    expect(requireToolFailure(ingestResponse, "ingest_documents")).toContain(
      "must NOT have fewer than 1 items"
    );
    expect(requireToolFailure(claimsResponse, "verify_claims")).toContain(
      "must contain at least one item"
    );
    expect(requireToolFailure(retrievalResponse, "retrieve_evidence")).toContain(
      "must contain at least one item"
    );
    expect(requireToolFailure(repairResponse, "repair_response")).toContain(
      "must contain at least one item"
    );
  });

  it("rejects unsupported fields before calling the API", async () => {
    const rpc = requireRpcClient(rpcClient);
    const response = await rpc.request("tools/call", {
      name: "repair_response",
      arguments: {
        tenant_id: "cross-tenant-attempt",
        message_text: "This should not cross tenant boundaries."
      }
    });

    expect(requireToolFailure(response, "repair_response")).toContain(
      "contains an unsupported field"
    );
  });
});

function structuredContent(value: unknown, context: string): Record<string, unknown> {
  const result = requireRecord(value, `${context} result`);
  expect(result.isError, context).toBe(false);
  const content = requireArray<Record<string, unknown>>(result, "content", `${context} result`);
  expect(content[0]).toEqual(expect.objectContaining({ type: "text" }));
  return requireRecord(result.structuredContent, `${context} structuredContent`);
}

function requireToolFailure(response: JsonRpcResponse, context: string): string {
  expect(response.error, context).toBeUndefined();
  const result = requireRecord(response.result, `${context} result`);
  expect(result.isError, context).toBe(true);
  const structured = requireRecord(
    result.structuredContent,
    `${context} failure structuredContent`
  );
  expect(requireString(structured, "trace_id", `${context} failure structuredContent`)).toMatch(
    /^tr_mcp_/u
  );
  return requireString(structured, "error", `${context} failure structuredContent`);
}

function startRpcClient(baseUrl: string): RpcClient {
  const serverEntrypoint = path.join(packageRoot, "dist", "server.js");
  if (!existsSync(serverEntrypoint)) {
    throw new Error(`built MCP server not found at ${serverEntrypoint}`);
  }
  const child = spawn(process.execPath, [serverEntrypoint], {
    cwd: packageRoot,
    env: {
      ...process.env,
      HALLU_DEFENSE_ENV: "test",
      HALLU_DEFENSE_API_BASE_URL: baseUrl,
      HALLU_DEFENSE_TENANT_ID: tenantId
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const rl = createInterface({ input: child.stdout });
  let nextId = 1;
  let stderr = "";
  const pending = new Map<
    number,
    {
      readonly resolve: (response: JsonRpcResponse) => void;
      readonly reject: (error: Error) => void;
      readonly timeout: NodeJS.Timeout;
    }
  >();

  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  rl.on("line", (line) => {
    let response: JsonRpcResponse;
    try {
      response = JSON.parse(line) as JsonRpcResponse;
    } catch (error) {
      for (const entry of pending.values()) {
        entry.reject(
          new Error(
            `MCP server emitted invalid JSON: ${line}. ${
              error instanceof Error ? error.message : String(error)
            }`
          )
        );
      }
      pending.clear();
      return;
    }

    const entry = pending.get(response.id);
    if (entry === undefined) {
      return;
    }
    clearTimeout(entry.timeout);
    pending.delete(response.id);
    entry.resolve(response);
  });
  child.once("exit", (code, signal) => {
    for (const entry of pending.values()) {
      entry.reject(new Error(`MCP server exited with code=${code} signal=${signal}: ${stderr}`));
    }
    pending.clear();
  });

  return {
    request: async (method: string, params?: unknown) => {
      const id = nextId;
      nextId += 1;
      const requestName =
        typeof params === "object" &&
        params !== null &&
        "name" in params &&
        typeof params.name === "string"
          ? `${method}:${params.name}`
          : method;
      const response = new Promise<JsonRpcResponse>((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Timed out waiting for MCP response to ${requestName}: ${stderr}`));
        }, 10000);
        pending.set(id, { resolve, reject, timeout });
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return response;
    },
    notify: (method: string, params?: unknown) => {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
    },
    stop: async () => {
      rl.close();
      await stopChild(child);
    }
  };
}

async function exportAudit(baseUrl: string, tenant: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${baseUrl}/audit/export`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-tenant-id": tenant,
      "x-trace-id": "tr_mcp_contract_audit"
    },
    body: JSON.stringify({ tenant_id: tenant, include_events: true })
  });
  expect(response.ok).toBe(true);
  return (await response.json()) as Record<string, unknown>;
}

function requireRpcClient(client: RpcClient | undefined): RpcClient {
  if (client === undefined) {
    throw new Error("RPC client did not start");
  }
  return client;
}

function requireApiServer(server: ApiServer | undefined): ApiServer {
  if (server === undefined) {
    throw new Error("API server did not start");
  }
  return server;
}

function requireRecord(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${context} must be an object`);
  }
  return value as Record<string, unknown>;
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

async function startApiServer(): Promise<ApiServer> {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const python = resolvePython();
  const sandboxWorkspace = mkdtempSync(path.join(tmpdir(), "hallu-mcp-sandbox-"));
  const sandboxRepoRef = "repo";
  const sandboxRepo = path.join(sandboxWorkspace, sandboxRepoRef);
  mkdirSync(sandboxRepo);
  writeFileSync(path.join(sandboxRepo, "service.py"), "def fetch():\n    return 'fresh'\n", {
    encoding: "utf8"
  });
  writeFileSync(
    path.join(sandboxWorkspace, "run"),
    [
      "from __future__ import annotations",
      "import json",
      "import sys",
      "from pathlib import Path",
      "from hallu_defense.services.sandbox import _workspace_fingerprint",
      "args = sys.argv[1:]",
      "mounts = [args[index + 1] for index, item in enumerate(args[:-1]) if item == '--mount']",
      "source_mount = next(item for item in mounts if 'target=/hallu-source' in item)",
      "source = next(item.split('=', 1)[1] for item in source_mount.split(',') if item.startswith('source='))",
      "commands = json.loads(args[-1])",
      "fingerprint = _workspace_fingerprint(Path(source))",
      "payload = {'schema_version': 'sandbox_execution_batch.v3', 'pre_snapshot_fingerprint': fingerprint, 'post_snapshot_fingerprint': fingerprint, 'executions': [{'returncode': 0, 'stdout': 'Python test runtime\\n', 'stderr': '', 'timed_out': False} for _ in commands], 'artifacts': []}",
      "print(json.dumps(payload, separators=(',', ':')))"
    ].join("\n"),
    { encoding: "utf8" }
  );
  const child = spawn(
    python,
    ["-m", "uvicorn", "hallu_defense.main:app", "--host", "127.0.0.1", "--port", String(port)],
    {
      cwd: sandboxWorkspace,
      env: {
        ...process.env,
        PYTHONPATH: path.join(repoRoot, "apps/api/src"),
        HALLU_DEFENSE_ALLOWED_WORKSPACE: sandboxWorkspace,
        HALLU_DEFENSE_ENV: "test",
        HALLU_DEFENSE_MAX_COMMAND_SECONDS: "5",
        HALLU_DEFENSE_SANDBOX_BACKEND: "docker",
        HALLU_DEFENSE_SANDBOX_DOCKER_PATH: python
      },
      stdio: ["pipe", "pipe", "pipe"]
    }
  );

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  try {
    await waitForHealth(baseUrl, 15000);
  } catch (error) {
    await stopChild(child);
    throw new Error(
      `FastAPI server failed to become healthy: ${
        error instanceof Error ? error.message : String(error)
      }\nstdout:\n${stdout}\nstderr:\n${stderr}`
    );
  }

  return {
    baseUrl,
    sandboxRepoRef,
    stop: async () => {
      await stopChild(child);
      cleanupTempDir(sandboxWorkspace);
    }
  };
}

function cleanupTempDir(target: string): void {
  const resolvedTarget = path.resolve(target);
  const resolvedTempRoot = path.resolve(tmpdir());
  if (!resolvedTarget.startsWith(`${resolvedTempRoot}${path.sep}`)) {
    throw new Error(`Refusing to clean non-temp directory: ${resolvedTarget}`);
  }
  rmSync(resolvedTarget, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100
  });
}

function resolvePython(): string {
  const candidate =
    process.platform === "win32"
      ? path.join(repoRoot, ".venv", "Scripts", "python.exe")
      : path.join(repoRoot, ".venv", "bin", "python");
  if (process.env.HALLU_CONTRACT_PYTHON !== undefined) {
    return process.env.HALLU_CONTRACT_PYTHON;
  }
  return existsSync(candidate) ? candidate : "python";
}

async function getFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Could not allocate a TCP port");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return address.port;
}

async function waitForHealth(baseUrl: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) {
        return;
      }
    } catch {
      // The server may still be booting; retry until the deadline.
    }
    await delay(150);
  }
  throw new Error(`Timed out waiting for ${baseUrl}/health`);
}

async function stopChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    if (!(await waitForChildClose(child, 5000))) {
      throw new Error("Child process streams did not close within the bounded shutdown window");
    }
    return;
  }
  const closed = waitForChildClose(child, 5000);
  child.kill();
  if (await closed) {
    return;
  }
  const forceClosed = waitForChildClose(child, 5000);
  child.kill("SIGKILL");
  if (!(await forceClosed)) {
    throw new Error("Child process did not terminate within the bounded shutdown window");
  }
}

function waitForChildClose(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number
): Promise<boolean> {
  if (
    (child.exitCode !== null || child.signalCode !== null) &&
    child.stdin.destroyed &&
    child.stdout.destroyed &&
    child.stderr.destroyed
  ) {
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    const onClose = (): void => {
      clearTimeout(timeout);
      resolve(true);
    };
    const timeout = setTimeout(() => {
      child.off("close", onClose);
      resolve(false);
    }, timeoutMs);
    child.once("close", onClose);
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function definedEnvironment(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)
  );
}
