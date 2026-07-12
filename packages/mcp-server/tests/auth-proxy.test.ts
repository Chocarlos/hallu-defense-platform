import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { loadMcpRuntimeConfig } from "../src/config.js";
import { createToolHandler } from "../src/server.js";

const tempDirectories: string[] = [];

afterEach(() => {
  for (const directory of tempDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("MCP API bearer proxy", () => {
  it("re-reads rotated bearer tokens and omits identity headers whenever bearer auth is used", async () => {
    const observedHeaders: IncomingHttpHeaders[] = [];
    const server = createServer((request, response) => {
      observedHeaders.push(request.headers);
      const traceId = headerValue(request.headers["x-trace-id"]);
      response.writeHead(200, { "content-type": "application/json" });
      if (request.url === "/documents/ingest/status") {
        response.end(
          JSON.stringify({
            trace_id: traceId,
            tenant_id: "tenant-auth",
            job_id: "job-1",
            corpus_id: "hr",
            job_type: "ingest",
            job_status: "succeeded",
            attempts: 1,
            available_at: "2026-07-10T00:00:00Z",
            created_at: "2026-07-10T00:00:00Z",
            updated_at: "2026-07-10T00:00:01Z"
          })
        );
        return;
      }
      response.end(
        JSON.stringify({
          trace_id: traceId,
          tenant_id: "tenant-auth",
          corpus_id: "hr",
          backend: "local",
          document_count: 1,
          indexed_count: 1,
          evidence_ids: [],
          warnings: [],
          job_id: null,
          job_status: null
        })
      );
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const tokenFile = createTokenFile("first-bearer\n");
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: tokenFile,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const argumentsPayload = {
        documents: [
          {
            source_ref: "document-1",
            content: "Verified content.",
            authority: "internal"
          }
        ],
        corpus_id: "hr"
      };

      expect((await handler("ingest_documents", argumentsPayload)).isError).toBe(false);
      replaceToken(tokenFile, "rotated-bearer\n");
      expect((await handler("ingest_documents", argumentsPayload)).isError).toBe(false);
      const statusResult = await handler("get_ingestion_status", { job_id: "job-1" });
      expect(statusResult.isError).toBe(false);
      expect(statusResult.structuredContent).toEqual(
        expect.objectContaining({
          tenant_id: "tenant-auth",
          job_id: "job-1",
          job_status: "succeeded"
        })
      );

      expect(observedHeaders).toHaveLength(3);
      expect(observedHeaders[0]?.authorization).toBe("Bearer first-bearer");
      expect(observedHeaders[1]?.authorization).toBe("Bearer rotated-bearer");
      expect(observedHeaders[2]?.authorization).toBe("Bearer rotated-bearer");
      for (const headers of observedHeaders) {
        expect(headers["x-tenant-id"]).toBeUndefined();
        expect(headers["x-subject-id"]).toBeUndefined();
        expect(headers["x-roles"]).toBeUndefined();
      }
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });

  it("rejects a payload tenant that differs from the bearer JWT tenant before API I/O", async () => {
    const token = jwtWithPayload({ tenant_id: "tenant-auth", exp: 4_102_444_800 });
    const tokenFile = createTokenFile(`${token}\n`);
    const handler = createToolHandler(
      loadMcpRuntimeConfig(
        {
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_API_BASE_URL: "https://127.0.0.1:9",
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: tokenFile,
          HALLU_DEFENSE_MCP_REQUEST_TIMEOUT_MS: "100"
        },
        "linux"
      )
    );

    const result = await handler("validate_tool_call", {
      tool_name: "read_document",
      input: { document_id: "document-1" },
      schema: { type: "object" },
      risk_level: "low",
      approval_required: false,
      caller_context: { tenant_id: "tenant-spoofed" }
    });

    expect(result.isError).toBe(true);
    expect(result.structuredContent.error).toContain(
      "caller tenant does not match authenticated tenant"
    );
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("never reflects bearer, JWT, credential names, or secret values from upstream errors", async () => {
    const reflectedBearer = "reflected-bearer-must-stay-secret";
    const reflectedJwt = jwtWithPayload({ tenant_id: "secret-tenant" });
    const reflectedApiKey = "super-secret-api-key";
    const reflectedPassword = "super-secret-password";
    let requestCount = 0;
    const upstreamSecret =
      `Bearer ${reflectedBearer}; jwt=${reflectedJwt}; ` +
      `api_key=${reflectedApiKey}; password=${reflectedPassword}`;
    const server = createServer((_request, response) => {
      response.writeHead(401, { "content-type": "application/json" });
      response.end(JSON.stringify(requestCount++ === 0
        ? { message: upstreamSecret }
        : { detail: upstreamSecret }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const tokenFile = createTokenFile(`${reflectedBearer}\n`);
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: tokenFile,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const argumentsPayload = {
        documents: [
          {
            source_ref: "document-1",
            content: "Verified content.",
            authority: "internal"
          }
        ]
      };
      const results = [
        await handler("ingest_documents", argumentsPayload),
        await handler("ingest_documents", argumentsPayload)
      ];

      for (const result of results) {
        expect(result.isError).toBe(true);
        expect(result.structuredContent).toEqual({
          trace_id: expect.stringMatching(/^tr_mcp_/u),
          error: "Upstream API request failed with status 401."
        });
      }
      const serialized = JSON.stringify(results);
      for (const sensitive of [
        reflectedBearer,
        reflectedJwt,
        reflectedApiKey,
        reflectedPassword,
        "Bearer",
        "jwt=",
        "api_key",
        "password"
      ]) {
        expect(serialized).not.toContain(sensitive);
      }
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });

  it("forwards fail-closed output-schema blocks without exposing the original", async () => {
    const original = "person@example.com";
    const server = createServer((request, response) => {
      const traceId = headerValue(request.headers["x-trace-id"]);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          trace_id: traceId,
          allowed: false,
          action: "block",
          reason: "Sanitized tool output does not conform to its trusted JSON Schema.",
          approval_required: false,
          approval_id: null,
          sanitized_output: null,
          policy_version: null,
          matched_rules: []
        })
      );
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const result = await handler("validate_tool_output", {
        tool_name: "read_document",
        input: { content: original },
        schema: {
          type: "object",
          properties: { content: { type: "string" } },
          required: ["content"],
          additionalProperties: false
        },
        risk_level: "low",
        approval_required: false,
        caller_context: { tenant_id: "tenant-auth" }
      });

      expect(result.isError).toBe(false);
      expect(result.structuredContent).toEqual(
        expect.objectContaining({
          allowed: false,
          action: "block",
          sanitized_output: null,
          trace_id: expect.stringMatching(/^tr_mcp_/u)
        })
      );
      expect(JSON.stringify(result)).not.toContain(original);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });

  it("rejects an empty upstream verdict set with a generic traced tool error", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ verdicts: [] }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const result = await handler("verify_claims", {
        claims: [
          {
            claim_id: "clm-auth-contract",
            text: "A grounded claim.",
            canonical_form: "a grounded claim",
            type: "doc_grounded",
            risk_level: "low",
            requires_evidence: true,
            source_span: null,
            metadata: {}
          }
        ],
        evidence: []
      });

      expect(result).toEqual({
        content: [{ type: "text", text: "Upstream API response failed contract validation." }],
        structuredContent: {
          trace_id: expect.stringMatching(/^tr_mcp_/u),
          error: "Upstream API response failed contract validation."
        },
        isError: true
      });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });

  it("does not expose malformed successful upstream payload details", async () => {
    const reflectedSecret = "Bearer malformed-success-password-api_key-jwt";
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ message: reflectedSecret, detail: reflectedSecret }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const results = [
        await handler("run_repo_checks", { commands: ["python --version"] }),
        await handler("repair_response", { message_text: "A response to verify." })
      ];

      for (const result of results) {
        expect(result.isError).toBe(true);
        expect(result.structuredContent).toEqual({
          trace_id: expect.stringMatching(/^tr_mcp_/u),
          error: "Upstream API response failed contract validation."
        });
        expect(JSON.stringify(result)).not.toContain(reflectedSecret);
      }
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });

  it("fails closed when a successful API response breaks trace correlation", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          trace_id: "tr_wrong_upstream_trace",
          tenant_id: "tenant-auth",
          corpus_id: "hr",
          backend: "local",
          document_count: 1,
          indexed_count: 1,
          evidence_ids: [],
          warnings: [],
          job_id: null,
          job_status: null
        })
      );
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("HTTP test server did not expose a port");
      }
      const handler = createToolHandler(
        loadMcpRuntimeConfig({
          HALLU_DEFENSE_API_BASE_URL: `http://127.0.0.1:${String(address.port)}`,
          HALLU_DEFENSE_TENANT_ID: "tenant-auth"
        })
      );
      const result = await handler("ingest_documents", {
        documents: [
          { source_ref: "document-1", content: "Verified content.", authority: "internal" }
        ]
      });

      expect(result.isError).toBe(true);
      expect(result.structuredContent).toEqual({
        trace_id: expect.stringMatching(/^tr_mcp_/u),
        error: "Tool call failed."
      });
      expect(JSON.stringify(result)).not.toContain("tr_wrong_upstream_trace");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });
});

function createTokenFile(contents: string): string {
  const directory = mkdtempSync(path.join(tmpdir(), "hallu-mcp-auth-"));
  tempDirectories.push(directory);
  const filename = path.join(directory, "api-token");
  writeFileSync(filename, contents, "utf8");
  chmodSync(filename, 0o440);
  return filename;
}

function replaceToken(filename: string, contents: string): void {
  chmodSync(filename, 0o600);
  writeFileSync(filename, contents, "utf8");
  chmodSync(filename, 0o440);
}

function jwtWithPayload(payload: Readonly<Record<string, unknown>>): string {
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" }), "utf8").toString("base64url"),
    Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"),
    "test-signature"
  ].join(".");
}

function headerValue(value: string | readonly string[] | undefined): string {
  if (Array.isArray(value)) {
    return value[0] ?? "missing-trace";
  }
  return value ?? "missing-trace";
}
