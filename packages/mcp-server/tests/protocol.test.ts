import { SUPPORTED_PROTOCOL_VERSIONS as SDK_SUPPORTED_PROTOCOL_VERSIONS } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import {
  JSON_RPC_ERROR,
  LATEST_PROTOCOL_VERSION,
  type McpCallToolResult,
  type McpToolDefinition,
  McpSession,
  SUPPORTED_PROTOCOL_VERSIONS,
  failedToolResult,
  successfulToolResult
} from "../src/protocol.js";

const testTool: McpToolDefinition = {
  name: "echo",
  description: "Echo a value.",
  inputSchema: { type: "object" },
  outputSchema: { type: "object" }
};

describe("MCP lifecycle and version negotiation", () => {
  it("keeps its supported protocol versions synchronized with the official SDK", () => {
    expect(SUPPORTED_PROTOCOL_VERSIONS).toEqual(SDK_SUPPORTED_PROTOCOL_VERSIONS);
  });

  it.each(SUPPORTED_PROTOCOL_VERSIONS)(
    "echoes a supported requested protocol version %s",
    async (protocolVersion) => {
      const session = createSession();
      const response = await session.processMessage(initializeRequest(protocolVersion));

      expect(response).toEqual(
        expect.objectContaining({
          id: 1,
          result: expect.objectContaining({ protocolVersion })
        })
      );
    }
  );

  it("offers the latest supported version when the client requests an unknown version", async () => {
    const session = createSession();
    const response = await session.processMessage(initializeRequest("1900-01-01"));

    expect(response).toEqual(
      expect.objectContaining({
        result: expect.objectContaining({ protocolVersion: LATEST_PROTOCOL_VERSION })
      })
    );
  });

  it("allows ping but blocks tools until initialize and initialized both complete", async () => {
    const session = createSession();
    expect(await session.processMessage(request(1, "ping"))).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: {}
    });
    expect(await session.processMessage(request(2, "tools/list"))).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest }) })
    );

    await session.processMessage(initializeRequest(LATEST_PROTOCOL_VERSION));
    expect(await session.processMessage(request(3, "tools/list"))).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest }) })
    );
    expect(
      await session.processMessage({ jsonrpc: "2.0", method: "notifications/initialized" })
    ).toBeUndefined();
    expect(await session.processMessage(request(4, "tools/list"))).toEqual(
      expect.objectContaining({ result: { tools: [testTool] } })
    );
  });

  it("rejects a second initialize request without corrupting the active session", async () => {
    const session = createSession();
    await initialize(session);

    expect(await session.processMessage(initializeRequest(LATEST_PROTOCOL_VERSION))).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest }) })
    );
    expect(await session.processMessage(request(3, "tools/list"))).toEqual(
      expect.objectContaining({ result: { tools: [testTool] } })
    );
  });
});

describe("JSON-RPC and MCP request semantics", () => {
  it("never replies to valid notifications or invokes tools from a notification", async () => {
    const handler = vi.fn(async () =>
      successfulToolResult("tr_protocol_notification", { echoed: true })
    );
    const session = new McpSession([testTool], handler);
    await initialize(session);

    expect(
      await session.processMessage({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: "echo", arguments: { value: "ignored" } }
      })
    ).toBeUndefined();
    expect(
      await session.processMessage({ jsonrpc: "2.0", method: "notifications/unknown" })
    ).toBeUndefined();
    expect(handler).not.toHaveBeenCalled();
  });

  it("returns canonical JSON-RPC errors without exposing internal failures", async () => {
    const session = createSession();
    expect(await session.processLine("{")) .toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.parseError }) })
    );
    expect(await session.processMessage([])).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest }) })
    );
    expect(
      await session.processMessage({ jsonrpc: "2.0", id: null, method: "ping" })
    ).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest }) })
    );
    await initialize(session);
    expect(await session.processMessage(request(4, "unknown/method"))).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.methodNotFound }) })
    );
    expect(
      await session.processMessage(
        request(5, "tools/call", { name: "unknown", arguments: {} })
      )
    ).toEqual(
      expect.objectContaining({ error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidParams }) })
    );

    const crashingSession = new McpSession([testTool], async () => {
      throw new Error("sensitive internal failure");
    });
    await initialize(crashingSession);
    expect(
      await crashingSession.processMessage(
        request(6, "tools/call", { name: "echo", arguments: {} })
      )
    ).toEqual({
      jsonrpc: "2.0",
      id: 6,
      error: { code: JSON_RPC_ERROR.internalError, message: "Internal error" }
    });
  });

  it("returns success and tool failures as complete CallToolResult objects", async () => {
    const results: McpCallToolResult[] = [
      successfulToolResult("tr_protocol_success", { echoed: "yes" }),
      failedToolResult("tr_protocol_failure", "safe failure")
    ];
    const session = new McpSession([testTool], async () => {
      const result = results.shift();
      if (result === undefined) {
        throw new Error("unexpected extra call");
      }
      return result;
    });
    await initialize(session);

    const success = await session.processMessage(
      request(10, "tools/call", { name: "echo", arguments: {} })
    );
    const failure = await session.processMessage(
      request(11, "tools/call", { name: "echo", arguments: {} })
    );
    expect(success).toEqual(
      expect.objectContaining({
        result: {
          content: [
            {
              type: "text",
              text: '{"echoed":"yes","trace_id":"tr_protocol_success"}'
            }
          ],
          structuredContent: { echoed: "yes", trace_id: "tr_protocol_success" },
          isError: false
        }
      })
    );
    expect(failure).toEqual(
      expect.objectContaining({
        result: {
          content: [{ type: "text", text: "safe failure" }],
          structuredContent: { trace_id: "tr_protocol_failure", error: "safe failure" },
          isError: true
        }
      })
    );
  });

  it("refuses to construct a tool result without a valid trace ID", () => {
    expect(() => successfulToolResult("", { echoed: true })).toThrow(/trace_id is invalid/u);
    expect(() => failedToolResult("not-a-trace", "safe failure")).toThrow(
      /trace_id is invalid/u
    );
  });
});

function createSession(): McpSession {
  return new McpSession([testTool], async () =>
    successfulToolResult("tr_protocol_session", { echoed: true })
  );
}

async function initialize(session: McpSession): Promise<void> {
  await session.processMessage(initializeRequest(LATEST_PROTOCOL_VERSION));
  await session.processMessage({ jsonrpc: "2.0", method: "notifications/initialized" });
}

function initializeRequest(protocolVersion: string): Record<string, unknown> {
  return request(1, "initialize", {
    protocolVersion,
    capabilities: {},
    clientInfo: { name: "protocol-test", version: "1.0.0" }
  });
}

function request(id: number, method: string, params?: unknown): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    method,
    ...(params !== undefined ? { params } : {})
  };
}
