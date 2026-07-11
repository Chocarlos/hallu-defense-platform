export const SUPPORTED_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
  "2024-10-07"
] as const;

export const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];
const MAX_RPC_ERROR_MESSAGE_CHARS = 1024;

export const JSON_RPC_ERROR = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603
} as const;

export type JsonRpcId = string | number;

export interface JsonRpcSuccessResponse {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly result: unknown;
}

export interface JsonRpcErrorResponse {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId | null;
  readonly error: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export interface McpTextContent {
  readonly type: "text";
  readonly text: string;
}

export type McpToolStructuredContent = Readonly<Record<string, unknown>> & {
  readonly trace_id: string;
};

export interface McpCallToolResult {
  readonly content: readonly McpTextContent[];
  readonly structuredContent: McpToolStructuredContent;
  readonly isError: boolean;
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  readonly outputSchema: Readonly<Record<string, unknown>>;
}

export type McpToolHandler = (
  name: string,
  args: unknown
) => Promise<McpCallToolResult>;

type LifecycleState = "uninitialized" | "awaiting_initialized" | "ready";

export class RpcError extends Error {
  constructor(
    readonly rpcCode: number,
    message: string,
    readonly rpcData?: unknown
  ) {
    super(message);
    this.name = "RpcError";
  }
}

export class McpSession {
  #state: LifecycleState = "uninitialized";

  constructor(
    private readonly tools: readonly McpToolDefinition[],
    private readonly callTool: McpToolHandler
  ) {}

  async processLine(line: string): Promise<JsonRpcResponse | undefined> {
    let value: unknown;
    try {
      value = JSON.parse(line) as unknown;
    } catch {
      return jsonRpcError(null, JSON_RPC_ERROR.parseError, "Parse error");
    }
    return this.processMessage(value);
  }

  async processMessage(value: unknown): Promise<JsonRpcResponse | undefined> {
    if (!isRecord(value) || Array.isArray(value)) {
      return jsonRpcError(null, JSON_RPC_ERROR.invalidRequest, "Invalid Request");
    }
    const hasId = Object.prototype.hasOwnProperty.call(value, "id");
    const id = value.id;
    if (value.jsonrpc !== "2.0" || typeof value.method !== "string") {
      return jsonRpcError(validIdOrNull(id), JSON_RPC_ERROR.invalidRequest, "Invalid Request");
    }
    if (!hasId) {
      this.#handleNotification(value.method);
      return undefined;
    }
    if (!isJsonRpcId(id)) {
      return jsonRpcError(null, JSON_RPC_ERROR.invalidRequest, "Invalid Request");
    }

    try {
      const result = await this.#handleRequest(value.method, value.params);
      return { jsonrpc: "2.0", id, result };
    } catch (error) {
      if (error instanceof RpcError) {
        return jsonRpcError(id, error.rpcCode, error.message, error.rpcData);
      }
      return jsonRpcError(id, JSON_RPC_ERROR.internalError, "Internal error");
    }
  }

  #handleNotification(method: string): void {
    if (method === "notifications/initialized" && this.#state === "awaiting_initialized") {
      this.#state = "ready";
    }
  }

  async #handleRequest(method: string, params: unknown): Promise<unknown> {
    if (method === "ping") {
      requireEmptyParams(params, "ping");
      return {};
    }
    if (method === "initialize") {
      if (this.#state !== "uninitialized") {
        throw new RpcError(JSON_RPC_ERROR.invalidRequest, "Server is already initialized");
      }
      const requestedVersion = requireInitializeParams(params);
      const negotiatedVersion = isSupportedProtocolVersion(requestedVersion)
        ? requestedVersion
        : LATEST_PROTOCOL_VERSION;
      this.#state = "awaiting_initialized";
      return {
        protocolVersion: negotiatedVersion,
        serverInfo: { name: "hallu-defense-mcp", version: "0.1.0" },
        capabilities: { tools: {} },
        instructions:
          "Use tools only for the authenticated tenant. Tool results include validated structured content and trace IDs."
      };
    }
    if (this.#state !== "ready") {
      throw new RpcError(
        JSON_RPC_ERROR.invalidRequest,
        "Initialize the MCP session before invoking this method"
      );
    }
    if (method === "tools/list") {
      requireEmptyOrCursorParams(params, "tools/list");
      return { tools: this.tools };
    }
    if (method === "tools/call") {
      const callParams = requireRecord(params, "tools/call params");
      assertAllowedKeys(callParams, ["name", "arguments", "_meta"], "tools/call params");
      const name = requireString(callParams, "name", "tools/call params");
      if (!this.tools.some((tool) => tool.name === name)) {
        throw new RpcError(JSON_RPC_ERROR.invalidParams, "Unknown tool");
      }
      return this.callTool(name, callParams.arguments);
    }
    throw new RpcError(JSON_RPC_ERROR.methodNotFound, "Method not found");
  }
}

export function successfulToolResult(
  traceId: string,
  structuredContent: Readonly<Record<string, unknown>>
): McpCallToolResult {
  const tracedContent = withTraceId(traceId, structuredContent);
  return {
    content: [{ type: "text", text: JSON.stringify(tracedContent) }],
    structuredContent: tracedContent,
    isError: false
  };
}

export function failedToolResult(traceId: string, message: string): McpCallToolResult {
  const structuredContent = withTraceId(traceId, { error: message });
  return {
    content: [{ type: "text", text: message }],
    structuredContent,
    isError: true
  };
}

function withTraceId(
  traceId: string,
  structuredContent: Readonly<Record<string, unknown>>
): McpToolStructuredContent {
  if (!/^tr_[A-Za-z0-9_-]+$/u.test(traceId)) {
    throw new Error("MCP tool result trace_id is invalid");
  }
  return { ...structuredContent, trace_id: traceId };
}

export function jsonRpcError(
  id: JsonRpcId | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcErrorResponse {
  const boundedMessage =
    message.length === 0 ? "Error" : message.slice(0, MAX_RPC_ERROR_MESSAGE_CHARS);
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message: boundedMessage, ...(data !== undefined ? { data } : {}) }
  };
}

function requireInitializeParams(params: unknown): string {
  const record = requireRecord(params, "initialize params");
  assertAllowedKeys(
    record,
    ["protocolVersion", "capabilities", "clientInfo", "_meta"],
    "initialize params"
  );
  const protocolVersion = requireString(record, "protocolVersion", "initialize params");
  requireRecord(record.capabilities, "initialize params.capabilities");
  const clientInfo = requireRecord(record.clientInfo, "initialize params.clientInfo");
  requireString(clientInfo, "name", "initialize params.clientInfo");
  requireString(clientInfo, "version", "initialize params.clientInfo");
  return protocolVersion;
}

function requireEmptyParams(params: unknown, context: string): void {
  if (params === undefined) {
    return;
  }
  const record = requireRecord(params, `${context} params`);
  assertAllowedKeys(record, ["_meta"], `${context} params`);
}

function requireEmptyOrCursorParams(params: unknown, context: string): void {
  if (params === undefined) {
    return;
  }
  const record = requireRecord(params, `${context} params`);
  assertAllowedKeys(record, ["cursor", "_meta"], `${context} params`);
  if (record.cursor !== undefined) {
    throw new RpcError(JSON_RPC_ERROR.invalidParams, `${context} does not support pagination`);
  }
}

function requireRecord(value: unknown, context: string): Record<string, unknown> {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new RpcError(JSON_RPC_ERROR.invalidParams, `${context} must be an object`);
  }
  return value;
}

function requireString(
  record: Record<string, unknown>,
  key: string,
  context: string
): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new RpcError(
      JSON_RPC_ERROR.invalidParams,
      `${context}.${key} must be a non-empty string`
    );
  }
  return value;
}

function assertAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  context: string
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new RpcError(
        JSON_RPC_ERROR.invalidParams,
        `${context} contains an unsupported field`
      );
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isJsonRpcId(value: unknown): value is JsonRpcId {
  return (
    typeof value === "string" ||
    (typeof value === "number" && Number.isSafeInteger(value))
  );
}

function validIdOrNull(value: unknown): JsonRpcId | null {
  return isJsonRpcId(value) ? value : null;
}

function isSupportedProtocolVersion(
  value: string
): value is (typeof SUPPORTED_PROTOCOL_VERSIONS)[number] {
  return (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(value);
}
