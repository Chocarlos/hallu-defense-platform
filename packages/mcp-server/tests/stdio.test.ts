import { Readable, Writable } from "node:stream";

import { describe, expect, it, vi } from "vitest";

import { JSON_RPC_ERROR, McpSession, successfulToolResult } from "../src/protocol.js";
import { runBoundedStdioServer } from "../src/stdio.js";

describe("bounded MCP stdio transport", () => {
  it("processes chunked CRLF messages and emits no notification response", async () => {
    const initialize = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "stdio-test", version: "1.0.0" }
      }
    });
    const initialized = JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized"
    });
    const list = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const input = Readable.from([
      Buffer.from(initialize.slice(0, 20)),
      Buffer.from(`${initialize.slice(20)}\r\n${initialized}\n${list}\n`)
    ]);

    const responses = await runAndCollect(input, 4096);
    expect(responses).toHaveLength(2);
    expect(responses[0]).toEqual(expect.objectContaining({ id: 1 }));
    expect(responses[1]).toEqual(expect.objectContaining({ id: 2, result: { tools: [] } }));
  });

  it("rejects an oversized line without retaining it and continues at the next line", async () => {
    const oversized = "x".repeat(128);
    const ping = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" });
    const responses = await runAndCollect(
      Readable.from([Buffer.from(oversized.slice(0, 50)), Buffer.from(`${oversized.slice(50)}\n${ping}\n`)]),
      64
    );

    expect(responses).toEqual([
      expect.objectContaining({
        id: null,
        error: expect.objectContaining({ code: JSON_RPC_ERROR.invalidRequest })
      }),
      { jsonrpc: "2.0", id: 9, result: {} }
    ]);
  });

  it("rejects invalid UTF-8 as a parse error", async () => {
    const responses = await runAndCollect(
      Readable.from([Buffer.from([0xc3, 0x28, 0x0a])]),
      1024
    );

    expect(responses).toEqual([
      expect.objectContaining({
        id: null,
        error: expect.objectContaining({ code: JSON_RPC_ERROR.parseError })
      })
    ]);
  });

  it("assembles a heavily fragmented bounded line with one concatenation", async () => {
    const ping = `${JSON.stringify({ jsonrpc: "2.0", id: 11, method: "ping" })}${" ".repeat(4096)}\n`;
    const chunks = [...Buffer.from(ping)].map((byte) => Buffer.from([byte]));
    const concatSpy = vi.spyOn(Buffer, "concat");

    try {
      const responses = await runAndCollect(Readable.from(chunks), 8192);

      expect(responses).toEqual([{ jsonrpc: "2.0", id: 11, result: {} }]);
      expect(concatSpy).toHaveBeenCalledTimes(1);
      expect(concatSpy.mock.calls[0]?.[1]).toBe(Buffer.byteLength(ping) - 1);
    } finally {
      concatSpy.mockRestore();
    }
  });
});

async function runAndCollect(
  input: Readable,
  maxInputBytes: number
): Promise<readonly Record<string, unknown>[]> {
  let outputText = "";
  const output = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      outputText += chunk.toString();
      callback();
    }
  });
  const session = new McpSession([], async () =>
    successfulToolResult("tr_stdio_test", {})
  );

  await runBoundedStdioServer(session, input, output, maxInputBytes);
  return outputText
    .trim()
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
