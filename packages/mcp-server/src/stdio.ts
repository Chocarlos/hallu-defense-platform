import type { Readable, Writable } from "node:stream";

import {
  JSON_RPC_ERROR,
  type JsonRpcResponse,
  McpSession,
  jsonRpcError
} from "./protocol.js";

const NEWLINE = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const ASSEMBLY_SLAB_BYTES = 64 * 1024;

export async function runBoundedStdioServer(
  session: McpSession,
  input: Readable,
  output: Writable,
  maxInputBytes: number
): Promise<void> {
  let pendingChunks: Buffer[] = [];
  let pendingBytes = 0;
  let pendingTailBytes = 0;
  let discardingOversizedLine = false;

  for await (const rawChunk of input) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(String(rawChunk), "utf8");
    let cursor = 0;
    while (cursor < chunk.length) {
      const newlineIndex = chunk.indexOf(NEWLINE, cursor);
      const segmentEnd = newlineIndex === -1 ? chunk.length : newlineIndex;
      const segment = chunk.subarray(cursor, segmentEnd);

      if (!discardingOversizedLine) {
        if (pendingBytes + segment.length > maxInputBytes) {
          pendingChunks = [];
          pendingBytes = 0;
          pendingTailBytes = 0;
          discardingOversizedLine = true;
        } else if (segment.length > 0) {
          pendingTailBytes = appendSegment(
            pendingChunks,
            pendingTailBytes,
            segment,
            Math.min(ASSEMBLY_SLAB_BYTES, maxInputBytes)
          );
          pendingBytes += segment.length;
        }
      }

      if (newlineIndex === -1) {
        break;
      }
      if (discardingOversizedLine) {
        await writeResponse(
          output,
          jsonRpcError(
            null,
            JSON_RPC_ERROR.invalidRequest,
            `Request exceeds maximum input size of ${String(maxInputBytes)} bytes`
          )
        );
        discardingOversizedLine = false;
      } else if (pendingBytes > 0) {
        await processChunks(session, pendingChunks, pendingBytes, output);
      }
      pendingChunks = [];
      pendingBytes = 0;
      pendingTailBytes = 0;
      cursor = newlineIndex + 1;
    }
  }

  if (discardingOversizedLine) {
    await writeResponse(
      output,
      jsonRpcError(
        null,
        JSON_RPC_ERROR.invalidRequest,
        `Request exceeds maximum input size of ${String(maxInputBytes)} bytes`
      )
    );
  } else if (pendingBytes > 0) {
    await processChunks(session, pendingChunks, pendingBytes, output);
  }
}

function appendSegment(
  chunks: Buffer[],
  tailBytes: number,
  segment: Buffer,
  slabBytes: number
): number {
  let sourceOffset = 0;
  let usedTailBytes = tailBytes;
  while (sourceOffset < segment.length) {
    if (chunks.length === 0 || usedTailBytes === slabBytes) {
      chunks.push(Buffer.allocUnsafe(slabBytes));
      usedTailBytes = 0;
    }
    const tail = chunks.at(-1);
    if (tail === undefined) {
      throw new Error("MCP stdio line assembler did not allocate a buffer");
    }
    const copyBytes = Math.min(slabBytes - usedTailBytes, segment.length - sourceOffset);
    segment.copy(
      tail,
      usedTailBytes,
      sourceOffset,
      sourceOffset + copyBytes
    );
    usedTailBytes += copyBytes;
    sourceOffset += copyBytes;
  }
  return usedTailBytes;
}

async function processChunks(
  session: McpSession,
  chunks: readonly Buffer[],
  totalBytes: number,
  output: Writable
): Promise<void> {
  const line = Buffer.concat(chunks, totalBytes);
  await processLine(session, line, output);
}

async function processLine(
  session: McpSession,
  rawLine: Buffer,
  output: Writable
): Promise<void> {
  const line =
    rawLine.at(-1) === CARRIAGE_RETURN ? rawLine.subarray(0, rawLine.length - 1) : rawLine;
  if (line.length === 0 || isAsciiWhitespaceOnly(line)) {
    return;
  }

  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(line);
  } catch {
    await writeResponse(
      output,
      jsonRpcError(null, JSON_RPC_ERROR.parseError, "Parse error")
    );
    return;
  }
  const response = await session.processLine(decoded);
  if (response !== undefined) {
    await writeResponse(output, response);
  }
}

function isAsciiWhitespaceOnly(value: Buffer): boolean {
  for (const byte of value) {
    if (byte !== 0x20 && byte !== 0x09 && byte !== CARRIAGE_RETURN) {
      return false;
    }
  }
  return true;
}

function writeResponse(output: Writable, response: JsonRpcResponse): Promise<void> {
  return new Promise((resolve, reject) => {
    output.write(`${JSON.stringify(response)}\n`, (error) => {
      if (error === null || error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}
