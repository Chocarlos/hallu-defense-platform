import { timingSafeEqual } from "node:crypto";

import {
  isValidMetricsBearer,
  loadDemoMetricsRuntimeConfig,
  readSecretBytes,
  type DemoMetricsRuntimeConfig
} from "./config";
import { demoMetrics, type DemoMetrics } from "./metrics";

const TOKEN_MAX_BYTES = 256;
const TOKEN_OVERSIZE_SENTINEL_BYTES = TOKEN_MAX_BYTES + 1;
const TOKEN_FRAME_BYTES = 2 + TOKEN_MAX_BYTES;

export interface MetricsHandlerDependencies {
  readonly config?: DemoMetricsRuntimeConfig;
  readonly metrics?: Pick<DemoMetrics, "render">;
  readonly secretReader?: (path: string) => Uint8Array;
}

export function createDemoMetricsHandler(
  dependencies: MetricsHandlerDependencies = {}
): (request: Request) => Response {
  const config = dependencies.config ?? loadDemoMetricsRuntimeConfig();
  const metrics = dependencies.metrics ?? demoMetrics;
  const secretReader = dependencies.secretReader ?? readSecretBytes;

  return (request: Request): Response => {
    if (!config.enabled || config.bearerFile === undefined) {
      return plainResponse("Metrics are unavailable.\n", 503);
    }
    let expectedToken: Uint8Array;
    try {
      expectedToken = secretReader(config.bearerFile);
    } catch {
      return plainResponse("Metrics are unavailable.\n", 503);
    }
    if (!isValidMetricsBearer(expectedToken)) {
      return plainResponse("Metrics are unavailable.\n", 503);
    }
    const suppliedToken = parseBearer(request.headers.get("authorization"));
    if (!constantTimeTokenEqual(suppliedToken, expectedToken)) {
      const response = plainResponse("Authentication is required.\n", 401);
      response.headers.set("www-authenticate", 'Bearer realm="hallu-defense-metrics"');
      return response;
    }
    return new Response(metrics.render(), {
      status: 200,
      headers: {
        "content-type": "text/plain; version=0.0.4; charset=utf-8",
        "cache-control": "no-store, max-age=0, private",
        pragma: "no-cache",
        "x-content-type-options": "nosniff"
      }
    });
  };
}

function parseBearer(value: string | null): Uint8Array | null {
  if (value === null) {
    return null;
  }
  const match = /^Bearer ([\x21-\x7e]+)$/iu.exec(value);
  if (match?.[1] === undefined) {
    return null;
  }
  return match[1].length > TOKEN_MAX_BYTES
    ? new Uint8Array(TOKEN_OVERSIZE_SENTINEL_BYTES)
    : Buffer.from(match[1], "utf8");
}

function constantTimeTokenEqual(
  supplied: Uint8Array | null,
  expected: Uint8Array
): boolean {
  const suppliedFrame = frameToken(supplied);
  const expectedFrame = frameToken(expected);
  const equal = timingSafeEqual(suppliedFrame, expectedFrame);
  return (
    supplied !== null &&
    supplied.byteLength <= TOKEN_MAX_BYTES &&
    expected.byteLength <= TOKEN_MAX_BYTES &&
    equal
  );
}

function frameToken(value: Uint8Array | null): Buffer {
  const frame = Buffer.alloc(TOKEN_FRAME_BYTES);
  const length = value?.byteLength ?? 0;
  frame.writeUInt16BE(Math.min(length, TOKEN_OVERSIZE_SENTINEL_BYTES), 0);
  if (value !== null) {
    frame.set(value.subarray(0, TOKEN_MAX_BYTES), 2);
  }
  return frame;
}

function plainResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store, max-age=0, private",
      pragma: "no-cache",
      "x-content-type-options": "nosniff"
    }
  });
}
