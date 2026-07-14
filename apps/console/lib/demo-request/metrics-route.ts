import { timingSafeEqual } from "node:crypto";

import {
  loadDemoMetricsRuntimeConfig,
  readSecretBytes,
  type DemoMetricsRuntimeConfig
} from "./config";
import { demoMetrics, type DemoMetrics } from "./metrics";

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
    if (expectedToken.byteLength < 32 || expectedToken.byteLength > 256) {
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
  const match = /^Bearer ([\x21-\x7e]{1,256})$/iu.exec(value);
  return match?.[1] === undefined ? null : Buffer.from(match[1], "utf8");
}

function constantTimeTokenEqual(
  supplied: Uint8Array | null,
  expected: Uint8Array
): boolean {
  if (supplied === null || supplied.byteLength !== expected.byteLength) {
    const padded = Buffer.alloc(expected.byteLength);
    if (supplied !== null) {
      Buffer.from(supplied).copy(padded, 0, 0, Math.min(supplied.byteLength, padded.byteLength));
    }
    timingSafeEqual(padded, Buffer.from(expected));
    return false;
  }
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
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
