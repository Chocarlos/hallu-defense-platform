import { createHash } from "node:crypto";

import {
  loadDemoRuntimeConfig,
  readSecretBytes,
  type DemoRuntimeConfig,
  type EnabledDemoRuntimeConfig
} from "./config";
import { DemoRequestError } from "./contracts";
import type {
  DemoRequestAcceptedResponseV1,
  DemoRequestErrorResponseV1
} from "./public-contract";
import {
  createLeaseToken,
  deriveDemoRequestId,
  digestNormalizedDemoRequest,
  digestNormalizedEmail
} from "./identity";
import {
  demoMetrics,
  type DemoMetricsRecorder
} from "./metrics";
import {
  createRedisDemoStore,
  type DemoReservation,
  type DemoStore
} from "./redis";
import { readAndNormalizeDemoRequest, validateDemoRequestSource } from "./request";
import { deliverDemoWebhook, DemoWebhookError } from "./webhook";

const MINIMUM_PUBLIC_RESPONSE_MILLISECONDS = 300;

export interface DemoRequestHandlerDependencies {
  readonly config?: DemoRuntimeConfig;
  readonly store?: DemoStore;
  readonly metrics?: DemoMetricsRecorder;
  readonly fetchImpl?: typeof fetch;
  readonly now?: () => Date;
  readonly secretReader?: (path: string) => Uint8Array;
  readonly leaseToken?: () => string;
  readonly monotonicNow?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly minimumResponseMilliseconds?: number;
}

export function createDemoRequestHandler(
  dependencies: DemoRequestHandlerDependencies = {}
): (request: Request) => Promise<Response> {
  const config = dependencies.config ?? loadDemoRuntimeConfig();
  const metrics = dependencies.metrics ?? demoMetrics;
  const store =
    dependencies.store ?? (config.enabled ? createRedisDemoStore(config) : undefined);
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  const now = dependencies.now ?? (() => new Date());
  const secretReader = dependencies.secretReader ?? readSecretBytes;
  const leaseToken = dependencies.leaseToken ?? createLeaseToken;
  const monotonicNow = dependencies.monotonicNow ?? (() => performance.now());
  const sleep = dependencies.sleep ?? delay;
  const minimumResponseMilliseconds =
    dependencies.minimumResponseMilliseconds ?? MINIMUM_PUBLIC_RESPONSE_MILLISECONDS;

  return async (request: Request): Promise<Response> => {
    const startedAt = monotonicNow();
    let response: Response;
    try {
      if (!config.enabled || store === undefined) {
        metrics.recordDemoResult("unavailable");
        response = errorResponse(503, "Demo requests are unavailable.");
      } else {
        response = await processEnabledRequest(request, {
          config,
          store,
          metrics,
          fetchImpl,
          now,
          secretReader,
          leaseToken
        });
      }
    } catch (error) {
      if (error instanceof DemoRequestError) {
        metrics.recordDemoResult(error.outcome);
        response = errorResponse(
          error.status,
          error.publicMessage,
          error.retryAfterSeconds
        );
      } else {
        metrics.recordDemoResult("unavailable");
        response = errorResponse(503, "Demo requests are unavailable.");
      }
    }
    const remaining = minimumResponseMilliseconds - (monotonicNow() - startedAt);
    if (remaining > 0) {
      await sleep(remaining);
    }
    return response;
  };
}

interface EnabledDependencies {
  readonly config: EnabledDemoRuntimeConfig;
  readonly store: DemoStore;
  readonly metrics: DemoMetricsRecorder;
  readonly fetchImpl: typeof fetch;
  readonly now: () => Date;
  readonly secretReader: (path: string) => Uint8Array;
  readonly leaseToken: () => string;
}

async function processEnabledRequest(
  request: Request,
  dependencies: EnabledDependencies
): Promise<Response> {
  validateDemoRequestSource(request, dependencies.config.publicOrigin);
  const globalStatus = await consumeGlobal(dependencies.store);
  if (globalStatus === "rate_global") {
    throw new DemoRequestError(429, "Too many requests.", "rate_limited", 60);
  }
  const demoRequest = await readAndNormalizeDemoRequest(request);
  const hmacSecret = dependencies.secretReader(
    dependencies.config.webhookHmacSecretFile
  );
  if (hmacSecret.byteLength < 32) {
    unavailable();
  }
  const requestId = deriveDemoRequestId(hmacSecret, demoRequest.submissionId);

  const submissionIdDigest = createHash("sha256")
    .update(demoRequest.submissionId, "ascii")
    .digest("hex");
  const reservation = await reserve(dependencies.store, {
    submissionIdDigest,
    emailDigest: digestNormalizedEmail(hmacSecret, demoRequest.email),
    payloadDigest: digestNormalizedDemoRequest(demoRequest),
    requestId,
    leaseToken: dependencies.leaseToken(),
  });
  if (reservation.status === "rate_email") {
    throw new DemoRequestError(429, "Too many requests.", "rate_limited", 3_600);
  }
  if (reservation.status === "duplicate") {
    dependencies.metrics.recordDemoResult("accepted");
    return acceptedResponse(requiredReservationRequestId(reservation));
  }
  if (reservation.status === "pending") {
    unavailable();
  }
  if (reservation.status === "conflict") {
    throw new DemoRequestError(422, "Request payload is invalid.", "invalid");
  }

  const reservedRequestId = requiredReservationRequestId(reservation);
  const currentLeaseToken = reservation.leaseToken;
  if (!(await beginDelivery(dependencies.store, submissionIdDigest, currentLeaseToken))) {
    unavailable();
  }
  if (!demoRequest.honeypot) {
    try {
      const delivered = await deliverDemoWebhook({
        webhookUrl: dependencies.config.webhookUrl,
        hmacSecret,
        request: demoRequest,
        requestId: reservedRequestId,
        now: dependencies.now(),
        fetchImpl: dependencies.fetchImpl,
        parentSignal: request.signal
      });
      dependencies.metrics.recordWebhook(delivered.outcome, delivered.durationSeconds);
    } catch (error) {
      if (error instanceof DemoWebhookError) {
        dependencies.metrics.recordWebhook(error.outcome, error.durationSeconds);
      }
      await dependencies.store
        .release(submissionIdDigest, currentLeaseToken)
        .catch(() => false);
      unavailable();
    }
  }

  // Once dispatch begins, Redis retains a 24-hour `dispatching` guard. If the
  // final CAS acknowledgement is lost after a successful webhook, returning
  // the accepted response prevents a client retry while the guard prevents a
  // second delivery. Explicit webhook failures are released above.
  await dependencies.store
    .finalize(submissionIdDigest, currentLeaseToken)
    .catch(() => false);
  dependencies.metrics.recordDemoResult("accepted");
  return acceptedResponse(reservedRequestId);
}

async function consumeGlobal(
  store: DemoStore
): Promise<Awaited<ReturnType<DemoStore["consumeGlobal"]>>> {
  try {
    return await store.consumeGlobal();
  } catch {
    unavailable();
  }
}

async function beginDelivery(
  store: DemoStore,
  submissionIdDigest: string,
  leaseToken: string
): Promise<boolean> {
  try {
    return await store.beginDelivery(submissionIdDigest, leaseToken);
  } catch {
    unavailable();
  }
}

async function reserve(
  store: DemoStore,
  input: Parameters<DemoStore["reserve"]>[0]
): Promise<DemoReservation & { readonly leaseToken: string }> {
  try {
    const reservation = await store.reserve(input);
    return { ...reservation, leaseToken: input.leaseToken };
  } catch {
    unavailable();
  }
}

function requiredReservationRequestId(reservation: DemoReservation): string {
  if (reservation.requestId === undefined) {
    unavailable();
  }
  return reservation.requestId;
}

function acceptedResponse(requestId: string): Response {
  const body: DemoRequestAcceptedResponseV1 = { request_id: requestId };
  return jsonResponse(body, 202);
}

function errorResponse(status: number, message: string, retryAfterSeconds?: number): Response {
  const body: DemoRequestErrorResponseV1 = { error: message };
  const response = jsonResponse(body, status);
  if (retryAfterSeconds !== undefined) {
    response.headers.set("retry-after", String(retryAfterSeconds));
  }
  return response;
}

function jsonResponse(
  body: DemoRequestAcceptedResponseV1 | DemoRequestErrorResponseV1,
  status: number
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store, max-age=0, private",
      pragma: "no-cache",
      vary: "Origin, Sec-Fetch-Site",
      "x-content-type-options": "nosniff"
    }
  });
}

function unavailable(): never {
  throw new DemoRequestError(503, "Demo requests are unavailable.", "unavailable");
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}
