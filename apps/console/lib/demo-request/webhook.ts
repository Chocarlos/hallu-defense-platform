import { createHmac } from "node:crypto";

import {
  DEMO_RETENTION_DAYS,
  DEMO_WEBHOOK_SCHEMA_VERSION,
  type DemoWebhookPayload,
  type NormalizedDemoRequest
} from "./contracts";
import type { WebhookOutcome } from "./metrics";

export const DEMO_WEBHOOK_TIMEOUT_MILLISECONDS = 5_000;

export interface WebhookDeliveryInput {
  readonly webhookUrl: string;
  readonly hmacSecret: Uint8Array;
  readonly request: NormalizedDemoRequest;
  readonly requestId: string;
  readonly now: Date;
  readonly fetchImpl: typeof fetch;
  readonly parentSignal?: AbortSignal;
  readonly timeoutMilliseconds?: number;
}

export interface WebhookDeliveryResult {
  readonly outcome: "success";
  readonly durationSeconds: number;
}

export class DemoWebhookError extends Error {
  constructor(
    readonly outcome: Exclude<WebhookOutcome, "success">,
    readonly durationSeconds: number
  ) {
    super("Demo webhook is unavailable.");
    this.name = "DemoWebhookError";
  }
}

export async function deliverDemoWebhook(
  input: WebhookDeliveryInput
): Promise<WebhookDeliveryResult> {
  const payload = buildWebhookPayload(input.request, input.now);
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  const timestamp = String(Math.floor(input.now.getTime() / 1_000));
  const signature = createHmac("sha256", input.hmacSecret)
    .update(timestamp, "ascii")
    .update(".", "ascii")
    .update(body)
    .digest("hex");
  const timeoutMilliseconds =
    input.timeoutMilliseconds ?? DEMO_WEBHOOK_TIMEOUT_MILLISECONDS;
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(), timeoutMilliseconds);
  const signal = input.parentSignal
    ? AbortSignal.any([input.parentSignal, timeoutController.signal])
    : timeoutController.signal;
  const startedAt = performance.now();

  try {
    let response: Response;
    try {
      response = await input.fetchImpl(input.webhookUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Hallu-Timestamp": timestamp,
          "X-Hallu-Signature": `sha256=${signature}`,
          "Idempotency-Key": input.request.submissionId,
          "X-Hallu-Request-Id": input.requestId
        },
        body,
        cache: "no-store",
        redirect: "error",
        signal
      });
    } catch {
      const durationSeconds = elapsedSeconds(startedAt);
      throw new DemoWebhookError(
        timeoutController.signal.aborted ? "timeout" : "network_error",
        durationSeconds
      );
    }
    await response.body?.cancel().catch(() => undefined);
    if (!response.ok) {
      throw new DemoWebhookError("http_error", elapsedSeconds(startedAt));
    }
    return { outcome: "success", durationSeconds: elapsedSeconds(startedAt) };
  } finally {
    clearTimeout(timeout);
  }
}

export function buildWebhookPayload(
  request: NormalizedDemoRequest,
  now: Date
): DemoWebhookPayload {
  const submittedAt = now.toISOString();
  return {
    schema_version: DEMO_WEBHOOK_SCHEMA_VERSION,
    submitted_at: submittedAt,
    locale: request.locale,
    contact: {
      email: request.email,
      ...(request.name === undefined ? {} : { name: request.name }),
      ...(request.company === undefined ? {} : { company: request.company })
    },
    use_case: request.useCase,
    consent: {
      accepted: true,
      privacy_version: request.privacyVersion,
      accepted_at: submittedAt
    },
    retention_days: DEMO_RETENTION_DAYS
  };
}

function elapsedSeconds(startedAt: number): number {
  return Math.max(0, (performance.now() - startedAt) / 1_000);
}
