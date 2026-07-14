import { createHmac, randomUUID } from "node:crypto";

import type { NormalizedDemoRequest } from "./contracts";

const REQUEST_ID_DOMAIN = "hallu-defense.demo-request.request-id.v1\0";
const EMAIL_DIGEST_DOMAIN = "hallu-defense.demo-request.email-rate-limit.v1\0";
const PAYLOAD_DIGEST_DOMAIN = "hallu-defense.demo-request.payload-idempotency.v1\0";

export function deriveDemoRequestId(secret: Uint8Array, submissionId: string): string {
  const digest = domainHmac(secret, REQUEST_ID_DOMAIN, submissionId)
    .subarray(0, 18)
    .toString("base64url");
  return `dr_${digest}`;
}

export function digestNormalizedEmail(secret: Uint8Array, email: string): string {
  return domainHmac(secret, EMAIL_DIGEST_DOMAIN, email).toString("hex");
}

export function digestNormalizedDemoRequest(
  request: NormalizedDemoRequest
): string {
  const canonicalPayload = JSON.stringify([
    request.locale,
    request.email,
    request.name ?? null,
    request.company ?? null,
    request.useCase,
    request.consent,
    request.privacyVersion
  ]);
  // The random UUIDv4 is not persisted in Redis (only its SHA-256 key is).
  // Using it as the per-submission HMAC key keeps contact data resistant to
  // offline guessing from Redis alone while preserving the full 24-hour
  // idempotency window across webhook-secret rotation.
  return domainHmac(
    Buffer.from(request.submissionId, "ascii"),
    PAYLOAD_DIGEST_DOMAIN,
    canonicalPayload
  ).toString("hex");
}

export function createLeaseToken(): string {
  return randomUUID();
}

function domainHmac(secret: Uint8Array, domain: string, value: string): Buffer {
  return createHmac("sha256", secret).update(domain, "utf8").update(value, "utf8").digest();
}

