import { createHmac, randomUUID } from "node:crypto";

const REQUEST_ID_DOMAIN = "hallu-defense.demo-request.request-id.v1\0";
const EMAIL_DIGEST_DOMAIN = "hallu-defense.demo-request.email-rate-limit.v1\0";

export function deriveDemoRequestId(secret: Uint8Array, submissionId: string): string {
  const digest = domainHmac(secret, REQUEST_ID_DOMAIN, submissionId)
    .subarray(0, 18)
    .toString("base64url");
  return `dr_${digest}`;
}

export function digestNormalizedEmail(secret: Uint8Array, email: string): string {
  return domainHmac(secret, EMAIL_DIGEST_DOMAIN, email).toString("hex");
}

export function createLeaseToken(): string {
  return randomUUID();
}

function domainHmac(secret: Uint8Array, domain: string, value: string): Buffer {
  return createHmac("sha256", secret).update(domain, "utf8").update(value, "utf8").digest();
}

