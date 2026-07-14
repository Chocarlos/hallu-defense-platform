import { describe, expect, it } from "vitest";

import type { NormalizedDemoRequest } from "./contracts";
import {
  digestNormalizedDemoRequest,
  digestNormalizedEmail
} from "./identity";

const secret = Buffer.from("x".repeat(48), "utf8");
const request: NormalizedDemoRequest = {
  submissionId: "123e4567-e89b-42d3-a456-426614174000",
  locale: "en",
  email: "person@example.invalid",
  name: "Ada",
  company: "Analytical Engines",
  useCase: "code_agents",
  consent: true,
  privacyVersion: "privacy.v1",
  honeypot: false
};
const changedRequests: readonly NormalizedDemoRequest[] = [
  { ...request, email: "other@example.invalid" },
  { ...request, name: "Grace" },
  { ...request, company: "Difference Engines" },
  { ...request, useCase: "enterprise_governance" }
];

describe("demo request Redis identities", () => {
  it("creates a stable domain-separated payload HMAC without retaining PII", () => {
    const digest = digestNormalizedDemoRequest(request);
    expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(digestNormalizedDemoRequest(request)).toBe(digest);
    expect(digest).not.toContain(request.email);
    expect(digest).not.toBe(digestNormalizedEmail(secret, request.email));
  });

  it.each(changedRequests)("changes when an idempotency-bound field changes: %j", (changed) => {
    expect(digestNormalizedDemoRequest(changed)).not.toBe(
      digestNormalizedDemoRequest(request)
    );
  });

  it("remains stable when the independently managed webhook secret rotates", () => {
    const beforeRotation = digestNormalizedDemoRequest(request);
    expect(digestNormalizedEmail(secret, request.email)).not.toBe(
      digestNormalizedEmail(Buffer.from("y".repeat(48), "utf8"), request.email)
    );
    expect(digestNormalizedDemoRequest(request)).toBe(beforeRotation);
  });
});
