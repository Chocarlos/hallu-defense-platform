import { describe, expect, it } from "vitest";

import { buildDemoRequestPayload } from "../marketing/demo-request";
import { normalizeDemoRequest } from "./request";
import { isDemoRequestAcceptedResponseV1 } from "./public-contract";

describe("demo request public contract v1", () => {
  it("keeps the marketing builder and server parser on the same wire shape", () => {
    const payload = buildDemoRequestPayload({
      submissionId: "123e4567-e89b-42d3-a456-426614174000",
      locale: "en",
      email: " Evidence@Example.Invalid ",
      name: " Ada ",
      company: " Hallu Defense ",
      useCase: "enterprise_governance",
      consent: true,
      website: ""
    });

    expect(normalizeDemoRequest(payload)).toEqual({
      submissionId: "123e4567-e89b-42d3-a456-426614174000",
      locale: "en",
      email: "evidence@example.invalid",
      name: "Ada",
      company: "Hallu Defense",
      useCase: "enterprise_governance",
      consent: true,
      privacyVersion: "privacy.v1",
      honeypot: false
    });
  });

  it("accepts only the exact generic success envelope", () => {
    expect(
      isDemoRequestAcceptedResponseV1({
        request_id: "dr_AbCdEfGhIjKlMnOpQrStUvWx"
      })
    ).toBe(true);
    expect(
      isDemoRequestAcceptedResponseV1({
        request_id: "dr_AbCdEfGhIjKlMnOpQrStUvWx",
        email: "pii@example.invalid"
      })
    ).toBe(false);
    expect(isDemoRequestAcceptedResponseV1({ request_id: "internal-uuid" })).toBe(false);
  });
});
