import { describe, expect, it } from "vitest";

import { DEMO_REQUEST_MAX_BYTES, DEMO_USE_CASES } from "./contracts";
import { readAndNormalizeDemoRequest, validateDemoRequestSource } from "./request";

const origin = "https://defense.example.test";

describe("demo request boundary", () => {
  it("normalizes the closed public schema and preserves the canonical code_agents enum", async () => {
    expect(DEMO_USE_CASES).toContain("code_agents");
    const request = validRequest({
      email: "  SECURITY@Example.Invalid ",
      name: "  Ada   Lovelace ",
      company: "   ",
      use_case: "code_agents"
    });

    validateDemoRequestSource(request, origin);
    await expect(readAndNormalizeDemoRequest(request)).resolves.toEqual({
      submissionId: "123e4567-e89b-42d3-a456-426614174000",
      locale: "es",
      email: "security@example.invalid",
      name: "Ada Lovelace",
      useCase: "code_agents",
      consent: true,
      privacyVersion: "privacy.v1",
      honeypot: false
    });
  });

  it.each([
    { header: "origin", value: "https://attacker.example.test" },
    { header: "sec-fetch-site", value: "cross-site" },
    { header: "sec-fetch-mode", value: "navigate" },
    { header: "sec-fetch-dest", value: "document" }
  ])("rejects invalid browser provenance: $header", ({ header, value }) => {
    const request = validRequest({}, { [header]: value });
    expect(() => validateDemoRequestSource(request, origin)).toThrow(
      expect.objectContaining({ status: 400 })
    );
  });

  it("rejects missing Fetch Metadata and query strings", () => {
    const missing = validRequest({}, { "sec-fetch-site": null });
    const query = validRequest({}, {}, `${origin}/demo-request?source=campaign`);
    expect(() => validateDemoRequestSource(missing, origin)).toThrow(
      expect.objectContaining({ status: 400 })
    );
    expect(() => validateDemoRequestSource(query, origin)).toThrow(
      expect.objectContaining({ status: 400 })
    );
  });

  it.each([
    "text/plain",
    "application/problem+json",
    "application/json; charset=iso-8859-1",
    "application/json; profile=unexpected",
    ""
  ])(
    "returns 415 semantics for an invalid media type: %s",
    async (contentType) => {
      const request = validRequest({}, { "content-type": contentType });
      await expect(readAndNormalizeDemoRequest(request)).rejects.toMatchObject({
        status: 415
      });
    }
  );

  it("accepts an explicit UTF-8 JSON charset", async () => {
    await expect(
      readAndNormalizeDemoRequest(
        validRequest({}, { "content-type": 'application/json; charset="UTF-8"' })
      )
    ).resolves.toMatchObject({ email: "security@example.invalid" });
  });

  it("enforces 8192 bytes against declared and streamed bodies", async () => {
    const json = JSON.stringify(validPayload());
    const exactBody = `${json}${" ".repeat(DEMO_REQUEST_MAX_BYTES - Buffer.byteLength(json))}`;
    await expect(readAndNormalizeDemoRequest(validRequest({}, {}, undefined, exactBody))).resolves
      .toMatchObject({ locale: "es" });

    const oversizedBody = `${json}${" ".repeat(
      DEMO_REQUEST_MAX_BYTES + 1 - Buffer.byteLength(json)
    )}`;
    await expect(
      readAndNormalizeDemoRequest(validRequest({}, {}, undefined, oversizedBody))
    ).rejects.toMatchObject({ status: 400 });
    await expect(
      readAndNormalizeDemoRequest(
        validRequest({}, { "content-length": String(DEMO_REQUEST_MAX_BYTES + 1) })
      )
    ).rejects.toMatchObject({ status: 400 });
    await expect(
      readAndNormalizeDemoRequest(validRequest({}, { "content-length": "1" }))
    ).rejects.toMatchObject({ status: 400 });
  });

  it.each([
    { consent: false },
    { privacy_version: "privacy.v2" },
    { use_case: "other" },
    { locale: "fr" },
    { submission_id: "not-a-uuid" },
    { email: "invalid@example" },
    { name: "x".repeat(101) },
    { company: "x".repeat(121) },
    { unexpected: "field" }
  ])("returns 422 semantics for an invalid schema: %j", async (override) => {
    await expect(readAndNormalizeDemoRequest(validRequest(override))).rejects.toMatchObject({
      status: 422
    });
  });

  it("detects a populated honeypot after otherwise valid validation", async () => {
    await expect(readAndNormalizeDemoRequest(validRequest({ website: "bot.invalid" }))).resolves
      .toMatchObject({ honeypot: true });
  });
});

function validPayload(overrides: Readonly<Record<string, unknown>> = {}) {
  return {
    submission_id: "123e4567-e89b-42d3-a456-426614174000",
    locale: "es",
    email: "security@example.invalid",
    use_case: "rag_verification",
    consent: true,
    privacy_version: "privacy.v1",
    website: "",
    ...overrides
  };
}

function validRequest(
  overrides: Readonly<Record<string, unknown>> = {},
  headerOverrides: Readonly<Record<string, string | null>> = {},
  url: string = `${origin}/demo-request`,
  body?: string
): Request {
  const headers = new Headers({
    origin,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "content-type": "application/json"
  });
  for (const [name, value] of Object.entries(headerOverrides)) {
    if (value === null) {
      headers.delete(name);
    } else {
      headers.set(name, value);
    }
  }
  return new Request(url, {
    method: "POST",
    headers,
    body: body ?? JSON.stringify(validPayload(overrides))
  });
}
