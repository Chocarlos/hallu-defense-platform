import { describe, expect, it } from "vitest";

import { DEMO_PRIVACY_VERSION, DEMO_REQUEST_MAX_BYTES } from "../demo-request/contracts";
import {
  buildDemoRequestPayload,
  DEMO_EMAIL_MAX_LENGTH,
  DEMO_REQUEST_FORM_FALLBACK,
  parseAcceptedDemoResponse,
  serializeDemoRequest
} from "./demo-request";

const draft = {
  submissionId: "85e1ddda-05f3-45b8-a466-5f94fe024e97",
  locale: "en" as const,
  email: " owner@example.com ",
  name: " ",
  company: " Acme ",
  useCase: "code_agents" as const,
  consent: true,
  website: ""
};

describe("demo request payload", () => {
  it("matches the shared server contract and omits empty optional fields", () => {
    expect(buildDemoRequestPayload(draft)).toEqual({
      submission_id: draft.submissionId,
      locale: "en",
      email: "owner@example.com",
      company: "Acme",
      use_case: "code_agents",
      consent: true,
      privacy_version: DEMO_PRIVACY_VERSION,
      website: ""
    });
  });

  it("preserves the caller's submission id across retries", () => {
    expect(buildDemoRequestPayload(draft).submission_id).toBe(
      buildDemoRequestPayload(draft).submission_id
    );
  });

  it("rejects missing consent", () => {
    expect(() => buildDemoRequestPayload({ ...draft, consent: false })).toThrow(/consent/iu);
  });

  it("enforces the shared maximum request size in UTF-8 bytes", () => {
    const payload = buildDemoRequestPayload({
      ...draft,
      company: "x".repeat(DEMO_REQUEST_MAX_BYTES)
    });
    expect(() => serializeDemoRequest(payload)).toThrow(/maximum JSON size/iu);
  });

  it("defines a POST-only no-JS fallback without query parameters", () => {
    expect(DEMO_REQUEST_FORM_FALLBACK).toEqual({
      action: "/demo-request",
      method: "post"
    });
    expect(DEMO_REQUEST_FORM_FALLBACK.action).not.toContain("?");
    expect(DEMO_EMAIL_MAX_LENGTH).toBe(254);
  });
});

describe("accepted demo response", () => {
  const requestId = `dr_${"A".repeat(24)}`;

  it("returns the public request reference from the exact JSON contract", async () => {
    await expect(
      parseAcceptedDemoResponse(
        response(JSON.stringify({ request_id: requestId }))
      )
    ).resolves.toBe(requestId);
  });

  it.each([
    ["empty body", ""],
    ["malformed JSON", "{"],
    ["null", "null"],
    ["array", JSON.stringify([{ request_id: requestId }])],
    ["missing key", JSON.stringify({})],
    ["wrong type", JSON.stringify({ request_id: 42 })],
    ["wrong prefix", JSON.stringify({ request_id: `id_${"A".repeat(24)}` })],
    ["wrong length", JSON.stringify({ request_id: "dr_short" })],
    ["extra key", JSON.stringify({ request_id: requestId, accepted: true })]
  ])("rejects %s", async (_label, body) => {
    await expect(parseAcceptedDemoResponse(response(body))).rejects.toThrow(
      /response is invalid/iu
    );
  });

  it("rejects a malformed 202 media type and any non-202 status", async () => {
    await expect(
      parseAcceptedDemoResponse(
        response(JSON.stringify({ request_id: requestId }), {
          contentType: "text/plain"
        })
      )
    ).rejects.toThrow(/response is invalid/iu);
    await expect(
      parseAcceptedDemoResponse(
        response(JSON.stringify({ request_id: requestId }), { status: 200 })
      )
    ).rejects.toThrow(/response is invalid/iu);
  });
});

function response(
  body: string,
  options: { readonly contentType?: string; readonly status?: number } = {}
): Response {
  return new Response(body, {
    status: options.status ?? 202,
    headers: { "content-type": options.contentType ?? "application/json; charset=utf-8" }
  });
}
