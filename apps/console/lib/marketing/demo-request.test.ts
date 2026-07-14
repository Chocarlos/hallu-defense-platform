import { describe, expect, it } from "vitest";

import { DEMO_PRIVACY_VERSION, DEMO_REQUEST_MAX_BYTES } from "../demo-request/contracts";
import { buildDemoRequestPayload, serializeDemoRequest } from "./demo-request";

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
});
