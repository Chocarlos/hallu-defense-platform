import { describe, expect, it } from "vitest";

import { parseBrowserSession } from "./browser-session";

const validSession = {
  csrfToken: "C".repeat(43),
  expiresAtSeconds: 2_000,
  tenantId: "tenant-a",
  subjectId: "reviewer",
  roles: ["verifier"]
} as const;

describe("browser session boundary", () => {
  it("accepts only non-credential session metadata", () => {
    expect(parseBrowserSession(validSession, 1_000)).toEqual(validSession);
  });

  it.each(["accessToken", "access_token", "idToken", "refresh_token"])(
    "fails closed when %s reaches browser JavaScript",
    (field) => {
      expect(() =>
        parseBrowserSession({ ...validSession, [field]: "secret-token" }, 1_000)
      ).toThrow(/forbidden credential/u);
    }
  );
});
