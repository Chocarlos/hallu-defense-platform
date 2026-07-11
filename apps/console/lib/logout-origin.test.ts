import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { isTrustedLogoutRequest } from "./request-security";

const expectedOrigin = "https://console.example.test";

describe("Console logout origin validation", () => {
  it("accepts an exact Origin", () => {
    expect(requestIsTrusted({ origin: expectedOrigin })).toBe(true);
  });

  it.each([
    { origin: "https://attacker.example.test" },
    {
      origin: expectedOrigin,
      "sec-fetch-site": "cross-site",
      "sec-fetch-mode": "navigate",
      "sec-fetch-user": "?1"
    },
    {
      origin: expectedOrigin,
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "sec-fetch-user": "?1"
    },
    { referer: "https://attacker.example.test/form" },
    {}
  ])("rejects an untrusted mutation: %j", (headers) => {
    expect(requestIsTrusted(headers)).toBe(false);
  });
});

function requestIsTrusted(headers: Readonly<Record<string, string>>): boolean {
  return isTrustedLogoutRequest(
    new NextRequest(`${expectedOrigin}/auth/logout`, {
      method: "POST",
      headers
    }),
    expectedOrigin
  );
}
