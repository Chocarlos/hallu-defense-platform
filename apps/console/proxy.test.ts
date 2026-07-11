import { describe, expect, it } from "vitest";

import { contentSecurityPolicy } from "./proxy";

describe("Console response security policy", () => {
  it("binds scripts and styles to a nonce and denies framing", () => {
    const policy = contentSecurityPolicy(
      "test-nonce",
      true
    );

    expect(policy).toContain("script-src 'nonce-test-nonce' 'strict-dynamic'");
    expect(policy).toContain("style-src 'self' 'nonce-test-nonce'");
    expect(policy).toContain("connect-src 'self'");
    expect(policy).not.toContain("https://api.example.test");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("upgrade-insecure-requests");
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("https://cdn.");
  });
});
