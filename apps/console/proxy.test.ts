import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import {
  contentSecurityPolicy,
  proxy,
  requiresAuthenticatedRuntime
} from "./proxy";

describe("Console response security policy", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

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

  it.each([
    ["/", false],
    ["/en", false],
    ["/privacy", false],
    ["/demo-request", false],
    ["/metrics", false],
    ["/console", true],
    ["/console/runs", true],
    ["/auth/login", true],
    ["/api/verification/run", true]
  ])("classifies the runtime boundary for %s", (pathname, expected) => {
    expect(requiresAuthenticatedRuntime(pathname)).toBe(expected);
  });

  it.each(["/", "/en", "/privacy", "/en/privacy"])(
    "keeps public route %s available when the authenticated runtime is broken",
    (pathname) => {
      stubProductionPublicBoundaryWithBrokenConsoleRuntime();

      const response = proxy(
        new NextRequest(`https://console.example.test${pathname}`)
      );

      expect(response.status).toBe(200);
      expect(response.headers.get("x-middleware-next")).toBe("1");
      expect(response.headers.get("strict-transport-security")).toBe(
        "max-age=63072000; includeSubDomains; preload"
      );
    }
  );

  it.each(["/console", "/auth/session", "/api/verification/run"])(
    "fails closed with production security headers for private route %s",
    (pathname) => {
      stubProductionPublicBoundaryWithBrokenConsoleRuntime();

      const response = proxy(
        new NextRequest(`https://console.example.test${pathname}`)
      );

      expect(response.status).toBe(503);
      expect(response.headers.get("cache-control")).toBe("no-store, max-age=0");
      expect(response.headers.get("x-robots-tag")).toBe(
        "noindex, nofollow, noarchive"
      );
      expect(response.headers.get("content-security-policy")).toBe(
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
      );
      expect(response.headers.get("strict-transport-security")).toBe(
        "max-age=63072000; includeSubDomains; preload"
      );
    }
  );
});

function stubProductionPublicBoundaryWithBrokenConsoleRuntime(): void {
  vi.stubEnv("HALLU_DEFENSE_ENV", "production");
  vi.stubEnv(
    "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN",
    "https://console.example.test"
  );
  vi.stubEnv("HALLU_DEFENSE_CONSOLE_API_ORIGIN", "");
}
