import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET as callback } from "../app/auth/callback/route";
import { GET as login } from "../app/auth/login/route";
import { resetAuthRateLimitForTests } from "./auth-rate-limit";
import { resetAuthStoreForTests } from "./auth-store";
import { resetOidcProviderCacheForTests } from "./oidc";

const issuer = "https://identity.example.test/realms/hallu-defense";
const rateCookieName = "__Host-hallu-auth-client";

describe("Console authentication route hardening", () => {
  beforeEach(() => {
    resetAuthStoreForTests();
    resetAuthRateLimitForTests();
    resetOidcProviderCacheForTests();
    stubProductionEnvironment();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("single-flights concurrent login discovery instead of amplifying provider traffic", async () => {
    let releaseFetch: (() => void) | undefined;
    const barrier = new Promise<void>((resolve) => {
      releaseFetch = resolve;
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      await barrier;
      return jsonResponse(discoveryDocument());
    });
    vi.stubGlobal("fetch", fetchImpl);
    const clientCookie = "R".repeat(43);
    const requests = Array.from({ length: 32 }, async () =>
      login(
        nextRequest("https://console.example.test/auth/login", {
          cookie: `${rateCookieName}=${clientCookie}`
        })
      )
    );

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    releaseFetch?.();
    const responses = await Promise.all(requests);
    expect(responses.every((response) => response.status === 302)).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("rate-limits callbacks despite spoofed forwarding headers and redacts callback values", async () => {
    vi.stubEnv("HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX", "1");
    const state = "sensitive-state-value-1234567890";
    const code = "sensitive-code-value-1234567890";
    const forgedRateCookie = `${"T".repeat(43)}.${"U".repeat(43)}`;
    const callbackUrl = `${callbackBase()}&state=${state}&code=${code}`;
    const first = await callback(
      nextRequest(callbackUrl, {
        "x-forwarded-for": "203.0.113.10",
        cookie: `${rateCookieName}=${forgedRateCookie}; __Host-hallu-oidc-state=${state}`
      })
    );
    const rateCookie = first.cookies.get(rateCookieName)?.value;

    expect(first.status).toBe(303);
    expect(first.headers.get("location")).toBe(
      "https://console.example.test/?auth_error=login_failed"
    );
    expect(first.headers.get("location")).not.toContain(state);
    expect(first.headers.get("location")).not.toContain(code);
    expect(rateCookie).toBeUndefined();

    const second = await callback(
      nextRequest(callbackUrl, {
        "x-forwarded-for": "198.51.100.20",
        cookie: `${rateCookieName}=attacker-rotated-cookie; __Host-hallu-oidc-state=${state}`
      })
    );
    const body = await second.text();
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBe("60");
    expect(body).not.toContain(state);
    expect(body).not.toContain(code);
    expect(body).not.toContain("attacker-rotated-cookie");
  });

  it("returns a generic unavailable response without exposing provider failures", async () => {
    const providerSecret = "client_secret=provider-secret-value";
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => {
        throw new Error(providerSecret);
      })
    );
    const response = await login(
      nextRequest("https://console.example.test/auth/login", {
        cookie: `${rateCookieName}=${"Q".repeat(43)}`
      })
    );
    const body = await response.text();

    expect(response.status).toBe(503);
    expect(body).toBe('{"error":"Authentication is unavailable."}');
    expect(body).not.toContain(providerSecret);
  });
});

function stubProductionEnvironment(): void {
  const env = {
    HALLU_DEFENSE_ENV: "production",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test",
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
    HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: issuer,
    HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
    HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
    HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier",
    HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX: "100",
    HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX: "100"
  } as const;
  for (const [name, value] of Object.entries(env)) {
    vi.stubEnv(name, value);
  }
}

function nextRequest(url: string, headers: Readonly<Record<string, string>>): NextRequest {
  return new NextRequest(url, { headers });
}

function callbackBase(): string {
  return `https://console.example.test/auth/callback?iss=${encodeURIComponent(issuer)}`;
}

function discoveryDocument(): Readonly<Record<string, unknown>> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"]
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
