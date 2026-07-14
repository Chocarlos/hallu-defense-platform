import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET as callback } from "../app/auth/callback/route";
import { GET as login } from "../app/auth/login/route";
import { resetAuthRateLimitForTests } from "./auth-rate-limit";
import {
  AuthorizationStateError,
  authStoreCountsForTests,
  consumeAuthorizationTransaction,
  createAuthorizationTransaction,
  createConsoleSession,
  getConsoleSession,
  rotateConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import { resetOidcProviderCacheForTests } from "./oidc";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

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
          ...navigationHeaders(),
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
    const config = loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
    const firstTransaction = createAuthorizationTransaction(config);
    const secondTransaction = createAuthorizationTransaction(config);
    const code = "sensitive-code-value-1234567890";
    const forgedRateCookie = `${"T".repeat(43)}.${"U".repeat(43)}`;
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => {
      throw new Error("provider unavailable");
    }));
    const firstUrl = `${callbackBase()}&state=${firstTransaction.state}&code=${code}`;
    const first = await callback(
      nextRequest(firstUrl, {
        "x-forwarded-for": "203.0.113.10",
        cookie: `${rateCookieName}=${forgedRateCookie}; __Host-hallu-oidc-state=${firstTransaction.state}`
      })
    );
    const rateCookie = first.cookies.get(rateCookieName)?.value;

    expect(first.status).toBe(303);
    expect(first.headers.get("location")).toBe(
      "https://console.example.test/console?auth_error=login_failed"
    );
    expect(first.headers.get("location")).not.toContain(firstTransaction.state);
    expect(first.headers.get("location")).not.toContain(code);
    expect(rateCookie).toBeUndefined();

    const secondUrl = `${callbackBase()}&state=${secondTransaction.state}&code=${code}`;
    const second = await callback(
      nextRequest(secondUrl, {
        "x-forwarded-for": "198.51.100.20",
        cookie: `${rateCookieName}=attacker-rotated-cookie; __Host-hallu-oidc-state=${secondTransaction.state}`
      })
    );
    const body = await second.text();
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBe("60");
    expect(body).not.toContain(secondTransaction.state);
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
        ...navigationHeaders(),
        cookie: `${rateCookieName}=${"Q".repeat(43)}`
      })
    );
    const body = await response.text();

    expect(response.status).toBe(503);
    expect(body).toBe('{"error":"Authentication is unavailable."}');
    expect(body).not.toContain(providerSecret);
  });

  it("deletes a failed login transaction without rotating its prior session", async () => {
    const prior = createConsoleSession(tokenSet("prior-token"));
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => {
        throw new Error("provider unavailable");
      })
    );

    const response = await login(
      nextRequest("https://console.example.test/auth/login", {
        ...navigationHeaders(),
        cookie: `__Host-hallu-console-session=${prior.sessionId}`
      })
    );

    expect(response.status).toBe(503);
    expect(getConsoleSession(prior.sessionId)).toBe(prior);
    expect(authStoreCountsForTests()).toEqual({ transactions: 0, sessions: 1 });
  });

  it("rejects cross-site or subresource login initiation before provider traffic", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchImpl);
    const response = await login(
      nextRequest("https://console.example.test/auth/login", {
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-dest": "image"
      })
    );

    expect(response.status).toBe(403);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(response.cookies.get("__Host-hallu-oidc-state")).toBeUndefined();
  });

  it("captures the active prior session in the one-shot login transaction", async () => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => jsonResponse(discoveryDocument())));
    const prior = createConsoleSession({
      accessToken: "A".repeat(64),
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
      tenantId: "tenant-a",
      subjectId: "reviewer",
      roles: ["verifier"]
    });
    const response = await login(
      nextRequest("https://console.example.test/auth/login", {
        ...navigationHeaders(),
        cookie: `__Host-hallu-console-session=${prior.sessionId}`
      })
    );
    const state = response.cookies.get("__Host-hallu-oidc-state")?.value;
    if (state === undefined) {
      throw new Error("Login did not issue an OIDC state cookie.");
    }

    const transaction = consumeAuthorizationTransaction(state, state);
    expect(transaction.priorSessionId).toBe(prior.sessionId);
  });

  it("binds the prior session before discovery and fails a stale sibling closed", async () => {
    let releaseDiscovery: (() => void) | undefined;
    const discoveryBarrier = new Promise<void>((resolve) => {
      releaseDiscovery = resolve;
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      await discoveryBarrier;
      return jsonResponse(discoveryDocument());
    });
    vi.stubGlobal("fetch", fetchImpl);
    const config = loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
    const prior = createConsoleSession(tokenSet("prior-token"));

    const pendingLogin = login(
      nextRequest("https://console.example.test/auth/login", {
        ...navigationHeaders(),
        cookie: `__Host-hallu-console-session=${prior.sessionId}`
      })
    );
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));

    const competing = createAuthorizationTransaction(config, {
      priorSessionId: prior.sessionId
    });
    const winner = rotateConsoleSession(
      consumeAuthorizationTransaction(competing.state, competing.state),
      tokenSet("winner-token")
    );
    releaseDiscovery?.();

    const response = await pendingLogin;
    const state = response.cookies.get("__Host-hallu-oidc-state")?.value;
    if (state === undefined) {
      throw new Error("Login did not issue an OIDC state cookie.");
    }
    const stale = consumeAuthorizationTransaction(state, state);

    expect(stale.priorSessionId).toBe(prior.sessionId);
    expect(() => rotateConsoleSession(stale, tokenSet("orphan-token"))).toThrow(
      AuthorizationStateError
    );
    expect(getConsoleSession(winner.sessionId)).toBe(winner);
    expect(authStoreCountsForTests()).toEqual({ transactions: 0, sessions: 1 });
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
    end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"]
  };
}

function navigationHeaders(): Readonly<Record<string, string>> {
  return {
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document"
  };
}

function tokenSet(accessToken: string) {
  return {
    accessToken: accessToken.padEnd(32, "x"),
    expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
    tenantId: "tenant-a",
    subjectId: "reviewer",
    roles: ["verifier"]
  } as const;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
