import { createSign, generateKeyPairSync } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET as callback } from "../app/auth/callback/route";
import { resetAuthRateLimitForTests } from "./auth-rate-limit";
import {
  consumeAuthorizationTransaction,
  createAuthorizationTransaction,
  createConsoleSession,
  getConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import { resetOidcProviderCacheForTests } from "./oidc";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

const consoleOrigin = "https://console.example.test";
const issuer = "https://identity.example.test/realms/hallu";
const sessionCookieName = "__Host-hallu-console-session";
const stateCookieName = "__Host-hallu-oidc-state";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "callback-rotation-key",
  use: "sig",
  alg: "RS256"
};

describe("OIDC callback Strict-session rotation", () => {
  beforeEach(() => {
    resetAuthStoreForTests();
    resetAuthRateLimitForTests();
    resetOidcProviderCacheForTests();
    stubEnvironment();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("revokes the transaction-bound prior session when the callback has no session cookie", async () => {
    const config = loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
    const prior = oldSession();
    const transaction = createAuthorizationTransaction(config, {
      priorSessionId: prior.sessionId
    });
    const fetchImpl = oidcFetch(transaction.nonce);
    vi.stubGlobal("fetch", fetchImpl);
    const request = callbackRequest(transaction.state, issuer);
    expect(request.cookies.get(sessionCookieName)).toBeUndefined();

    const response = await callback(request);
    const replacementId = response.cookies.get(sessionCookieName)?.value;
    if (replacementId === undefined) {
      throw new Error("Validated callback did not issue a replacement session.");
    }
    const replacement = getConsoleSession(replacementId);

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(`${consoleOrigin}/console`);
    expect(getConsoleSession(prior.sessionId)).toBeNull();
    expect(replacement).not.toBeNull();
    expect(replacement?.accessToken).toMatch(/^eyJ/u);
    expect(replacementId).not.toBe(prior.sessionId);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    const sessionSetCookie = response.headers
      .getSetCookie()
      .find((value) => value.startsWith(`${sessionCookieName}=`));
    expect(sessionSetCookie).toContain("HttpOnly");
    expect(sessionSetCookie).toContain("Secure");
    expect(sessionSetCookie?.toLowerCase()).toContain("samesite=strict");

    const replay = await callback(callbackRequest(transaction.state, issuer));
    expect(replay.status).toBe(303);
    expect(replay.headers.get("location")).toBe(
      `${consoleOrigin}/console?auth_error=login_failed`
    );
    expect(getConsoleSession(replacementId)).toBe(replacement);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("keeps the prior session when callback validation fails", async () => {
    const config = loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
    const prior = oldSession();
    const transaction = createAuthorizationTransaction(config, {
      priorSessionId: prior.sessionId
    });
    const fetchImpl = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchImpl);

    const response = await callback(
      callbackRequest(transaction.state, "https://identity.example.test/realms/other")
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      `${consoleOrigin}/console?auth_error=login_failed`
    );
    expect(response.cookies.get(sessionCookieName)).toBeUndefined();
    expect(getConsoleSession(prior.sessionId)).toBe(prior);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(() =>
      consumeAuthorizationTransaction(transaction.state, transaction.state)
    ).toThrow(/not found/u);
  });
});

function oldSession() {
  return createConsoleSession({
    accessToken: "old-stolen-session-token".padEnd(64, "x"),
    expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
    tenantId: "tenant-a",
    subjectId: "reviewer",
    roles: ["verifier"]
  });
}

function callbackRequest(state: string, responseIssuer: string): NextRequest {
  const url = new URL(`${consoleOrigin}/auth/callback`);
  url.searchParams.set("iss", responseIssuer);
  url.searchParams.set("state", state);
  url.searchParams.set("code", "authorization-code-with-sufficient-entropy");
  return new NextRequest(url, {
    headers: { cookie: `${stateCookieName}=${state}` }
  });
}

function oidcFetch(expectedNonce: string): ReturnType<typeof vi.fn<typeof fetch>> {
  const now = Math.floor(Date.now() / 1000);
  const idToken = signJwt({
    iss: issuer,
    aud: "hallu-defense-console",
    azp: "hallu-defense-console",
    sub: "reviewer",
    nonce: expectedNonce,
    iat: now,
    exp: now + 600,
    tenant_id: "tenant-a"
  });
  const accessToken = signJwt({
    iss: issuer,
    aud: "hallu-defense-api",
    azp: "hallu-defense-console",
    sub: "reviewer",
    iat: now,
    exp: now + 600,
    tenant_id: "tenant-a",
    roles: ["verifier"]
  });
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return jsonResponse({
        issuer,
        authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${issuer}/protocol/openid-connect/token`,
        jwks_uri: `${issuer}/protocol/openid-connect/certs`,
        end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
        code_challenge_methods_supported: ["S256"],
        response_types_supported: ["code"]
      });
    }
    if (url.endsWith("/protocol/openid-connect/token")) {
      return jsonResponse({
        token_type: "Bearer",
        access_token: accessToken,
        id_token: idToken
      });
    }
    if (url.endsWith("/protocol/openid-connect/certs")) {
      return jsonResponse({ keys: [publicJwk] });
    }
    throw new Error("Unexpected OIDC URL.");
  });
}

function signJwt(payload: Readonly<Record<string, unknown>>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid: publicJwk.kid }),
    "utf8"
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = `${header}.${body}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput, "ascii")
    .sign(privateKey, "base64url");
  return `${signingInput}.${signature}`;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}

function stubEnvironment(): void {
  const values = {
    HALLU_DEFENSE_ENV: "production",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: consoleOrigin,
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
    HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: issuer,
    HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
    HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
    HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier"
  } as const;
  for (const [name, value] of Object.entries(values)) {
    vi.stubEnv(name, value);
  }
}
