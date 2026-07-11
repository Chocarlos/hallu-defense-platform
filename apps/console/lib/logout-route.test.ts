import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { POST as logout } from "../app/auth/logout/route";
import {
  createConsoleSession,
  getConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import { resetOidcProviderCacheForTests } from "./oidc";

const consoleOrigin = "https://console.example.test";
const issuer = "https://identity.example.test/realms/hallu";

describe("Console provider logout", () => {
  beforeEach(() => {
    resetAuthStoreForTests();
    resetOidcProviderCacheForTests();
    stubEnvironment();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("invalidates locally before redirecting to the validated end-session endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        new Response(
          JSON.stringify({
            issuer,
            authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
            token_endpoint: `${issuer}/protocol/openid-connect/token`,
            jwks_uri: `${issuer}/protocol/openid-connect/certs`,
            end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
            code_challenge_methods_supported: ["S256"],
            response_types_supported: ["code"]
          }),
          { headers: { "content-type": "application/json" } }
        )
      )
    );
    const session = createConsoleSession({
      accessToken: "T".repeat(64),
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
      tenantId: "tenant-a",
      subjectId: "reviewer",
      roles: ["verifier"]
    });
    const response = await logout(
      new NextRequest(`${consoleOrigin}/auth/logout`, {
        method: "POST",
        headers: {
          origin: consoleOrigin,
          "sec-fetch-site": "same-origin",
          "sec-fetch-mode": "navigate",
          cookie: `__Host-hallu-console-session=${session.sessionId}`
        }
      })
    );
    const location = response.headers.get("location") ?? "";

    expect(response.status).toBe(303);
    expect(location).toContain(`${issuer}/protocol/openid-connect/logout?`);
    expect(location).toContain("client_id=hallu-defense-console");
    expect(location).toContain(
      `post_logout_redirect_uri=${encodeURIComponent(consoleOrigin)}`
    );
    expect(location).not.toContain(session.accessToken ?? "unreachable");
    expect(getConsoleSession(session.sessionId)).toBeNull();
    expect(response.headers.get("set-cookie")).toContain(
      "__Host-hallu-console-session=;"
    );
  });
});

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
