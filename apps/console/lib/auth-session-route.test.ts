import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET as getAuthSession } from "../app/auth/session/route";
import { createConsoleSession, resetAuthStoreForTests } from "./auth-store";

const consoleOrigin = "https://console.example.test";

describe("Console browser session route", () => {
  beforeEach(() => resetAuthStoreForTests());
  afterEach(() => vi.unstubAllEnvs());

  it("returns identity and CSRF metadata without OAuth credentials", async () => {
    stubOidcEnvironment();
    const session = createConsoleSession({
      accessToken: "S".repeat(64),
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
      tenantId: "tenant-a",
      subjectId: "reviewer",
      roles: ["verifier"]
    });
    const response = await getAuthSession(
      new NextRequest(`${consoleOrigin}/auth/session`, {
        headers: {
          cookie: `__Host-hallu-console-session=${session.sessionId}`
        }
      })
    );
    const text = await response.text();
    const payload = JSON.parse(text) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(payload.csrfToken).toBe(session.csrfToken);
    expect(payload.tenantId).toBe("tenant-a");
    expect(text).not.toContain(session.accessToken ?? "unreachable");
    expect(payload).not.toHaveProperty("accessToken");
    expect(payload).not.toHaveProperty("idToken");
    expect(payload).not.toHaveProperty("refreshToken");
  });

  it("creates a server-controlled unsigned-local session without browser identity input", async () => {
    stubUnsignedLocalEnvironment();
    const response = await getAuthSession(
      new NextRequest("http://127.0.0.1:3100/auth/session")
    );
    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.tenantId).toBe("tenant-a");
    expect(payload.subjectId).toBe("local-reviewer");
    expect(payload.roles).toEqual(["verifier"]);
    expect(response.headers.get("set-cookie")).toContain("hallu-console-session=");
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("SameSite=strict");
  });

  it("expires an unknown OIDC session cookie on 401", async () => {
    stubOidcEnvironment();
    const response = await getAuthSession(
      new NextRequest(`${consoleOrigin}/auth/session`, {
        headers: { cookie: `__Host-hallu-console-session=${"X".repeat(43)}` }
      })
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("set-cookie")).toContain(
      "__Host-hallu-console-session=;"
    );
  });
});

function stubOidcEnvironment(): void {
  stub({
    HALLU_DEFENSE_ENV: "production",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: consoleOrigin,
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
    HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://identity.example.test/realms/hallu",
    HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
    HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
    HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier"
  });
}

function stubUnsignedLocalEnvironment(): void {
  stub({
    HALLU_DEFENSE_ENV: "test",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3100",
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:8100",
    HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
    HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
    HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-a",
    HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "local-reviewer",
    HALLU_DEFENSE_CONSOLE_LOCAL_ROLES: "verifier"
  });
}

function stub(values: Readonly<Record<string, string>>): void {
  for (const [name, value] of Object.entries(values)) {
    vi.stubEnv(name, value);
  }
}
