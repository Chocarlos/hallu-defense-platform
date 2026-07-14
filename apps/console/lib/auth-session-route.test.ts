import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET as getAuthSession } from "../app/auth/session/route";
import {
  createConsoleSession,
  getConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

const consoleOrigin = "https://console.example.test";
const oidcRuntimeDrifts = [
  [
    "issuer",
    "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER",
    "https://identity.example.test/realms/rotated"
  ],
  ["client", "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID", "rotated-console"],
  ["audience", "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE", "rotated-api"],
  [
    "API origin",
    "HALLU_DEFENSE_CONSOLE_API_ORIGIN",
    "https://api-rotated.example.test"
  ],
  [
    "required roles",
    "HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES",
    "verifier,approval_reviewer"
  ]
] as const;

describe("Console browser session route", () => {
  beforeEach(() => resetAuthStoreForTests());
  afterEach(() => vi.unstubAllEnvs());

  it("returns identity and CSRF metadata without OAuth credentials", async () => {
    stubOidcEnvironment();
    const session = createConsoleSession(currentOidcConfig(), {
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
    expect(payload).not.toHaveProperty("runtimeFingerprint");
  });

  it.each(oidcRuntimeDrifts)(
    "invalidates an existing session when the OIDC %s changes",
    async (_label, name, value) => {
      stubOidcEnvironment();
      const session = createConsoleSession(currentOidcConfig(), {
        accessToken: "S".repeat(64),
        expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
        tenantId: "tenant-a",
        subjectId: "reviewer",
        roles: ["approval_reviewer", "verifier"]
      });
      vi.stubEnv(name, value);

      const response = await getAuthSession(
        new NextRequest(`${consoleOrigin}/auth/session`, {
          headers: {
            cookie: `__Host-hallu-console-session=${session.sessionId}`
          }
        })
      );
      const body = await response.text();

      expect(response.status).toBe(401);
      expect(response.headers.get("set-cookie")).toContain(
        "__Host-hallu-console-session=;"
      );
      expect(body).not.toContain(session.csrfToken);
      expect(body).not.toContain(session.runtimeFingerprint);
      expect(getConsoleSession(session.sessionId)).toBeNull();
    }
  );

  it("invalidates a legacy session without a runtime fingerprint", async () => {
    stubOidcEnvironment();
    const session = createConsoleSession(currentOidcConfig(), {
      accessToken: "S".repeat(64),
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
      tenantId: "tenant-a",
      subjectId: "reviewer",
      roles: ["verifier"]
    });
    delete (session as { runtimeFingerprint?: string }).runtimeFingerprint;

    const response = await getAuthSession(
      new NextRequest(`${consoleOrigin}/auth/session`, {
        headers: {
          cookie: `__Host-hallu-console-session=${session.sessionId}`
        }
      })
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("set-cookie")).toContain(
      "__Host-hallu-console-session=;"
    );
    expect(getConsoleSession(session.sessionId)).toBeNull();
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

  it("remints an unsigned-local session when its configured identity changes", async () => {
    stubUnsignedLocalEnvironment();
    const initial = await getAuthSession(
      new NextRequest("http://127.0.0.1:3100/auth/session")
    );
    const priorSessionId = initial.cookies.get("hallu-console-session")?.value;
    if (priorSessionId === undefined) {
      throw new Error("Unsigned-local session cookie was not created.");
    }
    vi.stubEnv("HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID", "rotated-reviewer");

    const replacement = await getAuthSession(
      new NextRequest("http://127.0.0.1:3100/auth/session", {
        headers: { cookie: `hallu-console-session=${priorSessionId}` }
      })
    );
    const payload = (await replacement.json()) as Record<string, unknown>;
    const replacementId = replacement.cookies.get("hallu-console-session")?.value;

    expect(replacement.status).toBe(200);
    expect(payload.subjectId).toBe("rotated-reviewer");
    expect(payload).not.toHaveProperty("runtimeFingerprint");
    expect(replacementId).toBeDefined();
    expect(replacementId).not.toBe(priorSessionId);
    expect(getConsoleSession(priorSessionId)).toBeNull();
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

function currentOidcConfig(): ConsoleOidcRuntimeConfig {
  return loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
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
