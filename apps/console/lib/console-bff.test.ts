import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import {
  createConsoleSession,
  createUnsignedLocalConsoleSession,
  getConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import { forwardConsoleApiRequest } from "./console-bff";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig,
  type ConsoleUnsignedLocalRuntimeConfig
} from "./runtime-config";

const consoleOrigin = "https://console.example.test";
const sessionCookie = "__Host-hallu-console-session";
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

describe("Console same-origin BFF", () => {
  beforeEach(() => {
    resetAuthStoreForTests();
    stubEnvironment();
  });

  afterEach(() => vi.unstubAllEnvs());

  it("adds the server-side bearer and drops browser-controlled identity headers", async () => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toBe(`Bearer ${"A".repeat(64)}`);
      expect(headers.get("x-tenant-id")).toBeNull();
      expect(headers.get("x-subject-id")).toBeNull();
      expect(headers.get("x-roles")).toBeNull();
      return jsonResponse({ approvals: [], trace_id: "tr_live" });
    });
    const response = await forwardConsoleApiRequest(
      request(session, {
        authorization: "Bearer browser-attacker-token",
        "x-tenant-id": "attacker",
        "x-subject-id": "attacker",
        "x-roles": "admin"
      }),
      ["approvals", "list"],
      fetchImpl
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ approvals: [], trace_id: "tr_live" });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it.each(oidcRuntimeDrifts)(
    "invalidates before forwarding when the OIDC %s changes",
    async (_label, name, value) => {
      const session = oidcSession();
      vi.stubEnv(name, value);
      const fetchImpl = vi.fn<typeof fetch>();

      const response = await forwardConsoleApiRequest(
        request(session),
        ["approvals", "list"],
        fetchImpl
      );

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "Authentication is required." });
      expect(response.headers.get("set-cookie")).toContain(`${sessionCookie}=`);
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(getConsoleSession(session.sessionId)).toBeNull();
    }
  );

  it("fails a legacy session without a runtime fingerprint closed", async () => {
    const session = oidcSession();
    delete (session as { runtimeFingerprint?: string }).runtimeFingerprint;
    const fetchImpl = vi.fn<typeof fetch>();

    const response = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      fetchImpl
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("set-cookie")).toContain(`${sessionCookie}=`);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(getConsoleSession(session.sessionId)).toBeNull();
  });

  it("forwards unsigned-local identity only while its runtime binding matches", async () => {
    stubUnsignedLocalEnvironment();
    const config = currentUnsignedLocalConfig();
    const session = createUnsignedLocalConsoleSession(config);
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const headers = new Headers(init?.headers);
      expect(String(input)).toBe("http://127.0.0.1:8100/approvals/list");
      expect(headers.get("authorization")).toBeNull();
      expect(headers.get("x-tenant-id")).toBe("tenant-a");
      expect(headers.get("x-subject-id")).toBe("local-reviewer");
      expect(headers.get("x-roles")).toBe("verifier");
      return jsonResponse({ approvals: [], trace_id: "tr_local" });
    });

    const response = await forwardConsoleApiRequest(
      localRequest(session),
      ["approvals", "list"],
      fetchImpl
    );

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it.each([
    ["API origin", "HALLU_DEFENSE_CONSOLE_API_ORIGIN", "http://127.0.0.1:8200"],
    [
      "identity",
      "HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID",
      "rotated-reviewer"
    ]
  ] as const)(
    "rejects an unsigned-local session before forwarding when %s changes",
    async (_label, name, value) => {
      stubUnsignedLocalEnvironment();
      const session = createUnsignedLocalConsoleSession(
        currentUnsignedLocalConfig()
      );
      vi.stubEnv(name, value);
      const fetchImpl = vi.fn<typeof fetch>();

      const response = await forwardConsoleApiRequest(
        localRequest(session),
        ["approvals", "list"],
        fetchImpl
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("set-cookie")).toContain(
        "hallu-console-session=;"
      );
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(getConsoleSession(session.sessionId)).toBeNull();
    }
  );

  it.each([
    { origin: "https://attacker.example.test", csrf: "valid" },
    { origin: consoleOrigin, csrf: "invalid" }
  ])("rejects untrusted origin or CSRF before upstream fetch: %j", async (input) => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>();
    const response = await forwardConsoleApiRequest(
      request(session, {
        origin: input.origin,
        "x-console-csrf": input.csrf === "valid" ? session.csrfToken : "invalid"
      }),
      ["approvals", "list"],
      fetchImpl
    );

    expect(response.status).toBe(403);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("sanitizes upstream failures and invalidates a rejected session", async () => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      jsonResponse({ detail: "Bearer secret-token-value" }, 401)
    );
    const response = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      fetchImpl
    );
    const body = await response.text();

    expect(response.status).toBe(401);
    expect(body).not.toContain("secret-token-value");
    expect(response.headers.get("set-cookie")).toContain(`${sessionCookie}=`);
    expect(getConsoleSession(session.sessionId)).toBeNull();
  });

  it("never forwards a raw 5xx body", async () => {
    const session = oidcSession();
    const response = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      vi.fn<typeof fetch>(async () =>
        jsonResponse({ detail: "database password=upstream-secret" }, 503)
      )
    );
    const body = await response.text();

    expect(response.status).toBe(503);
    expect(body).toBe('{"error":"Console API is unavailable."}');
    expect(body).not.toContain("upstream-secret");
    expect(getConsoleSession(session.sessionId)).not.toBeNull();
  });

  it("rejects non-allowlisted paths and oversized declared bodies", async () => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>();
    const unknown = await forwardConsoleApiRequest(
      request(session),
      ["admin", "secrets"],
      fetchImpl
    );
    const oversized = await forwardConsoleApiRequest(
      request(session, { "content-length": String(1024 * 1024 + 1) }),
      ["approvals", "list"],
      fetchImpl
    );

    expect(unknown.status).toBe(404);
    expect(oversized.status).toBe(400);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects invalid media types, non-object JSON, and streamed oversized bodies", async () => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>();
    const invalidMediaType = await forwardConsoleApiRequest(
      request(session, { "content-type": "text/plain" }),
      ["approvals", "list"],
      fetchImpl
    );
    const nonObjectJson = await forwardConsoleApiRequest(
      request(session, {}, "[]"),
      ["approvals", "list"],
      fetchImpl
    );
    const streamedOversized = await forwardConsoleApiRequest(
      request(session, {}, `{"value":"${"x".repeat(1024 * 1024)}"}`),
      ["approvals", "list"],
      fetchImpl
    );

    expect(invalidMediaType.status).toBe(415);
    expect(nonObjectJson.status).toBe(400);
    expect(streamedOversized.status).toBe(400);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("bounds and validates successful upstream response bodies", async () => {
    const session = oidcSession();
    const declaredOversized = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      vi.fn<typeof fetch>(async () =>
        new Response("{}", {
          status: 200,
          headers: {
            "content-type": "application/json",
            "content-length": String(4 * 1024 * 1024 + 1)
          }
        })
      )
    );
    const streamedOversized = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      vi.fn<typeof fetch>(async () =>
        new Response(`{"value":"${"x".repeat(4 * 1024 * 1024)}"}`, {
          status: 200,
          headers: { "content-type": "application/json" }
        })
      )
    );
    const nonJson = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      vi.fn<typeof fetch>(async () =>
        new Response("upstream secret", {
          status: 200,
          headers: { "content-type": "text/plain" }
        })
      )
    );
    const invalidJson = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      vi.fn<typeof fetch>(async () =>
        new Response("{not-json", {
          status: 200,
          headers: { "content-type": "application/json" }
        })
      )
    );

    for (const response of [declaredOversized, streamedOversized, nonJson, invalidJson]) {
      expect(response.status).toBe(502);
      expect(await response.text()).toBe(
        '{"error":"Console API returned an invalid response."}'
      );
    }
  });

  it("uses fetch redirect-error mode and sanitizes redirect rejection", async () => {
    const session = oidcSession();
    const fetchImpl = vi.fn<typeof fetch>(async (_input, init) => {
      expect(init?.redirect).toBe("error");
      throw new TypeError("redirect target contains upstream-secret");
    });

    const response = await forwardConsoleApiRequest(
      request(session),
      ["approvals", "list"],
      fetchImpl
    );

    expect(response.status).toBe(504);
    expect(await response.text()).toBe('{"error":"Console API is unavailable."}');
  });
});

function oidcSession() {
  return createConsoleSession(currentOidcConfig(), {
    accessToken: "A".repeat(64),
    expiresAtSeconds: Math.floor(Date.now() / 1000) + 600,
    tenantId: "tenant-a",
    subjectId: "reviewer",
    roles: ["approval_reviewer", "verifier"]
  });
}

function currentOidcConfig(): ConsoleOidcRuntimeConfig {
  return loadConsoleRuntimeConfig() as ConsoleOidcRuntimeConfig;
}

function currentUnsignedLocalConfig(): ConsoleUnsignedLocalRuntimeConfig {
  return loadConsoleRuntimeConfig() as ConsoleUnsignedLocalRuntimeConfig;
}

function request(
  session: ReturnType<typeof oidcSession>,
  overrides: Readonly<Record<string, string>> = {},
  body: string = "{}"
): NextRequest {
  return new NextRequest(`${consoleOrigin}/api/approvals/list`, {
    method: "POST",
    headers: {
      origin: consoleOrigin,
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "same-origin",
      "content-type": "application/json",
      cookie: `${sessionCookie}=${session.sessionId}`,
      "x-console-csrf": session.csrfToken,
      ...overrides
    },
    body
  });
}

function localRequest(
  session: ReturnType<typeof createUnsignedLocalConsoleSession>
): NextRequest {
  return new NextRequest("http://127.0.0.1:3100/api/approvals/list", {
    method: "POST",
    headers: {
      origin: "http://127.0.0.1:3100",
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "same-origin",
      "content-type": "application/json",
      cookie: `hallu-console-session=${session.sessionId}`,
      "x-console-csrf": session.csrfToken
    },
    body: "{}"
  });
}

function stubEnvironment(): void {
  const values = {
    HALLU_DEFENSE_ENV: "production",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: consoleOrigin,
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
    HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://identity.example.test/realms/hallu",
    HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
    HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
    HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier"
  } as const;
  for (const [name, value] of Object.entries(values)) {
    vi.stubEnv(name, value);
  }
}

function stubUnsignedLocalEnvironment(): void {
  const values = {
    HALLU_DEFENSE_ENV: "test",
    HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3100",
    HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:8100",
    HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
    HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
    HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-a",
    HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "local-reviewer",
    HALLU_DEFENSE_CONSOLE_LOCAL_ROLES: "verifier"
  } as const;
  for (const [name, value] of Object.entries(values)) {
    vi.stubEnv(name, value);
  }
}

function jsonResponse(body: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}
