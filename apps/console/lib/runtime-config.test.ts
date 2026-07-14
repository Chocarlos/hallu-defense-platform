import { describe, expect, it } from "vitest";

import {
  browserRuntimeConfig,
  ConsoleRuntimeConfigError,
  loadConsoleRuntimeConfig,
  loadPublicRuntimeConfig,
  parseIssuer,
  parseOrigin
} from "./runtime-config";

const productionOidcEnvironment = {
  HALLU_DEFENSE_ENV: "production",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://identity.example.test/realms/hallu",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier,approval_reviewer"
} as const;

describe("Console runtime configuration", () => {
  it("loads the public boundary without OIDC or API settings", () => {
    expect(
      loadPublicRuntimeConfig({
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test"
      })
    ).toEqual({
      allowInsecureLocalHttp: false,
      environment: "production",
      productionLike: true,
      publicOrigin: "https://console.example.test"
    });
  });

  it("loads different runtime origins from the same module without a baked localhost", () => {
    const first = loadConsoleRuntimeConfig(productionOidcEnvironment);
    const second = loadConsoleRuntimeConfig({
      ...productionOidcEnvironment,
      HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://review.example.test",
      HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://gateway.example.test"
    });

    expect(first.publicOrigin).toBe("https://console.example.test");
    expect(first.apiOrigin).toBe("https://api.example.test");
    expect(second.publicOrigin).toBe("https://review.example.test");
    expect(second.apiOrigin).toBe("https://gateway.example.test");
    expect(JSON.stringify([first, second])).not.toContain("localhost");
    if (first.authMode !== "oidc") {
      throw new Error("Expected OIDC configuration.");
    }
    expect(first.discoveryCacheTtlSeconds).toBe(300);
    expect(first.jwksCacheTtlSeconds).toBe(300);
    expect(first.providerFailureCooldownSeconds).toBe(5);
    expect(first.loginRateLimitMax).toBe(20);
    expect(first.callbackRateLimitMax).toBe(30);
    expect(first.trustedProxyHops).toBe(0);
    expect("demoFixtureEnabled" in first).toBe(false);
    expect(browserRuntimeConfig(first)).toEqual({ authMode: "oidc" });
    expect(JSON.stringify(browserRuntimeConfig(first))).not.toContain("api.example.test");
  });

  it.each([
    ["http://api.example.test", "HTTP outside loopback"],
    ["https://api.example.test/v1", "path"],
    ["https://user@api.example.test", "credentials"],
    ["https://api.example.test?tenant=a", "query"],
    ["https://api.example.test/", "non-canonical trailing slash"]
  ])("rejects an invalid API origin: %s (%s)", (origin) => {
    expect(() => parseOrigin(origin, "console API origin", false)).toThrow(
      ConsoleRuntimeConfigError
    );
  });

  it.each([
    "http://identity.example.test/realms/hallu",
    "https://identity.example.test/realms/hallu/",
    "https://identity.example.test/realms//hallu",
    "https://identity.example.test/realms/%68allu",
    "https://user@identity.example.test/realms/hallu",
    "https://identity.example.test/realms/hallu?client=console"
  ])("rejects a non-canonical or insecure issuer: %s", (issuer) => {
    expect(() => parseIssuer(issuer, false)).toThrow(ConsoleRuntimeConfigError);
  });

  it("allows HTTP only for an explicit loopback fixture", () => {
    expect(parseOrigin("http://127.0.0.1:8000", "API", true)).toBe(
      "http://127.0.0.1:8000"
    );
    expect(() => parseOrigin("http://127.0.0.1:8000", "API", false)).toThrow(
      ConsoleRuntimeConfigError
    );
  });

  it("fails closed when production tries to enable unsigned or insecure local mode", () => {
    expect(() =>
      loadConsoleRuntimeConfig({
        ...productionOidcEnvironment,
        HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true"
      })
    ).toThrow(ConsoleRuntimeConfigError);
    expect(() =>
      loadConsoleRuntimeConfig({
        ...productionOidcEnvironment,
        HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
        HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
        HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-a",
        HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "reviewer",
        HALLU_DEFENSE_CONSOLE_LOCAL_ROLES: "verifier"
      })
    ).toThrow(ConsoleRuntimeConfigError);
    expect(() =>
      loadConsoleRuntimeConfig({
        ...productionOidcEnvironment,
        HALLU_DEFENSE_CONSOLE_DEMO_FIXTURE_ENABLED: "true"
      })
    ).toThrow(ConsoleRuntimeConfigError);
  });

  it.each([
    ["HALLU_DEFENSE_CONSOLE_OIDC_DISCOVERY_CACHE_TTL_SECONDS", "29"],
    ["HALLU_DEFENSE_CONSOLE_OIDC_JWKS_CACHE_TTL_SECONDS", "86401"],
    ["HALLU_DEFENSE_CONSOLE_OIDC_FAILURE_COOLDOWN_SECONDS", "0"],
    ["HALLU_DEFENSE_CONSOLE_AUTH_RATE_LIMIT_WINDOW_SECONDS", "9"],
    ["HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX", "0"],
    ["HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX", "1001"],
    ["HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS", "9"]
  ])("rejects unsafe authentication tuning: %s=%s", (name, value) => {
    expect(() =>
      loadConsoleRuntimeConfig({ ...productionOidcEnvironment, [name]: value })
    ).toThrow(ConsoleRuntimeConfigError);
  });
});
