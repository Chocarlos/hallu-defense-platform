import { beforeEach, describe, expect, it } from "vitest";

import {
  AUTH_RATE_LIMIT_BUCKET_CAPACITY,
  consumeAuthRateLimit,
  resetAuthRateLimitForTests,
  type AuthRateLimitRequest
} from "./auth-rate-limit";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

const baseEnvironment = {
  HALLU_DEFENSE_ENV: "test",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3100",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:8100",
  HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "http://127.0.0.1:8081/realms/hallu-defense",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier",
  HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX: "1",
  HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX: "1",
  HALLU_DEFENSE_CONSOLE_AUTH_RATE_LIMIT_WINDOW_SECONDS: "10"
} as const;

describe("Console authentication rate limiter", () => {
  beforeEach(() => resetAuthRateLimitForTests());

  it("uses one unattributed bucket when proxy trust is disabled", () => {
    const config = runtimeConfig();
    const first = consumeAuthRateLimit(
      "login",
      request({ "x-forwarded-for": "203.0.113.10" }, undefined, config),
      config,
      1_000
    );
    const second = consumeAuthRateLimit(
      "login",
      request({ "x-forwarded-for": "198.51.100.20" }, "rotated-cookie-a", config),
      config,
      1_001
    );
    const third = consumeAuthRateLimit(
      "login",
      request({ "x-forwarded-for": "192.0.2.30" }, "rotated-cookie-b", config),
      config,
      1_002
    );

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
    expect(third.allowed).toBe(false);
    expect(third.retryAfterSeconds).toBe(10);
  });

  it("ignores forged client cookies and never issues rate-limit identities", () => {
    const config = runtimeConfig();
    const first = consumeAuthRateLimit(
      "login",
      request({}, `${"A".repeat(43)}.${"B".repeat(43)}`, config),
      config,
      1_000
    );
    const second = consumeAuthRateLimit(
      "login",
      request({}, `${"C".repeat(43)}.${"D".repeat(43)}`, config),
      config,
      1_001
    );

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
  });

  it("cannot amplify quota by rotating hundreds of cookies", () => {
    const config = runtimeConfig({ HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX: "20" });
    let allowed = 0;
    for (let index = 0; index < 420; index += 1) {
      const decision = consumeAuthRateLimit(
        "login",
        request(
          { "x-forwarded-for": `203.0.113.${index % 255}` },
          `attacker-cookie-${index}`,
          config
        ),
        config,
        1_000 + index
      );
      if (decision.allowed) {
        allowed += 1;
      }
    }

    expect(allowed).toBe(20);
  });

  it("uses only the configured right-side trusted proxy boundary", () => {
    const config = runtimeConfig({ HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS: "1" });
    const first = consumeAuthRateLimit(
      "login",
      request({ "x-forwarded-for": "203.0.113.10" }, "B".repeat(43), config),
      config,
      1_000
    );
    const spoofedPrefix = consumeAuthRateLimit(
      "login",
      request(
        { "x-forwarded-for": "198.51.100.77, 203.0.113.10" },
        "C".repeat(43),
        config
      ),
      config,
      1_001
    );

    expect(first.allowed).toBe(true);
    expect(spoofedPrefix.allowed).toBe(false);
  });

  it("keeps buckets bounded, fails closed at capacity, and recovers after expiry", () => {
    const config = runtimeConfig({ HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS: "1" });
    for (let index = 0; index < AUTH_RATE_LIMIT_BUCKET_CAPACITY; index += 1) {
      const address = `10.0.${Math.floor(index / 256)}.${index % 256}`;
      expect(
        consumeAuthRateLimit(
          "login",
          request({ "x-forwarded-for": address }, undefined, config),
          config,
          1_000
        ).allowed
      ).toBe(true);
    }

    const overflowHeaders = { "x-forwarded-for": "10.0.16.1" };
    expect(
      consumeAuthRateLimit("login", request(overflowHeaders, undefined, config), config, 1_001)
        .allowed
    ).toBe(false);
    expect(
      consumeAuthRateLimit("login", request(overflowHeaders, undefined, config), config, 11_000)
        .allowed
    ).toBe(true);
  });

  it("does not expose raw IP or secure-key material in decisions", () => {
    const config = runtimeConfig({ HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS: "1" });
    const rawIp = "203.0.113.88";
    const rawCookie = "S".repeat(43);
    const decision = consumeAuthRateLimit(
      "callback",
      request({ "x-forwarded-for": rawIp }, rawCookie, config),
      config,
      1_000
    );

    expect(JSON.stringify(decision)).not.toContain(rawIp);
    expect(JSON.stringify(decision)).not.toContain(rawCookie);
  });
});

function runtimeConfig(
  overrides: Readonly<Record<string, string>> = {}
): ConsoleOidcRuntimeConfig {
  return loadConsoleRuntimeConfig({ ...baseEnvironment, ...overrides }) as ConsoleOidcRuntimeConfig;
}

function request(
  headers: Readonly<Record<string, string>>,
  _cookie: string | undefined,
  _config: ConsoleOidcRuntimeConfig
): AuthRateLimitRequest {
  return {
    headers: new Headers(headers)
  };
}
