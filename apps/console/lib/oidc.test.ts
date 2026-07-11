import {
  createSign,
  generateKeyPairSync,
  type KeyObject
} from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildEndSessionUrl,
  discoverOidc,
  resetOidcProviderCacheForTests,
  validateTokenSet,
  type OidcDiscovery,
  type OidcTokenResponse
} from "./oidc";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

const NOW = 1_800_000_000;
const NONCE = "nonce-value-with-sufficient-entropy";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "console-test-key",
  use: "sig",
  alg: "RS256"
};

const config = loadConsoleRuntimeConfig({
  HALLU_DEFENSE_ENV: "production",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://identity.example.test/realms/hallu-defense",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier,approval_reviewer",
  HALLU_DEFENSE_CONSOLE_OIDC_CLOCK_SKEW_SECONDS: "30"
}) as ConsoleOidcRuntimeConfig;

const discovery: OidcDiscovery = {
  issuer: config.issuer,
  authorizationEndpoint: `${config.issuer}/protocol/openid-connect/auth`,
  tokenEndpoint: `${config.issuer}/protocol/openid-connect/token`,
  jwksUri: `${config.issuer}/protocol/openid-connect/certs`,
  endSessionEndpoint: `${config.issuer}/protocol/openid-connect/logout`
};

const idClaims = {
  iss: config.issuer,
  aud: config.clientId,
  azp: config.clientId,
  sub: "console-reviewer",
  nonce: NONCE,
  exp: NOW + 300,
  iat: NOW
};

const accessClaims = {
  iss: config.issuer,
  aud: [config.apiAudience],
  azp: config.clientId,
  sub: "console-reviewer",
  tenant_id: "tenant-a",
  roles: ["approval_reviewer", "verifier"],
  exp: NOW + 300,
  iat: NOW
};

describe("OIDC discovery and token validation", () => {
  beforeEach(() => resetOidcProviderCacheForTests());

  it("builds provider logout without placing an ID or access token in the URL", () => {
    const logout = new URL(buildEndSessionUrl(config, discovery));
    expect(logout.origin + logout.pathname).toBe(discovery.endSessionEndpoint);
    expect(logout.searchParams.get("client_id")).toBe(config.clientId);
    expect(logout.searchParams.get("post_logout_redirect_uri")).toBe(config.publicOrigin);
    expect(logout.search).not.toMatch(/token|id_token_hint|access/iu);
  });

  it("accepts a signed token set and derives identity only from access-token claims", async () => {
    const result = await validate(idClaims, accessClaims, NONCE);

    expect(result.tenantId).toBe("tenant-a");
    expect(result.subjectId).toBe("console-reviewer");
    expect(result.roles).toEqual(["approval_reviewer", "verifier"]);
    expect(result.expiresAtSeconds).toBe(NOW + 300);
  });

  it.each([
    ["nonce", { ...idClaims, nonce: "different-nonce-value-with-entropy" }, accessClaims, NONCE],
    ["issuer", { ...idClaims, iss: "https://attacker.example.test/realms/hallu" }, accessClaims, NONCE],
    ["audience", idClaims, { ...accessClaims, aud: ["other-api"] }, NONCE],
    ["expiry", idClaims, { ...accessClaims, exp: NOW - 120 }, NONCE]
  ])("rejects a token with invalid %s", async (_label, id, access, nonce) => {
    await expect(validate(id, access, nonce)).rejects.toThrow();
  });

  it("rejects discovery issuer mismatch and endpoints outside the issuer boundary", async () => {
    const mismatchFetch: typeof fetch = async () =>
      jsonResponse(discoveryDocument({ issuer: "https://attacker.example.test/realms/hallu" }));
    await expect(discoverOidc(config, mismatchFetch)).rejects.toThrow(/issuer/u);

    resetOidcProviderCacheForTests();
    const escapedEndpointFetch: typeof fetch = async () =>
      jsonResponse(
        discoveryDocument({
          token_endpoint: "https://identity.example.test/realms/other/token"
        })
      );
    await expect(discoverOidc(config, escapedEndpointFetch)).rejects.toThrow(/boundary/u);
  });

  it("single-flights discovery requests and refreshes only after its TTL", async () => {
    let releaseFetch: (() => void) | undefined;
    const barrier = new Promise<void>((resolve) => {
      releaseFetch = resolve;
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      await barrier;
      return jsonResponse(discoveryDocument());
    });
    const reads = Array.from({ length: 64 }, async () =>
      discoverOidc(config, fetchImpl, { currentTimeMs: 1_000 })
    );

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    releaseFetch?.();
    const values = await Promise.all(reads);
    expect(values.every((value) => value.issuer === config.issuer)).toBe(true);
    await discoverOidc(config, fetchImpl, {
      currentTimeMs: 1_000 + config.discoveryCacheTtlSeconds * 1000 - 1
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    await discoverOidc(config, fetchImpl, {
      currentTimeMs: 1_000 + config.discoveryCacheTtlSeconds * 1000
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("single-flights discovery outages, applies a failure cooldown, and redacts causes", async () => {
    let available = false;
    const secretCause = "client_secret=must-never-escape";
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      if (!available) {
        throw new Error(secretCause);
      }
      return jsonResponse(discoveryDocument());
    });
    const failures = await Promise.allSettled(
      Array.from({ length: 64 }, async () =>
        discoverOidc(config, fetchImpl, { currentTimeMs: 1_000 })
      )
    );

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(
      failures.every(
        (failure) =>
          failure.status === "rejected" && !String(failure.reason).includes(secretCause)
      )
    ).toBe(true);
    await expect(
      discoverOidc(config, fetchImpl, { currentTimeMs: 1_001 })
    ).rejects.toThrow(/temporarily unavailable/u);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    available = true;
    await expect(
      discoverOidc(config, fetchImpl, {
        currentTimeMs: 1_000 + config.providerFailureCooldownSeconds * 1000
      })
    ).resolves.toMatchObject({ issuer: config.issuer });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("single-flights JWKS reads and suppresses repeated provider outages", async () => {
    const tokenResponse = signedTokenResponse(idClaims, accessClaims);
    let available = true;
    let releaseFetch: (() => void) | undefined;
    const barrier = new Promise<void>((resolve) => {
      releaseFetch = resolve;
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      await barrier;
      if (!available) {
        throw new Error("access_token=must-never-escape");
      }
      return jsonResponse({ keys: [publicJwk] });
    });
    const validations = Array.from({ length: 32 }, async () =>
      validateTokenSet(config, discovery, tokenResponse, NONCE, {
        currentTimeSeconds: NOW,
        currentTimeMs: 1_000,
        fetchImpl
      })
    );

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    releaseFetch?.();
    await Promise.all(validations);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    resetOidcProviderCacheForTests();
    available = false;
    await expect(
      validateTokenSet(config, discovery, tokenResponse, NONCE, {
        currentTimeSeconds: NOW,
        currentTimeMs: 2_000,
        fetchImpl
      })
    ).rejects.not.toThrow(/access_token/u);
    const callsAfterFailure = fetchImpl.mock.calls.length;
    await expect(
      validateTokenSet(config, discovery, tokenResponse, NONCE, {
        currentTimeSeconds: NOW,
        currentTimeMs: 2_001,
        fetchImpl
      })
    ).rejects.toThrow(/temporarily unavailable/u);
    expect(fetchImpl).toHaveBeenCalledTimes(callsAfterFailure);

    available = true;
    await expect(
      validateTokenSet(config, discovery, tokenResponse, NONCE, {
        currentTimeSeconds: NOW,
        currentTimeMs: 2_000 + config.providerFailureCooldownSeconds * 1000,
        fetchImpl
      })
    ).resolves.toMatchObject({ tenantId: "tenant-a" });
    expect(fetchImpl).toHaveBeenCalledTimes(callsAfterFailure + 1);
  });

  it("allows only one forced JWKS refresh for concurrent unknown signing keys", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      jsonResponse({ keys: [publicJwk] })
    );
    await validateTokenSet(
      config,
      discovery,
      signedTokenResponse(idClaims, accessClaims),
      NONCE,
      { currentTimeSeconds: NOW, currentTimeMs: 1_000, fetchImpl }
    );
    const unknownKeyTokens: OidcTokenResponse = {
      accessToken: signJwt(accessClaims, privateKey, "unrecognized-key"),
      idToken: signJwt(idClaims, privateKey, "unrecognized-key"),
      tokenType: "Bearer"
    };

    const failures = await Promise.allSettled(
      Array.from({ length: 32 }, async () =>
        validateTokenSet(config, discovery, unknownKeyTokens, NONCE, {
          currentTimeSeconds: NOW,
          currentTimeMs: 7_000,
          fetchImpl
        })
      )
    );
    expect(failures.every((result) => result.status === "rejected")).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    await expect(
      validateTokenSet(config, discovery, unknownKeyTokens, NONCE, {
        currentTimeSeconds: NOW,
        currentTimeMs: 7_001,
        fetchImpl
      })
    ).rejects.toThrow(/signing key/u);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});

async function validate(
  id: Readonly<Record<string, unknown>>,
  access: Readonly<Record<string, unknown>>,
  expectedNonce: string
) {
  const tokenResponse = signedTokenResponse(id, access);
  const fetchImpl: typeof fetch = async () => jsonResponse({ keys: [publicJwk] });
  return validateTokenSet(config, discovery, tokenResponse, expectedNonce, {
    currentTimeSeconds: NOW,
    fetchImpl
  });
}

function signedTokenResponse(
  id: Readonly<Record<string, unknown>>,
  access: Readonly<Record<string, unknown>>
): OidcTokenResponse {
  const accessToken = signJwt(access, privateKey);
  return {
    accessToken,
    idToken: signJwt(id, privateKey),
    tokenType: "Bearer"
  };
}

function signJwt(
  payload: Readonly<Record<string, unknown>>,
  key: KeyObject,
  kid: string = publicJwk.kid
): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid }),
    "utf8"
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = `${header}.${body}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput, "ascii")
    .sign(key, "base64url");
  return `${signingInput}.${signature}`;
}

function discoveryDocument(
  overrides: Readonly<Record<string, unknown>> = {}
): Readonly<Record<string, unknown>> {
  return {
    issuer: config.issuer,
    authorization_endpoint: discovery.authorizationEndpoint,
    token_endpoint: discovery.tokenEndpoint,
    jwks_uri: discovery.jwksUri,
    end_session_endpoint: discovery.endSessionEndpoint,
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"],
    ...overrides
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
