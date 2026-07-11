import { createHash } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  AUTH_SESSION_CAPACITY,
  AUTH_TRANSACTION_CAPACITY,
  AuthorizationCapacityError,
  AuthorizationStateError,
  authStoreCountsForTests,
  consumeAuthorizationTransaction,
  createAuthorizationTransaction,
  createConsoleSession,
  getConsoleSession,
  rotateConsoleSession,
  resetAuthStoreForTests
} from "./auth-store";
import {
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  type OidcDiscovery
} from "./oidc";
import {
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "./runtime-config";

const config = loadConsoleRuntimeConfig({
  HALLU_DEFENSE_ENV: "test",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3100",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:8100",
  HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "http://127.0.0.1:8081/realms/hallu-defense",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier",
  HALLU_DEFENSE_CONSOLE_OIDC_TRANSACTION_TTL_SECONDS: "60"
}) as ConsoleOidcRuntimeConfig;

const discovery: OidcDiscovery = {
  issuer: config.issuer,
  authorizationEndpoint: `${config.issuer}/protocol/openid-connect/auth`,
  tokenEndpoint: `${config.issuer}/protocol/openid-connect/token`,
  jwksUri: `${config.issuer}/protocol/openid-connect/certs`,
  endSessionEndpoint: `${config.issuer}/protocol/openid-connect/logout`
};

describe("OIDC authorization state and PKCE", () => {
  beforeEach(() => resetAuthStoreForTests());

  it("creates an S256 challenge and includes state, nonce, and the exact callback", () => {
    const transaction = createAuthorizationTransaction(config, { nowMs: 1_000 });
    const authorizationUrl = new URL(
      buildAuthorizationUrl(config, discovery, transaction)
    );

    expect(transaction.challenge).toBe(
      createHash("sha256").update(transaction.verifier, "ascii").digest("base64url")
    );
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl.searchParams.get("state")).toBe(transaction.state);
    expect(authorizationUrl.searchParams.get("nonce")).toBe(transaction.nonce);
    expect(authorizationUrl.searchParams.get("redirect_uri")).toBe(
      "http://127.0.0.1:3100/auth/callback"
    );
  });

  it("rejects state mismatch, expiry, and replay", () => {
    const mismatch = createAuthorizationTransaction(config, { nowMs: 1_000 });
    expect(() =>
      consumeAuthorizationTransaction(mismatch.state, `${mismatch.state}x`, 2_000)
    ).toThrow(/state/u);

    const expired = createAuthorizationTransaction(config, { nowMs: 1_000 });
    expect(() =>
      consumeAuthorizationTransaction(expired.state, expired.state, 61_000)
    ).toThrow(/expired/u);

    const replayed = createAuthorizationTransaction(config, { nowMs: 1_000 });
    expect(consumeAuthorizationTransaction(replayed.state, replayed.state, 2_000)).toBe(
      replayed
    );
    expect(() =>
      consumeAuthorizationTransaction(replayed.state, replayed.state, 2_001)
    ).toThrow(/not found/u);
  });

  it("rejects an invalid PKCE verifier before contacting the token endpoint", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    await expect(
      exchangeAuthorizationCode(
        config,
        discovery,
        "authorization-code-value",
        "too-short",
        fetchImpl
      )
    ).rejects.toThrow(/callback values/u);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects new transactions at capacity without evicting a legitimate state", () => {
    const first = createAuthorizationTransaction(config, { nowMs: 1_000 });
    for (let index = 1; index < AUTH_TRANSACTION_CAPACITY; index += 1) {
      createAuthorizationTransaction(config, { nowMs: 1_000 });
    }

    let capacityError: unknown;
    try {
      createAuthorizationTransaction(config, { nowMs: 1_000 });
    } catch (error) {
      capacityError = error;
    }
    expect(capacityError).toBeInstanceOf(AuthorizationCapacityError);
    expect(String(capacityError)).not.toContain(first.state);
    expect(consumeAuthorizationTransaction(first.state, first.state, 2_000)).toBe(first);
  });

  it("binds an active prior session and rotates it atomically", () => {
    const prior = createConsoleSession(tokenSet("prior-token", 600), 1);
    const transaction = createAuthorizationTransaction(config, {
      nowMs: 1_000,
      priorSessionId: prior.sessionId
    });

    expect(transaction.priorSessionId).toBe(prior.sessionId);
    const replacement = rotateConsoleSession(
      consumeAuthorizationTransaction(transaction.state, transaction.state, 2_000),
      tokenSet("replacement-token", 700),
      2
    );
    expect(getConsoleSession(prior.sessionId, 2)).toBeNull();
    expect(getConsoleSession(replacement.sessionId, 2)).toBe(replacement);
    expect(replacement.sessionId).not.toBe(prior.sessionId);
  });

  it("lets only one sibling transaction replace a shared prior session", () => {
    const prior = createConsoleSession(tokenSet("prior-token", 10_000), 1);
    const first = createAuthorizationTransaction(config, {
      nowMs: 1_000,
      priorSessionId: prior.sessionId
    });
    const sibling = createAuthorizationTransaction(config, {
      nowMs: 1_000,
      priorSessionId: prior.sessionId
    });

    const winner = rotateConsoleSession(
      consumeAuthorizationTransaction(first.state, first.state, 2_000),
      tokenSet("winner-token", 10_000),
      2
    );
    const consumedSibling = consumeAuthorizationTransaction(
      sibling.state,
      sibling.state,
      2_000
    );

    expect(() =>
      rotateConsoleSession(consumedSibling, tokenSet("orphan-token", 10_000), 2)
    ).toThrow(AuthorizationStateError);
    expect(() =>
      consumeAuthorizationTransaction(sibling.state, sibling.state, 2_001)
    ).toThrow(/not found/u);
    expect(getConsoleSession(winner.sessionId, 2)).toBe(winner);
    expect(authStoreCountsForTests()).toEqual({ transactions: 0, sessions: 1 });
  });

  it("does not allocate orphan sessions during reauthentication and can replace at capacity", () => {
    const prior = createConsoleSession(tokenSet("prior-token", 10_000), 1);
    const transactions = [];
    for (let index = 0; index < AUTH_TRANSACTION_CAPACITY; index += 1) {
      transactions.push(
        createAuthorizationTransaction(config, {
          nowMs: 1_000,
          priorSessionId: prior.sessionId
        })
      );
    }
    expect(authStoreCountsForTests()).toEqual({
      transactions: AUTH_TRANSACTION_CAPACITY,
      sessions: 1
    });
    for (let index = 1; index < AUTH_SESSION_CAPACITY; index += 1) {
      createConsoleSession(tokenSet(`session-${index}`, 10_000), 1);
    }

    const winningTransaction = transactions[0];
    if (winningTransaction === undefined) {
      throw new Error("Missing winning authorization transaction.");
    }
    const replacement = rotateConsoleSession(
      consumeAuthorizationTransaction(
        winningTransaction.state,
        winningTransaction.state,
        2_000
      ),
      tokenSet("replacement-token", 10_000),
      2
    );
    for (const staleTransaction of transactions.slice(1)) {
      const consumed = consumeAuthorizationTransaction(
        staleTransaction.state,
        staleTransaction.state,
        2_000
      );
      expect(() =>
        rotateConsoleSession(consumed, tokenSet("orphan-token", 10_000), 2)
      ).toThrow(AuthorizationStateError);
    }
    expect(getConsoleSession(prior.sessionId, 2)).toBeNull();
    expect(getConsoleSession(replacement.sessionId, 2)).toBe(replacement);
    expect(authStoreCountsForTests()).toEqual({
      transactions: 0,
      sessions: AUTH_SESSION_CAPACITY
    });
    expect(() => createConsoleSession(tokenSet("overflow", 10_000), 2)).toThrow(
      AuthorizationCapacityError
    );
  });
});

function tokenSet(accessToken: string, expiresAtSeconds: number) {
  return {
    accessToken: accessToken.padEnd(32, "x"),
    expiresAtSeconds,
    tenantId: "tenant-a",
    subjectId: "reviewer",
    roles: ["verifier"]
  } as const;
}
