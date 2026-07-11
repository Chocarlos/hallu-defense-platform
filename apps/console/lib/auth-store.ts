import { randomBytes } from "node:crypto";

import {
  constantTimeEqual,
  createPkceMaterial,
  isOpaqueCallbackValue,
  type AuthenticatedTokenSet
} from "./oidc";
import type { ConsoleOidcRuntimeConfig } from "./runtime-config";

export const AUTH_TRANSACTION_CAPACITY = 2048;
export const AUTH_SESSION_CAPACITY = 2048;

export interface AuthorizationTransaction {
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  readonly challenge: string;
  readonly expiresAtMs: number;
}

export interface ConsoleSession extends AuthenticatedTokenSet {
  readonly sessionId: string;
}

interface AuthStore {
  readonly transactions: Map<string, AuthorizationTransaction>;
  readonly sessions: Map<string, ConsoleSession>;
}

export class AuthorizationStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationStateError";
  }
}

export class AuthorizationCapacityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationCapacityError";
  }
}

declare global {
  // Route handlers are emitted as separate modules. A process-global key keeps
  // their opaque in-memory session store consistent in the standalone server.
  var __halluConsoleAuthStore: AuthStore | undefined;
}

export function createAuthorizationTransaction(
  config: ConsoleOidcRuntimeConfig,
  nowMs: number = Date.now()
): AuthorizationTransaction {
  const material = createPkceMaterial();
  const transaction: AuthorizationTransaction = {
    ...material,
    expiresAtMs: nowMs + config.transactionTtlSeconds * 1000
  };
  const store = authStore();
  purgeExpired(store, nowMs);
  requireAvailableCapacity(
    store.transactions,
    AUTH_TRANSACTION_CAPACITY,
    "OIDC authorization transaction capacity is unavailable."
  );
  store.transactions.set(transaction.state, transaction);
  return transaction;
}

export function consumeAuthorizationTransaction(
  returnedState: string,
  cookieState: string | undefined,
  nowMs: number = Date.now()
): AuthorizationTransaction {
  if (
    cookieState === undefined ||
    !isOpaqueCallbackValue(returnedState, 128) ||
    !isOpaqueCallbackValue(cookieState, 128) ||
    !constantTimeEqual(returnedState, cookieState)
  ) {
    throw new AuthorizationStateError("OIDC authorization state is invalid.");
  }
  const store = authStore();
  const transaction = store.transactions.get(returnedState);
  if (transaction === undefined) {
    throw new AuthorizationStateError("OIDC authorization transaction was not found.");
  }
  store.transactions.delete(returnedState);
  if (transaction.expiresAtMs <= nowMs) {
    throw new AuthorizationStateError("OIDC authorization transaction expired.");
  }
  return transaction;
}

export function createConsoleSession(
  tokenSet: AuthenticatedTokenSet,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession {
  if (tokenSet.expiresAtSeconds <= nowSeconds) {
    throw new Error("OIDC access token is already expired.");
  }
  const session: ConsoleSession = {
    ...tokenSet,
    sessionId: randomBytes(32).toString("base64url")
  };
  const store = authStore();
  purgeExpired(store, nowSeconds * 1000);
  requireAvailableCapacity(
    store.sessions,
    AUTH_SESSION_CAPACITY,
    "OIDC console session capacity is unavailable."
  );
  store.sessions.set(session.sessionId, session);
  return session;
}

export function getConsoleSession(
  sessionId: string | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession | null {
  if (sessionId === undefined || !/^[A-Za-z0-9_-]{43}$/u.test(sessionId)) {
    return null;
  }
  const store = authStore();
  const session = store.sessions.get(sessionId);
  if (session === undefined) {
    return null;
  }
  if (session.expiresAtSeconds <= nowSeconds) {
    store.sessions.delete(sessionId);
    return null;
  }
  return session;
}

export function deleteConsoleSession(sessionId: string | undefined): void {
  if (sessionId !== undefined) {
    authStore().sessions.delete(sessionId);
  }
}

export function transactionCookieName(config: ConsoleOidcRuntimeConfig): string {
  return config.productionLike ? "__Host-hallu-oidc-state" : "hallu-oidc-state";
}

export function sessionCookieName(config: ConsoleOidcRuntimeConfig): string {
  return config.productionLike ? "__Host-hallu-console-session" : "hallu-console-session";
}

export function resetAuthStoreForTests(): void {
  globalThis.__halluConsoleAuthStore = { transactions: new Map(), sessions: new Map() };
}

function authStore(): AuthStore {
  globalThis.__halluConsoleAuthStore ??= {
    transactions: new Map(),
    sessions: new Map()
  };
  return globalThis.__halluConsoleAuthStore;
}

function purgeExpired(store: AuthStore, nowMs: number): void {
  for (const [state, transaction] of store.transactions) {
    if (transaction.expiresAtMs <= nowMs) {
      store.transactions.delete(state);
    }
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  for (const [sessionId, session] of store.sessions) {
    if (session.expiresAtSeconds <= nowSeconds) {
      store.sessions.delete(sessionId);
    }
  }
}

function requireAvailableCapacity<T>(
  items: Map<string, T>,
  maximum: number,
  message: string
): void {
  if (items.size >= maximum) {
    throw new AuthorizationCapacityError(message);
  }
}
