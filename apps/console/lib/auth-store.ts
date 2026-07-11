import { randomBytes } from "node:crypto";

import {
  constantTimeEqual,
  createPkceMaterial,
  isOpaqueCallbackValue,
  type AuthenticatedTokenSet
} from "./oidc";
import {
  CONSOLE_AUTH_MODE_OIDC,
  CONSOLE_AUTH_MODE_UNSIGNED_LOCAL,
  type ConsoleIdentity,
  type ConsoleOidcRuntimeConfig,
  type ConsoleRuntimeConfig
} from "./runtime-config";

export const AUTH_TRANSACTION_CAPACITY = 2048;
export const AUTH_SESSION_CAPACITY = 2048;
const LOCAL_SESSION_MAX_SECONDS = 3600;
const OPAQUE_VALUE_RE = /^[A-Za-z0-9_-]{43}$/u;

export interface AuthorizationTransaction {
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  readonly challenge: string;
  readonly priorSessionId: string | null;
  readonly expiresAtMs: number;
}

export interface AuthorizationTransactionOptions {
  readonly nowMs?: number;
  readonly priorSessionId?: string;
}

export interface ConsoleSession extends ConsoleIdentity {
  readonly sessionId: string;
  readonly csrfToken: string;
  readonly authMode:
    | typeof CONSOLE_AUTH_MODE_OIDC
    | typeof CONSOLE_AUTH_MODE_UNSIGNED_LOCAL;
  readonly accessToken: string | null;
  readonly expiresAtSeconds: number;
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
  options: AuthorizationTransactionOptions = {}
): AuthorizationTransaction {
  const nowMs = options.nowMs ?? Date.now();
  const material = createPkceMaterial();
  const transaction: AuthorizationTransaction = {
    ...material,
    priorSessionId: activeOidcSessionId(options.priorSessionId, nowMs),
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

export function deleteAuthorizationTransaction(state: string): void {
  if (OPAQUE_VALUE_RE.test(state)) {
    authStore().transactions.delete(state);
  }
}

export function createConsoleSession(
  tokenSet: AuthenticatedTokenSet,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession {
  if (tokenSet.expiresAtSeconds <= nowSeconds) {
    throw new Error("OIDC access token is already expired.");
  }
  return persistSession(
    {
      authMode: CONSOLE_AUTH_MODE_OIDC,
      accessToken: tokenSet.accessToken,
      expiresAtSeconds: tokenSet.expiresAtSeconds,
      tenantId: tokenSet.tenantId,
      subjectId: tokenSet.subjectId,
      roles: tokenSet.roles
    },
    nowSeconds
  );
}

export function rotateConsoleSession(
  transaction: AuthorizationTransaction,
  tokenSet: AuthenticatedTokenSet,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession {
  if (tokenSet.expiresAtSeconds <= nowSeconds) {
    throw new Error("OIDC access token is already expired.");
  }
  const store = authStore();
  purgeExpired(store, nowSeconds * 1000);
  const priorSession =
    transaction.priorSessionId === null
      ? undefined
      : store.sessions.get(transaction.priorSessionId);
  if (
    transaction.priorSessionId !== null &&
    priorSession?.authMode !== CONSOLE_AUTH_MODE_OIDC
  ) {
    // Multiple login tabs may bind the same prior session. Only the first
    // validated callback may replace it; siblings must fail closed instead of
    // allocating detached sessions after the prior session has disappeared.
    throw new AuthorizationStateError("Prior console session is no longer active.");
  }
  const replacesPriorOidcSession = priorSession !== undefined;
  if (store.sessions.size >= AUTH_SESSION_CAPACITY && !replacesPriorOidcSession) {
    throw new AuthorizationCapacityError("Console session capacity is unavailable.");
  }
  const replacement = buildSession({
    authMode: CONSOLE_AUTH_MODE_OIDC,
    accessToken: tokenSet.accessToken,
    expiresAtSeconds: tokenSet.expiresAtSeconds,
    tenantId: tokenSet.tenantId,
    subjectId: tokenSet.subjectId,
    roles: tokenSet.roles
  });
  if (transaction.priorSessionId !== null) {
    store.sessions.delete(transaction.priorSessionId);
  }
  store.sessions.set(replacement.sessionId, replacement);
  return replacement;
}

export function createUnsignedLocalConsoleSession(
  identity: ConsoleIdentity,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession {
  return persistSession(
    {
      authMode: CONSOLE_AUTH_MODE_UNSIGNED_LOCAL,
      accessToken: null,
      expiresAtSeconds: nowSeconds + LOCAL_SESSION_MAX_SECONDS,
      ...identity
    },
    nowSeconds
  );
}

export function getConsoleSession(
  sessionId: string | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): ConsoleSession | null {
  if (sessionId === undefined || !OPAQUE_VALUE_RE.test(sessionId)) {
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
  if (sessionId !== undefined && OPAQUE_VALUE_RE.test(sessionId)) {
    authStore().sessions.delete(sessionId);
  }
}

export function transactionCookieName(config: ConsoleOidcRuntimeConfig): string {
  return config.productionLike ? "__Host-hallu-oidc-state" : "hallu-oidc-state";
}

export function sessionCookieName(config: ConsoleRuntimeConfig): string {
  return config.productionLike ? "__Host-hallu-console-session" : "hallu-console-session";
}

export function resetAuthStoreForTests(): void {
  globalThis.__halluConsoleAuthStore = { transactions: new Map(), sessions: new Map() };
}

export function authStoreCountsForTests(): Readonly<{
  transactions: number;
  sessions: number;
}> {
  const store = authStore();
  return { transactions: store.transactions.size, sessions: store.sessions.size };
}

function persistSession(
  input: Omit<ConsoleSession, "sessionId" | "csrfToken">,
  nowSeconds: number
): ConsoleSession {
  const session = buildSession(input);
  const store = authStore();
  purgeExpired(store, nowSeconds * 1000);
  requireAvailableCapacity(
    store.sessions,
    AUTH_SESSION_CAPACITY,
    "Console session capacity is unavailable."
  );
  store.sessions.set(session.sessionId, session);
  return session;
}

function buildSession(
  input: Omit<ConsoleSession, "sessionId" | "csrfToken">
): ConsoleSession {
  return {
    ...input,
    sessionId: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url")
  };
}

function activeOidcSessionId(
  sessionId: string | undefined,
  nowMs: number
): string | null {
  const session = getConsoleSession(sessionId, Math.floor(nowMs / 1000));
  return session?.authMode === CONSOLE_AUTH_MODE_OIDC ? session.sessionId : null;
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
