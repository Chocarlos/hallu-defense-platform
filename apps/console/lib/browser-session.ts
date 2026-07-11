import type { ConsoleIdentity } from "./runtime-config";

const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_:-]{0,63}$/u;
const SUBJECT_RE = /^[^\u0000-\u001f\u007f]{1,256}$/u;

export interface BrowserAuthenticatedSession extends ConsoleIdentity {
  readonly accessToken: string | null;
  readonly expiresAtSeconds: number | null;
}

export function unsignedBrowserSession(
  identity: ConsoleIdentity
): BrowserAuthenticatedSession {
  return {
    accessToken: null,
    expiresAtSeconds: null,
    tenantId: identity.tenantId,
    subjectId: identity.subjectId,
    roles: identity.roles
  };
}

export function parseOidcBrowserSession(
  value: unknown,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): BrowserAuthenticatedSession {
  if (!isRecord(value)) {
    throw new Error("Authentication session is invalid.");
  }
  const accessToken = value.accessToken;
  const expiresAtSeconds = value.expiresAtSeconds;
  const tenantId = value.tenantId;
  const subjectId = value.subjectId;
  const roles = value.roles;
  if (
    typeof accessToken !== "string" ||
    accessToken.length < 16 ||
    accessToken.length > 32_768 ||
    /[\u0000-\u0020\u007f]/u.test(accessToken) ||
    typeof expiresAtSeconds !== "number" ||
    !Number.isSafeInteger(expiresAtSeconds) ||
    expiresAtSeconds <= nowSeconds ||
    typeof tenantId !== "string" ||
    !TENANT_RE.test(tenantId) ||
    typeof subjectId !== "string" ||
    subjectId.trim() !== subjectId ||
    !SUBJECT_RE.test(subjectId) ||
    !Array.isArray(roles) ||
    roles.length === 0 ||
    roles.some((role) => typeof role !== "string" || !ROLE_RE.test(role)) ||
    new Set(roles).size !== roles.length
  ) {
    throw new Error("Authentication session is invalid.");
  }
  return {
    accessToken,
    expiresAtSeconds,
    tenantId,
    subjectId,
    roles: Object.freeze([...roles].sort()) as readonly string[]
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
