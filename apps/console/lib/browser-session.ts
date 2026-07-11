import type { ConsoleIdentity } from "./runtime-config";

const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_:-]{0,63}$/u;
const SUBJECT_RE = /^[^\u0000-\u001f\u007f]{1,256}$/u;
const OPAQUE_VALUE_RE = /^[A-Za-z0-9_-]{43}$/u;

export interface BrowserAuthenticatedSession extends ConsoleIdentity {
  readonly csrfToken: string;
  readonly expiresAtSeconds: number;
}

export function parseBrowserSession(
  value: unknown,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): BrowserAuthenticatedSession {
  if (!isRecord(value)) {
    throw new Error("Authentication session is invalid.");
  }
  // Treat an accidental credential-bearing response as an authentication
  // failure. Browser JavaScript must never receive OAuth/OIDC credentials.
  if (
    "accessToken" in value ||
    "access_token" in value ||
    "idToken" in value ||
    "id_token" in value ||
    "refreshToken" in value ||
    "refresh_token" in value
  ) {
    throw new Error("Authentication session exposed a forbidden credential.");
  }
  const csrfToken = value.csrfToken;
  const expiresAtSeconds = value.expiresAtSeconds;
  const tenantId = value.tenantId;
  const subjectId = value.subjectId;
  const roles = value.roles;
  if (
    typeof csrfToken !== "string" ||
    !OPAQUE_VALUE_RE.test(csrfToken) ||
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
    csrfToken,
    expiresAtSeconds,
    tenantId,
    subjectId,
    roles: Object.freeze([...roles].sort()) as readonly string[]
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
