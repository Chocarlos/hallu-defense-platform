import {
  DEMO_PRIVACY_VERSION,
  DEMO_REQUEST_MAX_BYTES,
  DEMO_USE_CASES,
  DemoRequestError,
  type DemoUseCase,
  type NormalizedDemoRequest
} from "./contracts";

const ALLOWED_FIELDS = new Set([
  "submission_id",
  "locale",
  "email",
  "name",
  "company",
  "use_case",
  "consent",
  "privacy_version",
  "website"
]);
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EMAIL_LOCAL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u;
const JSON_CONTENT_TYPE_RE =
  /^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/iu;

export function validateDemoRequestSource(request: Request, expectedOrigin: string): void {
  const url = new URL(request.url);
  if (url.search !== "") {
    invalidRequest();
  }
  if (request.headers.get("origin") !== expectedOrigin) {
    invalidRequest();
  }
  if (request.headers.get("sec-fetch-site") !== "same-origin") {
    invalidRequest();
  }
  const mode = request.headers.get("sec-fetch-mode");
  if (mode !== "cors" && mode !== "same-origin") {
    invalidRequest();
  }
  if (request.headers.get("sec-fetch-dest") !== "empty") {
    invalidRequest();
  }
}

export async function readAndNormalizeDemoRequest(
  request: Request
): Promise<NormalizedDemoRequest> {
  const contentType = request.headers.get("content-type");
  const contentEncoding = request.headers.get("content-encoding");
  if (
    contentType === null ||
    !JSON_CONTENT_TYPE_RE.test(contentType) ||
    (contentEncoding !== null && contentEncoding.trim().toLowerCase() !== "identity")
  ) {
    throw new DemoRequestError(415, "Request content type is invalid.", "invalid");
  }

  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(0|[1-9][0-9]*)$/u.test(declaredLength) ||
      Number(declaredLength) > DEMO_REQUEST_MAX_BYTES)
  ) {
    invalidRequest();
  }
  if (request.body === null) {
    invalidRequest();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > DEMO_REQUEST_MAX_BYTES) {
        await reader.cancel();
        invalidRequest();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (declaredLength !== null && Number(declaredLength) !== totalBytes) {
    invalidRequest();
  }

  let parsed: unknown;
  try {
    const bytes = Buffer.concat(chunks, totalBytes);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text) as unknown;
  } catch {
    invalidRequest();
  }
  return normalizeDemoRequest(parsed);
}

export function normalizeDemoRequest(value: unknown): NormalizedDemoRequest {
  if (!isRecord(value)) {
    invalidSchema();
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !ALLOWED_FIELDS.has(key))) {
    invalidSchema();
  }

  const submissionId = requiredString(value, "submission_id");
  if (!UUID_V4_RE.test(submissionId)) {
    invalidSchema();
  }

  const locale = value.locale;
  if (locale !== "es" && locale !== "en") {
    invalidSchema();
  }

  const email = normalizeEmail(requiredString(value, "email"));
  const name = optionalHumanText(value, "name", 100);
  const company = optionalHumanText(value, "company", 120);
  const useCase = value.use_case;
  if (typeof useCase !== "string" || !isDemoUseCase(useCase)) {
    invalidSchema();
  }
  if (value.consent !== true || value.privacy_version !== DEMO_PRIVACY_VERSION) {
    invalidSchema();
  }
  if (value.website !== undefined && typeof value.website !== "string") {
    invalidSchema();
  }

  return {
    submissionId,
    locale,
    email,
    ...(name === undefined ? {} : { name }),
    ...(company === undefined ? {} : { company }),
    useCase,
    consent: true,
    privacyVersion: DEMO_PRIVACY_VERSION,
    honeypot: typeof value.website === "string" && value.website.trim() !== ""
  };
}

function normalizeEmail(value: string): string {
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > 254 ||
    /[\u0000-\u0020\u007f]/u.test(normalized)
  ) {
    invalidSchema();
  }
  const separator = normalized.lastIndexOf("@");
  if (separator <= 0 || separator !== normalized.indexOf("@")) {
    invalidSchema();
  }
  const local = normalized.slice(0, separator);
  const domain = normalized.slice(separator + 1);
  const labels = domain.split(".");
  if (
    local.length > 64 ||
    !EMAIL_LOCAL_RE.test(local) ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    labels.length < 2 ||
    labels.some((label) => !DOMAIN_LABEL_RE.test(label))
  ) {
    invalidSchema();
  }
  return normalized;
}

function optionalHumanText(
  value: Readonly<Record<string, unknown>>,
  key: "name" | "company",
  maximumCharacters: number
): string | undefined {
  const raw = value[key];
  if (raw === undefined) {
    return undefined;
  }
  if (typeof raw !== "string") {
    invalidSchema();
  }
  const normalized = raw.normalize("NFKC").trim().replace(/\s+/gu, " ");
  if (normalized === "") {
    return undefined;
  }
  if (
    [...normalized].length > maximumCharacters ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    invalidSchema();
  }
  return normalized;
}

function requiredString(
  value: Readonly<Record<string, unknown>>,
  key: "submission_id" | "email"
): string {
  const result = value[key];
  if (typeof result !== "string") {
    invalidSchema();
  }
  return result;
}

function isDemoUseCase(value: string): value is DemoUseCase {
  return (DEMO_USE_CASES as readonly string[]).includes(value);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalidRequest(): never {
  throw new DemoRequestError(400, "Request is invalid.", "invalid");
}

function invalidSchema(): never {
  throw new DemoRequestError(422, "Request payload is invalid.", "invalid");
}
