import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  deleteConsoleSession,
  getConsoleSession,
  sessionCookieName,
  type ConsoleSession
} from "./auth-store";
import { constantTimeEqual } from "./oidc";
import { isTrustedApiMutation } from "./request-security";
import {
  CONSOLE_AUTH_MODE_OIDC,
  CONSOLE_AUTH_MODE_UNSIGNED_LOCAL,
  loadConsoleRuntimeConfig,
  type ConsoleRuntimeConfig
} from "./runtime-config";

const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const LONG_RUNNING_TIMEOUT_MS = 335_000;

const ALLOWED_ENDPOINTS = new Map<string, number>([
  ["verification/run", DEFAULT_TIMEOUT_MS],
  ["verification/replay", DEFAULT_TIMEOUT_MS],
  ["verification/runs/list", DEFAULT_TIMEOUT_MS],
  ["rag/corpus-grants/upsert", DEFAULT_TIMEOUT_MS],
  ["rag/corpus-grants/list", DEFAULT_TIMEOUT_MS],
  ["documents/ingest", DEFAULT_TIMEOUT_MS],
  ["documents/ingest/status", DEFAULT_TIMEOUT_MS],
  ["evals/reports/list", DEFAULT_TIMEOUT_MS],
  ["approvals/list", DEFAULT_TIMEOUT_MS],
  ["approvals/decide", DEFAULT_TIMEOUT_MS],
  ["tools/validate-input", DEFAULT_TIMEOUT_MS],
  ["policy/evaluate", DEFAULT_TIMEOUT_MS],
  ["repo/checks/run", LONG_RUNNING_TIMEOUT_MS]
]);

export async function forwardConsoleApiRequest(
  request: NextRequest,
  pathSegments: readonly string[],
  fetchImpl: typeof fetch = globalThis.fetch
): Promise<NextResponse> {
  let config: ConsoleRuntimeConfig;
  try {
    config = loadConsoleRuntimeConfig();
  } catch {
    return jsonError("Console API is unavailable.", 503);
  }

  const endpoint = canonicalEndpoint(pathSegments);
  const timeoutMs = endpoint === null ? undefined : ALLOWED_ENDPOINTS.get(endpoint);
  if (timeoutMs === undefined || request.nextUrl.search !== "") {
    return jsonError("Console API endpoint is not available.", 404);
  }
  if (!isTrustedApiMutation(request, config.publicOrigin)) {
    return jsonError("Request origin is invalid.", 403);
  }
  if (mediaType(request.headers.get("content-type")) !== "application/json") {
    return jsonError("Request content type is invalid.", 415);
  }

  const cookieName = sessionCookieName(config);
  const sessionId = request.cookies.get(cookieName)?.value;
  const session = getConsoleSession(sessionId);
  if (!sessionMatchesConfig(session, config)) {
    deleteConsoleSession(sessionId);
    return clearSession(jsonError("Authentication is required.", 401), config);
  }
  const suppliedCsrf = request.headers.get("x-console-csrf");
  if (
    suppliedCsrf === null ||
    !/^[A-Za-z0-9_-]{43}$/u.test(suppliedCsrf) ||
    !constantTimeEqual(suppliedCsrf, session.csrfToken)
  ) {
    return jsonError("CSRF validation failed.", 403);
  }

  let body: string;
  try {
    body = await readJsonBody(request, MAX_REQUEST_BYTES);
  } catch {
    return jsonError("Request body is invalid.", 400);
  }

  const headers = new Headers({
    accept: "application/json",
    "content-type": "application/json"
  });
  if (config.authMode === CONSOLE_AUTH_MODE_OIDC) {
    headers.set("authorization", `Bearer ${session.accessToken}`);
  } else {
    headers.set("x-tenant-id", config.localIdentity.tenantId);
    headers.set("x-subject-id", config.localIdentity.subjectId);
    headers.set("x-roles", config.localIdentity.roles.join(","));
  }

  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(), timeoutMs);
  let upstream: Response;
  try {
    upstream = await fetchImpl(`${config.apiOrigin}/${endpoint}`, {
      method: "POST",
      headers,
      body,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.any([request.signal, timeoutController.signal])
    });
  } catch {
    clearTimeout(timeout);
    return jsonError("Console API is unavailable.", 504);
  }

  try {
    if (!upstream.ok) {
      await upstream.body?.cancel().catch(() => undefined);
      const response = jsonError(upstreamErrorMessage(upstream.status), upstream.status);
      copyRetryAfter(upstream, response);
      if (upstream.status === 401) {
        deleteConsoleSession(sessionId);
        clearSession(response, config);
      }
      return response;
    }
    if (mediaType(upstream.headers.get("content-type")) !== "application/json") {
      await upstream.body?.cancel().catch(() => undefined);
      return jsonError("Console API returned an invalid response.", 502);
    }

    let responseBody: string;
    try {
      responseBody = await readResponseBody(upstream, MAX_RESPONSE_BYTES);
      JSON.parse(responseBody);
    } catch {
      return timeoutController.signal.aborted
        ? jsonError("Console API is unavailable.", 504)
        : jsonError("Console API returned an invalid response.", 502);
    }
    return secureResponse(
      new NextResponse(responseBody, {
        status: upstream.status,
        headers: { "content-type": "application/json" }
      })
    );
  } finally {
    clearTimeout(timeout);
  }
}

function canonicalEndpoint(pathSegments: readonly string[]): string | null {
  if (
    pathSegments.length < 2 ||
    pathSegments.length > 4 ||
    pathSegments.some((segment) => !/^[a-z0-9-]+$/u.test(segment))
  ) {
    return null;
  }
  return pathSegments.join("/");
}

function sessionMatchesConfig(
  session: ConsoleSession | null,
  config: ConsoleRuntimeConfig
): session is ConsoleSession {
  if (session === null || session.authMode !== config.authMode) {
    return false;
  }
  if (config.authMode === CONSOLE_AUTH_MODE_OIDC) {
    return session.accessToken !== null;
  }
  return (
    session.authMode === CONSOLE_AUTH_MODE_UNSIGNED_LOCAL &&
    session.accessToken === null &&
    session.tenantId === config.localIdentity.tenantId &&
    session.subjectId === config.localIdentity.subjectId &&
    session.roles.join("\0") === config.localIdentity.roles.join("\0")
  );
}

async function readJsonBody(request: NextRequest, maximumBytes: number): Promise<string> {
  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > maximumBytes)
  ) {
    throw new Error("Request is too large.");
  }
  if (request.body === null) {
    throw new Error("Request body is missing.");
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("Request is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks, total);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Request JSON must be an object.");
  }
  return text;
}

async function readResponseBody(response: Response, maximumBytes: number): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > maximumBytes)
  ) {
    await response.body?.cancel();
    throw new Error("Response is too large.");
  }
  if (response.body === null) {
    throw new Error("Response body is missing.");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("Response is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
}

function mediaType(value: string | null): string | null {
  return value?.split(";", 1)[0]?.trim().toLowerCase() ?? null;
}

function upstreamErrorMessage(status: number): string {
  if (status === 401) {
    return "Authentication is required.";
  }
  if (status === 403) {
    return "Permission is required.";
  }
  if (status === 429) {
    return "Too many requests.";
  }
  return status >= 500
    ? "Console API is unavailable."
    : "Console API request was rejected.";
}

function copyRetryAfter(upstream: Response, response: NextResponse): void {
  const value = upstream.headers.get("retry-after");
  if (value !== null && /^(0|[1-9][0-9]{0,4})$/u.test(value) && Number(value) <= 86_400) {
    response.headers.set("retry-after", value);
  }
}

function clearSession(response: NextResponse, config: ConsoleRuntimeConfig): NextResponse {
  response.cookies.set(sessionCookieName(config), "", {
    httpOnly: true,
    secure: config.productionLike,
    sameSite: "strict",
    path: "/",
    expires: new Date(0)
  });
  return response;
}

function jsonError(message: string, status: number): NextResponse {
  return secureResponse(NextResponse.json({ error: message }, { status }));
}

function secureResponse(response: NextResponse): NextResponse {
  response.headers.set("cache-control", "no-store, max-age=0, private");
  response.headers.set("pragma", "no-cache");
  response.headers.set("vary", "Cookie, Origin");
  response.headers.set("x-content-type-options", "nosniff");
  return response;
}
