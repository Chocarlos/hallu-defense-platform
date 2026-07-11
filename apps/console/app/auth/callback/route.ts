import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  consumeAuthorizationTransaction,
  createConsoleSession,
  sessionCookieName,
  transactionCookieName
} from "../../../lib/auth-store";
import {
  consumeAuthRateLimit
} from "../../../lib/auth-rate-limit";
import {
  discoverOidc,
  exchangeAuthorizationCode,
  isOpaqueCallbackValue,
  validateTokenSet
} from "../../../lib/oidc";
import {
  CONSOLE_AUTH_MODE_OIDC,
  loadConsoleRuntimeConfig,
  type ConsoleOidcRuntimeConfig
} from "../../../lib/runtime-config";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<NextResponse> {
  let config: ConsoleOidcRuntimeConfig;
  try {
    const loaded = loadConsoleRuntimeConfig();
    if (loaded.authMode !== CONSOLE_AUTH_MODE_OIDC) {
      return unavailable();
    }
    config = loaded;
  } catch {
    return unavailable();
  }

  const rateLimit = consumeAuthRateLimit("callback", request, config);
  if (!rateLimit.allowed) {
    const response = NextResponse.json(
      { error: "Too many authentication requests." },
      { status: 429 }
    );
    response.headers.set("retry-after", String(rateLimit.retryAfterSeconds));
    secureResponse(response);
    return response;
  }

  try {
    const state = singletonParameter(request.nextUrl.searchParams, "state", 128);
    const issuer = singletonParameter(request.nextUrl.searchParams, "iss", 2048);
    const transaction = consumeAuthorizationTransaction(
      state,
      request.cookies.get(transactionCookieName(config))?.value
    );
    if (issuer !== config.issuer) {
      throw new Error("Authorization response issuer mismatch.");
    }
    if (request.nextUrl.searchParams.has("error")) {
      throw new Error("Authorization server rejected the request.");
    }
    const code = singletonParameter(request.nextUrl.searchParams, "code", 4096);
    if (!isOpaqueCallbackValue(code, 4096)) {
      throw new Error("Authorization code is invalid.");
    }

    const discovery = await discoverOidc(config);
    const tokenResponse = await exchangeAuthorizationCode(
      config,
      discovery,
      code,
      transaction.verifier
    );
    const tokenSet = await validateTokenSet(
      config,
      discovery,
      tokenResponse,
      transaction.nonce
    );
    const session = createConsoleSession(tokenSet);
    const response = NextResponse.redirect(config.publicOrigin, 303);
    response.cookies.set(sessionCookieName(config), session.sessionId, {
      httpOnly: true,
      secure: config.productionLike,
      sameSite: "lax",
      path: "/",
      maxAge: Math.max(1, session.expiresAtSeconds - Math.floor(Date.now() / 1000)),
      priority: "high"
    });
    clearTransactionCookie(response, config);
    secureResponse(response);
    return response;
  } catch {
    const failureUrl = new URL(config.publicOrigin);
    failureUrl.searchParams.set("auth_error", "login_failed");
    const response = NextResponse.redirect(failureUrl, 303);
    clearTransactionCookie(response, config);
    secureResponse(response);
    return response;
  }
}

function singletonParameter(
  parameters: URLSearchParams,
  name: string,
  maximumLength: number
): string {
  const values = parameters.getAll(name);
  const value = values[0];
  if (
    values.length !== 1 ||
    value === undefined ||
    value.length === 0 ||
    value.length > maximumLength ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Authorization response is invalid.");
  }
  return value;
}

function clearTransactionCookie(
  response: NextResponse,
  config: ConsoleOidcRuntimeConfig
): void {
  response.cookies.set(transactionCookieName(config), "", {
    httpOnly: true,
    secure: config.productionLike,
    sameSite: "lax",
    path: "/",
    expires: new Date(0)
  });
}

function unavailable(): NextResponse {
  const response = NextResponse.json(
    { error: "Authentication is unavailable." },
    { status: 503 }
  );
  noStore(response);
  return response;
}

function noStore(response: NextResponse): void {
  response.headers.set("cache-control", "no-store, max-age=0");
  response.headers.set("pragma", "no-cache");
}

function secureResponse(response: NextResponse): void {
  noStore(response);
}
