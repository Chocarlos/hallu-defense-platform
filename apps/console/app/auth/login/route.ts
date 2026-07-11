import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  createAuthorizationTransaction,
  deleteAuthorizationTransaction,
  sessionCookieName,
  transactionCookieName,
  type AuthorizationTransaction
} from "../../../lib/auth-store";
import {
  consumeAuthRateLimit
} from "../../../lib/auth-rate-limit";
import { buildAuthorizationUrl, discoverOidc } from "../../../lib/oidc";
import { isTrustedLoginNavigation } from "../../../lib/request-security";
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

  if (!isTrustedLoginNavigation(request)) {
    return jsonError("Authentication navigation is invalid.", 403);
  }

  const rateLimit = consumeAuthRateLimit("login", request, config);
  if (!rateLimit.allowed) {
    const response = NextResponse.json(
      { error: "Too many authentication requests." },
      { status: 429 }
    );
    response.headers.set("retry-after", String(rateLimit.retryAfterSeconds));
    secureResponse(response);
    return response;
  }

  let transaction: AuthorizationTransaction | undefined;
  try {
    const priorSessionId = request.cookies.get(sessionCookieName(config))?.value;
    // Capture the Strict-cookie session before the first await. A concurrent
    // callback can rotate it while discovery is in flight; the bound ID then
    // makes this authorization attempt fail closed instead of creating an
    // unrelated session.
    transaction = createAuthorizationTransaction(
      config,
      priorSessionId === undefined ? {} : { priorSessionId }
    );
    const discovery = await discoverOidc(config);
    const response = NextResponse.redirect(
      buildAuthorizationUrl(config, discovery, transaction),
      302
    );
    response.cookies.set(transactionCookieName(config), transaction.state, {
      httpOnly: true,
      secure: config.productionLike,
      sameSite: "lax",
      path: "/",
      maxAge: config.transactionTtlSeconds,
      priority: "high"
    });
    secureResponse(response);
    return response;
  } catch {
    if (transaction !== undefined) {
      deleteAuthorizationTransaction(transaction.state);
    }
    const response = unavailable();
    secureResponse(response);
    return response;
  }
}

function unavailable(): NextResponse {
  return jsonError("Authentication is unavailable.", 503);
}

function jsonError(message: string, status: number): NextResponse {
  const response = NextResponse.json({ error: message }, { status });
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
