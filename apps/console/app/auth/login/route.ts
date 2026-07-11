import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  createAuthorizationTransaction,
  transactionCookieName
} from "../../../lib/auth-store";
import {
  consumeAuthRateLimit
} from "../../../lib/auth-rate-limit";
import { buildAuthorizationUrl, discoverOidc } from "../../../lib/oidc";
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

  try {
    const discovery = await discoverOidc(config);
    const transaction = createAuthorizationTransaction(config);
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
    const response = unavailable();
    secureResponse(response);
    return response;
  }
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
