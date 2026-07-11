import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  deleteConsoleSession,
  sessionCookieName
} from "../../../lib/auth-store";
import {
  CONSOLE_AUTH_MODE_OIDC,
  loadConsoleRuntimeConfig
} from "../../../lib/runtime-config";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const config = loadConsoleRuntimeConfig();
    if (!isTrustedLogoutRequest(request, config.publicOrigin)) {
      return jsonError("Request origin is invalid.", 403);
    }
    if (config.authMode === CONSOLE_AUTH_MODE_OIDC) {
      deleteConsoleSession(request.cookies.get(sessionCookieName(config))?.value);
    }
    const response = NextResponse.redirect(config.publicOrigin, 303);
    if (config.authMode === CONSOLE_AUTH_MODE_OIDC) {
      response.cookies.set(sessionCookieName(config), "", {
        httpOnly: true,
        secure: config.productionLike,
        sameSite: "lax",
        path: "/",
        expires: new Date(0)
      });
    }
    noStore(response);
    return response;
  } catch {
    return jsonError("Logout is unavailable.", 503);
  }
}

export function isTrustedLogoutRequest(
  request: NextRequest,
  expectedOrigin: string
): boolean {
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== "null") {
    return origin === expectedOrigin;
  }
  if (
    origin === "null" &&
    request.headers.get("sec-fetch-site") === "same-origin" &&
    request.headers.get("sec-fetch-mode") === "navigate" &&
    request.headers.get("sec-fetch-user") === "?1"
  ) {
    return true;
  }
  const referer = request.headers.get("referer");
  if (referer === null) {
    return false;
  }
  try {
    return new URL(referer).origin === expectedOrigin;
  } catch {
    return false;
  }
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
