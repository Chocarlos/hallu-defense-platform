import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { deleteConsoleSession, sessionCookieName } from "../../../lib/auth-store";
import {
  buildEndSessionUrl,
  discoverOidc
} from "../../../lib/oidc";
import { isTrustedLogoutRequest } from "../../../lib/request-security";
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

    const cookieName = sessionCookieName(config);
    deleteConsoleSession(request.cookies.get(cookieName)?.value);

    let target = config.publicOrigin;
    if (config.authMode === CONSOLE_AUTH_MODE_OIDC) {
      try {
        target = buildEndSessionUrl(config, await discoverOidc(config));
      } catch {
        // Local logout already succeeded. Provider outage must not restore or
        // retain the Console session.
      }
    }

    const response = NextResponse.redirect(target, 303);
    response.cookies.set(cookieName, "", {
      httpOnly: true,
      secure: config.productionLike,
      sameSite: "strict",
      path: "/",
      expires: new Date(0)
    });
    noStore(response);
    return response;
  } catch {
    return jsonError("Logout is unavailable.", 503);
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
