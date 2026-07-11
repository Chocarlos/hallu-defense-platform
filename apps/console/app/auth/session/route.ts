import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { getConsoleSession, sessionCookieName } from "../../../lib/auth-store";
import {
  CONSOLE_AUTH_MODE_OIDC,
  loadConsoleRuntimeConfig
} from "../../../lib/runtime-config";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const config = loadConsoleRuntimeConfig();
    if (config.authMode !== CONSOLE_AUTH_MODE_OIDC) {
      return json({ error: "OIDC sessions are disabled." }, 404);
    }
    const session = getConsoleSession(
      request.cookies.get(sessionCookieName(config))?.value
    );
    if (session === null) {
      return json({ error: "Authentication is required." }, 401);
    }
    return json(
      {
        accessToken: session.accessToken,
        expiresAtSeconds: session.expiresAtSeconds,
        tenantId: session.tenantId,
        subjectId: session.subjectId,
        roles: session.roles
      },
      200
    );
  } catch {
    return json({ error: "Authentication is unavailable." }, 503);
  }
}

function json(body: object, status: number): NextResponse {
  const response = NextResponse.json(body, { status });
  response.headers.set("cache-control", "no-store, max-age=0, private");
  response.headers.set("pragma", "no-cache");
  return response;
}
