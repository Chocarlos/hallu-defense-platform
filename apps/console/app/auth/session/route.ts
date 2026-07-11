import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  createUnsignedLocalConsoleSession,
  deleteConsoleSession,
  getConsoleSession,
  sessionCookieName,
  type ConsoleSession
} from "../../../lib/auth-store";
import {
  CONSOLE_AUTH_MODE_OIDC,
  CONSOLE_AUTH_MODE_UNSIGNED_LOCAL,
  loadConsoleRuntimeConfig,
  type ConsoleRuntimeConfig
} from "../../../lib/runtime-config";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const config = loadConsoleRuntimeConfig();
    const cookieName = sessionCookieName(config);
    const oldSessionId = request.cookies.get(cookieName)?.value;
    let session = getConsoleSession(oldSessionId);

    if (config.authMode === CONSOLE_AUTH_MODE_UNSIGNED_LOCAL) {
      if (session?.authMode !== CONSOLE_AUTH_MODE_UNSIGNED_LOCAL) {
        deleteConsoleSession(oldSessionId);
        session = createUnsignedLocalConsoleSession(config.localIdentity);
      }
    } else if (session?.authMode !== CONSOLE_AUTH_MODE_OIDC) {
      deleteConsoleSession(oldSessionId);
      return clearSessionCookie(
        json({ error: "Authentication is required." }, 401),
        config
      );
    }

    const response = json(browserSessionBody(session), 200);
    if (config.authMode === CONSOLE_AUTH_MODE_UNSIGNED_LOCAL) {
      setSessionCookie(response, config, session);
    }
    return response;
  } catch {
    return json({ error: "Authentication is unavailable." }, 503);
  }
}

function clearSessionCookie(
  response: NextResponse,
  config: ConsoleRuntimeConfig
): NextResponse {
  response.cookies.set(sessionCookieName(config), "", {
    httpOnly: true,
    secure: config.productionLike,
    sameSite: "strict",
    path: "/",
    expires: new Date(0)
  });
  return response;
}

function browserSessionBody(session: ConsoleSession): object {
  return {
    expiresAtSeconds: session.expiresAtSeconds,
    tenantId: session.tenantId,
    subjectId: session.subjectId,
    roles: session.roles,
    csrfToken: session.csrfToken
  };
}

function setSessionCookie(
  response: NextResponse,
  config: ConsoleRuntimeConfig,
  session: ConsoleSession
): void {
  response.cookies.set(sessionCookieName(config), session.sessionId, {
    httpOnly: true,
    secure: config.productionLike,
    sameSite: "strict",
    path: "/",
    maxAge: Math.max(1, session.expiresAtSeconds - Math.floor(Date.now() / 1000)),
    priority: "high"
  });
}

function json(body: object, status: number): NextResponse {
  const response = NextResponse.json(body, { status });
  response.headers.set("cache-control", "no-store, max-age=0, private");
  response.headers.set("pragma", "no-cache");
  response.headers.set("vary", "Cookie");
  return response;
}
