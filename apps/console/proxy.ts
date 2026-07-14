import { randomBytes } from "node:crypto";

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  loadConsoleRuntimeConfig,
  loadPublicRuntimeConfig
} from "./lib/runtime-config";

export function proxy(request: NextRequest): NextResponse {
  const pathname = request.nextUrl.pathname;
  const authenticatedRuntimeRequired = requiresAuthenticatedRuntime(pathname);
  let productionLike = process.env.NODE_ENV === "production";
  if (authenticatedRuntimeRequired) {
    try {
      productionLike = loadConsoleRuntimeConfig().productionLike;
    } catch {
      try {
        // The public boundary is intentionally independent of API/OIDC. Keep
        // production transport policy even when private runtime validation
        // fails later on an authenticated-only setting.
        productionLike = loadPublicRuntimeConfig().productionLike;
      } catch {
        // NODE_ENV remains the conservative deployment fallback when even the
        // public boundary is malformed.
      }
      return unavailableResponse(productionLike);
    }
  } else {
    try {
      productionLike = loadPublicRuntimeConfig().productionLike;
    } catch {
      // Public marketing and privacy pages remain available even when the
      // authenticated Console runtime is not configured. Route handlers such
      // as /demo-request retain their own fail-closed configuration boundary.
    }
  }

  try {
    const nonce = randomBytes(16).toString("base64");
    const csp = contentSecurityPolicy(nonce, productionLike);
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set("x-nonce", nonce);
    requestHeaders.set("content-security-policy", csp);
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    applySecurityHeaders(response, csp, productionLike);
    if (shouldNoIndex(pathname)) {
      response.headers.set("x-robots-tag", "noindex, nofollow, noarchive");
    }
    return response;
  } catch {
    return unavailableResponse(productionLike);
  }
}

export function requiresAuthenticatedRuntime(pathname: string): boolean {
  return (
    pathname === "/console" ||
    pathname.startsWith("/console/") ||
    pathname === "/auth" ||
    pathname.startsWith("/auth/") ||
    pathname === "/api" ||
    pathname.startsWith("/api/")
  );
}

function shouldNoIndex(pathname: string): boolean {
  return (
    requiresAuthenticatedRuntime(pathname) ||
    pathname === "/demo-request" ||
    pathname === "/metrics"
  );
}

function unavailableResponse(productionLike: boolean): NextResponse {
  const response = new NextResponse(
    "Console runtime configuration is unavailable.",
    { status: 503 }
  );
  applySecurityHeaders(
    response,
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    productionLike
  );
  response.headers.set("cache-control", "no-store, max-age=0");
  response.headers.set("pragma", "no-cache");
  response.headers.set("x-robots-tag", "noindex, nofollow, noarchive");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)"]
};

export function contentSecurityPolicy(
  nonce: string,
  productionLike: boolean
): string {
  const directives = [
    "default-src 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'${productionLike ? "" : " 'unsafe-eval'"}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(productionLike ? ["upgrade-insecure-requests"] : [])
  ];
  return directives.join("; ");
}

function applySecurityHeaders(
  response: NextResponse,
  csp: string,
  productionLike: boolean
): void {
  response.headers.set("content-security-policy", csp);
  response.headers.set("referrer-policy", "no-referrer");
  response.headers.set("x-content-type-options", "nosniff");
  response.headers.set("x-frame-options", "DENY");
  response.headers.set(
    "permissions-policy",
    "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
  );
  response.headers.set("cross-origin-opener-policy", "same-origin");
  response.headers.set("cross-origin-resource-policy", "same-site");
  if (productionLike) {
    response.headers.set(
      "strict-transport-security",
      "max-age=63072000; includeSubDomains; preload"
    );
  }
}
