import type { NextRequest } from "next/server";

export function isTrustedLoginNavigation(request: NextRequest): boolean {
  const site = request.headers.get("sec-fetch-site");
  const mode = request.headers.get("sec-fetch-mode");
  const destination = request.headers.get("sec-fetch-dest");
  return (
    (site === "same-origin" || site === "none") &&
    mode === "navigate" &&
    destination === "document"
  );
}

export function isTrustedLogoutRequest(
  request: NextRequest,
  expectedOrigin: string
): boolean {
  if (request.headers.get("origin") !== expectedOrigin) {
    return false;
  }
  const site = request.headers.get("sec-fetch-site");
  const mode = request.headers.get("sec-fetch-mode");
  return (
    (site === null || site === "same-origin") &&
    (mode === null || mode === "navigate")
  );
}

export function isTrustedApiMutation(
  request: NextRequest,
  expectedOrigin: string
): boolean {
  if (request.headers.get("origin") !== expectedOrigin) {
    return false;
  }
  const site = request.headers.get("sec-fetch-site");
  const mode = request.headers.get("sec-fetch-mode");
  return (
    (site === null || site === "same-origin") &&
    (mode === null || mode === "same-origin" || mode === "cors")
  );
}
