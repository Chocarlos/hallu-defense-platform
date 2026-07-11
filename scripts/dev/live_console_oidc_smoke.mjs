import { createServer } from "node:http";

import { chromium } from "@playwright/test";

const enabled = process.env.HALLU_DEFENSE_LIVE_CONSOLE_OIDC_SMOKE_ENABLED === "true";
if (!enabled) {
  console.log("Console OIDC live smoke skipped (explicit opt-in is disabled).");
  process.exit(0);
}

const consoleOrigin = loopbackOrigin(
  process.env.HALLU_DEFENSE_LIVE_CONSOLE_OIDC_CONSOLE_ORIGIN ??
    "http://127.0.0.1:3100",
  "Console origin"
);
const apiOrigin = loopbackOrigin(
  process.env.HALLU_DEFENSE_LIVE_CONSOLE_OIDC_API_ORIGIN ??
    "http://127.0.0.1:18123",
  "API origin"
);
const username =
  process.env.HALLU_DEFENSE_LIVE_CONSOLE_OIDC_USERNAME ?? "console-reviewer";
const password =
  process.env.HALLU_DEFENSE_LIVE_CONSOLE_OIDC_PASSWORD ??
  "console-reviewer-local-only";

let resolveObservedHeaders;
const observedHeaders = new Promise((resolve) => {
  resolveObservedHeaders = resolve;
});
let headersCaptured = false;
const api = createServer((request, response) => {
  response.setHeader("access-control-allow-origin", consoleOrigin);
  response.setHeader("access-control-allow-methods", "POST, OPTIONS");
  response.setHeader(
    "access-control-allow-headers",
    "authorization, content-type, x-trace-id"
  );
  response.setHeader("vary", "origin");
  if (request.method === "OPTIONS") {
    response.writeHead(204).end();
    return;
  }
  if (request.method === "POST" && request.url === "/approvals/list") {
    if (!headersCaptured) {
      headersCaptured = true;
      resolveObservedHeaders({
        bearer: /^Bearer [A-Za-z0-9._~+/=-]+$/u.test(
          String(request.headers.authorization ?? "")
        ),
        tenantHeader: request.headers["x-tenant-id"] !== undefined,
        subjectHeader: request.headers["x-subject-id"] !== undefined,
        rolesHeader: request.headers["x-roles"] !== undefined
      });
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ trace_id: "tr_console_oidc_smoke", approvals: [] }));
    return;
  }
  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "not_found" }));
});

let browser;
try {
  await listen(api, new URL(apiOrigin));
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${consoleOrigin}/auth/login`, { waitUntil: "domcontentloaded" });
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await Promise.all([
    page.waitForURL(`${consoleOrigin}/**`, { timeout: 30_000 }),
    page.locator("#kc-login").click()
  ]);
  await page.getByRole("heading", { name: "Consola DevEx" }).waitFor();
  await page.getByText("tenant-a", { exact: true }).waitFor();

  const authenticatedSession = await context.request.get(`${consoleOrigin}/auth/session`);
  assert(authenticatedSession.status() === 200, "OIDC session endpoint was not authenticated");
  assert(
    authenticatedSession.headers()["cache-control"]?.includes("no-store") === true,
    "OIDC session response was cacheable"
  );
  const sessionBody = await authenticatedSession.json();
  assert(sessionBody.tenantId === "tenant-a", "Session tenant did not come from the token");
  assert(
    typeof sessionBody.subjectId === "string" &&
      sessionBody.subjectId.length > 0 &&
      sessionBody.subjectId.length <= 256,
    "Session subject was invalid"
  );
  assert(
    typeof sessionBody.accessToken === "string" && sessionBody.accessToken.length > 32,
    "Session did not contain a validated access token"
  );
  await page.getByText(sessionBody.subjectId, { exact: false }).waitFor();

  const headers = await withTimeout(observedHeaders, 15_000);
  assert(headers.bearer, "SDK request did not carry Bearer authentication");
  assert(!headers.tenantHeader, "SDK request leaked x-tenant-id beside Bearer");
  assert(!headers.subjectHeader, "SDK request leaked x-subject-id beside Bearer");
  assert(!headers.rolesHeader, "SDK request leaked x-roles beside Bearer");

  const [logoutResponse] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url() === `${consoleOrigin}/auth/logout` &&
        response.request().method() === "POST"
    ),
    page.getByRole("button", { name: "Cerrar sesion" }).click()
  ]);
  const logoutRequestHeaders = await logoutResponse.request().allHeaders();
  assert(
    logoutResponse.status() === 303,
    `Logout POST returned unexpected status ${logoutResponse.status()} ` +
      `(origin=${logoutRequestHeaders.origin ?? "missing"}, ` +
      `referer=${logoutRequestHeaders.referer ?? "missing"}, ` +
      `site=${logoutRequestHeaders["sec-fetch-site"] ?? "missing"}, ` +
      `mode=${logoutRequestHeaders["sec-fetch-mode"] ?? "missing"}, ` +
      `user=${logoutRequestHeaders["sec-fetch-user"] ?? "missing"})`
  );
  await page
    .getByRole("heading", { name: "Autenticacion requerida" })
    .waitFor({ timeout: 15_000 });
  const loggedOutSession = await context.request.get(`${consoleOrigin}/auth/session`);
  assert(loggedOutSession.status() === 401, "Logout did not invalidate the Console session");

  console.log(
    JSON.stringify({
      status: "passed",
      authorizationCodePkce: true,
      authenticatedTenant: "tenant-a",
      authenticatedSubject: "opaque-sub-claim",
      bearerOnlyIdentityHeaders: true,
      sessionNoStore: true,
      logoutInvalidatedSession: true
    })
  );
} finally {
  await browser?.close();
  await close(api);
}

function loopbackOrigin(raw, label) {
  const url = new URL(raw);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.origin !== raw
  ) {
    throw new Error(`${label} must be an exact loopback HTTP origin.`);
  }
  return url.origin;
}

function listen(server, url) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(url.port), url.hostname, resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Timed out waiting for API authentication.")), timeoutMs);
    })
  ]);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
