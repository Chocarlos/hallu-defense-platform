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

let resolveObservedBearer;
const observedBearer = new Promise((resolve) => {
  resolveObservedBearer = resolve;
});
let bearerResolved = false;
let sawCorsPreflight = false;
const api = createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    sawCorsPreflight = true;
    response.writeHead(405, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "cors_not_supported" }));
    return;
  }
  await drainRequest(request);
  const authorization = String(request.headers.authorization ?? "");
  const bearer = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (!bearerResolved && bearer.length > 0) {
    bearerResolved = true;
    resolveObservedBearer({
      value: bearer,
      validShape: /^[A-Za-z0-9._~+/=-]+$/u.test(bearer),
      tenantHeader: request.headers["x-tenant-id"] !== undefined,
      subjectHeader: request.headers["x-subject-id"] !== undefined,
      rolesHeader: request.headers["x-roles"] !== undefined,
      browserOriginHeader: request.headers.origin !== undefined
    });
  }

  if (request.method !== "POST") {
    return json(response, 405, { error: "method_not_allowed" });
  }
  if (request.url === "/approvals/list") {
    return json(response, 200, {
      trace_id: "tr_console_oidc_smoke",
      approvals: []
    });
  }
  if (request.url === "/verification/runs/list") {
    return json(response, 200, {
      trace_id: "tr_console_oidc_smoke",
      runs: [],
      next_cursor: null
    });
  }
  if (request.url === "/rag/corpus-grants/list") {
    return json(response, 200, {
      trace_id: "tr_console_oidc_smoke",
      grants: [],
      next_cursor: null
    });
  }
  if (request.url === "/evals/reports/list") {
    return json(response, 200, {
      trace_id: "tr_console_oidc_smoke",
      reports: [],
      next_cursor: null
    });
  }
  return json(response, 404, { error: "not_found" });
});

let browser;
try {
  await listen(api, new URL(apiOrigin));
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const directApiRequests = [];
  page.on("request", (request) => {
    if (new URL(request.url()).origin === apiOrigin) {
      directApiRequests.push(request.url());
    }
  });

  await page.goto(`${consoleOrigin}/auth/login`, { waitUntil: "domcontentloaded" });
  const authorizationUrl = new URL(page.url());
  const state = authorizationUrl.searchParams.get("state") ?? "";
  const nonce = authorizationUrl.searchParams.get("nonce") ?? "";
  const challenge = authorizationUrl.searchParams.get("code_challenge") ?? "";
  assert(opaqueValue(state), "Authorization request state was invalid");
  assert(opaqueValue(nonce), "Authorization request nonce was invalid");
  assert(opaqueValue(challenge), "Authorization request PKCE challenge was invalid");
  assert(
    authorizationUrl.searchParams.get("code_challenge_method") === "S256",
    "Authorization request did not require PKCE S256"
  );
  assert(
    authorizationUrl.searchParams.get("response_type") === "code",
    "Authorization request did not use code flow"
  );
  assert(
    authorizationUrl.searchParams.get("redirect_uri") === `${consoleOrigin}/auth/callback`,
    "Authorization callback was not exact"
  );

  const transactionCookie = (await context.cookies(consoleOrigin)).find((cookie) =>
    cookie.name.endsWith("hallu-oidc-state")
  );
  assert(transactionCookie?.value === state, "OIDC state cookie did not bind the request");
  assert(transactionCookie?.httpOnly === true, "OIDC state cookie was readable by JavaScript");
  assert(transactionCookie?.sameSite === "Lax", "OIDC state cookie SameSite was not Lax");

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
  assert(opaqueValue(sessionBody.csrfToken), "Session CSRF token was invalid");
  for (const forbidden of [
    "accessToken",
    "access_token",
    "idToken",
    "id_token",
    "refreshToken",
    "refresh_token"
  ]) {
    assert(!(forbidden in sessionBody), `Session exposed forbidden field ${forbidden}`);
  }

  const sessionCookie = (await context.cookies(consoleOrigin)).find((cookie) =>
    cookie.name.endsWith("hallu-console-session")
  );
  assert(sessionCookie?.httpOnly === true, "Console session cookie was readable by JavaScript");
  assert(sessionCookie?.sameSite === "Strict", "Console session cookie SameSite was not Strict");

  const observed = await withTimeout(observedBearer, 15_000);
  assert(observed.validShape, "BFF request did not carry Bearer authentication");
  assert(!observed.tenantHeader, "BFF leaked x-tenant-id beside Bearer");
  assert(!observed.subjectHeader, "BFF leaked x-subject-id beside Bearer");
  assert(!observed.rolesHeader, "BFF leaked x-roles beside Bearer");
  assert(!observed.browserOriginHeader, "API received a browser Origin header");
  assert(directApiRequests.length === 0, "Browser contacted the API origin directly");
  assert(!sawCorsPreflight, "Browser required CORS to reach the API");
  assert(!(await page.content()).includes(observed.value), "Bearer appeared in rendered HTML");
  assert(!JSON.stringify(sessionBody).includes(observed.value), "Bearer appeared in session JSON");

  const crossOriginBff = await context.request.post(
    `${consoleOrigin}/api/approvals/list`,
    {
      headers: {
        origin: "https://attacker.example.invalid",
        "content-type": "application/json",
        "x-console-csrf": sessionBody.csrfToken
      },
      data: {}
    }
  );
  assert(crossOriginBff.status() === 403, "BFF accepted a cross-origin mutation");
  const wrongCsrfBff = await context.request.post(`${consoleOrigin}/api/approvals/list`, {
    headers: {
      origin: consoleOrigin,
      "content-type": "application/json",
      "x-console-csrf": "invalid"
    },
    data: {}
  });
  assert(wrongCsrfBff.status() === 403, "BFF accepted an invalid CSRF token");

  const crossOriginLogout = await context.request.post(`${consoleOrigin}/auth/logout`, {
    headers: { origin: "https://attacker.example.invalid" }
  });
  assert(crossOriginLogout.status() === 403, "Logout accepted a cross-origin mutation");
  assert(
    (await context.request.get(`${consoleOrigin}/auth/session`)).status() === 200,
    "Rejected logout invalidated the legitimate session"
  );

  const logoutButton = page.getByRole("button", { name: "Cerrar sesion" });
  assert(await logoutButton.isVisible(), "Console did not expose its logout control");
  const logoutResponse = await context.request.post(`${consoleOrigin}/auth/logout`, {
    headers: { origin: consoleOrigin },
    maxRedirects: 0
  });
  const logoutResponseHeaders = logoutResponse.headers();
  assert(logoutResponse.status() === 303, "Console logout did not redirect with 303");
  const logoutLocation = logoutResponseHeaders.location;
  assert(typeof logoutLocation === "string", "Console logout did not include a location");
  const providerLogoutUrl = new URL(logoutLocation);
  assert(
    providerLogoutUrl.pathname.endsWith("/protocol/openid-connect/logout"),
    "Console logout did not target the OIDC provider"
  );
  assert(
    providerLogoutUrl.searchParams.get("client_id") === "hallu-defense-console",
    "Provider logout did not identify the public client"
  );
  assert(
    providerLogoutUrl.searchParams.get("post_logout_redirect_uri") === consoleOrigin,
    "Provider logout return URI was not exact"
  );
  for (const key of providerLogoutUrl.searchParams.keys()) {
    assert(!/token/iu.test(key), "Provider logout URL exposed a token parameter");
  }
  await page.goto(providerLogoutUrl.href, { waitUntil: "domcontentloaded" });

  await page.goto(`${consoleOrigin}/console`, { waitUntil: "domcontentloaded" });
  await page
    .getByRole("heading", { name: "Autenticacion requerida" })
    .waitFor({ timeout: 15_000 });
  const loggedOutSession = await context.request.get(`${consoleOrigin}/auth/session`);
  assert(loggedOutSession.status() === 401, "Logout did not invalidate the Console session");

  console.log(
    JSON.stringify({
      status: "passed",
      stateNoncePkceS256: true,
      browserCredentialExposure: false,
      sameOriginBff: true,
      csrfAndOriginEnforced: true,
      bearerOnlyServerIdentity: true,
      corsRequired: false,
      providerLogoutInvoked: true,
      localSessionInvalidated: true
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

function opaqueValue(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value);
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

function drainRequest(request) {
  return new Promise((resolve, reject) => {
    request.on("error", reject);
    request.on("end", resolve);
    request.resume();
  });
}

function json(response, status, body) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json"
  });
  response.end(JSON.stringify(body));
}

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Timed out waiting for BFF authentication.")),
      timeoutMs
    );
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeout);
        reject(error);
      }
    );
  });
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
