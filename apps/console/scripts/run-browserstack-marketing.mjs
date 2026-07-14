import { createHash, randomBytes } from "node:crypto";
import { Agent as HttpsAgent } from "node:https";
import process from "node:process";

import { chromium, firefox, webkit } from "@playwright/test";
import { Builder, By } from "selenium-webdriver";

const CATALOG_URL = "https://api.browserstack.com/automate/browsers.json";
const HUB_URL = "https://hub-cloud.browserstack.com/wd/hub";
const PLAYWRIGHT_ENDPOINT = "wss://cdp.browserstack.com/playwright";
const SAFE_EMAIL = "browserstack-smoke@example.invalid";
const DEFAULT_BUILD_NAME = "hallu-defense-marketing";
const EXPECTED_HEADLINE = "La confianza no se asume. Se demuestra.";
const EXPECTED_FORM_SUCCESS = "Solicitud recibida.";
const PUBLIC_REQUEST_ID_PATTERN = /\bdr_[A-Za-z0-9_-]{24}\b/u;
const LIVE_SMOKE_NONCE = randomBytes(6).toString("hex");

const CATALOG_TIMEOUT_MS = 20_000;
const REMOTE_CONNECT_TIMEOUT_MS = 60_000;
const NAVIGATION_TIMEOUT_MS = 60_000;
const ASSERTION_TIMEOUT_MS = 15_000;
const SESSION_DETAILS_TIMEOUT_MS = 15_000;
const MAX_CATALOG_BYTES = 5_000_000;
const MAX_DIAGNOSTIC_DIGESTS = 20;

const minimumRequirements = Object.freeze([
  Object.freeze({
    key: "chrome-111",
    mobile: false,
    catalogBrowser: "chrome",
    versionField: "browserVersion",
    versionPrefix: "111",
    browserName: "chrome"
  }),
  Object.freeze({
    key: "edge-111",
    mobile: false,
    catalogBrowser: "edge",
    versionField: "browserVersion",
    versionPrefix: "111",
    browserName: "edge"
  }),
  Object.freeze({
    key: "firefox-111",
    mobile: false,
    catalogBrowser: "firefox",
    versionField: "browserVersion",
    versionPrefix: "111",
    browserName: "firefox"
  }),
  Object.freeze({
    key: "safari-16.4",
    mobile: false,
    catalogBrowser: "safari",
    versionField: "browserVersion",
    versionPrefix: "16.4",
    browserName: "safari"
  }),
  Object.freeze({
    key: "ios-safari-16.4",
    mobile: true,
    catalogOs: "ios",
    versionField: "osVersion",
    versionPrefix: "16.4",
    requiresDevice: true,
    browserName: "safari"
  })
]);

const currentRequirements = Object.freeze([
  Object.freeze({
    key: "current-chrome",
    catalogBrowser: "chrome",
    capabilityBrowser: "chrome",
    engine: "chromium",
    branded: true,
    preferredOs: "windows"
  }),
  Object.freeze({
    key: "current-edge",
    catalogBrowser: "edge",
    capabilityBrowser: "edge",
    engine: "chromium",
    branded: true,
    preferredOs: "windows"
  }),
  Object.freeze({
    key: "current-firefox",
    catalogBrowser: "firefox",
    capabilityBrowser: "playwright-firefox",
    engine: "firefox",
    branded: false,
    preferredOs: "windows"
  }),
  Object.freeze({
    key: "current-webkit",
    catalogBrowser: "safari",
    capabilityBrowser: "playwright-webkit",
    engine: "webkit",
    branded: false,
    preferredOs: "osx"
  })
]);

const playwrightEngines = Object.freeze({ chromium, firefox, webkit });

class ConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigurationError";
  }
}

class RunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = "RunnerError";
  }
}

try {
  const checkOnly = parseArguments(process.argv.slice(2));
  if (checkOnly) {
    validateStaticContract();
    console.log(
      "Validated BrowserStack marketing runner contract; no remote compatibility result was claimed."
    );
  } else {
    await runRemoteMatrix();
  }
} catch (error) {
  const message =
    error instanceof ConfigurationError || error instanceof RunnerError
      ? error.message
      : "Unexpected internal runner failure.";
  console.error(`BrowserStack marketing gate failed: ${message}`);
  process.exitCode = 1;
}

async function runRemoteMatrix() {
  const credentials = readCredentials(process.env);
  if (credentials === undefined) {
    console.log(
      "BrowserStack marketing gate skipped: BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY are absent. No compatibility result is claimed."
    );
    return;
  }

  const runtime = readRuntimeConfiguration(process.env);
  const catalog = await fetchCatalog(credentials);
  const { minimumMatrix, playwrightMatrix } = resolveMatrices(catalog);

  console.log(
    JSON.stringify(
      {
        event: "browserstack-marketing-matrix",
        source: CATALOG_URL,
        formSmoke: runtime.liveFormEnabled ? "isolated-webhook-stub" : "non-submitting",
        playwright: playwrightMatrix.map(({ requirement, entry }) => ({
          requirement: requirement.key,
          capabilityBrowser: requirement.capabilityBrowser,
          engine: requirement.engine,
          ...publicCatalogEntry(entry)
        })),
        seleniumMinimums: minimumMatrix.map(({ requirement, entry }) => ({
          requirement: requirement.key,
          browserName: requirement.browserName,
          ...publicCatalogEntry(entry)
        }))
      },
      null,
      2
    )
  );

  for (const target of playwrightMatrix) {
    await runPlaywrightSmoke({
      ...target,
      runtime,
      credentials
    });
  }
  for (const target of minimumMatrix) {
    await runSeleniumSmoke({
      ...target,
      runtime,
      credentials
    });
  }

  console.log("BrowserStack marketing matrix completed without reducing required minimums.");
}

function parseArguments(args) {
  if (args.length === 0) return false;
  if (args.length === 1 && args[0] === "--check-config") return true;
  throw new ConfigurationError("Only the optional --check-config argument is supported.");
}

function readCredentials(environment) {
  const username = optionalEnvironmentString(environment, "BROWSERSTACK_USERNAME", 256);
  const accessKey = optionalEnvironmentString(environment, "BROWSERSTACK_ACCESS_KEY", 512);
  if (username === undefined && accessKey === undefined) return undefined;
  if (username === undefined || accessKey === undefined) {
    throw new ConfigurationError("BrowserStack credentials must be supplied together.");
  }
  return Object.freeze({ username, accessKey });
}

function readRuntimeConfiguration(environment) {
  const local = booleanEnvironment(environment, "BROWSERSTACK_LOCAL", false);
  const localIdentifier = optionalEnvironmentString(
    environment,
    "BROWSERSTACK_LOCAL_IDENTIFIER",
    256
  );
  if (local && localIdentifier === undefined) {
    throw new ConfigurationError(
      "BrowserStack Local requires BROWSERSTACK_LOCAL_IDENTIFIER."
    );
  }
  if (!local && localIdentifier !== undefined) {
    throw new ConfigurationError(
      "BROWSERSTACK_LOCAL_IDENTIFIER is only valid when BROWSERSTACK_LOCAL=true."
    );
  }

  const liveFormEnabled = booleanEnvironment(
    environment,
    "HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED",
    false
  );
  const webhookStub = booleanEnvironment(environment, "BROWSERSTACK_WEBHOOK_STUB", false);
  if (liveFormEnabled && !webhookStub) {
    throw new ConfigurationError(
      "Enabled form smoke requires an explicit isolated webhook stub."
    );
  }

  const rawBaseUrl = requiredEnvironmentString(environment, "BROWSERSTACK_BASE_URL", 2_048);
  const baseURL = validatedBaseUrl(rawBaseUrl, local);
  const buildName =
    optionalEnvironmentString(environment, "BROWSERSTACK_BUILD_NAME", 255) ??
    DEFAULT_BUILD_NAME;

  return Object.freeze({
    baseURL,
    buildName,
    local,
    localIdentifier,
    liveFormEnabled,
    webhookStub
  });
}

function optionalEnvironmentString(environment, name, maximumLength) {
  const raw = environment[name];
  // GitHub Actions materializes absent secrets as empty strings. Treat that
  // representation as absent, while rejecting whitespace and control chars.
  if (raw === undefined || raw === "") return undefined;
  if (
    typeof raw !== "string" ||
    raw.trim() !== raw ||
    raw.length > maximumLength ||
    /[\u0000-\u001f\u007f]/u.test(raw)
  ) {
    throw new ConfigurationError(`${name} is malformed.`);
  }
  return raw;
}

function requiredEnvironmentString(environment, name, maximumLength) {
  const value = optionalEnvironmentString(environment, name, maximumLength);
  if (value === undefined) {
    throw new ConfigurationError(`${name} is required when credentials are present.`);
  }
  return value;
}

function booleanEnvironment(environment, name, defaultValue) {
  const raw = environment[name];
  if (raw === undefined) return defaultValue;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new ConfigurationError(`${name} must be exactly true or false.`);
}

function validatedBaseUrl(raw, local) {
  if (raw.includes("?") || raw.includes("#")) {
    throw new ConfigurationError(
      "BROWSERSTACK_BASE_URL must not contain a query or fragment."
    );
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigurationError("BROWSERSTACK_BASE_URL must be an absolute URL.");
  }

  if (url.username || url.password) {
    throw new ConfigurationError("BROWSERSTACK_BASE_URL must not contain credentials.");
  }
  if (!url.hostname || (url.protocol !== "https:" && url.protocol !== "http:")) {
    throw new ConfigurationError("BROWSERSTACK_BASE_URL must use HTTP or HTTPS.");
  }
  if (!local && url.protocol !== "https:") {
    throw new ConfigurationError("Remote BrowserStack smoke requires an HTTPS staging URL.");
  }
  return url;
}

async function fetchCatalog(credentials) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CATALOG_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(CATALOG_URL, {
      headers: {
        authorization: `Basic ${Buffer.from(
          `${credentials.username}:${credentials.accessKey}`
        ).toString("base64")}`
      },
      redirect: "error",
      signal: controller.signal
    });
    if (!response.ok) {
      throw new RunnerError(`BrowserStack catalog returned HTTP ${response.status}.`);
    }
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_CATALOG_BYTES) {
      throw new RunnerError("BrowserStack catalog exceeded the response-size limit.");
    }
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > MAX_CATALOG_BYTES) {
      throw new RunnerError("BrowserStack catalog exceeded the response-size limit.");
    }

    let value;
    try {
      value = JSON.parse(body);
    } catch {
      throw new RunnerError("BrowserStack catalog response is not valid JSON.");
    }
    if (!Array.isArray(value) || value.length > 50_000) {
      throw new RunnerError("BrowserStack catalog response is not a bounded array.");
    }
    return value.map(parseCatalogEntry).filter((entry) => entry !== undefined);
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    if (controller.signal.aborted) {
      throw new RunnerError("BrowserStack catalog request timed out.");
    }
    throw new RunnerError("BrowserStack catalog request failed.");
  } finally {
    clearTimeout(timeout);
  }
}

function parseCatalogEntry(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  if (
    value.real_mobile !== undefined &&
    value.real_mobile !== null &&
    typeof value.real_mobile !== "boolean"
  ) {
    return undefined;
  }

  const browser = catalogString(value.browser);
  const os = catalogString(value.os);
  const osVersion = catalogString(value.os_version);
  const device = nullableCatalogString(value.device);
  const browserVersion = nullableCatalogString(value.browser_version);
  if (browser === undefined || os === undefined || osVersion === undefined) {
    return undefined;
  }

  const mobile = value.real_mobile === true || device !== undefined;
  if ((!mobile && browserVersion === undefined) || (mobile && device === undefined)) {
    return undefined;
  }
  return Object.freeze({ browser, browserVersion, os, osVersion, device, mobile });
}

function catalogString(value) {
  return typeof value === "string" &&
    value !== "" &&
    value.trim() === value &&
    value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value)
    ? value
    : undefined;
}

function nullableCatalogString(value) {
  if (value === null || value === undefined) return undefined;
  return catalogString(value);
}

function resolveMatrices(catalog) {
  const minimumMatrix = minimumRequirements.map((requirement) => {
    const candidates = catalog.filter((entry) => matchesMinimum(entry, requirement));
    candidates.sort((left, right) => compareMinimumCandidates(left, right, requirement));
    const entry = candidates[0];
    if (entry === undefined) {
      throw new RunnerError(
        `BrowserStack catalog does not expose required minimum ${requirement.key}; matrix was not reduced.`
      );
    }
    return Object.freeze({ requirement, entry });
  });

  const playwrightMatrix = currentRequirements.map((requirement) => {
    const candidates = catalog.filter(
      (entry) =>
        !entry.mobile &&
        normalizeBrowser(entry.browser) === requirement.catalogBrowser &&
        numericVersionParts(entry.browserVersion) !== undefined
    );
    candidates.sort((left, right) => compareCurrentCandidates(left, right, requirement));
    const entry = candidates[0];
    if (entry === undefined) {
      throw new RunnerError(
        `BrowserStack catalog exposes no current desktop ${requirement.catalogBrowser} candidate.`
      );
    }
    return Object.freeze({ requirement, entry });
  });

  return Object.freeze({
    minimumMatrix: Object.freeze(minimumMatrix),
    playwrightMatrix: Object.freeze(playwrightMatrix)
  });
}

function matchesMinimum(entry, requirement) {
  if (entry.mobile !== requirement.mobile) return false;
  if (
    requirement.catalogBrowser !== undefined &&
    normalizeBrowser(entry.browser) !== requirement.catalogBrowser
  ) {
    return false;
  }
  if (
    requirement.catalogOs !== undefined &&
    normalizeOs(entry.os) !== requirement.catalogOs
  ) {
    return false;
  }
  if (requirement.requiresDevice && entry.device === undefined) return false;
  return versionHasPrefix(entry[requirement.versionField], requirement.versionPrefix);
}

function compareMinimumCandidates(left, right, requirement) {
  const versionOrder = compareNumericVersions(
    left[requirement.versionField],
    right[requirement.versionField]
  );
  return versionOrder !== 0 ? versionOrder : compareCatalogIdentity(left, right);
}

function compareCurrentCandidates(left, right, requirement) {
  const versionOrder = compareNumericVersions(right.browserVersion, left.browserVersion);
  if (versionOrder !== 0) return versionOrder;
  const leftOsRank = normalizeOs(left.os) === requirement.preferredOs ? 0 : 1;
  const rightOsRank = normalizeOs(right.os) === requirement.preferredOs ? 0 : 1;
  if (leftOsRank !== rightOsRank) return leftOsRank - rightOsRank;
  return compareCatalogIdentity(left, right);
}

function compareCatalogIdentity(left, right) {
  const leftIdentity = catalogIdentity(left);
  const rightIdentity = catalogIdentity(right);
  if (leftIdentity < rightIdentity) return -1;
  if (leftIdentity > rightIdentity) return 1;
  return 0;
}

function catalogIdentity(entry) {
  return JSON.stringify([
    entry.browser,
    entry.browserVersion ?? "",
    entry.os,
    entry.osVersion,
    entry.device ?? "",
    entry.mobile
  ]);
}

function normalizeBrowser(value) {
  const browser = value.toLowerCase().replace(/[\s_-]+/gu, "");
  if (browser.includes("edge")) return "edge";
  if (browser.includes("firefox")) return "firefox";
  if (browser.includes("safari")) return "safari";
  if (browser.includes("chrome")) return "chrome";
  return browser;
}

function normalizeOs(value) {
  return value.toLowerCase().replace(/[\s_-]+/gu, "");
}

function versionHasPrefix(actual, requiredPrefix) {
  const actualParts = numericVersionParts(actual);
  const requiredParts = numericVersionParts(requiredPrefix);
  return (
    actualParts !== undefined &&
    requiredParts !== undefined &&
    actualParts.length >= requiredParts.length &&
    requiredParts.every((part, index) => actualParts[index] === part)
  );
}

function compareNumericVersions(left, right) {
  const leftParts = numericVersionParts(left);
  const rightParts = numericVersionParts(right);
  if (leftParts === undefined || rightParts === undefined) {
    throw new ConfigurationError("An internal catalog comparison received a nonnumeric version.");
  }
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function numericVersionParts(value) {
  if (typeof value !== "string" || !/^\d+(?:\.\d+)*$/u.test(value)) {
    return undefined;
  }
  const parts = value.split(".").map(Number);
  return parts.every((part) => Number.isSafeInteger(part)) ? parts : undefined;
}

function buildPlaywrightCapabilities(requirement, entry, runtime, credentials) {
  const capabilities = {
    browser: requirement.capabilityBrowser,
    os: entry.os,
    os_version: entry.osVersion,
    name: `Hallu Defense marketing Playwright ${requirement.key}`,
    build: runtime.buildName,
    "browserstack.username": credentials.username,
    "browserstack.accessKey": credentials.accessKey,
    "browserstack.local": runtime.local,
    "browserstack.console": "errors",
    "browserstack.debug": true,
    ...(runtime.localIdentifier === undefined
      ? {}
      : { "browserstack.localIdentifier": runtime.localIdentifier })
  };
  if (requirement.branded) {
    if (entry.browserVersion === undefined) {
      throw new ConfigurationError("A branded Playwright target has no browser version.");
    }
    capabilities.browser_version = entry.browserVersion;
  }
  return capabilities;
}

function buildSeleniumCapabilities(requirement, entry, runtime, credentials) {
  const bstackOptions = {
    userName: credentials.username,
    accessKey: credentials.accessKey,
    osVersion: entry.osVersion,
    sessionName: `Hallu Defense minimum ${requirement.key}`,
    buildName: runtime.buildName,
    local: runtime.local,
    idleTimeout: 90,
    consoleLogs: "errors",
    debug: true,
    ...(runtime.localIdentifier === undefined
      ? {}
      : { localIdentifier: runtime.localIdentifier }),
    ...(entry.mobile
      ? { deviceName: entry.device, realMobile: true }
      : { os: entry.os })
  };
  return {
    browserName: requirement.browserName,
    ...(entry.browserVersion === undefined
      ? {}
      : { browserVersion: entry.browserVersion }),
    "bstack:options": bstackOptions
  };
}

async function runPlaywrightSmoke({ requirement, entry, runtime, credentials }) {
  const engine = playwrightEngines[requirement.engine];
  if (engine === undefined) {
    throw new ConfigurationError(`No Playwright engine is registered for ${requirement.key}.`);
  }
  const capabilities = buildPlaywrightCapabilities(
    requirement,
    entry,
    runtime,
    credentials
  );
  const endpoint = `${PLAYWRIGHT_ENDPOINT}?caps=${encodeURIComponent(
    JSON.stringify(capabilities)
  )}`;

  let browser;
  try {
    browser = await engine.connect(endpoint, { timeout: REMOTE_CONNECT_TIMEOUT_MS });
  } catch {
    throw new RunnerError(`Playwright session ${requirement.key} could not connect.`);
  }

  let session;
  let page;
  let failure;
  const diagnostics = createDiagnostics();
  try {
    const context = await safeRemoteStep(
      () =>
        browser.newContext({
          viewport: { width: 1440, height: 1000 },
          ignoreHTTPSErrors: false
        }),
      `Playwright session ${requirement.key} could not create a context.`
    );
    context.setDefaultTimeout(ASSERTION_TIMEOUT_MS);
    context.setDefaultNavigationTimeout(NAVIGATION_TIMEOUT_MS);
    page = await safeRemoteStep(
      () => context.newPage(),
      `Playwright session ${requirement.key} could not create a page.`
    );
    attachPlaywrightDiagnostics(page, diagnostics);
    session = await getPlaywrightSessionDetails(page, requirement.key);

    await safeRemoteStep(
      () =>
        page.goto(runtime.baseURL.href, {
          waitUntil: "load",
          timeout: NAVIGATION_TIMEOUT_MS
        }),
      `Playwright session ${requirement.key} could not load the staging page.`,
      NAVIGATION_TIMEOUT_MS
    );
    const heading = await safeRemoteStep(
      () => page.locator("h1").first().textContent({ timeout: ASSERTION_TIMEOUT_MS }),
      `Playwright session ${requirement.key} could not read the headline.`
    );
    if (heading?.trim() !== EXPECTED_HEADLINE) {
      throw new RunnerError(`Unexpected Spanish headline on ${requirement.key}.`);
    }

    const overflow = await safeRemoteStep(
      () =>
        page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth + 1
        ),
      `Playwright session ${requirement.key} could not inspect page overflow.`
    );
    if (overflow) {
      throw new RunnerError(`Horizontal overflow detected on ${requirement.key}.`);
    }

    if (runtime.liveFormEnabled) {
      assertIsolatedWebhookStub(runtime, requirement.key);
      await completePlaywrightDemoRequest(
        page,
        requirement.key,
        liveSmokeEmail("playwright", requirement.key)
      );
    } else {
      await inspectPlaywrightDemoFormWithoutSubmitting(page, requirement.key);
    }

    if (diagnostics.pageErrors.total > 0 || diagnostics.consoleErrors.total > 0) {
      throw new RunnerError(
        `Browser runtime errors were captured on ${requirement.key}; inspect the recorded diagnostic digests.`
      );
    }
    await setPlaywrightSessionStatus(page, "passed", requirement.key);
    logSessionEvidence("playwright", requirement.key, "passed", session, diagnostics);
  } catch (error) {
    failure = safeRunnerFailure(
      error,
      `Playwright session ${requirement.key} failed unexpectedly.`
    );
    if (page !== undefined) {
      await setPlaywrightSessionStatus(page, "failed", requirement.key).catch(
        () => undefined
      );
    }
    if (session !== undefined) {
      logSessionEvidence("playwright", requirement.key, "failed", session, diagnostics);
    }
    throw failure;
  } finally {
    try {
      await safeRemoteStep(
        () => browser.close(),
        `Playwright session ${requirement.key} could not close cleanly.`
      );
    } catch {
      if (failure === undefined) {
        throw new RunnerError(`Playwright session ${requirement.key} could not close cleanly.`);
      }
    }
  }
}

async function runSeleniumSmoke({ requirement, entry, runtime, credentials }) {
  const capabilities = buildSeleniumCapabilities(
    requirement,
    entry,
    runtime,
    credentials
  );
  let driver;
  let httpAgent;
  try {
    ({ driver, httpAgent } = await buildSeleniumDriver(capabilities, requirement.key));
  } catch (error) {
    throw safeRunnerFailure(
      error,
      `Selenium session ${requirement.key} could not connect.`
    );
  }

  let session;
  let failure;
  let seleniumTransportUsable = true;
  const abortSeleniumTransport = () => {
    seleniumTransportUsable = false;
    httpAgent.destroy();
  };
  const seleniumStep = (action, message, milliseconds = ASSERTION_TIMEOUT_MS) =>
    safeRemoteStep(action, message, milliseconds, abortSeleniumTransport);
  try {
    await seleniumStep(
      () =>
        driver.manage().setTimeouts({
          implicit: 0,
          pageLoad: NAVIGATION_TIMEOUT_MS,
          script: ASSERTION_TIMEOUT_MS
      }),
      `Selenium session ${requirement.key} could not configure timeouts.`
    );
    session = await getSeleniumSessionDetails(
      driver,
      requirement.key,
      abortSeleniumTransport
    );
    await seleniumStep(
      () => driver.get(runtime.baseURL.href),
      `Selenium session ${requirement.key} could not load the staging page.`,
      NAVIGATION_TIMEOUT_MS
    );
    const heading = await seleniumStep(
      async () => (await driver.findElement(By.css("h1")).getText()).trim(),
      `Selenium session ${requirement.key} could not read the headline.`
    );
    if (heading !== EXPECTED_HEADLINE) {
      throw new RunnerError(`Unexpected Spanish headline for ${requirement.key}.`);
    }

    const overflow = await seleniumStep(
      () =>
        driver.executeScript(
          "return document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"
        ),
      `Selenium session ${requirement.key} could not inspect page overflow.`
    );
    if (overflow === true) {
      throw new RunnerError(`Horizontal overflow detected for ${requirement.key}.`);
    }

    if (runtime.liveFormEnabled) {
      assertIsolatedWebhookStub(runtime, requirement.key);
      await completeSeleniumDemoRequest(
        driver,
        seleniumStep,
        requirement.key,
        liveSmokeEmail("selenium", requirement.key)
      );
    } else {
      await inspectSeleniumDemoFormWithoutSubmitting(
        driver,
        seleniumStep,
        requirement.key
      );
    }
    await setSeleniumSessionStatus(
      driver,
      "passed",
      requirement.key,
      abortSeleniumTransport
    );
    logSessionEvidence("selenium", requirement.key, "passed", session, undefined);
  } catch (error) {
    failure = safeRunnerFailure(error, `Selenium session ${requirement.key} failed unexpectedly.`);
    if (seleniumTransportUsable) {
      await setSeleniumSessionStatus(
        driver,
        "failed",
        requirement.key,
        abortSeleniumTransport
      ).catch(() => undefined);
    }
    if (session !== undefined) {
      logSessionEvidence("selenium", requirement.key, "failed", session, undefined);
    }
    throw failure;
  } finally {
    try {
      if (seleniumTransportUsable) {
        await seleniumStep(
          () => driver.quit(),
          `Selenium session ${requirement.key} could not close cleanly.`,
          ASSERTION_TIMEOUT_MS
        );
      }
    } catch {
      if (failure === undefined) {
        throw new RunnerError(`Selenium session ${requirement.key} could not close cleanly.`);
      }
    } finally {
      httpAgent.destroy();
    }
  }
}

function assertIsolatedWebhookStub(runtime, requirementKey) {
  if (!runtime.webhookStub) {
    throw new ConfigurationError(
      `Enabled form smoke ${requirementKey} is not bound to an isolated webhook stub.`
    );
  }
}

async function inspectPlaywrightDemoFormWithoutSubmitting(page, requirementKey) {
  const email = page.locator('input[type="email"]');
  const emailCount = await safeRemoteStep(
    () => email.count(),
    `Playwright session ${requirementKey} could not inspect the email field.`
  );
  if (
    emailCount > 0 &&
    (await safeRemoteStep(
      () => email.first().isEnabled(),
      `Playwright session ${requirementKey} could not inspect the email field.`
    ))
  ) {
    await safeRemoteStep(
      () => email.first().fill(SAFE_EMAIL),
      `Playwright session ${requirementKey} could not fill synthetic contact data.`
    );
  }
}

async function completePlaywrightDemoRequest(page, requirementKey, email) {
  await safeRemoteStep(
    () => page.locator('[data-demo-form-hydrated="true"]').waitFor({ state: "visible" }),
    `Playwright session ${requirementKey} did not hydrate the enabled form.`
  );
  await safeRemoteStep(
    () => page.locator("#demo-email").fill(email),
    `Playwright session ${requirementKey} could not fill synthetic contact data.`
  );
  await safeRemoteStep(
    () => page.getByRole("button", { name: "Continuar", exact: true }).click(),
    `Playwright session ${requirementKey} could not continue the enabled form.`
  );
  await safeRemoteStep(
    () => page.locator("#demo-consent").check(),
    `Playwright session ${requirementKey} could not grant synthetic consent.`
  );

  const responsePromise = page.waitForResponse(
    (response) => {
      try {
        return (
          response.request().method() === "POST" &&
          new URL(response.url()).pathname === "/demo-request"
        );
      } catch {
        return false;
      }
    },
    { timeout: ASSERTION_TIMEOUT_MS }
  );
  const [response] = await safeRemoteStep(
    () =>
      Promise.all([
        responsePromise,
        page.getByRole("button", { name: "Solicitar demo", exact: true }).click()
      ]),
    `Playwright session ${requirementKey} did not complete the enabled form.`
  );
  if (response.status() !== 202) {
    throw new RunnerError(
      `Enabled form smoke returned HTTP ${response.status()} on ${requirementKey}.`
    );
  }

  const success = page.getByRole("status").filter({ hasText: EXPECTED_FORM_SUCCESS });
  await safeRemoteStep(
    () => success.waitFor({ state: "visible" }),
    `Playwright session ${requirementKey} did not render the 202 success state.`
  );
  const successText = await safeRemoteStep(
    () => success.textContent(),
    `Playwright session ${requirementKey} could not inspect the 202 success state.`
  );
  assertSuccessfulFormText(successText, requirementKey);
}

async function inspectSeleniumDemoFormWithoutSubmitting(
  driver,
  seleniumStep,
  requirementKey
) {
  const emails = await seleniumStep(
    () => driver.findElements(By.css('input[type="email"]:not([disabled])')),
    `Selenium session ${requirementKey} could not inspect the email field.`
  );
  if (emails.length > 0) {
    await seleniumStep(
      () => emails[0].sendKeys(SAFE_EMAIL),
      `Selenium session ${requirementKey} could not fill synthetic contact data.`
    );
  }
}

async function completeSeleniumDemoRequest(
  driver,
  seleniumStep,
  requirementKey,
  emailAddress
) {
  await seleniumStep(
    () =>
      driver.wait(async () => {
        const hydrated = await driver.findElements(
          By.css('[data-demo-form-hydrated="true"]')
        );
        return hydrated.length === 1;
      }, ASSERTION_TIMEOUT_MS),
    `Selenium session ${requirementKey} did not hydrate the enabled form.`
  );

  const email = await seleniumStep(
    () => driver.findElement(By.css("#demo-email")),
    `Selenium session ${requirementKey} could not find the enabled email field.`
  );
  await seleniumStep(
    () => email.sendKeys(emailAddress),
    `Selenium session ${requirementKey} could not fill synthetic contact data.`
  );
  const continueButton = await seleniumStep(
    () => driver.findElement(By.css('form button[type="submit"]')),
    `Selenium session ${requirementKey} could not find the continue button.`
  );
  await seleniumStep(
    () => continueButton.click(),
    `Selenium session ${requirementKey} could not continue the enabled form.`
  );

  const consent = await seleniumStep(
    () =>
      driver.wait(async () => {
        const matches = await driver.findElements(By.css("#demo-consent"));
        return matches[0] ?? false;
      }, ASSERTION_TIMEOUT_MS),
    `Selenium session ${requirementKey} could not find the consent control.`
  );
  await seleniumStep(
    () => driver.executeScript("arguments[0].scrollIntoView({block: 'center'});", consent),
    `Selenium session ${requirementKey} could not reveal the consent control.`
  );
  await seleniumStep(
    () => consent.click(),
    `Selenium session ${requirementKey} could not grant synthetic consent.`
  );
  const consentGranted = await seleniumStep(
    () => consent.isSelected(),
    `Selenium session ${requirementKey} could not verify synthetic consent.`
  );
  if (!consentGranted) {
    throw new RunnerError(
      `Selenium session ${requirementKey} did not retain synthetic consent.`
    );
  }

  await seleniumStep(
    () =>
      driver.executeScript(`
        window.__halluDefenseBrowserStackDemoStatus = null;
        const originalFetch = window.fetch.bind(window);
        window.fetch = async (...args) => {
          const response = await originalFetch(...args);
          const input = args[0];
          const rawUrl = typeof input === "string" ? input : input?.url;
          if (typeof rawUrl === "string" && new URL(rawUrl, window.location.href).pathname === "/demo-request") {
            window.__halluDefenseBrowserStackDemoStatus = response.status;
          }
          return response;
        };
      `),
    `Selenium session ${requirementKey} could not install the response-status probe.`
  );
  const submitButton = await seleniumStep(
    () => driver.findElement(By.css('form button[type="submit"]')),
    `Selenium session ${requirementKey} could not find the submit button.`
  );
  await seleniumStep(
    () => submitButton.click(),
    `Selenium session ${requirementKey} could not submit the enabled form.`
  );

  const successText = await seleniumStep(
    () =>
      driver.wait(async () => {
        const statuses = await driver.findElements(By.css('[role="status"]'));
        for (const status of statuses) {
          const text = await status.getText();
          if (text.includes(EXPECTED_FORM_SUCCESS)) return text;
        }
        return false;
      }, ASSERTION_TIMEOUT_MS),
    `Selenium session ${requirementKey} did not render the 202 success state.`
  );
  const responseStatus = await seleniumStep(
    () =>
      driver.executeScript(
        "return window.__halluDefenseBrowserStackDemoStatus;"
      ),
    `Selenium session ${requirementKey} could not inspect the form response status.`
  );
  if (responseStatus !== 202) {
    throw new RunnerError(
      `Enabled form smoke returned HTTP ${String(responseStatus)} for ${requirementKey}.`
    );
  }
  assertSuccessfulFormText(successText, requirementKey);
}

function assertSuccessfulFormText(value, requirementKey) {
  if (
    typeof value !== "string" ||
    !value.includes(EXPECTED_FORM_SUCCESS) ||
    !PUBLIC_REQUEST_ID_PATTERN.test(value)
  ) {
    throw new RunnerError(
      `Enabled form smoke ${requirementKey} rendered an invalid 202 success state.`
    );
  }
}

function liveSmokeEmail(runner, requirementKey) {
  const safeRequirementKey = requirementKey.toLowerCase().replace(/[^a-z0-9-]+/gu, "-");
  const localPart = `browserstack-smoke-${LIVE_SMOKE_NONCE}-${runner}-${safeRequirementKey}`;
  if (!/^[a-z0-9-]+$/u.test(localPart) || localPart.length > 64) {
    throw new ConfigurationError("BrowserStack live smoke email could not be generated safely.");
  }
  return `${localPart}@example.invalid`;
}

async function buildSeleniumDriver(capabilities, requirementKey) {
  const httpAgent = new HttpsAgent({
    keepAlive: true,
    maxSockets: 1,
    timeout: REMOTE_CONNECT_TIMEOUT_MS
  });
  const buildPromise = new Builder()
    .usingServer(HUB_URL)
    .usingHttpAgent(httpAgent)
    .withCapabilities(capabilities)
    .build();
  let timeout;
  try {
    const driver = await Promise.race([
      buildPromise,
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => {
            httpAgent.destroy();
            reject(new RunnerError(`Selenium session ${requirementKey} timed out connecting.`));
          },
          REMOTE_CONNECT_TIMEOUT_MS
        );
      })
    ]);
    return { driver, httpAgent };
  } catch (error) {
    // Destroying the agent aborts the in-flight HTTP request. BrowserStack's
    // bounded idleTimeout cleans a session that happened to be created at the
    // same instant as the local deadline without reopening this transport.
    httpAgent.destroy();
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function createDiagnostics() {
  return {
    pageErrors: { total: 0, digests: [] },
    consoleErrors: { total: 0, digests: [] },
    consoleWarnings: { total: 0, digests: [] }
  };
}

function attachPlaywrightDiagnostics(page, diagnostics) {
  page.on("pageerror", (error) => {
    recordDiagnostic(diagnostics.pageErrors, error instanceof Error ? error.message : error);
  });
  page.on("console", (message) => {
    if (message.type() === "error") {
      recordDiagnostic(diagnostics.consoleErrors, message.text());
    } else if (message.type() === "warning") {
      recordDiagnostic(diagnostics.consoleWarnings, message.text());
    }
  });
}

function recordDiagnostic(bucket, value) {
  bucket.total += 1;
  if (bucket.digests.length < MAX_DIAGNOSTIC_DIGESTS) {
    bucket.digests.push(
      createHash("sha256").update(String(value), "utf8").digest("hex").slice(0, 16)
    );
  }
}

async function getPlaywrightSessionDetails(page, requirementKey) {
  const executor = `browserstack_executor: ${JSON.stringify({
    action: "getSessionDetails"
  })}`;
  const raw = await safeRemoteStep(
    () => page.evaluate(() => undefined, executor),
    `Playwright session ${requirementKey} did not expose session details.`,
    SESSION_DETAILS_TIMEOUT_MS
  );
  return parseSessionDetails(raw, requirementKey);
}

async function getSeleniumSessionDetails(driver, requirementKey, abortTransport) {
  const raw = await safeRemoteStep(
    () =>
      driver.executeScript(
        'browserstack_executor: {"action":"getSessionDetails"}'
      ),
    `Selenium session ${requirementKey} did not expose session details.`,
    SESSION_DETAILS_TIMEOUT_MS,
    abortTransport
  );
  return parseSessionDetails(raw, requirementKey);
}

function parseSessionDetails(raw, requirementKey) {
  let value = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      throw new RunnerError(`BrowserStack session ${requirementKey} returned invalid details.`);
    }
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RunnerError(`BrowserStack session ${requirementKey} returned invalid details.`);
  }

  const hashedId = safeSessionIdentifier(value.hashed_id);
  if (hashedId === undefined) {
    throw new RunnerError(`BrowserStack session ${requirementKey} omitted hashed_id.`);
  }
  return Object.freeze({
    hashed_id: hashedId,
    browser: safeSessionField(value.browser),
    browser_version: safeSessionField(value.browser_version),
    os: safeSessionField(value.os),
    os_version: safeSessionField(value.os_version),
    device: safeSessionField(value.device),
    status: safeSessionField(value.status)
  });
}

function safeSessionIdentifier(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{8,128}$/u.test(value)
    ? value
    : undefined;
}

function safeSessionField(value) {
  return typeof value === "string" &&
    value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value)
    ? value
    : undefined;
}

async function setPlaywrightSessionStatus(page, status, requirementKey) {
  const executor = `browserstack_executor: ${JSON.stringify({
    action: "setSessionStatus",
    arguments: {
      status,
      reason: `Marketing smoke ${requirementKey} ${status}`
    }
  })}`;
  await safeRemoteStep(
    () => page.evaluate(() => undefined, executor),
    `Playwright session ${requirementKey} could not record its status.`,
    SESSION_DETAILS_TIMEOUT_MS
  );
}

async function setSeleniumSessionStatus(driver, status, requirementKey, abortTransport) {
  const executor = `browserstack_executor: ${JSON.stringify({
    action: "setSessionStatus",
    arguments: {
      status,
      reason: `Marketing smoke ${requirementKey} ${status}`
    }
  })}`;
  await safeRemoteStep(
    () => driver.executeScript(executor),
    `Selenium session ${requirementKey} could not record its status.`,
    SESSION_DETAILS_TIMEOUT_MS,
    abortTransport
  );
}

function logSessionEvidence(runner, requirement, result, session, diagnostics) {
  console.log(
    JSON.stringify({
      event: "browserstack-session",
      runner,
      requirement,
      result,
      session,
      ...(diagnostics === undefined ? {} : { diagnostics })
    })
  );
}

async function safeRemoteStep(
  action,
  message,
  milliseconds = ASSERTION_TIMEOUT_MS,
  onTimeout = undefined
) {
  if (onTimeout !== undefined && typeof onTimeout !== "function") {
    throw new ConfigurationError("A remote timeout callback is malformed.");
  }
  try {
    return await withDeadline(
      Promise.resolve().then(action),
      milliseconds,
      message,
      onTimeout
    );
  } catch (error) {
    if (error instanceof ConfigurationError || error instanceof RunnerError) throw error;
    throw new RunnerError(message);
  }
}

async function withDeadline(promise, milliseconds, message, onTimeout = undefined) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          try {
            onTimeout?.();
          } catch {
            // Timeout cleanup is best-effort; the bounded failure still wins.
          } finally {
            reject(new RunnerError(message));
          }
        }, milliseconds);
      })
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function safeRunnerFailure(error, fallbackMessage) {
  return error instanceof ConfigurationError || error instanceof RunnerError
    ? error
    : new RunnerError(fallbackMessage);
}

function publicCatalogEntry(entry) {
  return {
    browser: entry.browser,
    browserVersion: entry.browserVersion,
    os: entry.os,
    osVersion: entry.osVersion,
    device: entry.device,
    mobile: entry.mobile
  };
}

function validateStaticContract() {
  assertConfiguration(
    SAFE_EMAIL.endsWith("@example.invalid"),
    "BrowserStack smoke email must use example.invalid."
  );
  assertConfiguration(
    minimumRequirements.length === 5,
    "BrowserStack minimum matrix is incomplete."
  );
  assertConfiguration(
    currentRequirements.length === 4,
    "BrowserStack current matrix is incomplete."
  );

  const minimumKeys = new Set(minimumRequirements.map(({ key }) => key));
  for (const required of [
    "chrome-111",
    "edge-111",
    "firefox-111",
    "safari-16.4",
    "ios-safari-16.4"
  ]) {
    assertConfiguration(
      minimumKeys.has(required),
      `BrowserStack minimum matrix is missing ${required}.`
    );
  }
  assertConfiguration(
    JSON.stringify(currentRequirements.map(({ capabilityBrowser }) => capabilityBrowser)) ===
      JSON.stringify(["chrome", "edge", "playwright-firefox", "playwright-webkit"]),
    "BrowserStack current Playwright target set is incorrect."
  );
  for (const engine of Object.values(playwrightEngines)) {
    assertConfiguration(
      typeof engine?.connect === "function",
      "A declared @playwright/test engine is unavailable."
    );
  }
  for (const timeout of [
    CATALOG_TIMEOUT_MS,
    REMOTE_CONNECT_TIMEOUT_MS,
    NAVIGATION_TIMEOUT_MS,
    ASSERTION_TIMEOUT_MS,
    SESSION_DETAILS_TIMEOUT_MS
  ]) {
    assertConfiguration(
      Number.isSafeInteger(timeout) && timeout >= 5_000 && timeout <= 120_000,
      "BrowserStack runner timeout is outside its safe bounds."
    );
  }

  const fixture = syntheticCatalogFixture();
  const forward = resolveMatrices(
    fixture.map(parseCatalogEntry).filter((entry) => entry !== undefined)
  );
  const reverse = resolveMatrices(
    [...fixture]
      .reverse()
      .map(parseCatalogEntry)
      .filter((entry) => entry !== undefined)
  );
  assertConfiguration(
    matrixSignature(forward) === matrixSignature(reverse),
    "BrowserStack catalog selection depends on response order."
  );

  const iosTarget = forward.minimumMatrix.find(
    ({ requirement }) => requirement.key === "ios-safari-16.4"
  );
  assertConfiguration(
    iosTarget?.entry.browserVersion === undefined && iosTarget?.entry.device !== undefined,
    "The iOS minimum does not accept the official null browser_version catalog shape."
  );

  const selfCheckRuntime = {
    buildName: DEFAULT_BUILD_NAME,
    local: false,
    localIdentifier: undefined
  };
  const selfCheckCredentials = { username: "self-check", accessKey: "self-check-key" };
  for (const { requirement, entry } of forward.playwrightMatrix) {
    const capabilities = buildPlaywrightCapabilities(
      requirement,
      entry,
      selfCheckRuntime,
      selfCheckCredentials
    );
    assertConfiguration(
      Object.hasOwn(capabilities, "browser_version") === requirement.branded,
      `${requirement.key} violates the branded-only browser_version contract.`
    );
  }
  const iosCapabilities = buildSeleniumCapabilities(
    iosTarget.requirement,
    iosTarget.entry,
    selfCheckRuntime,
    selfCheckCredentials
  );
  assertConfiguration(
    iosCapabilities.browserName === "safari" &&
      !Object.hasOwn(iosCapabilities, "browserVersion") &&
      iosCapabilities["bstack:options"].deviceName === iosTarget.entry.device,
    "The iOS Selenium target must resolve by os_version/device with browserName safari."
  );

  assertConfiguration(readCredentials({}) === undefined, "Absent credentials must skip.");
  assertConfiguration(
    readCredentials({ BROWSERSTACK_USERNAME: "", BROWSERSTACK_ACCESS_KEY: "" }) ===
      undefined,
    "Empty GitHub secret values must skip."
  );
  expectConfigurationError(
    () => readCredentials({ BROWSERSTACK_USERNAME: "only-one" }),
    "Partial credentials"
  );
  expectConfigurationError(
    () => booleanEnvironment({ FLAG: "TRUE" }, "FLAG", false),
    "Noncanonical booleans"
  );
  expectConfigurationError(
    () => validatedBaseUrl("http://staging.example.test/", false),
    "Nonlocal HTTP URL"
  );
  expectConfigurationError(
    () => validatedBaseUrl("https://user:password@example.test/", false),
    "URL credentials"
  );
  assertConfiguration(
    validatedBaseUrl("http://localhost:3000/", true).protocol === "http:",
    "Local HTTP URL must be accepted only for BrowserStack Local."
  );
  const disabledFormRuntime = readRuntimeConfiguration({
    BROWSERSTACK_BASE_URL: "https://staging.example.invalid/"
  });
  assertConfiguration(
    disabledFormRuntime.liveFormEnabled === false &&
      disabledFormRuntime.webhookStub === false,
    "The default BrowserStack smoke must remain non-submitting."
  );
  const enabledFormRuntime = readRuntimeConfiguration({
    BROWSERSTACK_BASE_URL: "https://staging.example.invalid/",
    HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED: "true",
    BROWSERSTACK_WEBHOOK_STUB: "true"
  });
  assertConfiguration(
    enabledFormRuntime.liveFormEnabled === true && enabledFormRuntime.webhookStub === true,
    "Enabled form and webhook-stub flags must survive runtime parsing."
  );
  const liveEmails = [
    ...currentRequirements.map(({ key }) => liveSmokeEmail("playwright", key)),
    ...minimumRequirements.map(({ key }) => liveSmokeEmail("selenium", key))
  ];
  assertConfiguration(
    new Set(liveEmails).size === liveEmails.length &&
      liveEmails.every((email) => email.endsWith("@example.invalid")),
    "Enabled form smoke emails must be unique and reserved for testing."
  );
  expectConfigurationError(
    () =>
      readRuntimeConfiguration({
        BROWSERSTACK_BASE_URL: "https://staging.example.invalid/",
        HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED: "true"
      }),
    "Enabled form without webhook stub"
  );

  const safeSession = parseSessionDetails(
    {
      hashed_id: "0123456789abcdef0123456789abcdef01234567",
      browser: "playwright-firefox",
      browser_version: "current",
      os: "Windows",
      os_version: "11",
      status: "running",
      public_url: "https://example.test/?auth_token=must-not-leak"
    },
    "self-check"
  );
  assertConfiguration(
    safeSession.hashed_id === "0123456789abcdef0123456789abcdef01234567" &&
      !Object.hasOwn(safeSession, "public_url"),
    "Session evidence is not restricted to the safe allowlist."
  );
}

function syntheticCatalogFixture() {
  return [
    catalogFixture("chrome", "111.0", "Windows", "10"),
    catalogFixture("edge", "111.0.1661.41", "Windows", "10"),
    catalogFixture("firefox", "111.0", "Windows", "10"),
    catalogFixture("safari", "16.4", "OS X", "Ventura"),
    {
      browser: "iphone",
      browser_version: null,
      os: "ios",
      os_version: "16.4",
      device: "iPhone 14",
      real_mobile: true
    },
    catalogFixture("chrome", "125.0", "OS X", "Sonoma"),
    catalogFixture("chrome", "126.0", "Windows", "11"),
    catalogFixture("edge", "126.0", "Windows", "11"),
    catalogFixture("firefox", "127.0", "OS X", "Sonoma"),
    catalogFixture("firefox", "127.0", "Windows", "11"),
    catalogFixture("safari", "17.4", "OS X", "Sonoma")
  ];
}

function catalogFixture(browser, browserVersion, os, osVersion) {
  return {
    browser,
    browser_version: browserVersion,
    os,
    os_version: osVersion,
    device: null,
    real_mobile: null
  };
}

function matrixSignature(matrix) {
  return JSON.stringify({
    minimum: matrix.minimumMatrix.map(({ requirement, entry }) => [
      requirement.key,
      catalogIdentity(entry)
    ]),
    playwright: matrix.playwrightMatrix.map(({ requirement, entry }) => [
      requirement.key,
      catalogIdentity(entry)
    ])
  });
}

function assertConfiguration(condition, message) {
  if (!condition) throw new ConfigurationError(message);
}

function expectConfigurationError(action, label) {
  try {
    action();
  } catch (error) {
    if (error instanceof ConfigurationError) return;
    throw error;
  }
  throw new ConfigurationError(`${label} did not fail closed.`);
}
