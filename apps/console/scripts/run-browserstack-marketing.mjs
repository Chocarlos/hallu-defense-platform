import process from "node:process";

import { chromium, firefox } from "playwright";
import { Builder, By } from "selenium-webdriver";

const CATALOG_URL = "https://api.browserstack.com/automate/browsers.json";
const HUB_URL = "https://hub-cloud.browserstack.com/wd/hub";
const PLAYWRIGHT_ENDPOINT = "wss://cdp.browserstack.com/playwright";
const SAFE_EMAIL = "browserstack-smoke@example.invalid";

const minimumRequirements = [
  { key: "chrome-111", browser: "chrome", version: "111", mobile: false },
  { key: "edge-111", browser: "edge", version: "111", mobile: false },
  { key: "firefox-111", browser: "firefox", version: "111", mobile: false },
  { key: "safari-16.4", browser: "safari", version: "16.4", mobile: false },
  { key: "ios-safari-16.4", browser: "safari", version: "16.4", mobile: true }
];

const checkOnly = process.argv.includes("--check-config");
const username = clean(process.env.BROWSERSTACK_USERNAME);
const accessKey = clean(process.env.BROWSERSTACK_ACCESS_KEY);

if (checkOnly) {
  validateStaticContract();
  console.log(
    "Validated BrowserStack marketing runner contract; no remote compatibility result was claimed."
  );
  process.exit(0);
}

if (username === undefined && accessKey === undefined) {
  console.log(
    "BrowserStack marketing gate skipped: BROWSERSTACK_USERNAME and BROWSERSTACK_ACCESS_KEY are absent. No compatibility result is claimed."
  );
  process.exit(0);
}
if (username === undefined || accessKey === undefined) {
  throw new Error("BrowserStack credentials must be supplied together.");
}

const baseURL = validatedBaseUrl(process.env.BROWSERSTACK_BASE_URL);
const local = process.env.BROWSERSTACK_LOCAL === "true";
const localIdentifier = clean(process.env.BROWSERSTACK_LOCAL_IDENTIFIER);
if (local && localIdentifier === undefined) {
  throw new Error("BrowserStack Local requires BROWSERSTACK_LOCAL_IDENTIFIER.");
}
if (!local && baseURL.protocol !== "https:") {
  throw new Error("Remote BrowserStack smoke requires an HTTPS synthetic staging URL.");
}
if (
  process.env.HALLU_DEFENSE_MARKETING_LIVE_FORM_ENABLED === "true" &&
  process.env.BROWSERSTACK_WEBHOOK_STUB !== "true"
) {
  throw new Error("Enabled form smoke requires an explicit isolated webhook stub.");
}

const catalog = await fetchCatalog(username, accessKey);
const minimumMatrix = minimumRequirements.map((requirement) => {
  const match = catalog.find((entry) => matchesMinimum(entry, requirement));
  if (match === undefined) {
    throw new Error(
      `BrowserStack catalog does not expose required exact minimum ${requirement.key}; matrix was not reduced.`
    );
  }
  return { requirement: requirement.key, entry: match };
});

const playwrightMatrix = ["chrome", "edge", "firefox"].map((browser) => {
  const candidates = catalog.filter(
    (entry) => !entry.mobile && normalizeBrowser(entry.browser) === browser
  );
  const latest = candidates.sort(compareVersionsDescending)[0];
  if (latest === undefined) {
    throw new Error(`BrowserStack catalog exposes no desktop ${browser} candidate.`);
  }
  return latest;
});

console.log(
  JSON.stringify(
    {
      source: CATALOG_URL,
      playwright: playwrightMatrix.map(publicCatalogEntry),
      seleniumMinimums: minimumMatrix.map(({ requirement, entry }) => ({
        requirement,
        ...publicCatalogEntry(entry)
      }))
    },
    null,
    2
  )
);

for (const entry of playwrightMatrix) {
  await runPlaywrightSmoke({
    entry,
    baseURL,
    username,
    accessKey,
    local,
    localIdentifier
  });
}
for (const { requirement, entry } of minimumMatrix) {
  await runSeleniumSmoke({
    requirement,
    entry,
    baseURL,
    username,
    accessKey,
    local,
    localIdentifier
  });
}

console.log("BrowserStack marketing matrix completed without reducing required minimums.");

function validateStaticContract() {
  if (SAFE_EMAIL.endsWith("@example.invalid") === false) {
    throw new Error("BrowserStack smoke email must use example.invalid.");
  }
  if (minimumRequirements.length !== 5) {
    throw new Error("BrowserStack minimum matrix is incomplete.");
  }
  const keys = new Set(minimumRequirements.map(({ key }) => key));
  for (const required of [
    "chrome-111",
    "edge-111",
    "firefox-111",
    "safari-16.4",
    "ios-safari-16.4"
  ]) {
    if (!keys.has(required)) {
      throw new Error(`BrowserStack minimum matrix is missing ${required}.`);
    }
  }
}

async function fetchCatalog(user, key) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(CATALOG_URL, {
      headers: { authorization: `Basic ${Buffer.from(`${user}:${key}`).toString("base64")}` },
      redirect: "error",
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`BrowserStack catalog returned HTTP ${response.status}.`);
    }
    const value = await response.json();
    if (!Array.isArray(value)) {
      throw new Error("BrowserStack catalog response is not an array.");
    }
    return value.map(parseCatalogEntry).filter((entry) => entry !== undefined);
  } finally {
    clearTimeout(timeout);
  }
}

function parseCatalogEntry(value) {
  if (value === null || typeof value !== "object") return undefined;
  const browser = clean(value.browser);
  const browserVersion = clean(value.browser_version);
  const os = clean(value.os);
  const osVersion = clean(value.os_version);
  if ([browser, browserVersion, os, osVersion].some((item) => item === undefined)) {
    return undefined;
  }
  const device = clean(value.device);
  return {
    browser,
    browserVersion,
    os,
    osVersion,
    device,
    mobile: value.real_mobile === true || device !== undefined
  };
}

function matchesMinimum(entry, requirement) {
  return (
    entry.mobile === requirement.mobile &&
    normalizeBrowser(entry.browser) === requirement.browser &&
    entry.browserVersion === requirement.version
  );
}

function normalizeBrowser(value) {
  const browser = value.toLowerCase().replace(/[\s_-]+/gu, "");
  if (browser.includes("edge")) return "edge";
  if (browser.includes("firefox")) return "firefox";
  if (browser.includes("safari")) return "safari";
  if (browser.includes("chrome")) return "chrome";
  return browser;
}

function compareVersionsDescending(left, right) {
  return compareVersion(right.browserVersion, left.browserVersion);
}

function compareVersion(left, right) {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

async function runPlaywrightSmoke(options) {
  const browserName = normalizeBrowser(options.entry.browser);
  const browserType = browserName === "firefox" ? firefox : chromium;
  const caps = {
    browser: browserName,
    browser_version: options.entry.browserVersion,
    os: options.entry.os,
    os_version: options.entry.osVersion,
    name: `Hallu Defense marketing Playwright ${browserName}`,
    build: process.env.BROWSERSTACK_BUILD_NAME ?? "hallu-defense-marketing",
    "browserstack.username": options.username,
    "browserstack.accessKey": options.accessKey,
    "browserstack.local": options.local,
    ...(options.localIdentifier === undefined
      ? {}
      : { "browserstack.localIdentifier": options.localIdentifier })
  };
  const endpoint = `${PLAYWRIGHT_ENDPOINT}?caps=${encodeURIComponent(JSON.stringify(caps))}`;
  const browser = await browserType.connect(endpoint, { timeout: 60_000 });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    await page.goto(options.baseURL.href, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const heading = (await page.locator("h1").first().textContent())?.trim();
    if (heading !== "La confianza no se asume. Se demuestra.") {
      throw new Error(`Unexpected Spanish headline on ${browserName}.`);
    }
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
    );
    if (overflow) throw new Error(`Horizontal overflow detected on ${browserName}.`);
    const email = page.locator('input[type="email"]');
    if ((await email.count()) > 0 && (await email.first().isEnabled())) {
      await email.first().fill(SAFE_EMAIL);
    }
  } finally {
    await browser.close();
  }
}

async function runSeleniumSmoke(options) {
  const bstackOptions = {
    userName: options.username,
    accessKey: options.accessKey,
    os: options.entry.os,
    osVersion: options.entry.osVersion,
    sessionName: `Hallu Defense minimum ${options.requirement}`,
    buildName: process.env.BROWSERSTACK_BUILD_NAME ?? "hallu-defense-marketing",
    local: options.local ? "true" : "false",
    ...(options.localIdentifier === undefined
      ? {}
      : { localIdentifier: options.localIdentifier }),
    ...(options.entry.device === undefined
      ? {}
      : { deviceName: options.entry.device, realMobile: "true" })
  };
  const driver = await new Builder()
    .usingServer(HUB_URL)
    .withCapabilities({
      browserName: options.entry.browser,
      browserVersion: options.entry.browserVersion,
      "bstack:options": bstackOptions
    })
    .build();
  try {
    await driver.get(options.baseURL.href);
    const heading = (await driver.findElement(By.css("h1")).getText()).trim();
    if (heading !== "La confianza no se asume. Se demuestra.") {
      throw new Error(`Unexpected headline for ${options.requirement}.`);
    }
    const overflow = await driver.executeScript(
      "return document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"
    );
    if (overflow === true) {
      throw new Error(`Horizontal overflow detected for ${options.requirement}.`);
    }
    const emails = await driver.findElements(By.css('input[type="email"]:not([disabled])'));
    if (emails.length > 0) await emails[0].sendKeys(SAFE_EMAIL);
  } finally {
    await driver.quit();
  }
}

function validatedBaseUrl(raw) {
  const value = clean(raw);
  if (value === undefined) {
    throw new Error("BROWSERSTACK_BASE_URL is required when credentials are present.");
  }
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("BROWSERSTACK_BASE_URL must not contain credentials, query, or fragment.");
  }
  return url;
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

function clean(value) {
  return typeof value === "string" && value.trim() === value && value !== ""
    ? value
    : undefined;
}
