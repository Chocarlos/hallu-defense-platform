import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "@playwright/test";

const configDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(configDir, "../..");
const port = Number(process.env.MARKETING_E2E_PORT ?? "3200");
const baseURL = `http://127.0.0.1:${port}`;

const browsers = ["chromium", "firefox", "webkit"] as const;
const viewports = [
  { name: "mobile-320", width: 320, height: 800 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "desktop-1440", width: 1440, height: 1000 }
] as const;

const projects = browsers.flatMap((browserName) =>
  viewports.map(({ name, width, height }) => ({
    name: `${browserName}-${name}`,
    use: { browserName, viewport: { width, height } }
  }))
);

export default defineConfig({
  testDir: "./e2e-marketing",
  outputDir: "./test-results/marketing",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  timeout: 45_000,
  expect: { timeout: 10_000 },
  projects,
  use: {
    baseURL,
    colorScheme: "dark",
    locale: "es-PA",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure"
  },
  webServer: {
    command:
      `npm --prefix "${repoRoot}" run build --workspace @hallu-defense/contracts && ` +
      `npm --prefix "${repoRoot}" run build --workspace @hallu-defense/sdk && ` +
      `npm run build && npx next start --port ${port}`,
    cwd: configDir,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 300_000,
    env: {
      HALLU_DEFENSE_ENV: "test",
      HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false",
      HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "",
      HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
      HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: baseURL,
      HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:18100",
      HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
      HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
      HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-marketing-e2e",
      HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "marketing-reviewer",
      HALLU_DEFENSE_CONSOLE_LOCAL_ROLES: "verifier"
    }
  }
});
