import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

import { defineConfig } from "@playwright/test";

const configDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(configDir, "../..");
const apiPort = Number(process.env.E2E_API_PORT ?? "18100");
const consolePort = Number(process.env.E2E_CONSOLE_PORT ?? "3100");
const apiBaseUrl = `http://127.0.0.1:${apiPort}`;
const consoleBaseUrl = `http://127.0.0.1:${consolePort}`;
const e2eStateDir = path.join(repoRoot, "var", "e2e");
const defaultPythonBin =
  process.platform === "win32"
    ? path.join(repoRoot, ".venv", "Scripts", "python.exe")
    : path.join(repoRoot, ".venv", "bin", "python");
const pythonBin = process.env.E2E_PYTHON_BIN ?? (existsSync(defaultPythonBin) ? defaultPythonBin : "python");

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  reporter: [["list"]],
  use: {
    baseURL: consoleBaseUrl,
    trace: "retain-on-failure"
  },
  webServer: [
    {
      // Reset the persistent e2e queue/ledger state, then boot the real API.
      command: `node "apps/console/e2e/clean-state.mjs" && "${pythonBin}" -m uvicorn hallu_defense.main:app --host 127.0.0.1 --port ${apiPort}`,
      url: `${apiBaseUrl}/health`,
      cwd: repoRoot,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        HALLU_DEFENSE_ENV: "local",
        HALLU_DEFENSE_ALLOWED_WORKSPACE: repoRoot,
        HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND: "jsonl",
        HALLU_DEFENSE_APPROVAL_QUEUE_PATH: path.join(e2eStateDir, "approval-queue.jsonl"),
        HALLU_DEFENSE_AUDIT_LEDGER_BACKEND: "jsonl",
        HALLU_DEFENSE_AUDIT_LEDGER_PATH: path.join(e2eStateDir, "audit-ledger.jsonl"),
        HALLU_DEFENSE_CORS_ALLOW_ORIGINS: `http://127.0.0.1:${consolePort},http://localhost:${consolePort}`
      }
    },
    {
      command: `npm run build && npx next start --port ${consolePort}`,
      url: consoleBaseUrl,
      cwd: configDir,
      reuseExistingServer: false,
      timeout: 300_000,
      env: {
        NEXT_PUBLIC_API_BASE_URL: apiBaseUrl
      }
    }
  ]
});
