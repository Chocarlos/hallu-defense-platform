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
      // The sandbox backend is intentionally Docker-only in local/test. Build
      // the exact image used by this suite so a stale local tag cannot make
      // the browser flow exercise an older sandbox control protocol.
      command:
        `docker build -f "infra/docker/sandbox.Dockerfile" -t hallu-defense-sandbox:ci . && ` +
        `node "apps/console/e2e/clean-state.mjs" && ` +
        `"${pythonBin}" -m uvicorn hallu_defense.main:app --host 127.0.0.1 --port ${apiPort}`,
      url: `${apiBaseUrl}/health`,
      cwd: repoRoot,
      reuseExistingServer: false,
      timeout: 300_000,
      env: {
        HALLU_DEFENSE_ENV: "local",
        HALLU_DEFENSE_ALLOWED_WORKSPACE: e2eStateDir,
        HALLU_DEFENSE_SANDBOX_BACKEND: "docker",
        HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE: "hallu-defense-sandbox:ci",
        HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND: "jsonl",
        HALLU_DEFENSE_APPROVAL_QUEUE_PATH: path.join(e2eStateDir, "approval-queue.jsonl"),
        HALLU_DEFENSE_AUDIT_LEDGER_BACKEND: "jsonl",
        HALLU_DEFENSE_AUDIT_LEDGER_PATH: path.join(e2eStateDir, "audit-ledger.jsonl"),
        HALLU_DEFENSE_CORS_ALLOW_ORIGINS: `http://127.0.0.1:${consolePort},http://localhost:${consolePort}`
      }
    },
    {
      command:
        `npm --prefix "${repoRoot}" run build --workspace @hallu-defense/contracts && ` +
        `npm --prefix "${repoRoot}" run build --workspace @hallu-defense/sdk && ` +
        `npm run build && npx next start --port ${consolePort}`,
      url: consoleBaseUrl,
      cwd: configDir,
      reuseExistingServer: false,
      timeout: 300_000,
      env: {
        HALLU_DEFENSE_ENV: "test",
        HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
        HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: consoleBaseUrl,
        HALLU_DEFENSE_CONSOLE_API_ORIGIN: apiBaseUrl,
        HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
        HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
        HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-a",
        HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "console-reviewer",
        HALLU_DEFENSE_CONSOLE_LOCAL_ROLES:
          "verifier,approval_reviewer,policy_evaluator,rag_writer,sandbox_runner,tool_operator"
      }
    }
  ]
});
