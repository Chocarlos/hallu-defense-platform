import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "@playwright/test";

import {
  resolveApiSourceRoot,
  resolvePythonExecutable
} from "./lib/e2e-python-runtime";
import { resolveSandboxImageTag, resolveSandboxRunId } from "./lib/e2e-sandbox";

const configDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(configDir, "../..");
const apiPort = Number(process.env.E2E_API_PORT ?? "18100");
const consolePort = Number(process.env.E2E_CONSOLE_PORT ?? "3100");
const apiBaseUrl = `http://127.0.0.1:${apiPort}`;
const consoleBaseUrl = `http://127.0.0.1:${consolePort}`;
const e2eStateDir = path.join(repoRoot, "var", "e2e");
const API_WEB_SERVER_TIMEOUT_MS = 300_000;
const apiSourceRoot = resolveApiSourceRoot(repoRoot);
const pythonBin = resolvePythonExecutable({
  env: process.env
});
const sandboxRunId = resolveSandboxRunId(process.env, process.pid);
const sandboxImageTag = resolveSandboxImageTag(repoRoot, sandboxRunId);
// Global teardown is loaded from the same Playwright process. Pin the fallback
// pid-derived ID into the environment so every hook sees the exact same tag.
process.env.E2E_RUN_ID = sandboxRunId;

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
  globalTeardown: "./e2e/global-teardown",
  webServer: [
    {
      // The committed wrapper verifies Python/import provenance before Docker,
      // builds a unique scratch image, boots the API, and runs bounded cleanup
      // on normal exit, signal, or startup failure.
      command: "node --import tsx apps/console/scripts/run-e2e-api-webserver.ts",
      url: `${apiBaseUrl}/health`,
      cwd: repoRoot,
      reuseExistingServer: false,
      timeout: API_WEB_SERVER_TIMEOUT_MS,
      env: {
        E2E_RUN_ID: sandboxRunId,
        E2E_API_PORT: String(apiPort),
        E2E_REPO_ROOT: repoRoot,
        E2E_PYTHON_BIN: pythonBin,
        PYTHONPATH: apiSourceRoot,
        HALLU_DEFENSE_ENV: "local",
        HALLU_DEFENSE_ALLOWED_WORKSPACE: e2eStateDir,
        HALLU_DEFENSE_SANDBOX_BACKEND: "docker",
        HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE: sandboxImageTag,
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
