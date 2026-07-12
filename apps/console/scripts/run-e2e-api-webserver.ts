import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runE2eApiLifecycle } from "../lib/e2e-api-lifecycle";
import {
  pythonSourcePreflightArgs,
  resolveApiSourceRoot,
  resolvePythonExecutable
} from "../lib/e2e-python-runtime";
import {
  assertExpectedSandboxImageTag,
  assertOwnedSandboxImageTag,
  assertScopedE2eStateDir,
  removeE2eStateDir,
  removeSandboxImageIfPresent,
  resolveE2eStateDir,
  resolveSandboxRunId
} from "../lib/e2e-sandbox";

const PREFLIGHT_TIMEOUT_MS = 15_000;
const SANDBOX_BUILD_TIMEOUT_MS = 240_000;
const API_STOP_TIMEOUT_MS = 5_000;
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const actualRepoRoot = path.resolve(scriptDir, "../../..");

async function main(): Promise<void> {
  const repoRoot = requiredAbsolutePath("E2E_REPO_ROOT");
  if (repoRoot !== actualRepoRoot) {
    throw new Error("E2E_REPO_ROOT does not identify this wrapper's worktree.");
  }
  const apiSourceRoot = resolveApiSourceRoot(repoRoot);
  const configuredPythonPath = requiredAbsolutePath("PYTHONPATH");
  if (configuredPythonPath !== apiSourceRoot) {
    throw new Error("PYTHONPATH must equal this worktree's apps/api/src.");
  }
  const pythonBin = resolvePythonExecutable({ env: process.env });
  const sandboxImageTag = requiredEnvironment("HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE");
  assertOwnedSandboxImageTag(sandboxImageTag, repoRoot);
  const sandboxRunId = resolveSandboxRunId(process.env, process.pid);
  assertExpectedSandboxImageTag(sandboxImageTag, repoRoot, sandboxRunId);
  const stateDir = resolveE2eStateDir(repoRoot);
  assertScopedE2eStateDir(requiredAbsolutePath("HALLU_DEFENSE_ALLOWED_WORKSPACE"), repoRoot);
  const apiPort = requiredPort("E2E_API_PORT");
  let api: ChildProcess | undefined;
  let apiStopTimer: NodeJS.Timeout | undefined;
  let stopRequested = false;
  const requestStop = () => {
    stopRequested = true;
    if (api !== undefined && api.exitCode === null && api.signalCode === null) {
      api.kill("SIGTERM");
      apiStopTimer = setTimeout(() => api?.kill("SIGKILL"), API_STOP_TIMEOUT_MS);
      apiStopTimer.unref();
    }
  };
  process.once("SIGINT", requestStop);
  process.once("SIGTERM", requestStop);

  try {
    await runE2eApiLifecycle({
      preflight: () =>
        runChecked(
          pythonBin,
          pythonSourcePreflightArgs(repoRoot, apiSourceRoot),
          PREFLIGHT_TIMEOUT_MS,
          repoRoot
        ),
      preCleanup: () => cleanupScratch(sandboxImageTag, stateDir, repoRoot),
      prepareState: () => mkdirSync(stateDir, { recursive: true }),
      buildSandbox: () =>
        runChecked(
          "docker",
          [
            "build",
            "-f",
            "infra/docker/sandbox.Dockerfile",
            "-t",
            sandboxImageTag,
            "."
          ],
          SANDBOX_BUILD_TIMEOUT_MS,
          repoRoot
        ),
      serveApi: async () => {
        if (stopRequested) {
          throw new Error("E2E API webServer stop requested during startup.");
        }
        api = spawn(
          pythonBin,
          [
            "-m",
            "uvicorn",
            "hallu_defense.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            String(apiPort)
          ],
          { cwd: repoRoot, env: process.env, stdio: "inherit", windowsHide: true }
        );
        await waitForApiExit(api);
      },
      finalCleanup: () => {
        if (api !== undefined && api.exitCode === null) {
          api.kill("SIGKILL");
        }
        cleanupScratch(sandboxImageTag, stateDir, repoRoot);
      }
    });
  } finally {
    process.off("SIGINT", requestStop);
    process.off("SIGTERM", requestStop);
    if (apiStopTimer !== undefined) {
      clearTimeout(apiStopTimer);
    }
  }
}

function cleanupScratch(tag: string, stateDir: string, repoRoot: string): void {
  removeSandboxImageIfPresent(tag, repoRoot);
  removeE2eStateDir(stateDir, repoRoot);
}

function runChecked(
  command: string,
  args: readonly string[],
  timeout: number,
  cwd: string
): void {
  const result = spawnSync(command, [...args], {
    cwd,
    env: process.env,
    stdio: "inherit",
    timeout,
    windowsHide: true
  });
  if (result.error !== undefined || result.status !== 0) {
    throw new Error(`E2E prerequisite command failed: ${path.basename(command)}.`);
  }
}

function waitForApiExit(api: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    api.once("error", reject);
    api.once("exit", (code, signal) => {
      if (code === 0 || signal === "SIGTERM" || signal === "SIGKILL") {
        resolve();
      } else {
        reject(new Error("E2E API webServer exited unexpectedly."));
      }
    });
  });
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0 || /[\r\n]/u.test(value)) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function requiredAbsolutePath(name: string): string {
  const value = requiredEnvironment(name);
  if (!path.isAbsolute(value)) {
    throw new Error(`${name} must be absolute.`);
  }
  return path.resolve(value);
}

function requiredPort(name: string): number {
  const value = requiredEnvironment(name);
  if (!/^[1-9][0-9]{0,4}$/u.test(value)) {
    throw new Error(`${name} must be a valid port.`);
  }
  const port = Number(value);
  if (port > 65_535) {
    throw new Error(`${name} must be a valid port.`);
  }
  return port;
}

await main();
