import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const require = createRequire(import.meta.url);
const playwrightCli = require.resolve("@playwright/test/cli");
const consoleDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryPrefix = "hallu-defense-marketing-e2e-";
const managedEnvironmentNames = [
  "HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE",
  "HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE",
  "HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN",
  "HALLU_DEFENSE_DEMO_REDIS_URL_FILE",
  "HALLU_DEFENSE_DEMO_REDIS_CA_PATH",
  "HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE",
  "HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL"
];

const options = parseOptions(process.argv.slice(2));
const phases = options.phase === "all" ? ["production", "form"] : [options.phase];
let activeChild;
let receivedSignal;

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    receivedSignal ??= signal;
    activeChild?.kill(signal);
  });
}

for (const phase of phases) {
  if (receivedSignal !== undefined) break;
  const runtime = phase === "form" ? createSyntheticRuntime() : undefined;
  try {
    console.log(`Running marketing Playwright ${phase} phase.`);
    const code = await runPlaywright(phase, options.list, runtime?.environment ?? {});
    if (code !== 0) {
      process.exitCode = code;
      break;
    }
  } finally {
    if (runtime !== undefined) cleanupSyntheticRuntime(runtime.directory);
  }
}

if (receivedSignal !== undefined) {
  process.exitCode = receivedSignal === "SIGINT" ? 130 : 143;
}

function parseOptions(args) {
  let phase = "all";
  let list = false;
  for (const argument of args) {
    if (argument === "--list") {
      list = true;
    } else if (argument.startsWith("--phase=")) {
      phase = argument.slice("--phase=".length);
    } else {
      throw new Error(`Unsupported marketing suite argument: ${argument}`);
    }
  }
  if (!["all", "production", "form"].includes(phase)) {
    throw new Error("Marketing suite phase must be all, production, or form.");
  }
  return { phase, list };
}

function createSyntheticRuntime() {
  const directory = mkdtempSync(path.join(tmpdir(), temporaryPrefix));
  const paths = {
    webhook: path.join(directory, "webhook-url"),
    hmac: path.join(directory, "webhook-hmac"),
    redis: path.join(directory, "redis-url"),
    metrics: path.join(directory, "metrics-bearer")
  };
  try {
    writeSyntheticFile(paths.webhook, "https://crm.example.invalid/hooks/demo\n");
    writeSyntheticFile(paths.hmac, Buffer.alloc(48, 0x68));
    writeSyntheticFile(paths.redis, "redis://127.0.0.1:1/0\n");
    writeSyntheticFile(paths.metrics, Buffer.alloc(48, 0x6d));
  } catch (error) {
    cleanupSyntheticRuntime(directory);
    throw error;
  }
  return {
    directory,
    environment: {
      HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE: paths.webhook,
      HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE: paths.hmac,
      HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN: "https://crm.example.invalid",
      HALLU_DEFENSE_DEMO_REDIS_URL_FILE: paths.redis,
      HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE: paths.metrics,
      HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "privacy@example.invalid"
    }
  };
}

function writeSyntheticFile(file, value) {
  writeFileSync(file, value, { flag: "wx", mode: 0o600 });
}

function cleanupSyntheticRuntime(directory) {
  const resolved = path.resolve(directory);
  if (
    path.dirname(resolved) !== path.resolve(tmpdir()) ||
    !path.basename(resolved).startsWith(temporaryPrefix)
  ) {
    throw new Error("Refusing to remove an unmanaged marketing E2E directory.");
  }
  rmSync(resolved, { recursive: true, force: true, maxRetries: 3 });
}

async function runPlaywright(phase, list, syntheticEnvironment) {
  const environment = { ...process.env };
  for (const name of managedEnvironmentNames) delete environment[name];
  delete environment.MARKETING_E2E_PORT;
  const port = await findAvailablePort();
  Object.assign(environment, syntheticEnvironment, {
    MARKETING_E2E_MODE: phase,
    MARKETING_E2E_PORT: String(port),
    HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: phase === "form" ? "true" : "false"
  });
  const grepArguments =
    phase === "form" ? ["--grep", "@form"] : ["--grep-invert", "@form"];
  const arguments_ = [
    playwrightCli,
    "test",
    "--config",
    "playwright.marketing.config.ts",
    ...grepArguments,
    ...(list ? ["--list"] : [])
  ];
  const child = spawn(process.execPath, arguments_, {
    cwd: consoleDirectory,
    env: environment,
    stdio: "inherit",
    windowsHide: true
  });
  activeChild = child;
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) => resolve(code ?? 1));
    });
  } finally {
    activeChild = undefined;
  }
}

async function findAvailablePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("Could not allocate an isolated marketing E2E port."));
        return;
      }
      server.close((error) => {
        if (error === undefined) resolve(address.port);
        else reject(error);
      });
    });
  });
}
