import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  removeE2eStateDir,
  removeSandboxImageIfPresent,
  resolveE2eStateDir,
  resolveSandboxImageTag,
  resolveSandboxRunId
} from "../lib/e2e-sandbox";

const e2eDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(e2eDir, "..", "..", "..");

/**
 * Playwright final teardown: an idempotent bounded backstop after the test
 * run. The API wrapper also cleans on process exit/startup failure because
 * Playwright tears this hook down before its webServer plugin. Safe when
 * Docker is unavailable; never touches another worktree/run tag or state path.
 */
export default async function globalTeardown(): Promise<void> {
  const runId = resolveSandboxRunId(process.env, process.pid);
  const tag = resolveSandboxImageTag(repoRoot, runId);
  removeSandboxImageIfPresent(tag, repoRoot);
  removeE2eStateDir(resolveE2eStateDir(repoRoot), repoRoot);
}
