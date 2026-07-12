import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, rmSync } from "node:fs";
import type { ExecFileSyncOptions } from "node:child_process";

export class E2eSandboxScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "E2eSandboxScopeError";
  }
}

export const SANDBOX_IMAGE_REPOSITORY = "hallu-defense-sandbox";
export const DOCKER_CLEANUP_TIMEOUT_MS = 5_000;

const RUN_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;

export interface E2eSandboxEnv {
  readonly [key: string]: string | undefined;
}

export type E2ePathKind = "missing" | "directory" | "symlink" | "other";

export type E2eCommandRunner = (
  command: string,
  args: readonly string[],
  options: Readonly<Pick<ExecFileSyncOptions, "stdio" | "timeout" | "windowsHide">>
) => void;

/** A deterministic run identity: an explicit `E2E_RUN_ID`, else this process's pid. */
export function resolveSandboxRunId(env: E2eSandboxEnv, pid: number): string {
  const explicit = env.E2E_RUN_ID?.trim();
  if (!explicit) {
    return String(pid);
  }
  if (!RUN_ID_PATTERN.test(explicit)) {
    throw new E2eSandboxScopeError(
      `E2E_RUN_ID must match ${RUN_ID_PATTERN.source} to be safe inside a Docker image tag; got: "${explicit}"`
    );
  }
  return explicit;
}

function worktreeDigest(repoRoot: string): string {
  return createHash("sha256").update(path.resolve(repoRoot)).digest("hex").slice(0, 12);
}

function sandboxTagPrefix(repoRoot: string): string {
  return `${SANDBOX_IMAGE_REPOSITORY}:e2e-${worktreeDigest(repoRoot)}-`;
}

/** A scratch tag deterministically derived from this exact worktree path and run id. */
export function resolveSandboxImageTag(repoRoot: string, runId: string): string {
  if (!RUN_ID_PATTERN.test(runId)) {
    throw new E2eSandboxScopeError(`Unsafe sandbox run id: "${runId}"`);
  }
  return `${sandboxTagPrefix(repoRoot)}${runId}`;
}

/** Fails closed unless `tag` is this exact worktree's scratch tag pattern. */
export function assertOwnedSandboxImageTag(tag: string, repoRoot: string): void {
  const prefix = sandboxTagPrefix(repoRoot);
  const suffix = tag.startsWith(prefix) ? tag.slice(prefix.length) : null;
  if (suffix === null || suffix.length === 0 || !RUN_ID_PATTERN.test(suffix)) {
    throw new E2eSandboxScopeError(
      `Refusing to act on a sandbox image tag that is not this worktree's scratch tag: "${tag}"`
    );
  }
}

export function assertExpectedSandboxImageTag(
  tag: string,
  repoRoot: string,
  runId: string
): void {
  const expected = resolveSandboxImageTag(repoRoot, runId);
  if (tag !== expected) {
    throw new E2eSandboxScopeError(
      `Refusing to act on another run's sandbox image tag: "${tag}"`
    );
  }
}

export function resolveE2eStateDir(repoRoot: string): string {
  return path.join(path.resolve(repoRoot), "var", "e2e");
}

/** Fails closed unless `candidate` is exactly this worktree's `var/e2e` directory. */
export function assertScopedE2eStateDir(candidate: string, repoRoot: string): void {
  const expected = resolveE2eStateDir(repoRoot);
  const resolvedCandidate = path.resolve(candidate);
  if (resolvedCandidate !== expected) {
    throw new E2eSandboxScopeError(
      `Refusing to remove a path other than this worktree's e2e state directory: "${resolvedCandidate}"`
    );
  }
  assertNoLinkedPath(path.join(path.resolve(repoRoot), "var"));
  assertNoLinkedPath(expected);
}

/**
 * Best-effort removal of a previously built scratch sandbox image.
 *
 * Validates the tag belongs to this worktree before acting, and is safe to
 * call when Docker is unavailable or the image does not exist.
 */
export function removeSandboxImageIfPresent(
  tag: string,
  repoRoot: string,
  run: E2eCommandRunner = defaultDockerRun
): void {
  assertOwnedSandboxImageTag(tag, repoRoot);
  try {
    run("docker", ["image", "rm", "-f", tag], {
      stdio: "ignore",
      timeout: DOCKER_CLEANUP_TIMEOUT_MS,
      windowsHide: true
    });
  } catch {
    // Docker absent, daemon hung, cleanup timed out, or image absent.
  }
}

function defaultDockerRun(
  command: string,
  args: readonly string[],
  options: Readonly<Pick<ExecFileSyncOptions, "stdio" | "timeout" | "windowsHide">>
): void {
  execFileSync(command, [...args], options);
}

/**
 * Removes this worktree's bounded e2e scratch state directory.
 *
 * Validates the path belongs to this worktree before acting.
 */
export function removeE2eStateDir(
  stateDir: string,
  repoRoot: string,
  remove: (target: string) => void = (target) => rmSync(target, { recursive: true, force: true }),
  inspect: (target: string) => E2ePathKind = defaultPathKind
): void {
  assertScopedE2eStateDirWithInspector(stateDir, repoRoot, inspect);
  remove(stateDir);
}

function assertScopedE2eStateDirWithInspector(
  candidate: string,
  repoRoot: string,
  inspect: (target: string) => E2ePathKind
): void {
  const resolvedRoot = path.resolve(repoRoot);
  const expected = resolveE2eStateDir(resolvedRoot);
  if (path.resolve(candidate) !== expected) {
    throw new E2eSandboxScopeError(
      `Refusing to remove a path other than this worktree's e2e state directory: "${path.resolve(candidate)}"`
    );
  }
  for (const component of [path.join(resolvedRoot, "var"), expected]) {
    const kind = inspect(component);
    if (kind === "symlink" || kind === "other") {
      throw new E2eSandboxScopeError(
        `Refusing to remove e2e state through a linked or non-directory path: "${component}"`
      );
    }
  }
}

function assertNoLinkedPath(candidate: string): void {
  const kind = defaultPathKind(candidate);
  if (kind === "symlink" || kind === "other") {
    throw new E2eSandboxScopeError(
      `Refusing to use a linked or non-directory e2e path: "${candidate}"`
    );
  }
}

function defaultPathKind(candidate: string): E2ePathKind {
  try {
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink()) {
      return "symlink";
    }
    return stat.isDirectory() ? "directory" : "other";
  } catch (error) {
    return isMissingPathError(error) ? "missing" : "other";
  }
}

function isMissingPathError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
