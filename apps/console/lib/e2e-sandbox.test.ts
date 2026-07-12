import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  DOCKER_CLEANUP_TIMEOUT_MS,
  E2eSandboxScopeError,
  assertExpectedSandboxImageTag,
  assertOwnedSandboxImageTag,
  assertScopedE2eStateDir,
  removeE2eStateDir,
  removeSandboxImageIfPresent,
  resolveE2eStateDir,
  resolveSandboxImageTag,
  resolveSandboxRunId
} from "./e2e-sandbox";

const repoRoot = path.resolve("test-worktrees", "front-e");
const otherRepoRoot = path.resolve("test-worktrees", "front-f");

describe("resolveSandboxRunId", () => {
  it("defaults to the process pid when E2E_RUN_ID is unset", () => {
    expect(resolveSandboxRunId({}, 4242)).toBe("4242");
  });

  it("uses an explicit safe E2E_RUN_ID", () => {
    expect(resolveSandboxRunId({ E2E_RUN_ID: "run-7" }, 4242)).toBe("run-7");
  });

  it("rejects an E2E_RUN_ID with shell-unsafe characters", () => {
    expect(() => resolveSandboxRunId({ E2E_RUN_ID: "run 7;rm" }, 4242)).toThrow();
  });

  it("rejects an overlong E2E_RUN_ID", () => {
    expect(() => resolveSandboxRunId({ E2E_RUN_ID: "a".repeat(65) }, 4242)).toThrow();
  });
});

describe("resolveSandboxImageTag", () => {
  it("is deterministic for the same worktree and run id", () => {
    const first = resolveSandboxImageTag(repoRoot, "77");
    const second = resolveSandboxImageTag(repoRoot, "77");
    expect(first).toBe(second);
  });

  it("differs across worktrees for the same run id", () => {
    expect(resolveSandboxImageTag(repoRoot, "77")).not.toBe(
      resolveSandboxImageTag(otherRepoRoot, "77")
    );
  });

  it("differs across run ids for the same worktree", () => {
    expect(resolveSandboxImageTag(repoRoot, "77")).not.toBe(
      resolveSandboxImageTag(repoRoot, "78")
    );
  });

  it("never returns the previously shared static tag", () => {
    expect(resolveSandboxImageTag(repoRoot, "77")).not.toBe("hallu-defense-sandbox:ci");
  });
});

describe("assertOwnedSandboxImageTag", () => {
  it("accepts a tag this worktree generated", () => {
    const tag = resolveSandboxImageTag(repoRoot, "77");
    expect(() => assertOwnedSandboxImageTag(tag, repoRoot)).not.toThrow();
  });

  it("rejects the old shared hallu-defense-sandbox:ci tag", () => {
    expect(() => assertOwnedSandboxImageTag("hallu-defense-sandbox:ci", repoRoot)).toThrow(
      E2eSandboxScopeError
    );
  });

  it("rejects a tag generated for a different worktree", () => {
    const foreignTag = resolveSandboxImageTag(otherRepoRoot, "77");
    expect(() => assertOwnedSandboxImageTag(foreignTag, repoRoot)).toThrow(E2eSandboxScopeError);
  });
});

describe("assertExpectedSandboxImageTag", () => {
  it("accepts only the exact worktree and run tag", () => {
    const tag = resolveSandboxImageTag(repoRoot, "77");
    expect(() => assertExpectedSandboxImageTag(tag, repoRoot, "77")).not.toThrow();
    expect(() => assertExpectedSandboxImageTag(tag, repoRoot, "78")).toThrow(
      E2eSandboxScopeError
    );
  });
});

describe("resolveE2eStateDir / assertScopedE2eStateDir", () => {
  it("resolves to var/e2e under the worktree root", () => {
    expect(resolveE2eStateDir(repoRoot)).toBe(path.join(repoRoot, "var", "e2e"));
  });

  it("accepts the exact expected state directory", () => {
    expect(() =>
      assertScopedE2eStateDir(resolveE2eStateDir(repoRoot), repoRoot)
    ).not.toThrow();
  });

  it("rejects the worktree root itself", () => {
    expect(() => assertScopedE2eStateDir(repoRoot, repoRoot)).toThrow(E2eSandboxScopeError);
  });

  it("rejects a path traversal outside the worktree", () => {
    const outside = path.join(repoRoot, "var", "e2e", "..", "..", "..", "etc");
    expect(() => assertScopedE2eStateDir(outside, repoRoot)).toThrow(E2eSandboxScopeError);
  });

  it("rejects a sibling directory under var/", () => {
    expect(() =>
      assertScopedE2eStateDir(path.join(repoRoot, "var", "other"), repoRoot)
    ).toThrow(E2eSandboxScopeError);
  });
});

describe("removeSandboxImageIfPresent", () => {
  it("invokes docker image rm for an owned tag", () => {
    const tag = resolveSandboxImageTag(repoRoot, "77");
    const run = vi.fn();
    removeSandboxImageIfPresent(tag, repoRoot, run);
    expect(run).toHaveBeenCalledWith("docker", ["image", "rm", "-f", tag], {
      stdio: "ignore",
      timeout: DOCKER_CLEANUP_TIMEOUT_MS,
      windowsHide: true
    });
  });

  it("refuses to run docker against a foreign tag", () => {
    const run = vi.fn();
    expect(() =>
      removeSandboxImageIfPresent("hallu-defense-sandbox:ci", repoRoot, run)
    ).toThrow(E2eSandboxScopeError);
    expect(run).not.toHaveBeenCalled();
  });

  it("is safe when docker is unavailable", () => {
    const tag = resolveSandboxImageTag(repoRoot, "77");
    const run = vi.fn(() => {
      throw new Error("spawn docker ENOENT");
    });
    expect(() => removeSandboxImageIfPresent(tag, repoRoot, run)).not.toThrow();
  });
});

describe("removeE2eStateDir", () => {
  it("removes exactly the resolved state directory", () => {
    const remove = vi.fn();
    const stateDir = resolveE2eStateDir(repoRoot);
    removeE2eStateDir(stateDir, repoRoot, remove);
    expect(remove).toHaveBeenCalledWith(stateDir);
  });

  it("refuses to remove a path outside the worktree's e2e state directory", () => {
    const remove = vi.fn();
    expect(() => removeE2eStateDir(repoRoot, repoRoot, remove)).toThrow(E2eSandboxScopeError);
    expect(remove).not.toHaveBeenCalled();
  });

  it("refuses to traverse a symlinked var parent", () => {
    const remove = vi.fn();
    const stateDir = resolveE2eStateDir(repoRoot);
    const inspect = vi.fn((candidate: string) =>
      candidate === path.join(repoRoot, "var") ? "symlink" as const : "missing" as const
    );

    expect(() => removeE2eStateDir(stateDir, repoRoot, remove, inspect)).toThrow(
      E2eSandboxScopeError
    );
    expect(remove).not.toHaveBeenCalled();
  });
});
