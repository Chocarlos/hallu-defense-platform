import { describe, expect, it, vi } from "vitest";

import {
  runE2eApiLifecycle,
  type E2eApiLifecycleDependencies
} from "./e2e-api-lifecycle";

describe("runE2eApiLifecycle", () => {
  it("does not touch scratch resources when import preflight fails", async () => {
    const calls: string[] = [];
    const dependencies = lifecycle(calls, {
      preflight: () => {
        calls.push("preflight");
        throw new Error("wrong checkout");
      }
    });

    await expect(runE2eApiLifecycle(dependencies)).rejects.toThrow("wrong checkout");
    expect(calls).toEqual(["preflight"]);
  });

  it("runs final cleanup when sandbox build fails after pre-cleanup", async () => {
    const calls: string[] = [];
    const dependencies = lifecycle(calls, {
      buildSandbox: () => {
        calls.push("build");
        throw new Error("build failed");
      }
    });

    await expect(runE2eApiLifecycle(dependencies)).rejects.toThrow("build failed");
    expect(calls).toEqual(["preflight", "pre-clean", "prepare", "build", "final-clean"]);
  });

  it("runs final cleanup when API boot fails after a successful build", async () => {
    const calls: string[] = [];
    const dependencies = lifecycle(calls, {
      serveApi: async () => {
        calls.push("serve");
        throw new Error("boot failed");
      }
    });

    await expect(runE2eApiLifecycle(dependencies)).rejects.toThrow("boot failed");
    expect(calls).toEqual([
      "preflight",
      "pre-clean",
      "prepare",
      "build",
      "serve",
      "final-clean"
    ]);
  });

  it("runs final cleanup after a normal API lifecycle", async () => {
    const calls: string[] = [];

    await runE2eApiLifecycle(lifecycle(calls));

    expect(calls).toEqual([
      "preflight",
      "pre-clean",
      "prepare",
      "build",
      "serve",
      "final-clean"
    ]);
  });
});

function lifecycle(
  calls: string[],
  overrides: Partial<E2eApiLifecycleDependencies> = {}
): E2eApiLifecycleDependencies {
  return {
    preflight: vi.fn(() => calls.push("preflight")),
    preCleanup: vi.fn(() => calls.push("pre-clean")),
    prepareState: vi.fn(() => calls.push("prepare")),
    buildSandbox: vi.fn(() => calls.push("build")),
    serveApi: vi.fn(async () => {
      calls.push("serve");
    }),
    finalCleanup: vi.fn(() => calls.push("final-clean")),
    ...overrides
  };
}
