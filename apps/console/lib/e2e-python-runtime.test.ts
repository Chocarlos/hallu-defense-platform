import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  PythonRuntimeResolutionError,
  pythonSourcePreflightArgs,
  resolveApiSourceRoot,
  resolvePythonExecutable
} from "./e2e-python-runtime";

const repoRoot = path.resolve("repo-root");

describe("resolveApiSourceRoot", () => {
  it("returns this worktree's apps/api/src, not an installed package path", () => {
    expect(resolveApiSourceRoot(repoRoot, () => true)).toBe(
      path.join(repoRoot, "apps", "api", "src")
    );
  });

  it("fails closed when this worktree's API source root is missing", () => {
    expect(() => resolveApiSourceRoot(repoRoot, () => false)).toThrow(
      PythonRuntimeResolutionError
    );
  });
});

describe("resolvePythonExecutable", () => {
  it("uses an explicit absolute E2E_PYTHON_BIN path", () => {
    const explicit = path.resolve("fake-tools", "python");
    const resolved = resolvePythonExecutable({
      env: { E2E_PYTHON_BIN: explicit },
      isExecutable: (candidate) => candidate === explicit
    });
    expect(resolved).toBe(explicit);
  });

  it("rejects a bare command name passed through E2E_PYTHON_BIN", () => {
    expect(() =>
      resolvePythonExecutable({
        env: { E2E_PYTHON_BIN: "python" },
        isExecutable: () => true
      })
    ).toThrow(PythonRuntimeResolutionError);
  });

  it("requires E2E_PYTHON_BIN even if a worktree venv might exist", () => {
    expect(() =>
      resolvePythonExecutable({
        env: {},
        isExecutable: () => true
      })
    ).toThrow(PythonRuntimeResolutionError);
  });

  it("rejects an absolute path that is not an executable file", () => {
    const explicit = path.resolve("fake-tools", "missing-python");
    expect(() =>
      resolvePythonExecutable({
        env: { E2E_PYTHON_BIN: explicit },
        isExecutable: () => false
      })
    ).toThrow(PythonRuntimeResolutionError);
  });

  it("never returns the bare string \"python\" under any resolvable configuration", () => {
    const explicit = path.resolve("fake-tools", "python");
    const resolved = resolvePythonExecutable({
      env: { E2E_PYTHON_BIN: explicit },
      isExecutable: () => true
    });
    expect(resolved).not.toBe("python");
  });
});

describe("pythonSourcePreflightArgs", () => {
  it("selects the committed checker and exact source root without a shell", () => {
    const apiSourceRoot = resolveApiSourceRoot(repoRoot, () => true);
    expect(pythonSourcePreflightArgs(repoRoot, apiSourceRoot)).toEqual([
      path.join(repoRoot, "scripts", "ci", "check_e2e_python_source.py"),
      apiSourceRoot
    ]);
  });
});
