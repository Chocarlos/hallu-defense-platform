import path from "node:path";
import { accessSync, constants, statSync } from "node:fs";

export class PythonRuntimeResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PythonRuntimeResolutionError";
  }
}

export interface PythonRuntimeEnv {
  readonly [key: string]: string | undefined;
}

export interface ResolvePythonExecutableOptions {
  readonly env: PythonRuntimeEnv;
  readonly isExecutable?: (candidate: string) => boolean;
}

/** The exact API source root this worktree's Playwright webServer must import from. */
export function resolveApiSourceRoot(
  repoRoot: string,
  isDirectory: (candidate: string) => boolean = defaultIsDirectory
): string {
  const sourceRoot = path.resolve(repoRoot, "apps", "api", "src");
  if (!isDirectory(sourceRoot)) {
    throw new PythonRuntimeResolutionError(
      `The Playwright API source root does not exist: "${sourceRoot}".`
    );
  }
  return sourceRoot;
}

/**
 * Resolve an explicit, usable Python executable for the Playwright API webServer.
 *
 * This never falls back to a bare `python`/`python3` command: a bare command name
 * resolves through PATH and can silently pick up an unrelated checkout's
 * interpreter or editable install. Callers must supply an explicit executable
 * path via `E2E_PYTHON_BIN`. CI uses the absolute `actions/setup-python`
 * output; local runs may point at a safely resolved shared root venv.
 */
export function resolvePythonExecutable(options: ResolvePythonExecutableOptions): string {
  const { env, isExecutable = defaultIsExecutable } = options;
  const explicit = env.E2E_PYTHON_BIN?.trim();
  if (explicit === undefined || explicit.length === 0) {
    throw new PythonRuntimeResolutionError(
      "E2E_PYTHON_BIN is required and must name an absolute, executable Python path. " +
        'Refusing to fall back to a worktree .venv or bare "python" on PATH.'
    );
  }
  if (!path.isAbsolute(explicit) || /["\r\n]/u.test(explicit)) {
    throw new PythonRuntimeResolutionError(
      `E2E_PYTHON_BIN must be an absolute interpreter path: "${explicit}".`
    );
  }
  const resolved = path.resolve(explicit);
  if (!isExecutable(resolved)) {
    throw new PythonRuntimeResolutionError(
      `E2E_PYTHON_BIN is not an executable file: "${resolved}".`
    );
  }
  return resolved;
}

/** Arguments for the committed preflight invoked by the API wrapper. */
export function pythonSourcePreflightArgs(
  repoRoot: string,
  apiSourceRoot: string
): readonly [string, string] {
  const checkerScript = path.join(repoRoot, "scripts", "ci", "check_e2e_python_source.py");
  return [checkerScript, apiSourceRoot];
}

function defaultIsDirectory(candidate: string): boolean {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function defaultIsExecutable(candidate: string): boolean {
  try {
    if (!statSync(candidate).isFile()) {
      return false;
    }
    accessSync(candidate, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}
