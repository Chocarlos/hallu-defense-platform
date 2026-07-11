import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

type RootManifest = {
  allowScripts?: Record<string, boolean>;
  devDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  overrides?: Record<string, unknown>;
  packageManager?: string;
};

type ConsoleManifest = {
  dependencies?: Record<string, string>;
};

type PackageLock = {
  packages?: Record<
    string,
    {
      engines?: Record<string, string>;
      hasInstallScript?: boolean;
      version?: string;
    }
  >;
};

function readJson<T>(relativePath: string): T {
  const url = new URL(relativePath, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as T;
}

describe("frontend dependency security policy", () => {
  it("pins stable Next and permits only the scoped PostCSS correction", () => {
    const root = readJson<RootManifest>("../../../package.json");
    const console = readJson<ConsoleManifest>("../package.json");

    expect(root.devDependencies?.next).toBe("16.2.10");
    expect(root.devDependencies?.["eslint-config-next"]).toBe("16.2.10");
    expect(console.dependencies?.next).toBe("16.2.10");
    expect(root.overrides).toEqual({
      next: {
        postcss: "8.5.10",
      },
    });
  });

  it("locks the PostCSS correction beneath Next", () => {
    const lock = readJson<PackageLock>("../../../package-lock.json");

    expect(lock.packages?.["node_modules/next/node_modules/postcss"]?.version).toBe(
      "8.5.10",
    );
  });

  it("fails closed on dependency install scripts with the pinned npm policy", () => {
    const root = readJson<RootManifest>("../../../package.json");
    const lock = readJson<PackageLock>("../../../package-lock.json");
    const npmrc = readFileSync(
      new URL("../../../.npmrc", import.meta.url),
      "utf8",
    );

    expect(root.packageManager).toBe("npm@11.16.0");
    expect(root.engines).toEqual({ node: "24.18.0", npm: "11.16.0" });
    expect(lock.packages?.[""]?.engines).toEqual(root.engines);
    expect(root.allowScripts).toEqual({
      esbuild: false,
      fsevents: false,
      sharp: false,
      "unrs-resolver": false,
    });
    expect(npmrc.trim().split(/\r?\n/)).toEqual([
      "ignore-scripts=true",
      "strict-allow-scripts=true",
    ]);

    const expectedDeniedScripts = new Map<string, ReadonlySet<string>>([
      ["esbuild", new Set(["0.28.1"])],
      ["fsevents", new Set(["2.3.2", "2.3.3"])],
      ["sharp", new Set(["0.34.5"])],
      ["unrs-resolver", new Set(["1.12.2"])],
    ]);
    const installScriptPackages = Object.entries(lock.packages ?? {})
      .filter(([, entry]) => entry.hasInstallScript === true)
      .map(([path, entry]) => {
        const marker = "node_modules/";
        const packageName = path.slice(path.lastIndexOf(marker) + marker.length);
        return [packageName, entry.version] as const;
      });

    expect(installScriptPackages).toHaveLength(5);
    for (const [packageName, version] of installScriptPackages) {
      expect(expectedDeniedScripts.get(packageName)?.has(version ?? "")).toBe(true);
      expect(root.allowScripts?.[packageName]).toBe(false);
    }
  });
});
