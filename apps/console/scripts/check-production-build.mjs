import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const buildDirectory = path.resolve(process.cwd(), ".next");
const deployableDirectories = ["server", "static"].map((name) =>
  path.join(buildDirectory, name)
);
const forbiddenPatterns = [
  { label: "demo trace fixture", pattern: /tr_demo/iu },
  { label: "initial run fixture", pattern: /initialRun/iu },
  { label: "demo run fixture", pattern: /demoRun|demo-run/iu },
  { label: "demo reset control", pattern: /Restaurar demo/iu },
  {
    label: "demo API key payload",
    pattern: /api[_-]?key["']?\s*:\s*["']demo["']/iu
  }
];

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(entryPath)));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

let files;
try {
  files = (
    await Promise.all(deployableDirectories.map((directory) => collectFiles(directory)))
  ).flat();
} catch (error) {
  const detail = error instanceof Error ? error.message : String(error);
  throw new Error(`Production build directory is unavailable: ${detail}`);
}

const findings = [];
for (const file of files) {
  const content = (await readFile(file)).toString("utf8");
  for (const forbidden of forbiddenPatterns) {
    if (forbidden.pattern.test(content)) {
      findings.push(`${path.relative(buildDirectory, file)}: ${forbidden.label}`);
    }
  }
}

if (findings.length > 0) {
  throw new Error(
    `Production Console build contains forbidden demo material:\n${findings
      .sort()
      .map((finding) => `- ${finding}`)
      .join("\n")}`
  );
}

console.log(`Console production build check passed (${files.length} artifacts scanned).`);
