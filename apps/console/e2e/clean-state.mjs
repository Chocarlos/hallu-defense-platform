import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const e2eStateDir = path.join(repoRoot, "var", "e2e");

rmSync(e2eStateDir, { recursive: true, force: true });
mkdirSync(e2eStateDir, { recursive: true });
console.log(`Cleaned e2e state directory: ${e2eStateDir}`);
