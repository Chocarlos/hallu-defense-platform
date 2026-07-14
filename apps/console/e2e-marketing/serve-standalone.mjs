import { cpSync, existsSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const consoleDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const standaloneDirectory = path.join(consoleDirectory, ".next", "standalone");
const standaloneConsoleDirectory = path.join(
  standaloneDirectory,
  "apps",
  "console"
);

const port = parsePort(process.argv.slice(2));
copyBuildDirectory(
  path.join(consoleDirectory, ".next", "static"),
  path.join(standaloneConsoleDirectory, ".next", "static"),
  true
);
copyBuildDirectory(
  path.join(consoleDirectory, "public"),
  path.join(standaloneConsoleDirectory, "public"),
  false
);

const serverPath = path.join(standaloneConsoleDirectory, "server.js");
if (!isRegularFile(serverPath)) {
  throw new Error("The Next.js standalone server artifact is missing.");
}

process.env.HOSTNAME = "127.0.0.1";
process.env.PORT = String(port);
process.chdir(standaloneDirectory);
try {
  await import(pathToFileURL(serverPath).href);
} catch (error) {
  throw new Error("The Next.js standalone server failed to start.", { cause: error });
}

function parsePort(args) {
  if (args.length !== 2 || args[0] !== "--port" || !/^\d{1,5}$/u.test(args[1])) {
    throw new Error("Usage: node serve-standalone.mjs --port <1-65535>");
  }
  const value = Number(args[1]);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) {
    throw new Error("The standalone server port is outside the valid range.");
  }
  return value;
}

function copyBuildDirectory(source, destination, required) {
  if (!existsSync(source)) {
    if (required) throw new Error(`Required standalone asset directory is missing: ${source}`);
    return;
  }
  if (!statSync(source).isDirectory()) {
    throw new Error(`Standalone asset source is not a directory: ${source}`);
  }
  cpSync(source, destination, { recursive: true, force: true });
}

function isRegularFile(file) {
  return existsSync(file) && statSync(file).isFile();
}
