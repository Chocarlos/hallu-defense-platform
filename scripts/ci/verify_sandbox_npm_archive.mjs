import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const [lockPath, archivePath] = process.argv.slice(2);
if (!lockPath || !archivePath) {
  throw new Error("usage: verify_sandbox_npm_archive.mjs LOCK ARCHIVE");
}

const lock = JSON.parse(await readFile(lockPath, "utf8"));
const archive = await readFile(archivePath);
const expectedTarball = `https://registry.npmjs.org/npm/-/npm-${lock.version}.tgz`;
if (
  lock.schema_version !== "sandbox-npm-lock.v1" ||
  lock.package !== "npm" ||
  lock.version !== "12.0.0" ||
  lock.tarball !== expectedTarball ||
  new URL(lock.tarball).origin !== "https://registry.npmjs.org" ||
  lock.bytes !== archive.byteLength
) {
  throw new Error("sandbox npm archive metadata does not match its locked manifest");
}

const sha256 = createHash("sha256").update(archive).digest("hex");
const integrity = `sha512-${createHash("sha512").update(archive).digest("base64")}`;
if (sha256 !== lock.sha256 || integrity !== lock.integrity) {
  throw new Error("sandbox npm archive digest does not match its locked manifest");
}
