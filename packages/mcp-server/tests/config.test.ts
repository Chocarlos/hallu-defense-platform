import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  McpConfigurationError,
  loadMcpRuntimeConfig,
  readApiAuthContext,
  readBoundedSecretFile,
  validateSecretFileMode
} from "../src/config.js";

const tempDirectories: string[] = [];

afterEach(() => {
  for (const directory of tempDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("MCP production configuration", () => {
  it("requires HTTPS, a token file, token-derived tenancy, and a POSIX host", () => {
    expect(() =>
      loadMcpRuntimeConfig(
        {
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_API_BASE_URL: "http://api.example.test",
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: "/run/secrets/mcp-token"
        },
        "linux"
      )
    ).toThrow(/must use HTTPS/u);
    expect(() =>
      loadMcpRuntimeConfig(
        {
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_API_BASE_URL: "https://api.example.test"
        },
        "linux"
      )
    ).toThrow(/TOKEN_FILE is required/u);
    expect(() =>
      loadMcpRuntimeConfig(
        {
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_API_BASE_URL: "https://api.example.test",
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: "/run/secrets/mcp-token",
          HALLU_DEFENSE_TENANT_ID: "spoofed"
        },
        "linux"
      )
    ).toThrow(/TENANT_ID is forbidden/u);
    expect(() =>
      loadMcpRuntimeConfig(
        {
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_API_BASE_URL: "https://api.example.test",
          HALLU_DEFENSE_MCP_API_TOKEN_FILE: "/run/secrets/mcp-token"
        },
        "win32"
      )
    ).toThrow(/POSIX host/u);
  });

  it("rejects raw token environment variables and insecure non-loopback HTTP", () => {
    expect(() =>
      loadMcpRuntimeConfig({ HALLU_DEFENSE_MCP_API_TOKEN: "must-not-live-in-env" })
    ).toThrow(/is forbidden/u);
    expect(() =>
      loadMcpRuntimeConfig({ HALLU_DEFENSE_API_BASE_URL: "http://api.example.test" })
    ).toThrow(/loopback/u);
    expect(() => loadMcpRuntimeConfig({ HALLU_DEFENSE_ENV: "prodution" })).toThrow(
      /HALLU_DEFENSE_ENV must be/u
    );
  });

  it("requires an absolute token path and bounded numeric settings", () => {
    expect(() =>
      loadMcpRuntimeConfig({ HALLU_DEFENSE_MCP_API_TOKEN_FILE: "relative-token" })
    ).toThrow(/must be absolute/u);
    expect(() =>
      loadMcpRuntimeConfig({ HALLU_DEFENSE_MCP_MAX_INPUT_BYTES: "999" })
    ).toThrow(/between 1024/u);
    expect(() =>
      loadMcpRuntimeConfig({ HALLU_DEFENSE_MCP_REQUEST_TIMEOUT_MS: "NaN" })
    ).toThrow(/must be an integer/u);
  });
});

describe("MCP bearer token files", () => {
  it("re-reads the token file for atomic rotation instead of caching the bearer", () => {
    const tokenFile = createTokenFile("first-token\n");
    const config = loadMcpRuntimeConfig({
      HALLU_DEFENSE_MCP_API_TOKEN_FILE: tokenFile,
      HALLU_DEFENSE_TENANT_ID: "tenant-local"
    });

    expect(readApiAuthContext(config, "win32")).toEqual({
      token: "first-token",
      tenantId: "tenant-local"
    });
    replaceToken(tokenFile, "rotated-token\n");
    expect(readApiAuthContext(config, "win32")).toEqual({
      token: "rotated-token",
      tenantId: "tenant-local"
    });
  });

  it("derives the production tenant from the configured JWT claim", () => {
    const token = jwtWithPayload({ tenant_id: "tenant-from-token", exp: 4_102_444_800 });
    const tokenFile = createTokenFile(`${token}\n`);
    const config = loadMcpRuntimeConfig(
      {
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_API_BASE_URL: "https://api.example.test",
        HALLU_DEFENSE_MCP_API_TOKEN_FILE: tokenFile
      },
      "linux"
    );

    expect(readApiAuthContext(config, "win32")).toEqual({
      token,
      tenantId: "tenant-from-token"
    });
  });

  it("rejects malformed, multiline, empty, and oversized token material", () => {
    const malformed = createTokenFile(" not-trimmed \n");
    const multiline = createTokenFile("line-one\nline-two\n");
    const oversized = createTokenFile("x".repeat(64 * 1024 + 1));

    expect(() => readBoundedSecretFile(malformed, "win32")).toThrow(/one non-empty line/u);
    expect(() => readBoundedSecretFile(multiline, "win32")).toThrow(/one non-empty line/u);
    expect(() => readBoundedSecretFile(oversized, "win32")).toThrow(/between 1 and/u);
  });

  it("enforces exact POSIX mode 0440", () => {
    expect(() => validateSecretFileMode(0o100440, "linux")).not.toThrow();
    expect(() => validateSecretFileMode(0o100400, "linux")).toThrow(/mode 0440/u);
    expect(() => validateSecretFileMode(0o100640, "linux")).toThrow(/mode 0440/u);
  });

  it("uses sanitized file errors that never include token contents", () => {
    const tokenFile = createTokenFile("secret-material-that-must-not-appear\n");
    replaceToken(tokenFile, "");

    try {
      readBoundedSecretFile(tokenFile, "win32");
      throw new Error("expected readBoundedSecretFile to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(McpConfigurationError);
      expect(String(error)).not.toContain("secret-material-that-must-not-appear");
    }
  });
});

function createTokenFile(contents: string): string {
  const directory = mkdtempSync(path.join(tmpdir(), "hallu-mcp-token-"));
  tempDirectories.push(directory);
  const filename = path.join(directory, "api-token");
  writeFileSync(filename, contents, "utf8");
  chmodSync(filename, 0o440);
  return filename;
}

function replaceToken(filename: string, contents: string): void {
  chmodSync(filename, 0o600);
  writeFileSync(filename, contents, "utf8");
  chmodSync(filename, 0o440);
}

function jwtWithPayload(payload: Readonly<Record<string, unknown>>): string {
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" }), "utf8").toString("base64url"),
    Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"),
    "test-signature"
  ].join(".");
}
