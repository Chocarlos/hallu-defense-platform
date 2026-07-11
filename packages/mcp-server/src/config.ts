import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import path from "node:path";

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_MAX_INPUT_BYTES = 1024 * 1024;
const MAX_SECRET_BYTES = 64 * 1024;
const MAX_CONFIGURED_INPUT_BYTES = 16 * 1024 * 1024;
const POSIX_SECRET_MODE = 0o440;

const productionEnvironments = new Set(["production", "staging"]);
const supportedEnvironments = new Set([
  "local",
  "development",
  "test",
  "staging",
  "production"
]);

export interface McpRuntimeConfig {
  readonly apiBaseUrl: string;
  readonly apiTokenFile?: string;
  readonly environment: string;
  readonly maxInputBytes: number;
  readonly oidcTenantClaim: string;
  readonly requestTimeoutMs: number;
  readonly tenantId?: string;
}

export interface ApiAuthContext {
  readonly tenantId?: string;
  readonly token?: string;
}

export class McpConfigurationError extends Error {
  readonly code = "MCP_CONFIGURATION_ERROR" as const;

  constructor(message: string) {
    super(message);
    this.name = "McpConfigurationError";
  }
}

export function loadMcpRuntimeConfig(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): McpRuntimeConfig {
  const environment = (env.HALLU_DEFENSE_ENV ?? "local").trim().toLowerCase();
  if (!supportedEnvironments.has(environment)) {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_ENV must be local, development, test, staging, or production."
    );
  }
  const productionLike = productionEnvironments.has(environment);
  const rawToken = env.HALLU_DEFENSE_MCP_API_TOKEN;
  if (rawToken !== undefined) {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_MCP_API_TOKEN is forbidden; mount HALLU_DEFENSE_MCP_API_TOKEN_FILE instead."
    );
  }

  const apiBaseUrl = validateApiBaseUrl(
    env.HALLU_DEFENSE_API_BASE_URL ?? DEFAULT_API_BASE_URL,
    productionLike
  );
  const apiTokenFile = optionalNonEmpty(env.HALLU_DEFENSE_MCP_API_TOKEN_FILE);
  if (apiTokenFile !== undefined && !path.isAbsolute(apiTokenFile)) {
    throw new McpConfigurationError("HALLU_DEFENSE_MCP_API_TOKEN_FILE must be absolute.");
  }
  if (productionLike && apiTokenFile === undefined) {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_MCP_API_TOKEN_FILE is required in production and staging."
    );
  }
  if (productionLike && platform === "win32") {
    throw new McpConfigurationError(
      "Production MCP requires a POSIX host where token mode 0440 can be enforced."
    );
  }

  const tenantId = optionalNonEmpty(env.HALLU_DEFENSE_TENANT_ID);
  if (productionLike && tenantId !== undefined) {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_TENANT_ID is forbidden in production; tenant identity must come from the verified bearer token."
    );
  }

  const oidcTenantClaim =
    optionalNonEmpty(env.HALLU_DEFENSE_MCP_OIDC_TENANT_CLAIM) ?? "tenant_id";
  const requestTimeoutMs = parseBoundedInteger(
    env.HALLU_DEFENSE_MCP_REQUEST_TIMEOUT_MS,
    10_000,
    100,
    60_000,
    "HALLU_DEFENSE_MCP_REQUEST_TIMEOUT_MS"
  );
  const maxInputBytes = parseBoundedInteger(
    env.HALLU_DEFENSE_MCP_MAX_INPUT_BYTES,
    DEFAULT_MAX_INPUT_BYTES,
    1024,
    MAX_CONFIGURED_INPUT_BYTES,
    "HALLU_DEFENSE_MCP_MAX_INPUT_BYTES"
  );

  return {
    apiBaseUrl,
    environment,
    maxInputBytes,
    oidcTenantClaim,
    requestTimeoutMs,
    ...(apiTokenFile !== undefined ? { apiTokenFile } : {}),
    ...(tenantId !== undefined ? { tenantId } : {})
  };
}

export function readApiAuthContext(
  config: McpRuntimeConfig,
  platform: NodeJS.Platform = process.platform
): ApiAuthContext {
  if (config.apiTokenFile === undefined) {
    return config.tenantId === undefined ? {} : { tenantId: config.tenantId };
  }

  const bearerToken = readBoundedSecretFile(config.apiTokenFile, platform);
  if (productionEnvironments.has(config.environment)) {
    const tenantId = readJwtStringClaim(bearerToken, config.oidcTenantClaim);
    return { tenantId, token: bearerToken };
  }
  return {
    token: bearerToken,
    ...(config.tenantId !== undefined ? { tenantId: config.tenantId } : {})
  };
}

export function readBoundedSecretFile(
  filename: string,
  platform: NodeJS.Platform = process.platform
): string {
  if (!path.isAbsolute(filename)) {
    throw new McpConfigurationError("MCP API token file must be absolute.");
  }
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  let descriptor: number | undefined;
  try {
    const linkStat = lstatSync(filename);
    if (linkStat.isSymbolicLink()) {
      throw new McpConfigurationError("MCP API token file must not be a symbolic link.");
    }
    descriptor = openSync(filename, constants.O_RDONLY | noFollow);
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) {
      throw new McpConfigurationError("MCP API token path must be a regular file.");
    }
    if (stat.size <= 0 || stat.size > MAX_SECRET_BYTES) {
      throw new McpConfigurationError(
        `MCP API token file must contain between 1 and ${String(MAX_SECRET_BYTES)} bytes.`
      );
    }
    validateSecretFileMode(stat.mode, platform);
    const raw = readFileSync(descriptor);
    if (raw.length !== stat.size || raw.length > MAX_SECRET_BYTES) {
      throw new McpConfigurationError("MCP API token file changed while it was being read.");
    }
    return decodeSecret(raw);
  } catch (error) {
    if (error instanceof McpConfigurationError) {
      throw error;
    }
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String(error.code)
        : "UNKNOWN";
    throw new McpConfigurationError(`Unable to read MCP API token file (${code}).`);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
}

export function validateSecretFileMode(mode: number, platform: NodeJS.Platform): void {
  if (platform === "win32") {
    return;
  }
  const permissions = mode & 0o777;
  if (permissions !== POSIX_SECRET_MODE) {
    throw new McpConfigurationError(
      `MCP API token file must have mode 0440; found ${permissions.toString(8).padStart(4, "0")}.`
    );
  }
}

function validateApiBaseUrl(value: string, productionLike: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new McpConfigurationError("HALLU_DEFENSE_API_BASE_URL must be an absolute URL.");
  }
  if (
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_API_BASE_URL must not contain credentials, query parameters, or a fragment."
    );
  }
  if (productionLike && parsed.protocol !== "https:") {
    throw new McpConfigurationError(
      "HALLU_DEFENSE_API_BASE_URL must use HTTPS in production and staging."
    );
  }
  if (parsed.protocol === "http:" && !isLoopbackHostname(parsed.hostname)) {
    throw new McpConfigurationError("Plain HTTP is allowed only for loopback development APIs.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new McpConfigurationError("HALLU_DEFENSE_API_BASE_URL must use HTTP or HTTPS.");
  }
  return parsed.toString().replace(/\/+$/u, "");
}

function readJwtStringClaim(bearerToken: string, claimName: string): string {
  const segments = bearerToken.split(".");
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new McpConfigurationError(
      "Production MCP bearer token must be a three-segment JWT."
    );
  }
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(segments[1] ?? "", "base64url").toString("utf8")) as unknown;
  } catch {
    throw new McpConfigurationError("Production MCP bearer token has an invalid JWT payload.");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new McpConfigurationError("Production MCP bearer token payload must be an object.");
  }
  const claim = (payload as Record<string, unknown>)[claimName];
  if (typeof claim !== "string" || claim.trim().length === 0 || claim !== claim.trim()) {
    throw new McpConfigurationError(
      `Production MCP bearer token must contain non-empty string claim '${claimName}'.`
    );
  }
  return claim;
}

function decodeSecret(raw: Buffer): string {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    throw new McpConfigurationError("MCP API token file must contain valid UTF-8.");
  }
  if (decoded.includes("\0")) {
    throw new McpConfigurationError("MCP API token file must not contain NUL bytes.");
  }
  const material = decoded.endsWith("\n") ? decoded.slice(0, -1) : decoded;
  const withoutCarriageReturn = material.endsWith("\r")
    ? material.slice(0, -1)
    : material;
  if (
    withoutCarriageReturn.length === 0 ||
    withoutCarriageReturn.trim() !== withoutCarriageReturn ||
    withoutCarriageReturn.includes("\n") ||
    withoutCarriageReturn.includes("\r")
  ) {
    throw new McpConfigurationError(
      "MCP API token file must contain one non-empty line without surrounding whitespace."
    );
  }
  return withoutCarriageReturn;
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function optionalNonEmpty(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  return trimmed;
}

function parseBoundedInteger(
  raw: string | undefined,
  defaultValue: number,
  minimum: number,
  maximum: number,
  name: string
): number {
  if (raw === undefined) {
    return defaultValue;
  }
  if (!/^[0-9]+$/u.test(raw)) {
    throw new McpConfigurationError(`${name} must be an integer.`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new McpConfigurationError(
      `${name} must be between ${String(minimum)} and ${String(maximum)}.`
    );
  }
  return value;
}
