import { readFileSync } from "node:fs";

const PRODUCTION_LIKE_ENVIRONMENTS = new Set(["production", "staging"]);
const SECRET_FILE_MAX_BYTES = 8 * 1024;

export interface DisabledDemoRuntimeConfig {
  readonly enabled: false;
  readonly environment: string;
  readonly productionLike: boolean;
}

export interface EnabledDemoRuntimeConfig {
  readonly enabled: true;
  readonly environment: string;
  readonly productionLike: boolean;
  readonly publicOrigin: string;
  readonly privacyContactEmail: string;
  readonly webhookUrl: string;
  readonly webhookAllowedOrigin: string;
  readonly webhookHmacSecretFile: string;
  readonly redisUrl: string;
  readonly redisCaPath?: string;
  readonly metricsBearerFile: string;
}

export type DemoRuntimeConfig = DisabledDemoRuntimeConfig | EnabledDemoRuntimeConfig;

export interface DemoMetricsRuntimeConfig {
  readonly enabled: boolean;
  readonly bearerFile?: string;
}

export type EnvironmentSource = Readonly<Record<string, string | undefined>>;

export class DemoConfigurationError extends Error {
  constructor() {
    super("Demo request runtime configuration is invalid.");
    this.name = "DemoConfigurationError";
  }
}

export function loadDemoRuntimeConfig(
  env: EnvironmentSource = process.env
): DemoRuntimeConfig {
  const environment = (env.HALLU_DEFENSE_ENV ?? "local").trim().toLowerCase();
  const productionLike = PRODUCTION_LIKE_ENVIRONMENTS.has(environment);
  const enabled = strictBoolean(env.HALLU_DEFENSE_DEMO_REQUESTS_ENABLED);
  if (!enabled) {
    return { enabled: false, environment, productionLike };
  }

  try {
    return loadEnabledConfig(env, environment, productionLike);
  } catch {
    if (productionLike) {
      throw new DemoConfigurationError();
    }
    return { enabled: false, environment, productionLike };
  }
}

export function loadDemoMetricsRuntimeConfig(
  env: EnvironmentSource = process.env
): DemoMetricsRuntimeConfig {
  const bearerFile = cleanValue(env.HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE);
  if (bearerFile === undefined) {
    return { enabled: false };
  }
  return { enabled: true, bearerFile };
}

export function readSecretBytes(path: string): Buffer {
  const bytes = readFileSync(path);
  if (bytes.byteLength === 0 || bytes.byteLength > SECRET_FILE_MAX_BYTES) {
    throw new DemoConfigurationError();
  }
  if (bytes.at(-1) === 0x0a) {
    const withoutLf = bytes.subarray(0, bytes.byteLength - 1);
    return withoutLf.at(-1) === 0x0d
      ? Buffer.from(withoutLf.subarray(0, withoutLf.byteLength - 1))
      : Buffer.from(withoutLf);
  }
  return Buffer.from(bytes);
}

function loadEnabledConfig(
  env: EnvironmentSource,
  environment: string,
  productionLike: boolean
): EnabledDemoRuntimeConfig {
  const publicOrigin = parseOrigin(required(env, "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN"), {
    allowLoopbackHttp: !productionLike
  });
  const privacyContactEmail = required(
    env,
    "HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL"
  ).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(privacyContactEmail)) {
    throw new DemoConfigurationError();
  }

  const webhookUrlFile = required(env, "HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE");
  const webhookHmacSecretFile = required(
    env,
    "HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE"
  );
  const webhookAllowedOrigin = parseOrigin(
    required(env, "HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN"),
    { allowLoopbackHttp: false }
  );
  const redisUrlFile = required(env, "HALLU_DEFENSE_DEMO_REDIS_URL_FILE");
  const metricsBearerFile = required(
    env,
    "HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE"
  );
  const redisCaPath = cleanValue(env.HALLU_DEFENSE_DEMO_REDIS_CA_PATH);

  const webhookUrl = decodeSecretText(readSecretBytes(webhookUrlFile));
  validateWebhookUrl(webhookUrl, webhookAllowedOrigin);
  const redisUrl = decodeSecretText(readSecretBytes(redisUrlFile));
  validateRedisUrl(redisUrl, productionLike, redisCaPath);
  if (readSecretBytes(webhookHmacSecretFile).byteLength < 32) {
    throw new DemoConfigurationError();
  }
  const metricsBearer = readSecretBytes(metricsBearerFile);
  if (metricsBearer.byteLength < 32 || metricsBearer.byteLength > 256) {
    throw new DemoConfigurationError();
  }
  if (redisCaPath !== undefined && readSecretBytes(redisCaPath).byteLength === 0) {
    throw new DemoConfigurationError();
  }

  return {
    enabled: true,
    environment,
    productionLike,
    publicOrigin,
    privacyContactEmail,
    webhookUrl,
    webhookAllowedOrigin,
    webhookHmacSecretFile,
    redisUrl,
    ...(redisCaPath === undefined ? {} : { redisCaPath }),
    metricsBearerFile
  };
}

function validateWebhookUrl(value: string, allowedOrigin: string): void {
  const url = parseAbsoluteUrl(value);
  if (
    url.protocol !== "https:" ||
    url.origin !== allowedOrigin ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.search !== ""
  ) {
    throw new DemoConfigurationError();
  }
}

function validateRedisUrl(
  value: string,
  productionLike: boolean,
  caPath: string | undefined
): void {
  const url = parseAbsoluteUrl(value);
  if (
    (url.protocol !== "redis:" && url.protocol !== "rediss:") ||
    url.hostname === "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !/^\/(?:|0|[1-9][0-9]*)$/u.test(url.pathname)
  ) {
    throw new DemoConfigurationError();
  }
  if (productionLike && (url.protocol !== "rediss:" || caPath === undefined)) {
    throw new DemoConfigurationError();
  }
}

function parseOrigin(
  value: string,
  options: { readonly allowLoopbackHttp: boolean }
): string {
  const url = parseAbsoluteUrl(value);
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol !== "https:" &&
      !(options.allowLoopbackHttp && loopback && url.protocol === "http:")) ||
    value !== url.origin
  ) {
    throw new DemoConfigurationError();
  }
  return url.origin;
}

function parseAbsoluteUrl(value: string): URL {
  if (value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new DemoConfigurationError();
  }
  try {
    return new URL(value);
  } catch {
    throw new DemoConfigurationError();
  }
}

function decodeSecretText(bytes: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new DemoConfigurationError();
  }
}

function strictBoolean(value: string | undefined): boolean {
  if (value === undefined || value === "" || value === "false") {
    return false;
  }
  if (value === "true") {
    return true;
  }
  throw new DemoConfigurationError();
}

function required(env: EnvironmentSource, name: string): string {
  const value = cleanValue(env[name]);
  if (value === undefined) {
    throw new DemoConfigurationError();
  }
  return value;
}

function cleanValue(value: string | undefined): string | undefined {
  if (
    value === undefined ||
    value === "" ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    return undefined;
  }
  return value;
}
