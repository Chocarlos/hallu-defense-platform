import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rootCertificates } from "node:tls";

import { describe, expect, it } from "vitest";

import {
  DemoConfigurationError,
  isDemoRequestIntakeEnabled,
  loadDemoRuntimeConfig,
  readSecretBytes
} from "./config";

describe("demo runtime configuration", () => {
  it("is disabled in development when launch inputs are absent", () => {
    expect(
      loadDemoRuntimeConfig({
        HALLU_DEFENSE_ENV: "development",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"
      })
    ).toEqual({ enabled: false, environment: "development", productionLike: false });
  });

  it("fails closed in production when enabled launch inputs are absent", () => {
    const env = {
      HALLU_DEFENSE_ENV: "production",
      HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"
    } as const;
    expect(() => loadDemoRuntimeConfig(env)).toThrow(DemoConfigurationError);
    expect(isDemoRequestIntakeEnabled(env)).toBe(false);
  });

  it("treats the Next.js production runtime as production-like when the deployment environment is absent", () => {
    const fixture = productionFixture();
    writeSecureSecret(fixture.redisFile, "redis://redis.example.test:6379/0\n");

    expect(() =>
      loadDemoRuntimeConfig({
        ...fixture.env,
        HALLU_DEFENSE_ENV: undefined,
        NODE_ENV: "production"
      })
    ).toThrow(DemoConfigurationError);
  });

  it("loads HTTPS webhook, rediss, CA, and secrets exclusively from files", () => {
    const fixture = productionFixture();
    const config = loadDemoRuntimeConfig(fixture.env);
    expect(config).toMatchObject({
      enabled: true,
      webhookUrl: "https://crm.example.test/hooks/demo",
      webhookAllowedOrigin: "https://crm.example.test",
      redisUrl: "rediss://demo:secret@redis.example.test:6380/0"
    });
    expect(JSON.stringify(config)).not.toContain("metrics-bearer-value");
    expect(JSON.stringify(config)).not.toContain("webhook-hmac-value");
    expect(isDemoRequestIntakeEnabled(fixture.env)).toBe(true);
  });

  it("accepts a 254-character privacy contact and fails closed at 255", () => {
    const fixture = productionFixture();
    const maxLengthEmail = `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(53)}.invalid`;
    const overlongEmail = `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(54)}.invalid`;
    expect(maxLengthEmail).toHaveLength(254);
    expect(overlongEmail).toHaveLength(255);

    expect(
      loadDemoRuntimeConfig({
        ...fixture.env,
        HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: maxLengthEmail
      })
    ).toMatchObject({ enabled: true, privacyContactEmail: maxLengthEmail });

    const overlongEnv = {
      ...fixture.env,
      HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: overlongEmail
    };
    expect(() => loadDemoRuntimeConfig(overlongEnv)).toThrow(DemoConfigurationError);
    expect(isDemoRequestIntakeEnabled(overlongEnv)).toBe(false);
  });

  it("rejects webhook origin drift and plaintext production Redis", () => {
    const fixture = productionFixture();
    expect(() =>
      loadDemoRuntimeConfig({
        ...fixture.env,
        HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN: "https://other.example.test"
      })
    ).toThrow(DemoConfigurationError);

    writeSecureSecret(fixture.redisFile, "redis://redis.example.test:6379/0\n");
    expect(() => loadDemoRuntimeConfig(fixture.env)).toThrow(DemoConfigurationError);
  });

  it("rejects a non-certificate Redis trust file during startup", () => {
    const fixture = productionFixture();
    writeSecureSecret(fixture.caFile, "synthetic-ca-certificate");

    expect(() => loadDemoRuntimeConfig(fixture.env)).toThrow(DemoConfigurationError);
    expect(isDemoRequestIntakeEnabled(fixture.env)).toBe(false);
  });

  it("rejects unbounded, relative, permission-unsafe, and non-HTTP bearer files", () => {
    const fixture = productionFixture();
    writeSecureSecret(fixture.metricsFile, Buffer.alloc(32));
    expect(() => loadDemoRuntimeConfig(fixture.env)).toThrow(DemoConfigurationError);

    writeSecureSecret(fixture.metricsFile, Buffer.alloc(8 * 1024 + 1, 0x78));
    expect(() => readSecretBytes(fixture.metricsFile)).toThrow(DemoConfigurationError);
    expect(() => readSecretBytes("relative-secret-file")).toThrow(
      DemoConfigurationError
    );

    writeSecureSecret(fixture.metricsFile, Buffer.alloc(32, 0x78));
    chmodSync(fixture.metricsFile, 0o666);
    expect(() => readSecretBytes(fixture.metricsFile, "linux")).toThrow(
      DemoConfigurationError
    );
  });
});

function productionFixture() {
  const directory = mkdtempSync(join(tmpdir(), "hallu-demo-config-"));
  const webhookFile = join(directory, "webhook-url");
  const hmacFile = join(directory, "webhook-hmac");
  const redisFile = join(directory, "redis-url");
  const caFile = join(directory, "redis-ca.pem");
  const metricsFile = join(directory, "metrics-bearer");
  writeSecureSecret(webhookFile, "https://crm.example.test/hooks/demo\n");
  writeSecureSecret(hmacFile, `webhook-hmac-value-${"x".repeat(32)}\n`);
  writeSecureSecret(
    redisFile,
    "rediss://demo:secret@redis.example.test:6380/0\n"
  );
  writeSecureSecret(caFile, rootCertificates[0] ?? "");
  writeSecureSecret(metricsFile, `metrics-bearer-value-${"x".repeat(32)}\n`);
  return {
    redisFile,
    caFile,
    metricsFile,
    env: {
      HALLU_DEFENSE_ENV: "production",
      HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true",
      HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://defense.example.test",
      HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "privacy@example.invalid",
      HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE: webhookFile,
      HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE: hmacFile,
      HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN: "https://crm.example.test",
      HALLU_DEFENSE_DEMO_REDIS_URL_FILE: redisFile,
      HALLU_DEFENSE_DEMO_REDIS_CA_PATH: caFile,
      HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE: metricsFile
    }
  } as const;
}

function writeSecureSecret(path: string, contents: string | Uint8Array): void {
  try {
    chmodSync(path, 0o600);
  } catch {
    // The file does not exist yet.
  }
  writeFileSync(path, contents);
  chmodSync(path, 0o440);
}
