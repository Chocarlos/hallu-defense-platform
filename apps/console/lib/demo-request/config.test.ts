import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { DemoConfigurationError, loadDemoRuntimeConfig } from "./config";

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
    expect(() =>
      loadDemoRuntimeConfig({
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"
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
  });

  it("rejects webhook origin drift and plaintext production Redis", () => {
    const fixture = productionFixture();
    expect(() =>
      loadDemoRuntimeConfig({
        ...fixture.env,
        HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN: "https://other.example.test"
      })
    ).toThrow(DemoConfigurationError);

    writeFileSync(fixture.redisFile, "redis://redis.example.test:6379/0\n", "utf8");
    expect(() => loadDemoRuntimeConfig(fixture.env)).toThrow(DemoConfigurationError);
  });
});

function productionFixture() {
  const directory = mkdtempSync(join(tmpdir(), "hallu-demo-config-"));
  const webhookFile = join(directory, "webhook-url");
  const hmacFile = join(directory, "webhook-hmac");
  const redisFile = join(directory, "redis-url");
  const caFile = join(directory, "redis-ca.pem");
  const metricsFile = join(directory, "metrics-bearer");
  writeFileSync(webhookFile, "https://crm.example.test/hooks/demo\n", "utf8");
  writeFileSync(hmacFile, `webhook-hmac-value-${"x".repeat(32)}\n`, "utf8");
  writeFileSync(
    redisFile,
    "rediss://demo:secret@redis.example.test:6380/0\n",
    "utf8"
  );
  writeFileSync(caFile, "synthetic-ca-certificate", "utf8");
  writeFileSync(metricsFile, `metrics-bearer-value-${"x".repeat(32)}\n`, "utf8");
  return {
    redisFile,
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

