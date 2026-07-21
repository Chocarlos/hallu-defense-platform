import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rootCertificates } from "node:tls";

import { afterEach, describe, expect, it } from "vitest";

import * as demoRuntimeConfig from "../demo-request/config";
import {
  loadMarketingPublicConfig,
  MarketingConfigurationError,
  resolveMarketingOrigin,
  safeContactEmail
} from "./config";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("public marketing config", () => {
  it("renders safely when local console and demo environment are absent", () => {
    expect(loadMarketingPublicConfig({})).toEqual({
      demoRequestsEnabled: false,
      privacyContactEmail: null,
      siteOrigin: "http://localhost:3000"
    });
  });

  it("uses the canonical intake helper when integrated and otherwise fails closed", () => {
    expect(
      loadMarketingPublicConfig({
        HALLU_DEFENSE_ENV: "development",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"
      }).demoRequestsEnabled
    ).toBe(false);

    const config = loadMarketingPublicConfig(productionFixture());
    const canonicalHelperAvailable =
      typeof Reflect.get(demoRuntimeConfig, "isDemoRequestIntakeEnabled") === "function";
    expect(config).toEqual({
      demoRequestsEnabled: canonicalHelperAvailable,
      privacyContactEmail: "Privacy@example.invalid",
      siteOrigin: "https://defense.example.test"
    });
    expect(JSON.stringify(config)).not.toMatch(/hmac|redis|bearer|webhook/iu);
  });

  it("keeps the public site available with intake disabled when production secrets are invalid", () => {
    expect(
      loadMarketingPublicConfig({
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true",
        HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://defense.example.test",
        HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "privacy@example.invalid"
      })
    ).toEqual({
      demoRequestsEnabled: false,
      privacyContactEmail: "privacy@example.invalid",
      siteOrigin: "https://defense.example.test"
    });
  });

  it("fails closed for an absent, invalid, or HTTP production origin", () => {
    for (const origin of [undefined, "not-a-url", "http://public.example"] as const) {
      expect(() =>
        loadMarketingPublicConfig({
          HALLU_DEFENSE_ENV: "production",
          HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: origin
        })
      ).toThrow(MarketingConfigurationError);
    }
    expect(() =>
      loadMarketingPublicConfig({
        HALLU_DEFENSE_ENV: "local",
        NODE_ENV: "production"
      })
    ).toThrow(MarketingConfigurationError);
  });

  it("allows HTTPS everywhere and loopback HTTP only outside production", () => {
    expect(resolveMarketingOrigin("https://hallu.example", true)).toBe(
      "https://hallu.example"
    );
    expect(resolveMarketingOrigin("http://127.0.0.1:3200")).toBe(
      "http://127.0.0.1:3200"
    );
    expect(resolveMarketingOrigin("http://public.example")).toBe(
      "http://localhost:3000"
    );
    expect(() => resolveMarketingOrigin("http://localhost:3000", true)).toThrow(
      MarketingConfigurationError
    );
    expect(
      loadMarketingPublicConfig({
        HALLU_DEFENSE_ENV: "test",
        NODE_ENV: "production",
        HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3200"
      }).siteOrigin
    ).toBe("http://127.0.0.1:3200");
  });

  it("accepts only canonical ASCII mailboxes safe for a mailto link", () => {
    expect(safeContactEmail("Privacy@Example.Invalid")).toBe(
      "Privacy@example.invalid"
    );
    for (const email of [
      "privacy@example.invalid?subject=Injected",
      "privacy@example.invalid#fragment",
      "privacy%0d@example.invalid",
      "privacy@example.invalid&bcc=x",
      "privacy@exam\u202Eple.invalid",
      "privacy..team@example.invalid"
    ]) {
      expect(safeContactEmail(email)).toBeNull();
    }
  });

  it("uses exactly the same legal-contact decision as the intake runtime", () => {
    const env = {
      ...productionFixture(),
      HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "team%security@example.invalid"
    };

    expect(safeContactEmail(env.HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL)).toBeNull();
    expect(demoRuntimeConfig.isDemoRequestIntakeEnabled(env)).toBe(false);
    expect(loadMarketingPublicConfig(env).demoRequestsEnabled).toBe(false);
  });
});

function productionFixture(): Readonly<Record<string, string>> {
  const directory = mkdtempSync(join(tmpdir(), "hallu-marketing-config-"));
  temporaryDirectories.push(directory);
  const webhookFile = join(directory, "webhook-url");
  const hmacFile = join(directory, "webhook-hmac");
  const redisFile = join(directory, "redis-url");
  const caFile = join(directory, "redis-ca.pem");
  const metricsFile = join(directory, "metrics-bearer");
  writeFileSync(webhookFile, "https://crm.example.test/hooks/demo\n", "utf8");
  writeFileSync(hmacFile, `webhook-hmac-${"x".repeat(32)}\n`, "utf8");
  writeFileSync(
    redisFile,
    "rediss://demo:secret@redis.example.test:6380/0\n",
    "utf8"
  );
  writeFileSync(caFile, rootCertificates[0] ?? "", "utf8");
  writeFileSync(metricsFile, `metrics-bearer-${"x".repeat(32)}\n`, "utf8");
  return {
    HALLU_DEFENSE_ENV: "production",
    HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true",
    HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://defense.example.test",
    HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "Privacy@Example.Invalid",
    HALLU_DEFENSE_DEMO_WEBHOOK_URL_FILE: webhookFile,
    HALLU_DEFENSE_DEMO_WEBHOOK_HMAC_SECRET_FILE: hmacFile,
    HALLU_DEFENSE_DEMO_WEBHOOK_ALLOWED_ORIGIN: "https://crm.example.test",
    HALLU_DEFENSE_DEMO_REDIS_URL_FILE: redisFile,
    HALLU_DEFENSE_DEMO_REDIS_MODE: "cluster",
    HALLU_DEFENSE_DEMO_REDIS_CA_PATH: caFile,
    HALLU_DEFENSE_CONSOLE_METRICS_BEARER_FILE: metricsFile
  };
}
