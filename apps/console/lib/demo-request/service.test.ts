import { describe, expect, it, vi } from "vitest";

import type { EnabledDemoRuntimeConfig } from "./config";
import { DemoMetrics } from "./metrics";
import type { DemoStore } from "./redis";
import { createDemoRequestHandler } from "./service";

const origin = "https://defense.example.test";
const secret = Buffer.from("server-secret-value-that-is-at-least-32-bytes", "utf8");

describe("demo request service", () => {
  it("accepts, finalizes, and never exposes contact PII", async () => {
    const store = reservingStore();
    const metrics = new DemoMetrics();
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const handler = createHandler({ store, metrics, fetchImpl });

    const response = await handler(validRequest());
    const body = await response.text();

    expect(response.status).toBe(202);
    expect(body).toMatch(/^\{"request_id":"dr_[A-Za-z0-9_-]{24}"\}$/u);
    expect(body).not.toContain("person@example.invalid");
    expect(store.finalize).toHaveBeenCalledOnce();
    expect(store.release).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(metrics.render()).not.toContain("person@example.invalid");
    const reservation = vi.mocked(store.reserve).mock.calls[0]?.[0];
    expect(reservation?.emailDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(JSON.stringify(reservation)).not.toContain("person@example.invalid");
  });

  it("makes a honeypot publicly indistinguishable without Redis or webhook", async () => {
    const store = reservingStore();
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const handler = createHandler({ store, fetchImpl });
    const accepted = await handler(validRequest());
    vi.mocked(store.reserve).mockClear();
    vi.mocked(store.finalize).mockClear();
    fetchImpl.mockClear();

    const honeypot = await handler(validRequest({ website: "https://bot.invalid" }));

    expect(honeypot.status).toBe(accepted.status);
    expect(await honeypot.text()).toBe(await accepted.text());
    for (const name of [
      "content-type",
      "cache-control",
      "pragma",
      "vary",
      "x-content-type-options"
    ]) {
      expect(honeypot.headers.get(name)).toBe(accepted.headers.get(name));
    }
    expect(store.reserve).not.toHaveBeenCalled();
    expect(store.finalize).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    ["duplicate", 202],
    ["pending", 202],
    ["rate_global", 429],
    ["rate_email", 429]
  ] as const)("maps Redis %s to the public contract", async (status, expectedStatus) => {
    const store = reservingStore(status);
    const fetchImpl = vi.fn<typeof fetch>();
    const response = await createHandler({ store, fetchImpl })(validRequest());

    expect(response.status).toBe(expectedStatus);
    expect(fetchImpl).not.toHaveBeenCalled();
    if (expectedStatus === 429) {
      expect(response.headers.get("retry-after")).toMatch(/^(60|3600)$/u);
    }
  });

  it("fails closed when Redis is unavailable", async () => {
    const store = reservingStore();
    vi.mocked(store.reserve).mockRejectedValueOnce(
      new Error("redis://user:password@redis.invalid person@example.invalid")
    );
    const fetchImpl = vi.fn<typeof fetch>();
    const response = await createHandler({ store, fetchImpl })(validRequest());
    const body = await response.text();

    expect(response.status).toBe(503);
    expect(body).toBe('{"error":"Demo requests are unavailable."}');
    expect(body).not.toContain("password");
    expect(body).not.toContain("person@example.invalid");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("releases its CAS reservation and sanitizes webhook failures", async () => {
    const store = reservingStore();
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      throw new Error("CRM response leaked person@example.invalid");
    });
    const response = await createHandler({ store, fetchImpl })(validRequest());

    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("person@example.invalid");
    expect(store.release).toHaveBeenCalledOnce();
    expect(store.finalize).not.toHaveBeenCalled();
  });

  it.each([
    ["text/plain", 415],
    ["application/json", 422]
  ])("returns the bounded invalid response for %s", async (contentType, status) => {
    const request = validRequest(
      contentType === "application/json" ? { consent: false } : {},
      { "content-type": contentType }
    );
    const response = await createHandler({ store: reservingStore() })(request);
    expect(response.status).toBe(status);
    expect(await response.text()).not.toContain("person@example.invalid");
  });

  it("returns 503 without inspecting PII when capture is disabled", async () => {
    const response = await createDemoRequestHandler({
      config: { enabled: false, environment: "development", productionLike: false },
      metrics: new DemoMetrics()
    })(validRequest());
    expect(response.status).toBe(503);
    expect(await response.text()).toBe('{"error":"Demo requests are unavailable."}');
  });
});

function createHandler(
  overrides: {
    readonly store: DemoStore;
    readonly metrics?: DemoMetrics;
    readonly fetchImpl?: typeof fetch;
  }
) {
  return createDemoRequestHandler({
    config,
    store: overrides.store,
    metrics: overrides.metrics ?? new DemoMetrics(),
    fetchImpl: overrides.fetchImpl ?? vi.fn(async () => new Response(null, { status: 204 })),
    now: () => new Date("2026-07-13T12:00:00.000Z"),
    secretReader: () => secret,
    leaseToken: () => "00000000-0000-4000-8000-000000000001"
  });
}

function reservingStore(
  status: "reserved" | "duplicate" | "pending" | "rate_global" | "rate_email" =
    "reserved"
): DemoStore {
  return {
    reserve: vi.fn(async (input) =>
      status === "rate_global" || status === "rate_email"
        ? { status }
        : { status, requestId: input.requestId }
    ),
    finalize: vi.fn(async () => true),
    release: vi.fn(async () => true)
  };
}

function validRequest(
  overrides: Readonly<Record<string, unknown>> = {},
  headerOverrides: Readonly<Record<string, string>> = {}
): Request {
  return new Request(`${origin}/demo-request`, {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "sec-fetch-dest": "empty",
      "content-type": "application/json",
      ...headerOverrides
    },
    body: JSON.stringify({
      submission_id: "123e4567-e89b-42d3-a456-426614174000",
      locale: "en",
      email: "person@example.invalid",
      name: "Ada",
      company: "Analytical Engines",
      use_case: "code_agents",
      consent: true,
      privacy_version: "privacy.v1",
      website: "",
      ...overrides
    })
  });
}

const config: EnabledDemoRuntimeConfig = {
  enabled: true,
  environment: "production",
  productionLike: true,
  publicOrigin: origin,
  privacyContactEmail: "privacy@example.invalid",
  webhookUrl: "https://crm.example.test/hooks/demo",
  webhookAllowedOrigin: "https://crm.example.test",
  webhookHmacSecretFile: "/run/secrets/demo-webhook-hmac",
  redisUrl: "rediss://redis.example.test:6380/0",
  redisCaPath: "/run/secrets/redis-ca.pem",
  metricsBearerFile: "/run/secrets/metrics-bearer"
};
