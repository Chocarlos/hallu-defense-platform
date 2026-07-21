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
    expect(store.consumeGlobal).toHaveBeenCalledOnce();
    expect(store.beginDelivery).toHaveBeenCalledOnce();
    expect(store.finalize).toHaveBeenCalledOnce();
    expect(store.release).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(metrics.render()).not.toContain("person@example.invalid");
    const reservation = vi.mocked(store.reserve).mock.calls[0]?.[0];
    expect(reservation?.emailDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(reservation?.payloadDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(JSON.stringify(reservation)).not.toContain("person@example.invalid");
  });

  it("matches the accepted public contract, quotas, and state transitions without a webhook", async () => {
    const store = reservingStore();
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const handler = createHandler({ store, fetchImpl });
    const accepted = await handler(validRequest());
    vi.mocked(store.reserve).mockClear();
    vi.mocked(store.consumeGlobal).mockClear();
    vi.mocked(store.beginDelivery).mockClear();
    vi.mocked(store.finalize).mockClear();
    fetchImpl.mockClear();

    const honeypot = await handler(validRequest({ website: "https://bot.invalid" }));

    expect(honeypot.status).toBe(accepted.status);
    expect(await honeypot.text()).toBe(await accepted.text());
    expect(headerRecord(honeypot.headers)).toEqual(headerRecord(accepted.headers));
    expect(honeypot.headers.has("server-timing")).toBe(false);
    expect(honeypot.headers.has("set-cookie")).toBe(false);
    expect(store.consumeGlobal).toHaveBeenCalledOnce();
    expect(store.reserve).toHaveBeenCalledOnce();
    expect(store.beginDelivery).toHaveBeenCalledOnce();
    expect(store.finalize).toHaveBeenCalledOnce();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("applies the same public response floor to real and honeypot successes", async () => {
    const store = reservingStore();
    const sleep = vi.fn(async () => undefined);
    const handler = createDemoRequestHandler({
      config,
      store,
      metrics: new DemoMetrics(),
      fetchImpl: vi.fn(async () => new Response(null, { status: 204 })),
      now: () => new Date("2026-07-13T12:00:00.000Z"),
      secretReader: () => secret,
      leaseToken: () => "00000000-0000-4000-8000-000000000001",
      monotonicNow: () => 0,
      sleep
    });

    await handler(validRequest());
    await handler(
      validRequest({
        submission_id: "123e4567-e89b-42d3-a456-426614174001",
        website: "bot.invalid"
      })
    );

    expect(sleep).toHaveBeenNthCalledWith(1, 300);
    expect(sleep).toHaveBeenNthCalledWith(2, 300);
  });

  it.each([
    ["duplicate", 202],
    ["pending", 503],
    ["dispatching", 503],
    ["conflict", 422],
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

  it("does not report a concurrent retry accepted before the original delivery resolves", async () => {
    const store = reservingStore();
    vi.mocked(store.reserve)
      .mockImplementationOnce(async (input) => ({
        status: "reserved",
        requestId: input.requestId
      }))
      .mockImplementationOnce(async (input) => ({
        status: "pending",
        requestId: input.requestId
      }));
    let rejectWebhook: ((reason: Error) => void) | undefined;
    const fetchImpl = vi.fn<typeof fetch>(
      async () =>
        new Promise<Response>((_resolve, reject) => {
          rejectWebhook = reject;
        })
    );
    const handler = createHandler({ store, fetchImpl });

    const original = handler(validRequest());
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledOnce());
    const retry = await handler(validRequest());
    expect(retry.status).toBe(503);

    rejectWebhook?.(new Error("synthetic upstream failure"));
    await expect(original).resolves.toMatchObject({ status: 503 });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(store.release).toHaveBeenCalledOnce();
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

  it("counts a same-origin malformed request against the global boundary", async () => {
    const store = reservingStore();
    const response = await createHandler({ store })(
      validRequest({ consent: false })
    );

    expect(response.status).toBe(422);
    expect(store.consumeGlobal).toHaveBeenCalledOnce();
    expect(store.reserve).not.toHaveBeenCalled();
  });

  it("does not redeliver after a successful webhook when finalization is ambiguous", async () => {
    const store = reservingStore();
    vi.mocked(store.reserve)
      .mockImplementationOnce(async (input) => ({
        status: "reserved",
        requestId: input.requestId
      }))
      .mockImplementationOnce(async (input) => ({
        status: "pending",
        requestId: input.requestId
      }));
    vi.mocked(store.finalize).mockRejectedValueOnce(new Error("lost acknowledgement"));
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const handler = createHandler({ store, fetchImpl });

    await expect(handler(validRequest())).resolves.toMatchObject({ status: 202 });
    await expect(handler(validRequest())).resolves.toMatchObject({ status: 503 });
    expect(fetchImpl).toHaveBeenCalledOnce();
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
      metrics: new DemoMetrics(),
      minimumResponseMilliseconds: 0
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
    leaseToken: () => "00000000-0000-4000-8000-000000000001",
    minimumResponseMilliseconds: 0
  });
}

function reservingStore(
  status:
    | "reserved"
    | "duplicate"
    | "pending"
    | "dispatching"
    | "conflict"
    | "rate_global"
    | "rate_email" = "reserved"
): DemoStore {
  return {
    consumeGlobal: vi.fn(async () =>
      status === "rate_global" ? "rate_global" : "allowed"
    ),
    reserve: vi.fn(async (input) => {
      if (status === "conflict" || status === "rate_email") {
        return { status };
      }
      return {
        status: status === "rate_global" ? "reserved" : status,
        requestId: input.requestId
      };
    }),
    beginDelivery: vi.fn(async () => true),
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
  redisMode: "cluster",
  redisCaPath: "/run/secrets/redis-ca.pem",
  metricsBearerFile: "/run/secrets/metrics-bearer"
};

function headerRecord(headers: Headers): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}
