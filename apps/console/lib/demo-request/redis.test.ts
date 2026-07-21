import { describe, expect, it, vi } from "vitest";

import {
  BEGIN_DELIVERY_SCRIPT,
  FINALIZE_SCRIPT,
  GLOBAL_LIMIT_SCRIPT,
  RELEASE_SCRIPT,
  RESERVE_SCRIPT,
  RedisDemoStore,
  createRedisDemoStore,
  redisClusterClientOptions,
  type DemoRedisClientFactory,
  type RedisCommandClient
} from "./redis";

const requestId = `dr_${"A".repeat(24)}`;
const payloadDigest = "c".repeat(64);

describe("Redis demo request state", () => {
  it("propagates decoded authentication to every discovered cluster node", () => {
    const redisUrl = new URL("redis://redis.example.test:6379/0");
    redisUrl.username = "cluster-user";
    redisUrl.password = ["p", "@ssword"].join("");
    const redisUrlText = redisUrl.toString();
    const options = redisClusterClientOptions({
      enabled: true,
      environment: "development",
      productionLike: false,
      publicOrigin: "http://localhost:3000",
      privacyContactEmail: "privacy@example.invalid",
      webhookUrl: "https://crm.example.test/hooks/demo",
      webhookAllowedOrigin: "https://crm.example.test",
      webhookHmacSecretFile: "/run/secrets/webhook-hmac",
      redisUrl: redisUrlText,
      redisMode: "cluster",
      metricsBearerFile: "/run/secrets/metrics-bearer"
    });

    expect(options.rootNodes).toEqual([
      {
        url: redisUrlText
      }
    ]);
    expect(options.defaults).toMatchObject({
      username: "cluster-user",
      password: "p@ssword",
      socket: {
        connectTimeout: 1_000,
        socketTimeout: 1_000,
        reconnectStrategy: false
      }
    });
  });

  it.each(["standalone", "cluster"] as const)(
    "selects the explicit %s client topology",
    (redisMode) => {
      const client = fakeClient("allowed");
      const factory: DemoRedisClientFactory = {
        createStandalone: vi.fn(() => client),
        createCluster: vi.fn(() => client)
      };

      createRedisDemoStore(
        {
          enabled: true,
          environment: redisMode === "cluster" ? "production" : "development",
          productionLike: redisMode === "cluster",
          publicOrigin: "https://defense.example.test",
          privacyContactEmail: "privacy@example.invalid",
          webhookUrl: "https://crm.example.test/hooks/demo",
          webhookAllowedOrigin: "https://crm.example.test",
          webhookHmacSecretFile: "/run/secrets/webhook-hmac",
          redisUrl: "rediss://redis.example.test:6380/0",
          redisMode,
          redisCaPath: "/run/secrets/redis-ca.pem",
          metricsBearerFile: "/run/secrets/metrics-bearer"
        },
        factory
      );

      expect(factory.createCluster).toHaveBeenCalledTimes(
        redisMode === "cluster" ? 1 : 0
      );
      expect(factory.createStandalone).toHaveBeenCalledTimes(
        redisMode === "standalone" ? 1 : 0
      );
    }
  );

  it("consumes the global boundary before parsing with a bounded Lua result", async () => {
    const client = fakeClient("allowed");
    const store = new RedisDemoStore(client);

    await expect(store.consumeGlobal()).resolves.toBe("allowed");
    const command = vi.mocked(client.sendCommand).mock.calls[0]?.[0];
    expect(command).toEqual([
      "EVAL",
      GLOBAL_LIMIT_SCRIPT,
      "1",
      "hallu-defense:{demo-request-v1}:global",
      "60",
      "60000"
    ]);
    expect(GLOBAL_LIMIT_SCRIPT).toContain("INCR");
    expect(GLOBAL_LIMIT_SCRIPT).toContain("PEXPIRE");
  });

  it("reserves email-digest and idempotency keys in one cluster-safe Lua operation", async () => {
    const client = fakeClient(["reserved", requestId]);
    const store = new RedisDemoStore(client);
    const emailDigest = "b".repeat(64);

    await expect(
      store.reserve(reservationInput({ emailDigest }))
    ).resolves.toEqual({ status: "reserved", requestId });

    const command = vi.mocked(client.sendCommand).mock.calls[0]?.[0];
    expect(command?.slice(0, 3)).toEqual(["EVAL", RESERVE_SCRIPT, "2"]);
    expect(command?.join(" ")).toContain(`:email:${emailDigest}`);
    const keys = command?.slice(3, 5) ?? [];
    expect(keys).toHaveLength(2);
    expect(keys.every((key) => key.includes("{demo-request-v1}"))).toBe(true);
    expect(command?.join(" ")).not.toContain("person@example.invalid");
    expect(command?.slice(5)).toEqual([
      "3",
      "3600000",
      "86400000",
      "lease-token",
      "15000",
      requestId,
      payloadDigest
    ]);
    expect(RESERVE_SCRIPT).toContain("redis.call('TIME')");
    expect(RESERVE_SCRIPT).toContain("'payload_digest', ARGV[7]");
    expect(RESERVE_SCRIPT).toContain("state[4] ~= ARGV[7]");
    expect(RESERVE_SCRIPT).toContain("state[1] == 'dispatching'");
    expect(RESERVE_SCRIPT).toContain("PEXPIRE");
  });

  it("guards dispatch before webhook and uses compare-and-set finalize/release", async () => {
    const client = fakeClient(1);
    const store = new RedisDemoStore(client);
    await expect(store.beginDelivery("a".repeat(64), "lease-token")).resolves.toBe(true);
    await expect(store.finalize("a".repeat(64), "lease-token")).resolves.toBe(true);
    await expect(store.release("a".repeat(64), "lease-token")).resolves.toBe(true);

    expect(vi.mocked(client.sendCommand).mock.calls[0]?.[0]?.[1]).toBe(
      BEGIN_DELIVERY_SCRIPT
    );
    expect(vi.mocked(client.sendCommand).mock.calls[1]?.[0]?.[1]).toBe(FINALIZE_SCRIPT);
    expect(vi.mocked(client.sendCommand).mock.calls[2]?.[0]?.[1]).toBe(RELEASE_SCRIPT);
    expect(BEGIN_DELIVERY_SCRIPT).toContain("dispatching");
    expect(FINALIZE_SCRIPT).toContain("dispatching");
    expect(FINALIZE_SCRIPT).toContain("lease_token");
    expect(RELEASE_SCRIPT).toContain("retryable");
  });

  it.each([
    ["duplicate", requestId],
    ["pending", requestId],
    ["dispatching", requestId],
    ["conflict", ""],
    ["rate_email", ""]
  ])("parses the bounded Redis result %s", async (status, id) => {
    const store = new RedisDemoStore(fakeClient([status, id]));
    await expect(
      store.reserve(reservationInput())
    ).resolves.toEqual(id === "" ? { status } : { status, requestId });
  });

  it("fails closed on malformed global-limit responses", async () => {
    await expect(new RedisDemoStore(fakeClient("rate_global")).consumeGlobal()).resolves.toBe(
      "rate_global"
    );
    await expect(new RedisDemoStore(fakeClient("unexpected")).consumeGlobal()).rejects.toThrow(
      "unavailable"
    );
  });

  it("fails closed on malformed protocol responses", async () => {
    const store = new RedisDemoStore(fakeClient(["reserved", "email@example.invalid"]));
    await expect(
      store.reserve(reservationInput())
    ).rejects.toThrow("unavailable");
  });

  it("rejects non-digest Redis identities before any command can persist PII", async () => {
    const client = fakeClient(["reserved", requestId]);
    const store = new RedisDemoStore(client);

    await expect(
      store.reserve(reservationInput({ emailDigest: "person@example.invalid" }))
    ).rejects.toThrow(TypeError);
    expect(client.sendCommand).not.toHaveBeenCalled();
  });

  it("reconnects on the first command after a completed connection later closes", async () => {
    let open = false;
    const client: RedisCommandClient = {
      get isOpen() {
        return open;
      },
      connect: vi.fn(async () => {
        open = true;
      }),
      sendCommand: vi.fn(async () => {
        if (!open) {
          throw new Error("closed");
        }
        return ["reserved", requestId];
      })
    };
    const store = new RedisDemoStore(client);

    await expect(store.reserve(reservationInput())).resolves.toMatchObject({
      status: "reserved"
    });
    open = false;
    await expect(store.reserve(reservationInput())).resolves.toMatchObject({
      status: "reserved"
    });
    expect(client.connect).toHaveBeenCalledTimes(2);
  });

  it("shares one connection attempt across concurrent initial commands", async () => {
    let open = false;
    let finishConnect: (() => void) | undefined;
    const client: RedisCommandClient = {
      get isOpen() {
        return open;
      },
      connect: vi.fn(
        () =>
          new Promise<void>((resolve) => {
            finishConnect = () => {
              open = true;
              resolve();
            };
          })
      ),
      sendCommand: vi.fn(async () => ["reserved", requestId])
    };
    const store = new RedisDemoStore(client);

    const first = store.reserve(reservationInput());
    const second = store.reserve(
      reservationInput({ submissionIdDigest: "d".repeat(64) })
    );
    expect(client.connect).toHaveBeenCalledOnce();
    finishConnect?.();
    await expect(Promise.all([first, second])).resolves.toHaveLength(2);
    expect(client.sendCommand).toHaveBeenCalledTimes(2);
  });

  it("aborts an unresponsive Redis command within the configured bound", async () => {
    const client: RedisCommandClient = {
      isOpen: true,
      connect: vi.fn(async () => undefined),
      sendCommand: vi.fn(
        async (_arguments, options) =>
          new Promise<never>((_resolve, reject) => {
            options?.abortSignal?.addEventListener(
              "abort",
              () => reject(new DOMException("aborted", "AbortError")),
              { once: true }
            );
          })
      )
    };
    const store = new RedisDemoStore(client, 5);

    await expect(store.reserve(reservationInput())).rejects.toThrow(
      "Demo request state is unavailable."
    );
  });
});

function reservationInput(
  overrides: Partial<Parameters<RedisDemoStore["reserve"]>[0]> = {}
): Parameters<RedisDemoStore["reserve"]>[0] {
  return {
    submissionIdDigest: "a".repeat(64),
    emailDigest: "b".repeat(64),
    payloadDigest,
    requestId,
    leaseToken: "lease-token",
    ...overrides
  };
}

function fakeClient(result: unknown): RedisCommandClient {
  return {
    isOpen: true,
    connect: vi.fn(async () => undefined),
    sendCommand: vi.fn(async () => result)
  };
}
