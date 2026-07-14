import { describe, expect, it, vi } from "vitest";

import {
  FINALIZE_SCRIPT,
  RELEASE_SCRIPT,
  RESERVE_SCRIPT,
  RedisDemoStore,
  type RedisCommandClient
} from "./redis";

const requestId = `dr_${"A".repeat(24)}`;
const payloadDigest = "c".repeat(64);

describe("Redis demo request state", () => {
  it("reserves global, email-digest, and idempotency keys in one Lua operation", async () => {
    const client = fakeClient(["reserved", requestId]);
    const store = new RedisDemoStore(client);
    const emailDigest = "b".repeat(64);

    await expect(
      store.reserve(reservationInput({ emailDigest }))
    ).resolves.toEqual({ status: "reserved", requestId });

    const command = vi.mocked(client.sendCommand).mock.calls[0]?.[0];
    expect(command?.slice(0, 3)).toEqual(["EVAL", RESERVE_SCRIPT, "3"]);
    expect(command?.join(" ")).toContain(`:email:${emailDigest}`);
    expect(command?.join(" ")).not.toContain("person@example.invalid");
    expect(command?.slice(6)).toEqual([
      "60",
      "60000",
      "3",
      "3600000",
      "86400000",
      "lease-token",
      "15000",
      requestId,
      payloadDigest
    ]);
    expect(RESERVE_SCRIPT.indexOf("INCR', KEYS[1]")).toBeLessThan(
      RESERVE_SCRIPT.indexOf("HMGET")
    );
    expect(RESERVE_SCRIPT).toContain("redis.call('TIME')");
    expect(RESERVE_SCRIPT).toContain("'payload_digest', ARGV[9]");
    expect(RESERVE_SCRIPT).toContain("state[4] ~= ARGV[9]");
    expect(RESERVE_SCRIPT).toContain("PEXPIRE");
  });

  it("uses compare-and-set Lua operations for finalize and release", async () => {
    const client = fakeClient(1);
    const store = new RedisDemoStore(client);
    await expect(store.finalize("a".repeat(64), "lease-token")).resolves.toBe(true);
    await expect(store.release("a".repeat(64), "lease-token")).resolves.toBe(true);

    expect(vi.mocked(client.sendCommand).mock.calls[0]?.[0]?.[1]).toBe(FINALIZE_SCRIPT);
    expect(vi.mocked(client.sendCommand).mock.calls[1]?.[0]?.[1]).toBe(RELEASE_SCRIPT);
    expect(FINALIZE_SCRIPT).toContain("lease_token");
    expect(RELEASE_SCRIPT).toContain("retryable");
  });

  it.each([
    ["duplicate", requestId],
    ["pending", requestId],
    ["conflict", ""],
    ["rate_global", ""],
    ["rate_email", ""]
  ])("parses the bounded Redis result %s", async (status, id) => {
    const store = new RedisDemoStore(fakeClient([status, id]));
    await expect(
      store.reserve(reservationInput())
    ).resolves.toEqual(id === "" ? { status } : { status, requestId });
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

