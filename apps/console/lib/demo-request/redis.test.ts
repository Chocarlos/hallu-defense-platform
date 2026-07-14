import { describe, expect, it, vi } from "vitest";

import {
  FINALIZE_SCRIPT,
  RELEASE_SCRIPT,
  RESERVE_SCRIPT,
  RedisDemoStore,
  type RedisCommandClient
} from "./redis";

const requestId = `dr_${"A".repeat(24)}`;

describe("Redis demo request state", () => {
  it("reserves global, email-digest, and idempotency keys in one Lua operation", async () => {
    const client = fakeClient(["reserved", requestId]);
    const store = new RedisDemoStore(client);
    const emailDigest = "b".repeat(64);

    await expect(
      store.reserve({
        submissionIdDigest: "a".repeat(64),
        emailDigest,
        requestId,
        leaseToken: "lease-token",
        nowMilliseconds: 1_000
      })
    ).resolves.toEqual({ status: "reserved", requestId });

    const command = vi.mocked(client.sendCommand).mock.calls[0]?.[0];
    expect(command?.slice(0, 3)).toEqual(["EVAL", RESERVE_SCRIPT, "3"]);
    expect(command?.join(" ")).toContain(`:email:${emailDigest}`);
    expect(command?.join(" ")).not.toContain("person@example.invalid");
    expect(RESERVE_SCRIPT.indexOf("HMGET")).toBeLessThan(RESERVE_SCRIPT.indexOf("INCR"));
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
    ["rate_global", ""],
    ["rate_email", ""]
  ])("parses the bounded Redis result %s", async (status, id) => {
    const store = new RedisDemoStore(fakeClient([status, id]));
    await expect(
      store.reserve({
        submissionIdDigest: "a".repeat(64),
        emailDigest: "b".repeat(64),
        requestId,
        leaseToken: "lease-token",
        nowMilliseconds: 1_000
      })
    ).resolves.toEqual(id === "" ? { status } : { status, requestId });
  });

  it("fails closed on malformed protocol responses", async () => {
    const store = new RedisDemoStore(fakeClient(["reserved", "email@example.invalid"]));
    await expect(
      store.reserve({
        submissionIdDigest: "a".repeat(64),
        emailDigest: "b".repeat(64),
        requestId,
        leaseToken: "lease-token",
        nowMilliseconds: 1_000
      })
    ).rejects.toThrow("unavailable");
  });
});

function fakeClient(result: unknown): RedisCommandClient {
  return {
    isOpen: true,
    connect: vi.fn(async () => undefined),
    sendCommand: vi.fn(async () => result)
  };
}

