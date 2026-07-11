import { describe, expect, it, vi } from "vitest";
import { createRequestCoordinator } from "./request-coordinator";

describe("request coordinator", () => {
  it("prevents a slow request from overwriting a newer response", async () => {
    const coordinator = createRequestCoordinator();
    let resolveSlow: ((value: string) => void) | undefined;
    const slow = new Promise<string>((resolve) => {
      resolveSlow = resolve;
    });
    const first = coordinator.run("history", "page-a", async () => slow);
    const second = coordinator.run("history", "page-b", async () => "new");
    resolveSlow?.("old");

    await expect(second).resolves.toEqual({ kind: "current", value: "new" });
    await expect(first).resolves.toEqual({ kind: "superseded" });
  });

  it("deduplicates identical requests already in flight", async () => {
    const coordinator = createRequestCoordinator();
    const request = vi.fn(async () => "value");
    const first = coordinator.run("grants", "first-page", request);
    const second = coordinator.run("grants", "first-page", request);

    expect(second).toBe(first);
    await expect(first).resolves.toEqual({ kind: "current", value: "value" });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("absorbs an SDK abort timeout only when its coordinator signal was aborted", async () => {
    const coordinator = createRequestCoordinator();
    let rejectRequest: ((error: unknown) => void) | undefined;
    const pending = coordinator.run(
      "evals",
      "first-page",
      async () =>
        new Promise<string>((_resolve, reject) => {
          rejectRequest = reject;
        })
    );
    coordinator.abort("evals");
    rejectRequest?.(Object.assign(new Error("secret timeout"), { status: 408 }));
    await expect(pending).resolves.toEqual({ kind: "superseded" });

    await expect(
      coordinator.run("evals", "retry", async () => {
        throw Object.assign(new Error("genuine timeout"), { status: 408 });
      })
    ).rejects.toMatchObject({ status: 408 });
  });

  it("preserves synchronous errors and permits a retry with the same fingerprint", async () => {
    const coordinator = createRequestCoordinator();
    const failure = Object.assign(new Error("synchronous failure"), { status: 500 });
    const request = vi
      .fn<(signal: AbortSignal) => Promise<string>>()
      .mockImplementationOnce(() => {
        throw failure;
      })
      .mockResolvedValueOnce("recovered");

    await expect(coordinator.run("history", "page-a", request)).rejects.toBe(failure);
    await expect(coordinator.run("history", "page-a", request)).resolves.toEqual({
      kind: "current",
      value: "recovered"
    });
    expect(request).toHaveBeenCalledTimes(2);
  });
});
