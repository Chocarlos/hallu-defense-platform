import { afterEach, describe, expect, it, vi } from "vitest";

describe("demo request route bootstrap", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("fails while loading when production enables capture without launch secrets", async () => {
    vi.stubEnv("HALLU_DEFENSE_ENV", "production");
    vi.stubEnv("HALLU_DEFENSE_DEMO_REQUESTS_ENABLED", "true");

    await expect(import("./route")).rejects.toThrow(
      "Demo request runtime configuration is invalid."
    );
  });
});
