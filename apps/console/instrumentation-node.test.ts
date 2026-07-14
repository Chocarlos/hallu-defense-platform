import { describe, expect, it } from "vitest";

import { validateServerStartup } from "./instrumentation-node";
import { DemoConfigurationError } from "./lib/demo-request/config";

describe("Console server startup validation", () => {
  it("allows the explicitly disabled intake without authenticated settings", () => {
    expect(() =>
      validateServerStartup({
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "false"
      })
    ).not.toThrow();
  });

  it("fails server startup when production intake is enabled without secrets", () => {
    expect(() =>
      validateServerStartup({
        HALLU_DEFENSE_ENV: "production",
        HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true"
      })
    ).toThrow(DemoConfigurationError);
  });
});
