import type { VerificationRun } from "@hallu-defense/contracts";

import type { ConsoleRuntimeConfig } from "./runtime-config";

export async function loadInitialVerificationRun(
  config: ConsoleRuntimeConfig
): Promise<VerificationRun | null> {
  if (!config.demoFixtureEnabled) {
    return null;
  }

  // Keep the fixture out of the production/OIDC execution path entirely.
  const { demoRun } = await import("./demo-run");
  return demoRun;
}
