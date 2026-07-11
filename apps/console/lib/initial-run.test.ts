import { describe, expect, it } from "vitest";

import { loadInitialVerificationRun } from "./initial-run";
import { ConsoleRuntimeConfigError, loadConsoleRuntimeConfig } from "./runtime-config";

const productionOidcEnvironment = {
  HALLU_DEFENSE_ENV: "production",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "oidc",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
  HALLU_DEFENSE_CONSOLE_OIDC_ISSUER: "https://identity.example.test/realms/hallu",
  HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID: "hallu-defense-console",
  HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE: "hallu-defense-api",
  HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES: "verifier,approval_reviewer"
} as const;

const localUnsignedEnvironment = {
  HALLU_DEFENSE_ENV: "test",
  HALLU_DEFENSE_CONSOLE_AUTH_MODE: "unsigned-local",
  HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "http://127.0.0.1:3100",
  HALLU_DEFENSE_CONSOLE_API_ORIGIN: "http://127.0.0.1:18100",
  HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "true",
  HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL: "true",
  HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID: "tenant-a",
  HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID: "console-reviewer",
  HALLU_DEFENSE_CONSOLE_LOCAL_ROLES: "verifier"
} as const;

describe("initial verification run", () => {
  it("is empty in production OIDC and never exposes tr_demo", async () => {
    const config = loadConsoleRuntimeConfig(productionOidcEnvironment);

    const initialRun = await loadInitialVerificationRun(config);

    expect(initialRun).toBeNull();
    expect(JSON.stringify(initialRun)).not.toContain("tr_demo");
  });

  it("is empty locally unless the demo fixture flag is explicit", async () => {
    const config = loadConsoleRuntimeConfig(localUnsignedEnvironment);

    expect(await loadInitialVerificationRun(config)).toBeNull();
  });

  it("loads tr_demo only for an explicit unsigned loopback fixture", async () => {
    const config = loadConsoleRuntimeConfig({
      ...localUnsignedEnvironment,
      HALLU_DEFENSE_CONSOLE_DEMO_FIXTURE_ENABLED: "true"
    });

    expect((await loadInitialVerificationRun(config))?.trace_id).toBe("tr_demo");
  });

  it("rejects the demo fixture outside loopback even in local mode", () => {
    expect(() =>
      loadConsoleRuntimeConfig({
        ...localUnsignedEnvironment,
        HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN: "https://console.example.test",
        HALLU_DEFENSE_CONSOLE_API_ORIGIN: "https://api.example.test",
        HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP: "false",
        HALLU_DEFENSE_CONSOLE_DEMO_FIXTURE_ENABLED: "true"
      })
    ).toThrow(ConsoleRuntimeConfigError);
  });
});
