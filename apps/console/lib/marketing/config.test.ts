import { describe, expect, it } from "vitest";

import { loadMarketingPublicConfig, resolveMarketingOrigin } from "./config";

describe("public marketing config", () => {
  it("renders safely when the console and demo environment are absent", () => {
    expect(loadMarketingPublicConfig({})).toEqual({
      demoRequestsEnabled: false,
      privacyContactEmail: null,
      siteOrigin: "http://localhost:3000"
    });
  });

  it("enables demo requests only for the exact public flag", () => {
    expect(loadMarketingPublicConfig({ HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "true" }).demoRequestsEnabled).toBe(true);
    expect(loadMarketingPublicConfig({ HALLU_DEFENSE_DEMO_REQUESTS_ENABLED: "TRUE" }).demoRequestsEnabled).toBe(false);
  });

  it("accepts only a bare HTTP(S) origin and a plausible contact email", () => {
    expect(resolveMarketingOrigin("https://hallu.example")).toBe("https://hallu.example");
    expect(resolveMarketingOrigin("https://user:hush@hallu.example/path")).toBe("http://localhost:3000");
    expect(loadMarketingPublicConfig({ HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "not-an-email" }).privacyContactEmail).toBeNull();
    expect(loadMarketingPublicConfig({ HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL: "privacy@hallu.example" }).privacyContactEmail).toBe("privacy@hallu.example");
  });
});
