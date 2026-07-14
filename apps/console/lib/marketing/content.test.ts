import { describe, expect, it } from "vitest";

import {
  DEMO_USE_CASES,
  MARKETING_LOCALES,
  MARKETING_SECTION_IDS,
  SDK_SNIPPET,
  marketingContent
} from "./content";

describe("marketing content", () => {
  it("keeps the two dictionaries structurally aligned", () => {
    expect(MARKETING_LOCALES).toEqual(["es", "en"]);
    expect(Object.keys(marketingContent.es)).toEqual(Object.keys(marketingContent.en));
    expect(marketingContent.es.tour.steps.map(({ key }) => key)).toEqual(
      marketingContent.en.tour.steps.map(({ key }) => key)
    );
    expect(marketingContent.es.workflow.steps).toHaveLength(marketingContent.en.workflow.steps.length);
    expect(marketingContent.es.surfaces.items).toHaveLength(marketingContent.en.surfaces.items.length);
  });

  it("preserves the approved headlines and public anchors", () => {
    expect(marketingContent.es.hero.title).toBe("La confianza no se asume. Se demuestra.");
    expect(marketingContent.en.hero.title).toBe("Trust isn’t assumed. It’s proven.");
    expect(marketingContent.es.navigation.items.map(({ id }) => id)).toEqual(
      MARKETING_SECTION_IDS.filter((id) => id !== "demo")
    );
    expect(new Set(MARKETING_SECTION_IDS).size).toBe(MARKETING_SECTION_IDS.length);
  });

  it("keeps all scenarios explicitly illustrative and exactly five FAQs per locale", () => {
    for (const locale of MARKETING_LOCALES) {
      const copy = marketingContent[locale];
      expect(copy.scenarios.items).toHaveLength(3);
      expect(copy.scenarios.illustrativeLabel.length).toBeGreaterThan(0);
      expect(copy.faq.items).toHaveLength(5);
    }
  });

  it("uses the real SDK surface and the shared demo enum", () => {
    expect(SDK_SNIPPET).toContain('import { HalluDefenseClient } from "@hallu-defense/sdk";');
    expect(SDK_SNIPPET).toContain("client.runVerification");
    expect(DEMO_USE_CASES).toContain("code_agents");
    expect(DEMO_USE_CASES).not.toContain("code_evidence");
  });
});
