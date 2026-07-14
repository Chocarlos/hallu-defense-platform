import { describe, expect, it } from "vitest";

import {
  DEMO_USE_CASES,
  MARKETING_LOCALES,
  MARKETING_SECTION_IDS,
  SDK_SNIPPETS,
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
    expect(Object.keys(marketingContent.es.hero.system)).toEqual(
      Object.keys(marketingContent.en.hero.system)
    );
    expect(Object.keys(marketingContent.es.demo)).toEqual(
      Object.keys(marketingContent.en.demo)
    );
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
    expect(SDK_SNIPPETS.es).toContain('import { HalluDefenseClient } from "@hallu-defense/sdk";');
    expect(SDK_SNIPPETS.en).toContain("client.runVerification");
    expect(SDK_SNIPPETS.es).toContain("La política interna permite esta acción.");
    expect(SDK_SNIPPETS.en).toContain("The internal policy allows this action.");
    expect(SDK_SNIPPETS.en).not.toContain("La política interna");
    expect(DEMO_USE_CASES).toContain("code_agents");
    expect(DEMO_USE_CASES).not.toContain("code_evidence");
  });

  it("keeps legal status provisional and expresses CRM retention as an operator duty", () => {
    expect(marketingContent.es.privacy.sections[0]?.title.toLowerCase()).toContain("provisional");
    expect(marketingContent.en.privacy.sections[0]?.title.toLowerCase()).toContain("provisional");
    expect(marketingContent.es.footer.launchNoteEnabled).toContain("debe eliminar");
    expect(marketingContent.en.footer.launchNoteEnabled).toContain("must delete");
    expect(marketingContent.es.privacy.sections[3]?.body).toContain("hasta 24 horas");
    expect(marketingContent.en.privacy.sections[3]?.body).toContain("up to 24 hours");
  });
});
