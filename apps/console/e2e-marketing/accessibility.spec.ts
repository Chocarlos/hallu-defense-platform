import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

for (const path of ["/", "/en", "/privacy", "/en/privacy"] as const) {
  test(`axe WCAG 2.2 AA baseline: ${path}`, async ({ page }) => {
    await page.goto(path);
    const results = await new AxeBuilder({ page })
      .options({
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]
        },
        rules: { "target-size": { enabled: true } }
      })
      .analyze();
    expect(results.violations).toEqual([]);
    expect(
      [
        ...results.passes,
        ...results.incomplete,
        ...results.inapplicable,
        ...results.violations
      ].some(({ id }) => id === "target-size")
    ).toBe(true);
  });
}
