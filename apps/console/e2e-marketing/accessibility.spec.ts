import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

for (const path of ["/", "/en", "/privacy", "/en/privacy"] as const) {
  test(`axe WCAG 2.2 AA baseline: ${path}`, async ({ page }) => {
    await page.goto(path);
    await expectAxeWcag22Aa(page);
  });
}

for (const locale of [
  {
    path: "/",
    emailLabel: "Correo de trabajo",
    continueButton: "Continuar",
    submitButton: "Solicitar demo"
  },
  {
    path: "/en",
    emailLabel: "Work email",
    continueButton: "Continue",
    submitButton: "Request a demo"
  }
] as const) {
  test(`@form axe WCAG 2.2 AA enabled form states: ${locale.path}`, async ({
    page
  }) => {
    await page.goto(locale.path);
    await expect(page.locator('[data-demo-form-hydrated="true"]')).toBeVisible();
    await expectAxeWcag22Aa(page);

    await page.getByLabel(locale.emailLabel).fill("axe@example.invalid");
    await page.getByRole("button", { name: locale.continueButton }).click();
    await expectAxeWcag22Aa(page);

    await page.getByRole("button", { name: locale.submitButton }).click();
    await expectAxeWcag22Aa(page);
  });
}

async function expectAxeWcag22Aa(page: Page) {
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
}
