import { expect, test, type Page } from "@playwright/test";

const locales = [
  { path: "/", emailLabel: "Correo de trabajo", continueButton: "Continuar" },
  { path: "/en", emailLabel: "Work email", continueButton: "Continue" }
] as const;

test.use({
  javaScriptEnabled: false,
  contextOptions: { reducedMotion: "no-preference" }
});

test.beforeEach(async ({}, testInfo) => {
  test.skip(
    testInfo.project.name !== "chromium-desktop-1440",
    "One no-JavaScript Chromium project is sufficient for progressive enhancement."
  );
});

for (const locale of locales) {
  test(`${locale.path} keeps primary content perceptible without JavaScript`, async ({ page }) => {
    await page.goto(locale.path);
    await expect(page.locator("main")).toBeVisible();
    for (const selector of ["#platform", "#how-it-works", "#security", "#demo", "#faq"]) {
      const section = page.locator(selector);
      await expect(section).toBeVisible();
      expect(await hasNoTransparentContent(section)).toBe(true);
    }
  });

  for (const trigger of ["enter", "button"] as const) {
    test(`@form ${locale.path} ${trigger} cannot place form PII in a no-JavaScript URL`, async ({
      page
    }) => {
      const email = `${trigger}-nojs@example.invalid`;
      await page.goto(locale.path);
      await page.getByLabel(locale.emailLabel).fill(email);
      const leakingRequests: string[] = [];
      await page.route("**/*", async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        if (decodeURIComponent(url.search).includes(email)) leakingRequests.push(request.url());
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
          await route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html>" });
          return;
        }
        await route.continue();
      });
      const navigation = page.waitForNavigation({ waitUntil: "commit", timeout: 750 }).catch(
        () => null
      );
      if (trigger === "enter") {
        await page.getByLabel(locale.emailLabel).press("Enter");
      } else {
        await page.getByRole("button", { name: locale.continueButton }).click();
      }
      await navigation;
      expect(leakingRequests).toEqual([]);
      expect(decodeURIComponent(new URL(page.url()).search)).not.toContain(email);
    });
  }
}

async function hasNoTransparentContent(locator: ReturnType<Page["locator"]>): Promise<boolean> {
  return locator.evaluate((element) => {
    let current: Element | null = element;
    while (current !== null) {
      if (Number.parseFloat(getComputedStyle(current).opacity) === 0) return false;
      current = current.parentElement;
    }
    return Array.from(element.querySelectorAll("*")).every(
      (descendant) => Number.parseFloat(getComputedStyle(descendant).opacity) !== 0
    );
  });
}
