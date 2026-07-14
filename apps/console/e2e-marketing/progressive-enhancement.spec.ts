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
    test(`@form ${locale.path} ${trigger} cannot transmit form PII without JavaScript`, async ({
      page
    }) => {
      const email = `${trigger}-nojs@example.invalid`;
      await page.goto(locale.path);
      const emailInput = page.getByLabel(locale.emailLabel);
      const continueButton = page.getByRole("button", { name: locale.continueButton });
      const inputWasEnabled = await emailInput.isEnabled();
      const buttonWasEnabled = await continueButton.isEnabled();
      const leakingChannels: string[] = [];
      await page.route("**/*", async (route) => {
        const request = route.request();
        if (containsEncodedValue(request.url(), email)) leakingChannels.push("url");
        if (
          containsEncodedValue(
            Object.entries(request.headers()).flat().join("\n"),
            email
          )
        ) {
          leakingChannels.push("headers");
        }
        if (containsEncodedValue(request.postData() ?? "", email)) {
          leakingChannels.push("body");
        }
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
          await route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html>" });
          return;
        }
        await route.continue();
      });
      if (inputWasEnabled && buttonWasEnabled) {
        await emailInput.fill(email);
        const navigation = page
          .waitForNavigation({ waitUntil: "commit", timeout: 750 })
          .catch(() => null);
        if (trigger === "enter") {
          await emailInput.press("Enter");
        } else {
          await continueButton.click();
        }
        await navigation;
      }
      expect(inputWasEnabled).toBe(false);
      expect(buttonWasEnabled).toBe(false);
      expect(leakingChannels).toEqual([]);
      expect(decodeURIComponent(new URL(page.url()).search)).not.toContain(email);
    });
  }
}

function containsEncodedValue(value: string, expected: string): boolean {
  if (value.includes(expected)) return true;
  try {
    return decodeURIComponent(value).includes(expected);
  } catch {
    return false;
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
