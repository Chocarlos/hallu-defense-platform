import { expect, test, type Page } from "@playwright/test";

const locales = [
  {
    path: "/",
    lang: "es",
    title: "La confianza no se asume. Se demuestra.",
    privacyPath: "/privacy",
    privacyTitle: "Aviso de privacidad",
    disabled: "Las solicitudes de demo están desactivadas"
  },
  {
    path: "/en",
    lang: "en",
    title: "Trust isn’t assumed. It’s proven.",
    privacyPath: "/en/privacy",
    privacyTitle: "Privacy notice",
    disabled: "Demo requests are disabled"
  }
] as const;

for (const locale of locales) {
  test(`${locale.lang} landing preserves content, navigation, and disabled intake`, async ({
    page
  }) => {
    await page.goto(locale.path);
    await expect(page.locator("html")).toHaveAttribute("lang", locale.lang);
    await expect(page.getByRole("heading", { level: 1, name: locale.title })).toBeVisible();
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("#platform")).toBeVisible();
    await expect(page.locator("#how-it-works")).toBeVisible();
    await expect(page.locator("#security")).toBeVisible();
    await expect(page.locator("#faq")).toBeVisible();
    await expect(page.getByText(locale.disabled, { exact: false })).toBeVisible();
    await assertNoHorizontalOverflow(page);

    await page.goto(locale.privacyPath);
    await expect(page.locator("html")).toHaveAttribute("lang", locale.lang);
    await expect(page.getByRole("heading", { level: 1, name: locale.privacyTitle })).toBeVisible();
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
      "content",
      /noindex\s*,\s*follow/iu
    );
    await assertNoHorizontalOverflow(page);
  });
}

test("language switch and Console link preserve their public routes", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: /sitio en inglés/iu })).toHaveAttribute(
    "href",
    "/en"
  );
  await expect(page.getByRole("link", { name: /consola/iu }).first()).toHaveAttribute(
    "href",
    "/console"
  );
  await page.goto("/console");
  await expect(page).toHaveURL(/\/console$/u);
  await expect(page.locator("main")).toBeVisible();
});

test("tour is keyboard-operable and user interaction stops automatic cycling", async ({
  page
}) => {
  await page.goto("/");
  const tabs = page.getByRole("tab");
  await expect(tabs).toHaveCount(4);
  await tabs.last().focus();
  await page.keyboard.press("Enter");
  await expect(tabs.last()).toHaveAttribute("aria-selected", "true");
  await expect(
    page.getByText(/Recorrido automático detenido|Automatic tour stopped/iu)
  ).toBeVisible();
});

test("reduced motion disables active CSS animation and transition durations", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  const activeMotion = await page.locator("body *").evaluateAll((elements) =>
    elements
      .map((element) => {
        const style = getComputedStyle(element);
        return {
          animation: style.animationDuration,
          transition: style.transitionDuration
        };
      })
      .filter(({ animation, transition }) =>
        [...animation.split(","), ...transition.split(",")].some(
          (duration) => Number.parseFloat(duration) > 0
        )
      )
  );
  expect(activeMotion).toEqual([]);
});

test("synthetic 200% zoom viewport has no horizontal overflow", async ({ page }, testInfo) => {
  test.skip(!testInfo.project.name.endsWith("desktop-1440"));
  await page.setViewportSize({ width: 720, height: 500 });
  await page.goto("/");
  await assertNoHorizontalOverflow(page);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
});

async function assertNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
}
