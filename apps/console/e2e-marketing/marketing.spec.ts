import { expect, test, type Page } from "@playwright/test";

const locales = [
  {
    path: "/",
    lang: "es",
    title: "La confianza no se asume. Se demuestra.",
    privacyPath: "/privacy",
    privacyTitle: "Aviso de privacidad",
    stopped: "Recorrido automático detenido"
  },
  {
    path: "/en",
    lang: "en",
    title: "Trust isn’t assumed. It’s proven.",
    privacyPath: "/en/privacy",
    privacyTitle: "Privacy notice",
    stopped: "Automatic tour stopped"
  }
] as const;

for (const locale of locales) {
  test(`${locale.lang} landing preserves content, navigation, and public routes`, async ({
    page
  }) => {
    const browserErrors = collectBrowserErrors(page);
    await page.goto(locale.path);
    await expect(page.locator("html")).toHaveAttribute("lang", locale.lang);
    await expect(page.getByRole("heading", { level: 1, name: locale.title })).toBeVisible();
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("#platform")).toBeVisible();
    await expect(page.locator("#how-it-works")).toBeVisible();
    await expect(page.locator("#security")).toBeVisible();
    await expect(page.locator("#faq")).toBeVisible();
    await assertNoHorizontalOverflow(page);

    await page.goto(locale.privacyPath);
    await expect(page.locator("html")).toHaveAttribute("lang", locale.lang);
    await expect(page.getByRole("heading", { level: 1, name: locale.privacyTitle })).toBeVisible();
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute(
      "content",
      /noindex\s*,\s*follow/iu
    );
    await assertNoHorizontalOverflow(page);
    expect(browserErrors).toEqual([]);
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

for (const locale of locales) {
  test(`${locale.lang} tour supports arrow keys and stops after interaction`, async ({ page }) => {
    await page.goto(locale.path);
    const tabs = page.getByRole("tab");
    await expect(tabs).toHaveCount(4);
    await tabs.first().focus();
    await page.keyboard.press("ArrowRight");
    await expect(tabs.nth(1)).toBeFocused();
    await expect(tabs.nth(1)).toHaveAttribute("aria-selected", "true");
    await expect(page.getByText(locale.stopped, { exact: true })).toBeVisible();
  });
}

for (const locale of locales) {
  test(`${locale.lang} reduced motion disables CSS motion and tour cycling`, async ({
    page
  }, testInfo) => {
    test.skip(!testInfo.project.name.endsWith("desktop-1440"));
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(locale.path);
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
    const firstTab = page.getByRole("tab").first();
    await expect(firstTab).toHaveAttribute("aria-selected", "true");
    await expect(page.getByText(locale.stopped, { exact: true })).toBeVisible();
    await page.waitForTimeout(6_750);
    await expect(firstTab).toHaveAttribute("aria-selected", "true");
  });
}

for (const locale of locales) {
  test(`${locale.lang} Chromium 200% scale equivalence reflows without overflow (not browser UI zoom)`, async ({
    browser
  }, testInfo) => {
    test.skip(
      testInfo.project.name !== "chromium-desktop-1440",
      "Playwright deviceScaleFactor is reproducible here only in Chromium; this is not native browser UI zoom."
    );
    testInfo.annotations.push({
      type: "limitation",
      description:
        "Chromium deviceScaleFactor 2 laboratory equivalence; not native browser UI zoom or a cross-engine zoom claim."
    });
    const baseURL = testInfo.project.use.baseURL;
    if (typeof baseURL !== "string") throw new Error("Marketing E2E baseURL is unavailable.");
    const context = await browser.newContext({
      baseURL,
      viewport: { width: 720, height: 500 },
      deviceScaleFactor: 2,
      colorScheme: "dark",
      locale: "es-PA"
    });
    try {
      const scaledPage = await context.newPage();
      await scaledPage.goto(locale.path);
      const scale = await scaledPage.evaluate(() => ({
        cssWidth: window.innerWidth,
        deviceScaleFactor: window.devicePixelRatio,
        physicalWidth: window.innerWidth * window.devicePixelRatio
      }));
      expect(scale).toEqual({ cssWidth: 720, deviceScaleFactor: 2, physicalWidth: 1440 });
      await assertNoHorizontalOverflow(scaledPage);
      await expect(scaledPage.getByRole("heading", { level: 1 })).toBeVisible();

      await scaledPage.keyboard.press("Tab");
      const skipLink = scaledPage.getByRole("link", {
        name: /saltar al contenido principal|skip to main content/iu
      });
      await expect(skipLink).toBeFocused();
      const focusBounds = await skipLink.boundingBox();
      expect(focusBounds).not.toBeNull();
      expect(focusBounds?.x ?? -1).toBeGreaterThanOrEqual(0);
      expect((focusBounds?.x ?? 721) + (focusBounds?.width ?? 0)).toBeLessThanOrEqual(720);
      await skipLink.press("Enter");
      await expect(scaledPage.locator("main")).toBeFocused();
    } finally {
      await context.close();
    }
  });
}

async function assertNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => {
    const root = document.documentElement;
    const body = document.body;
    const scroller = document.scrollingElement;
    const initialScrollLeft = scroller?.scrollLeft ?? 0;
    if (scroller !== null) scroller.scrollLeft = 1;
    const horizontalScrollProbe = scroller?.scrollLeft ?? 0;
    if (scroller !== null) scroller.scrollLeft = initialScrollLeft;
    const minimumClientWidth = Math.min(root.clientWidth, body.clientWidth);
    const overflowingElements = Array.from(body.querySelectorAll("*"))
      .filter((element) => {
        const bounds = element.getBoundingClientRect();
        if (bounds.left >= -1 && bounds.right <= minimumClientWidth + 1) return false;
        let ancestor = element.parentElement;
        while (ancestor !== null && ancestor !== body) {
          const overflowX = getComputedStyle(ancestor).overflowX;
          if (["auto", "hidden", "scroll", "clip"].includes(overflowX)) return false;
          ancestor = ancestor.parentElement;
        }
        return true;
      })
      .slice(0, 10)
      .map((element) => {
        const bounds = element.getBoundingClientRect();
        return {
          tag: element.tagName.toLowerCase(),
          id: element.id,
          left: bounds.left,
          right: bounds.right
        };
      });
    return {
      minimumClientWidth,
      maximumScrollWidth: Math.max(
        root.scrollWidth,
        body.scrollWidth,
        scroller?.scrollWidth ?? 0
      ),
      documentClientWidth: root.clientWidth,
      documentScrollWidth: root.scrollWidth,
      documentScrollLeft: root.scrollLeft,
      bodyClientWidth: body.clientWidth,
      bodyScrollWidth: body.scrollWidth,
      bodyScrollLeft: body.scrollLeft,
      scrollingElementScrollLeft: initialScrollLeft,
      horizontalScrollProbe,
      bodyMinimumWidth: Number.parseFloat(getComputedStyle(body).minWidth) || 0,
      viewportWidth: window.innerWidth,
      hasVerticalScroll: root.scrollHeight > root.clientHeight,
      overflowingElements
    };
  });
  expect(
    dimensions.maximumScrollWidth,
    `Horizontal overflow metrics: ${JSON.stringify(dimensions)}`
  ).toBeLessThanOrEqual(dimensions.minimumClientWidth + 1);
  expect(dimensions.horizontalScrollProbe, JSON.stringify(dimensions)).toBe(0);
  expect(dimensions.overflowingElements, JSON.stringify(dimensions)).toEqual([]);
  if (dimensions.hasVerticalScroll && dimensions.bodyMinimumWidth > 0) {
    expect(
      dimensions.bodyMinimumWidth,
      `The body minimum width must leave room for a classic 15px scrollbar: ${JSON.stringify(dimensions)}`
    ).toBeLessThanOrEqual(dimensions.viewportWidth - 15);
  }
}

function collectBrowserErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(`console.error: ${message.text()}`);
  });
  return errors;
}
