import { expect, test, type Page } from "@playwright/test";

const budgets = {
  lcpMilliseconds: 2_500,
  syntheticInpMilliseconds: 200,
  cls: 0.1
} as const;

type LabMetrics = {
  lcpMilliseconds: number | null;
  cls: number;
  maximumInteractionDuration: number | null;
  interactionCount: number;
  supportedEntryTypes: string[];
};

test.beforeEach(async ({}, testInfo) => {
  test.skip(
    testInfo.project.name !== "chromium-desktop-1440",
    "Synthetic performance budgets run once in desktop Chromium, not across the compatibility matrix."
  );
});

for (const path of ["/", "/en"] as const) {
  test(`@lab-performance ${path} stays within synthetic LCP, INP, and CLS budgets`, async ({
    page
  }) => {
    await installLabObservers(page);
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(500);

    const secondTourTab = page.getByRole("tab").nth(1);
    await secondTourTab.click();
    await expect(secondTourTab).toHaveAttribute("aria-selected", "true");
    await page.waitForTimeout(250);

    const metrics = await readLabMetrics(page);
    expect(metrics.supportedEntryTypes, JSON.stringify(metrics)).toEqual(
      expect.arrayContaining(["largest-contentful-paint", "layout-shift", "event"])
    );
    expect(metrics.lcpMilliseconds, JSON.stringify(metrics)).not.toBeNull();
    expect(metrics.lcpMilliseconds ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(
      budgets.lcpMilliseconds
    );
    expect(metrics.interactionCount, JSON.stringify(metrics)).toBeGreaterThan(0);
    expect(metrics.maximumInteractionDuration, JSON.stringify(metrics)).not.toBeNull();
    expect(metrics.maximumInteractionDuration ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(
      budgets.syntheticInpMilliseconds
    );
    expect(metrics.cls, JSON.stringify(metrics)).toBeLessThanOrEqual(budgets.cls);
  });
}

test("@lab-performance replaced visual resources reserve layout dimensions", async ({ page }) => {
  await page.goto("/");
  const unreservedResources = await page.locator("img, video, iframe").evaluateAll((elements) =>
    elements.flatMap((element) => {
      const style = getComputedStyle(element);
      const width = Number.parseFloat(element.getAttribute("width") ?? "");
      const height = Number.parseFloat(element.getAttribute("height") ?? "");
      const hasIntrinsicDimensions = width > 0 && height > 0;
      const hasCssReservation = style.aspectRatio !== "auto";
      return hasIntrinsicDimensions || hasCssReservation
        ? []
        : [
            {
              tag: element.tagName.toLowerCase(),
              source: element.getAttribute("src") ?? "",
              aspectRatio: style.aspectRatio
            }
          ];
    })
  );
  expect(unreservedResources).toEqual([]);
});

async function installLabObservers(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const supportedEntryTypes = [...PerformanceObserver.supportedEntryTypes];
    const metrics: LabMetrics = {
      lcpMilliseconds: null,
      cls: 0,
      maximumInteractionDuration: null,
      interactionCount: 0,
      supportedEntryTypes
    };
    const interactions = new Map<number, number>();
    let clsSessionStart = 0;
    let clsSessionLast = 0;
    let clsSessionValue = 0;

    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) metrics.lcpMilliseconds = entry.startTime;
    }).observe({ type: "largest-contentful-paint", buffered: true });

    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const shift = entry as PerformanceEntry & { hadRecentInput: boolean; value: number };
        if (shift.hadRecentInput) continue;
        if (
          clsSessionStart === 0 ||
          shift.startTime - clsSessionLast > 1_000 ||
          shift.startTime - clsSessionStart > 5_000
        ) {
          clsSessionStart = shift.startTime;
          clsSessionValue = shift.value;
        } else {
          clsSessionValue += shift.value;
        }
        clsSessionLast = shift.startTime;
        metrics.cls = Math.max(metrics.cls, clsSessionValue);
      }
    }).observe({ type: "layout-shift", buffered: true });

    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const event = entry as PerformanceEntry & { duration: number; interactionId: number };
        if (event.interactionId === 0) continue;
        interactions.set(
          event.interactionId,
          Math.max(interactions.get(event.interactionId) ?? 0, event.duration)
        );
      }
      metrics.interactionCount = interactions.size;
      metrics.maximumInteractionDuration =
        interactions.size === 0 ? null : Math.max(...interactions.values());
    }).observe({
      type: "event",
      buffered: true,
      durationThreshold: 16
    } as PerformanceObserverInit & { durationThreshold: number });

    (window as typeof window & { __halluPerformanceLab: LabMetrics }).__halluPerformanceLab =
      metrics;
  });
}

async function readLabMetrics(page: Page): Promise<LabMetrics> {
  return page.evaluate(
    () =>
      (window as typeof window & { __halluPerformanceLab: LabMetrics })
        .__halluPerformanceLab
  );
}
