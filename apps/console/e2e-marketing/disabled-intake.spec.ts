import { expect, test } from "@playwright/test";

for (const locale of [
  {
    path: "/",
    disabled: "Las solicitudes de demo están desactivadas"
  },
  {
    path: "/en",
    disabled: "Demo requests are disabled"
  }
] as const) {
  test(`@disabled ${locale.path} renders an inert intake state`, async ({ page }) => {
    const demoRequests: string[] = [];
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/demo-request") {
        demoRequests.push(request.url());
      }
    });
    await page.goto(locale.path);
    await expect(page.getByText(locale.disabled, { exact: false })).toBeVisible();
    await expect(page.locator('input[type="email"]')).toHaveCount(0);
    expect(demoRequests).toEqual([]);
  });
}
