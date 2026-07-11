import { expect, test, type Page } from "@playwright/test";

async function openConsole(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Consola DevEx" })).toBeVisible();
}

test.describe("replay console flow", () => {
  test("starts without the demo fixture when its local flag is absent", async ({ page }) => {
    await openConsole(page);

    const traceValue = page.locator(".metric", { hasText: "Trace" }).locator("strong");
    await expect(traceValue).toHaveText("Sin run");
    await expect(page.locator("body")).not.toContainText("tr_demo");
    await expect(page.getByRole("button", { name: "Usar trace actual" })).toBeDisabled();
  });

  test("replays a verification run created from the console", async ({ page }) => {
    await openConsole(page);

    const traceValue = page.locator(".metric", { hasText: "Trace" }).locator("strong");
    await expect(traceValue).toHaveText("Sin run");

    await page
      .locator("form.verify-panel")
      .getByRole("button", { name: /Ejecutar|Ejecutando/ })
      .click();
    await expect(traceValue).toHaveText(/^tr_(?!demo$).+/, { timeout: 30_000 });
    const traceId = ((await traceValue.textContent()) ?? "").trim();
    expect(traceId).toMatch(/^tr_/);

    const replayPanel = page.locator(".replay-panel");
    await replayPanel.getByRole("button", { name: "Usar trace actual" }).click();
    await expect(replayPanel.getByLabel("Trace a reproducir")).toHaveValue(traceId);

    await replayPanel.getByRole("button", { name: /^(Replay|Reproduciendo)$/ }).click();
    const resultCard = replayPanel.locator(".evidence-card");
    await expect(resultCard).toContainText("decision estable", { timeout: 30_000 });
    await expect(resultCard).toContainText(`Fuente ${traceId}`);
    await expect(resultCard).toContainText("origen");
    await expect(resultCard).toContainText("replay");
  });

  test("shows a fail-closed error when the trace does not exist", async ({ page }) => {
    await openConsole(page);

    const replayPanel = page.locator(".replay-panel");
    await replayPanel.getByLabel("Trace a reproducir").fill("tr_e2e_missing_trace");
    await replayPanel.getByRole("button", { name: /^(Replay|Reproduciendo)$/ }).click();

    await expect(replayPanel.getByRole("alert")).toContainText("was not found", {
      timeout: 30_000
    });
  });

  test("redacts sensitive claim and verdict text in the run ledger", async ({ page }) => {
    await openConsole(page);

    const secret = "sk-" + "1".repeat(24);
    const message = `The deployment api_key=${secret} was rotated yesterday.`;
    await page.getByLabel("Respuesta candidata").fill(message);
    await page.getByLabel("Evidencia documental").fill(message);

    await page
      .locator("form.verify-panel")
      .getByRole("button", { name: /Ejecutar|Ejecutando/ })
      .click();

    const claimsPanel = page.locator(".ledger-panel").filter({ hasText: "Claims" });
    const verdictPanel = page.locator(".ledger-panel").filter({ hasText: "Veredictos" });
    await expect(claimsPanel).toContainText("[redacted]", { timeout: 30_000 });
    await expect(claimsPanel).not.toContainText(secret);
    await expect(verdictPanel).not.toContainText(secret);
  });
});
