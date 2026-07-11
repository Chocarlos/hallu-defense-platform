import { expect, test, type Page } from "@playwright/test";

async function openConsole(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Consola DevEx" })).toBeVisible();
}

test.describe("operations console flow", () => {
  test("evaluates policy decisions from the browser", async ({ page }) => {
    await openConsole(page);

    const policyPanel = page.locator('section[aria-label="Policy explanation"]');
    await expect(policyPanel).toBeVisible();
    await policyPanel.getByLabel("Accion").fill("publish_output");
    await policyPanel.getByLabel("Recurso").fill("model-response");
    await policyPanel.getByLabel("Riesgo").selectOption("high");
    await policyPanel.getByLabel("Atributos JSON").fill(
      JSON.stringify(
        {
          secret_detected: true,
          tenant_id: "tenant-a"
        },
        null,
        2
      )
    );

    await policyPanel.getByRole("button", { name: /^(Evaluar|Evaluando)$/ }).click();

    const result = policyPanel.locator(".evidence-card").filter({ hasText: "Policy" });
    await expect(result).toContainText("blocked", { timeout: 30_000 });
    await expect(result).toContainText("block");
    await expect(result).toContainText("secret_leakage_blocks_output");
    await expect(result).toContainText("Tool or model output contains secret-like material");
  });

  test("runs sandbox evidence from the browser", async ({ page }) => {
    await openConsole(page);

    const sandboxPanel = page.locator('section[aria-label="Sandbox evidence"]');
    await expect(sandboxPanel).toBeVisible();
    await sandboxPanel.getByLabel("Repo ref").fill(".");
    await sandboxPanel.getByLabel("Network").selectOption("deny");
    await sandboxPanel.getByLabel("Comandos").fill("python --version");

    await sandboxPanel.getByRole("button", { name: /^(Ejecutar|Ejecutando)$/ }).click();

    const result = sandboxPanel.locator(".sandbox-result");
    await expect(result).toContainText("SUPPORTED", { timeout: 30_000 });
    await expect(result).toContainText("deny / 0 artifacts");

    const commands = sandboxPanel.locator('section[aria-label="Sandbox commands"]');
    await expect(commands).toContainText("python --version");
    await expect(commands).toContainText(/exit \d+/);
  });
});
