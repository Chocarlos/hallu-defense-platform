import { expect, test, type APIRequestContext, type Route } from "@playwright/test";

const API_BASE_URL = `http://127.0.0.1:${process.env.E2E_API_PORT ?? "18100"}`;
const JSON_HEADERS = { "content-type": "application/json" };

test("renders tenant-scoped run, grant, ingestion, and eval data from the live API", async ({
  page,
  request
}) => {
  await seedLiveDashboardData(request);
  await page.goto("/console");

  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "Saltar al contenido principal" });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const history = page.locator('section[aria-label="Historial de runs"]');
  await expect(history).toContainText("tr_console_live_history");
  await expect(history).toContainText("Usar en replay");
  await history
    .locator("li", { hasText: "tr_console_live_history" })
    .getByRole("button", { name: "Usar en replay" })
    .click();
  const replayInput = page.getByLabel("Trace a reproducir");
  await expect(replayInput).toHaveValue("tr_console_live_history");
  await expect(replayInput).toBeFocused();
  await expect(page.locator("#replay-selection-status")).toContainText(
    "Trace tr_console_live_history seleccionado para replay."
  );

  const corpus = page.locator('section[aria-label="Corpus e ingesta"]');
  await expect(corpus).toContainText("console-live-corpus");
  await expect(corpus).toContainText("v1");
  await corpus.getByLabel("Corpus ID").fill("console-live-corpus");
  await corpus.getByLabel("Source ref").fill("console-live-document");
  await corpus
    .getByLabel("Documento")
    .fill("The console displays only data returned by tenant-scoped API endpoints.");
  await corpus.getByRole("button", { name: "Ingestar documento" }).click();
  await expect(corpus.locator(".ingestion-result")).toContainText("backend local", {
    timeout: 30_000
  });
  await expect(corpus.locator(".ingestion-result")).toContainText("0 indexados de 1");

  const evals = page.locator('section[aria-label="Reportes de eval"]');
  await expect(evals).toContainText("console-live-eval-run");
  await expect(evals).toContainText("96%");
  await expect(evals).toContainText("12.5 ms");

  for (const width of [320, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await expect
      .poll(() =>
        page.evaluate(
          () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
        )
      )
      .toBe(true);
  }
});

test("shows deterministic loading, empty, and error states", async ({ page }) => {
  await page.route("**/verification/runs/list", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
    await fulfillJson(route, 200, {
      trace_id: "tr_empty_history",
      runs: [],
      next_cursor: null
    });
  });
  await page.route("**/rag/corpus-grants/list", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
    await fulfillJson(route, 200, { grants: [], next_cursor: null });
  });
  await page.route("**/evals/reports/list", (route) =>
    route.request().method() === "POST"
      ? fulfillJson(route, 503, {
          trace_id: "tr_eval_unavailable",
          error: "service_unavailable",
          message: "Eval report service is unavailable.",
          details: {}
        })
      : route.continue()
  );

  await page.goto("/console");
  const history = page.locator('section[aria-label="Historial de runs"]');
  await expect(history).toContainText("Cargando historial de runs");
  await expect(page.locator('section[aria-label="Corpus e ingesta"]')).toContainText(
    "Cargando grants de corpus"
  );
  await expect(history).toContainText("Sin runs completados registrados");
  await expect(page.locator('section[aria-label="Corpus e ingesta"]')).toContainText(
    "Sin grants de corpus registrados"
  );
  const evalReports = page.locator('section[aria-label="Reportes de eval"]');
  await expect(evalReports).toContainText(
    "El servicio no esta disponible temporalmente."
  );
  await expect(evalReports).not.toContainText("Eval report service is unavailable.");
});

async function seedLiveDashboardData(request: APIRequestContext): Promise<void> {
  const run = await request.post(`${API_BASE_URL}/verification/run`, {
    headers: {
      ...JSON_HEADERS,
      "x-tenant-id": "tenant-a",
      "x-trace-id": "tr_console_live_history",
      "x-subject-id": "console-verifier",
      "x-roles": "verifier"
    },
    data: { message_text: "The live console has a verification history." }
  });
  expect(run.ok(), await run.text()).toBe(true);

  const grant = await request.post(`${API_BASE_URL}/rag/corpus-grants/upsert`, {
    headers: {
      ...JSON_HEADERS,
      "x-tenant-id": "tenant-a",
      "x-trace-id": "tr_console_live_grant",
      "x-subject-id": "console-rag-writer",
      "x-roles": "rag_writer"
    },
    data: {
      corpus_id: "console-live-corpus",
      reader_roles: [],
      writer_roles: [],
      expected_version: 0
    }
  });
  expect(grant.ok(), await grant.text()).toBe(true);

  const evalReport = await request.post(`${API_BASE_URL}/evals/reports/publish`, {
    headers: {
      ...JSON_HEADERS,
      "x-tenant-id": "tenant-a",
      "x-trace-id": "tr_console_live_eval",
      "x-subject-id": "console-eval-publisher",
      "x-roles": "eval_publisher"
    },
    data: {
      suite: "console-live",
      run_id: "console-live-eval-run",
      source: "console-e2e",
      metrics: {
        scenario_count: 25,
        pass_rate: 0.96,
        p95_latency_ms: 12.5,
        groundedness: 0.98,
        faithfulness: 0.99
      },
      payload: {}
    }
  });
  expect(evalReport.ok(), await evalReport.text()).toBe(true);
}

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    headers: {
      "access-control-allow-origin": "http://127.0.0.1:3100",
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
}
