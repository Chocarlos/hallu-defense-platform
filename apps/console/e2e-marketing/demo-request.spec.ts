import { expect, test, type Page } from "@playwright/test";

const PUBLIC_REQUEST_ID = "dr_AbCdEfGhIjKlMnOpQrStUvWx";

const locales = [
  {
    path: "/",
    locale: "es",
    emailLabel: "Correo de trabajo",
    continueButton: "Continuar",
    backButton: "Volver",
    stepTwo: "Paso 2 de 2: contexto y consentimiento",
    submitButton: "Solicitar demo",
    retryButton: "Reintentar",
    consentLabel: /Acepto el aviso de privacidad/iu,
    privacyPath: "/privacy",
    success: "Solicitud recibida.",
    generic:
      "No pudimos enviar la solicitud. Reinténtalo: el formulario conservará el identificador del intento.",
    invalid: "Revisa los campos y el consentimiento antes de continuar.",
    unavailable: "La recepción segura de solicitudes no está disponible temporalmente."
  },
  {
    path: "/en",
    locale: "en",
    emailLabel: "Work email",
    continueButton: "Continue",
    backButton: "Back",
    stepTwo: "Step 2 of 2: context and consent",
    submitButton: "Request a demo",
    retryButton: "Retry",
    consentLabel: /I accept the privacy notice/iu,
    privacyPath: "/en/privacy",
    success: "Request received.",
    generic:
      "We could not send the request. Retry: the form will preserve the attempt identifier.",
    invalid: "Review the fields and consent before continuing.",
    unavailable: "Secure request intake is temporarily unavailable."
  }
] as const;

for (const locale of locales) {
  test(`@form ${locale.locale} two-step form manages focus, consent, and 202`, async ({
    page
  }) => {
    const payloads = await interceptDemoRequests(page, [202]);
    await advanceToStepTwo(page, locale);

    await page.getByRole("button", { name: locale.backButton, exact: true }).click();
    const email = page.getByLabel(locale.emailLabel);
    await expect(email).toBeFocused();
    await expect(email).toHaveValue(`${locale.locale}-e2e@example.invalid`);
    await page.getByRole("button", { name: locale.continueButton }).click();
    await expect(
      page.getByRole("heading", { level: 3, name: locale.stepTwo })
    ).toBeFocused();

    const consent = page.getByLabel(locale.consentLabel);
    await page.getByRole("button", { name: locale.submitButton }).click();
    expect(await consent.evaluate((input: HTMLInputElement) => input.validity.valueMissing)).toBe(
      true
    );
    expect(payloads).toHaveLength(0);
    await expect(page.getByRole("link", { name: /privacidad|privacy/iu })).toHaveAttribute(
      "href",
      locale.privacyPath
    );

    await consent.check();
    await page.getByRole("button", { name: locale.submitButton }).click();
    const status = page.getByRole("status");
    await expect(status).toContainText(locale.success);
    await expect(status).toBeFocused();
    await expect(status).toContainText(PUBLIC_REQUEST_ID);
    await expect.poll(() => payloads.length).toBe(1);
    assertPayload(payloads[0], locale.locale);
    await expect(status).not.toContainText(String(payloads[0]?.submission_id));
  });

  test(`@form ${locale.locale} retries 422 and 503 with one submission_id before 202`, async ({
    page
  }) => {
    const payloads = await interceptDemoRequests(page, [422, 503, 202]);
    await advanceToStepTwo(page, locale);
    await page.getByLabel(locale.consentLabel).check();

    await page.getByRole("button", { name: locale.submitButton }).click();
    await expect(page.getByRole("alert").filter({ hasText: locale.invalid })).toBeVisible();
    const retryButton = page.getByRole("button", { name: locale.retryButton });
    await expect(retryButton).toBeFocused();
    await retryButton.click();
    await expect(page.getByRole("alert").filter({ hasText: locale.unavailable })).toBeVisible();
    await expect(retryButton).toBeFocused();
    await retryButton.click();
    const status = page.getByRole("status");
    await expect(status).toContainText(locale.success);
    await expect(status).toBeFocused();
    await expect(status).toContainText(PUBLIC_REQUEST_ID);
    await expect.poll(() => payloads.length).toBe(3);

    for (const payload of payloads) assertPayload(payload, locale.locale);
    expect(new Set(payloads.map((payload) => payload.submission_id)).size).toBe(1);
    await expect(status).not.toContainText(String(payloads[0]?.submission_id));
  });

  test(`@form ${locale.locale} rejects a malformed 202 response without showing success`, async ({
    page
  }) => {
    const payloads = await interceptDemoRequests(page, [202], [
      { request_id: "synthetic-browser-response" }
    ]);
    await advanceToStepTwo(page, locale);
    await page.getByLabel(locale.consentLabel).check();

    await page.getByRole("button", { name: locale.submitButton }).click();
    await expect(page.getByRole("alert").filter({ hasText: locale.generic })).toBeVisible();
    await expect(page.getByText(locale.success, { exact: false })).toHaveCount(0);
    const retryButton = page.getByRole("button", { name: locale.retryButton });
    await expect(retryButton).toBeVisible();
    await expect(retryButton).toBeFocused();
    await expect.poll(() => payloads.length).toBe(1);
    assertPayload(payloads[0], locale.locale);
  });
}

async function advanceToStepTwo(
  page: Page,
  locale: (typeof locales)[number]
): Promise<void> {
  await page.goto(locale.path);
  await page.getByLabel(locale.emailLabel).fill(`${locale.locale}-e2e@example.invalid`);
  await page.getByRole("button", { name: locale.continueButton }).click();
  await expect(
    page.getByRole("heading", { level: 3, name: locale.stepTwo })
  ).toBeFocused();
}

async function interceptDemoRequests(
  page: Page,
  statuses: readonly number[],
  bodies: readonly Record<string, unknown>[] = []
) {
  const payloads: Array<Record<string, unknown>> = [];
  let index = 0;
  await page.route("**/demo-request", async (route) => {
    const request = route.request();
    expect(request.method()).toBe("POST");
    expect(request.headers()["content-type"]).toContain("application/json");
    payloads.push(JSON.parse(request.postData() ?? "") as Record<string, unknown>);
    const status = statuses[index] ?? statuses.at(-1) ?? 503;
    index += 1;
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(bodies[index - 1] ?? { request_id: PUBLIC_REQUEST_ID })
    });
  });
  return payloads;
}

function assertPayload(payload: Record<string, unknown> | undefined, locale: "es" | "en") {
  expect(payload).toBeDefined();
  expect(payload).toMatchObject({
    locale,
    email: `${locale}-e2e@example.invalid`,
    use_case: "rag_verification",
    consent: true,
    privacy_version: "privacy.v1",
    website: ""
  });
  expect(payload?.submission_id).toEqual(expect.stringMatching(/^[0-9a-f-]{36}$/iu));
}
