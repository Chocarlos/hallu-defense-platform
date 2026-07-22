import { expect, test, type Locator, type Page } from "@playwright/test";

const PUBLIC_REQUEST_ID = "dr_AbCdEfGhIjKlMnOpQrStUvWx";

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
});

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
    page,
    browserName
  }) => {
    const payloads = await interceptDemoRequests(page, [202]);
    await openHydratedStepOne(page, locale);
    const email = page.getByLabel(locale.emailLabel);
    const continueButton = page.getByRole("button", { name: locale.continueButton });
    const name = page.locator("#demo-name");
    const company = page.locator("#demo-company");
    const useCase = page.locator("#demo-use-case");
    const consent = page.getByLabel(locale.consentLabel);
    const privacyLink = page.locator('label[for="demo-consent"] a');
    const backButton = page.getByRole("button", {
      name: locale.backButton,
      exact: true
    });
    const submitButton = page.getByRole("button", { name: locale.submitButton });

    await email.fill(`${locale.locale}-e2e@example.invalid`);
    await expect(email).toBeFocused();
    await expect(email).toHaveValue(`${locale.locale}-e2e@example.invalid`);
    await tabTo(page, continueButton);
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("heading", { level: 3, name: locale.stepTwo })
    ).toBeFocused();

    await tabTo(page, name);
    await tabTo(page, company);
    await tabTo(page, useCase);
    await tabTo(page, consent);
    await expect(privacyLink).toHaveAttribute("href", locale.privacyPath);
    await tabFromConsentToBack(page, browserName, privacyLink, backButton);
    await tabTo(page, submitButton);
    await page.keyboard.press("Enter");
    expect(await consent.evaluate((input: HTMLInputElement) => input.validity.valueMissing)).toBe(
      true
    );
    await expect(consent).toBeFocused();
    expect(payloads).toHaveLength(0);

    await page.keyboard.press("Space");
    await expect(consent).toBeChecked();
    await tabFromConsentToBack(page, browserName, privacyLink, backButton);
    await page.keyboard.press("Enter");
    await expect(email).toBeFocused();
    await expect(email).toHaveValue(`${locale.locale}-e2e@example.invalid`);

    await tabTo(page, continueButton);
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("heading", { level: 3, name: locale.stepTwo })
    ).toBeFocused();
    await tabTo(page, name);
    await tabTo(page, company);
    await tabTo(page, useCase);
    await tabTo(page, consent);
    await expect(consent).toBeChecked();
    await tabFromConsentToBack(page, browserName, privacyLink, backButton);
    await tabTo(page, submitButton);
    await page.keyboard.press("Enter");
    const status = page.getByRole("status").filter({ hasText: locale.success });
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
    await checkConsent(page.getByLabel(locale.consentLabel));

    await submitForm(page, locale.submitButton);
    await expect(page.getByRole("alert").filter({ hasText: locale.invalid })).toBeVisible();
    const retryButton = page.getByRole("button", { name: locale.retryButton });
    await expect(retryButton).toBeFocused();
    await retryButton.click();
    await expect(page.getByRole("alert").filter({ hasText: locale.unavailable })).toBeVisible();
    await expect(retryButton).toBeFocused();
    await retryButton.click();
    const status = page.getByRole("status").filter({ hasText: locale.success });
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
    await checkConsent(page.getByLabel(locale.consentLabel));

    await submitForm(page, locale.submitButton);
    await expect(page.getByRole("alert").filter({ hasText: locale.generic })).toBeVisible();
    await expect(page.getByText(locale.success, { exact: false })).toHaveCount(0);
    const retryButton = page.getByRole("button", { name: locale.retryButton });
    await expect(retryButton).toBeVisible();
    await expect(retryButton).toBeFocused();
    await expect.poll(() => payloads.length).toBe(1);
    assertPayload(payloads[0], locale.locale);
  });
}

test("@form captures the current DOM email when React state missed the change", async ({
  page
}, testInfo) => {
  test.skip(
    testInfo.project.name !== "chromium-desktop-1440",
    "The DOM/state fallback is framework-level; the full keyboard flow covers every browser and viewport."
  );

  const locale = locales[0];
  const currentDomEmail = "current-dom-value@example.invalid";
  const payloads = await interceptDemoRequests(page, [202]);
  await openHydratedStepOne(page, locale);
  const email = page.getByLabel(locale.emailLabel);

  // React can finish hydration after the browser value changes but before an
  // onChange reaches controlled state. Setting the native value without an
  // input event reproduces that exact DOM-newer-than-state invariant without
  // claiming that Playwright controls React's event-replay timing.
  await email.evaluate((input: HTMLInputElement, value) => {
    const setter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    )?.set;
    if (setter === undefined) throw new Error("HTMLInputElement.value setter is unavailable.");
    setter.call(input, value);
  }, currentDomEmail);
  await expect(email).toHaveValue(currentDomEmail);
  await email.press("Tab");
  await expect(page.getByRole("button", { name: locale.continueButton })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { level: 3, name: locale.stepTwo })
  ).toBeFocused();

  await checkConsent(page.getByLabel(locale.consentLabel));
  await submitForm(page, locale.submitButton);
  await expect(page.getByRole("status").filter({ hasText: locale.success })).toBeFocused();
  await expect.poll(() => payloads.length).toBe(1);
  assertPayload(payloads[0], locale.locale, currentDomEmail);
});

async function advanceToStepTwo(
  page: Page,
  locale: (typeof locales)[number]
): Promise<void> {
  await openHydratedStepOne(page, locale);
  await page.getByLabel(locale.emailLabel).fill(`${locale.locale}-e2e@example.invalid`);
  await page.getByRole("button", { name: locale.continueButton }).click();
  await expect(
    page.getByRole("heading", { level: 3, name: locale.stepTwo })
  ).toBeFocused();
}

async function openHydratedStepOne(
  page: Page,
  locale: (typeof locales)[number]
): Promise<void> {
  await page.goto(locale.path);
  await expect(page.locator('[data-demo-form-hydrated="true"]')).toBeVisible();
}

async function tabTo(
  page: Page,
  target: Locator
): Promise<void> {
  await page.keyboard.press("Tab");
  await expect(target).toBeFocused();
}

async function tabFromConsentToBack(
  page: Page,
  browserName: "chromium" | "firefox" | "webkit",
  privacyLink: Locator,
  backButton: Locator
): Promise<void> {
  await page.keyboard.press("Tab");
  const privacyLinkFocused = await privacyLink.evaluate(
    (element) => element === element.ownerDocument.activeElement
  );
  if (browserName !== "webkit" || privacyLinkFocused) {
    await expect(privacyLink).toBeFocused();
    await tabTo(page, backButton);
    return;
  }

  // WebKit follows the host platform's full-keyboard-access preference: some
  // environments include links and others move directly to the next form
  // control. In both native sequences, Back must be the next button reached.
  await expect(backButton).toBeFocused();
}

async function checkConsent(consent: ReturnType<Page["getByLabel"]>): Promise<void> {
  await consent.focus();
  await expect(consent).toBeFocused();
  await consent.press("Space");
  await expect(consent).toBeChecked();
}

async function submitForm(page: Page, name: string): Promise<void> {
  const submit = page.getByRole("button", { name });
  await submit.focus();
  await expect(submit).toBeFocused();
  await submit.press("Enter");
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

function assertPayload(
  payload: Record<string, unknown> | undefined,
  locale: "es" | "en",
  expectedEmail = `${locale}-e2e@example.invalid`
) {
  expect(payload).toBeDefined();
  expect(payload).toMatchObject({
    locale,
    email: expectedEmail,
    use_case: "rag_verification",
    consent: true,
    privacy_version: "privacy.v1",
    website: ""
  });
  expect(payload?.submission_id).toEqual(expect.stringMatching(/^[0-9a-f-]{36}$/iu));
}
