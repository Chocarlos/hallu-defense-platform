import { expect, test, type APIRequestContext, type Locator, type Page } from "@playwright/test";

const API_BASE_URL = `http://127.0.0.1:${process.env.E2E_API_PORT ?? "18100"}`;
const REVIEWER_HEADERS = {
  "content-type": "application/json",
  "x-tenant-id": "console",
  "x-subject-id": "e2e-reviewer",
  "x-roles": "approval_reviewer"
};

interface ApprovalRecordPayload {
  readonly approval_id: string;
  readonly status: string;
  readonly decided_by?: string | null;
  readonly tool_call: {
    readonly tool_name: string;
    readonly input: Readonly<Record<string, unknown>>;
  };
}

interface ApprovalListPayload {
  readonly approvals: readonly ApprovalRecordPayload[];
}

async function openConsole(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Consola DevEx" })).toBeVisible();
}

async function enqueueHighRiskToolCall(page: Page): Promise<string> {
  await page.getByRole("button", { name: "Encolar" }).click();
  const message = page.locator(".approval-message");
  await expect(message).toContainText("Pendiente apr_", { timeout: 20_000 });
  const text = (await message.textContent()) ?? "";
  const match = text.match(/apr_[a-f0-9]+/);
  if (match === null) {
    throw new Error(`Approval id was not found in message: ${text}`);
  }
  return match[0];
}

function approvalRow(page: Page, approvalId: string): Locator {
  return page.locator(".approval-list li", { hasText: approvalId });
}

async function listApprovals(
  request: APIRequestContext,
  status: "pending" | "approved" | "rejected"
): Promise<ApprovalListPayload> {
  const response = await request.post(`${API_BASE_URL}/approvals/list`, {
    headers: REVIEWER_HEADERS,
    data: { status }
  });
  expect(response.ok()).toBeTruthy();
  return (await response.json()) as ApprovalListPayload;
}

test.describe("approval queue console flow", () => {
  test("enqueues, redacts, approves, and clears a high-risk tool call", async ({
    page,
    request
  }) => {
    await openConsole(page);

    const approvalId = await enqueueHighRiskToolCall(page);
    const row = approvalRow(page, approvalId);
    await expect(row).toBeVisible();
    await expect(row).toContainText("delete_repository");
    await expect(row).toContainText("pending");
    // The API must have redacted the sensitive input before it reaches the UI.
    await expect(row.locator(".approval-input-snippet")).toContainText(/\[redacted\]/i);

    const pending = await listApprovals(request, "pending");
    const record = pending.approvals.find((item) => item.approval_id === approvalId);
    expect(record).toBeDefined();
    expect(record?.tool_call.tool_name).toBe("delete_repository");
    expect(record?.tool_call.input["api_key"]).toBe("[REDACTED]");
    expect(JSON.stringify(pending)).not.toContain('"api_key":"demo"');
    expect(await page.content()).not.toContain('"api_key":"demo"');

    await row.getByRole("button", { name: "Aprobar" }).click();
    await expect(page.locator(".approval-message")).toHaveText("Aprobado", { timeout: 20_000 });
    await expect(approvalRow(page, approvalId)).toHaveCount(0);

    await page.reload();
    await expect(page.getByRole("heading", { name: "Consola DevEx" })).toBeVisible();
    await expect(approvalRow(page, approvalId)).toHaveCount(0);

    const approved = await listApprovals(request, "approved");
    const decided = approved.approvals.find((item) => item.approval_id === approvalId);
    expect(decided?.status).toBe("approved");
    expect(decided?.decided_by).toBe("console-reviewer");
    expect(decided?.tool_call.input["api_key"]).toBe("[REDACTED]");
  });

  test("rejects a queued high-risk tool call from the UI", async ({ page, request }) => {
    await openConsole(page);

    const approvalId = await enqueueHighRiskToolCall(page);
    const row = approvalRow(page, approvalId);
    await expect(row).toBeVisible();

    await row.getByRole("button", { name: "Rechazar" }).click();
    await expect(page.locator(".approval-message")).toHaveText("Rechazado", { timeout: 20_000 });
    await expect(approvalRow(page, approvalId)).toHaveCount(0);

    await page.reload();
    await expect(page.getByRole("heading", { name: "Consola DevEx" })).toBeVisible();
    await expect(approvalRow(page, approvalId)).toHaveCount(0);

    const rejected = await listApprovals(request, "rejected");
    const decided = rejected.approvals.find((item) => item.approval_id === approvalId);
    expect(decided?.status).toBe("rejected");
    expect(decided?.decided_by).toBe("console-reviewer");
  });
});
