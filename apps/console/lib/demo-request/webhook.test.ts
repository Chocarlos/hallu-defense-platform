import { createHmac } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import type { NormalizedDemoRequest } from "./contracts";
import {
  DEMO_WEBHOOK_TIMEOUT_MILLISECONDS,
  deliverDemoWebhook,
  DemoWebhookError
} from "./webhook";

const hmacSecret = Buffer.from("hmac-secret-value-that-is-at-least-32-bytes", "utf8");

describe("demo webhook", () => {
  it("signs and sends the exact serialized bytes with the required headers", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (_url, init) => {
      const body = Buffer.from(init?.body as Uint8Array);
      const headers = new Headers(init?.headers);
      const timestamp = headers.get("X-Hallu-Timestamp") ?? "";
      const expected = createHmac("sha256", hmacSecret)
        .update(timestamp, "ascii")
        .update(".", "ascii")
        .update(body)
        .digest("hex");
      expect(headers.get("X-Hallu-Signature")).toBe(`sha256=${expected}`);
      expect(headers.get("Idempotency-Key")).toBe(demoRequest.submissionId);
      expect(headers.get("X-Hallu-Request-Id")).toBe(`dr_${"A".repeat(24)}`);
      expect(init?.redirect).toBe("error");
      expect(init?.body).toEqual(body);
      const payload = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
      expect(payload).toMatchObject({
        schema_version: "demo-request.v1",
        retention_days: 90,
        locale: "en",
        use_case: "code_agents"
      });
      const serialized = body.toString("utf8");
      for (const forbidden of ["ip", "user-agent", "referrer", "utm"]) {
        expect(serialized.toLowerCase()).not.toContain(forbidden);
      }
      return new Response(null, { status: 204 });
    });

    await expect(
      deliverDemoWebhook({
        webhookUrl: "https://crm.example.test/hooks/demo",
        hmacSecret,
        request: demoRequest,
        requestId: `dr_${"A".repeat(24)}`,
        now: new Date("2026-07-13T12:00:00.000Z"),
        fetchImpl
      })
    ).resolves.toMatchObject({ outcome: "success" });
    expect(DEMO_WEBHOOK_TIMEOUT_MILLISECONDS).toBe(5_000);
  });

  it("classifies non-success HTTP without consuming its body", async () => {
    const response = new Response("sensitive upstream detail", { status: 302 });
    const cancel = vi.spyOn(response.body!, "cancel");
    await expect(
      deliverDemoWebhook({
        webhookUrl: "https://crm.example.test/hooks/demo",
        hmacSecret,
        request: demoRequest,
        requestId: `dr_${"A".repeat(24)}`,
        now: new Date(),
        fetchImpl: vi.fn(async () => response)
      })
    ).rejects.toMatchObject({ outcome: "http_error" });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("aborts a hung webhook at the bounded timeout", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true }
        );
      })
    );
    const promise = deliverDemoWebhook({
      webhookUrl: "https://crm.example.test/hooks/demo",
      hmacSecret,
      request: demoRequest,
      requestId: `dr_${"A".repeat(24)}`,
      now: new Date(),
      fetchImpl,
      timeoutMilliseconds: 5
    });
    await expect(promise).rejects.toSatisfy(
      (error: unknown) => error instanceof DemoWebhookError && error.outcome === "timeout"
    );
  });
});

const demoRequest: NormalizedDemoRequest = {
  submissionId: "123e4567-e89b-42d3-a456-426614174000",
  locale: "en",
  email: "person@example.invalid",
  name: "Ada",
  company: "Analytical Engines",
  useCase: "code_agents",
  consent: true,
  privacyVersion: "privacy.v1",
  honeypot: false
};
