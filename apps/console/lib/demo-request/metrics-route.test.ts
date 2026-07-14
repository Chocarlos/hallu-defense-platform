import { describe, expect, it } from "vitest";

import { DemoMetrics } from "./metrics";
import { createDemoMetricsHandler } from "./metrics-route";

const token = "metrics-bearer-token-with-at-least-32-characters";

describe("demo metrics route", () => {
  it("requires a bearer read from file and exposes only bounded labels", () => {
    const metrics = new DemoMetrics();
    metrics.recordDemoResult("accepted");
    metrics.recordDemoResult("invalid");
    metrics.recordWebhook("success", 0.25);
    const handler = createDemoMetricsHandler({
      config: { enabled: true, bearerFile: "/run/secrets/metrics-bearer" },
      metrics,
      secretReader: () => Buffer.from(token, "utf8")
    });

    const unauthorized = handler(new Request("https://defense.example.test/metrics"));
    const authorized = handler(
      new Request("https://defense.example.test/metrics", {
        headers: { authorization: `Bearer ${token}` }
      })
    );

    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("www-authenticate")).toContain("Bearer");
    expect(authorized.status).toBe(200);
    const bodyPromise = authorized.text();
    return bodyPromise.then((body) => {
      expect(body).toContain('hallu_demo_requests_total{outcome="accepted"} 1');
      expect(body).toContain('hallu_demo_webhook_requests_total{outcome="success"} 1');
      expect(body).not.toContain(token);
      expect(body).not.toContain("email");
      expect(body).not.toContain("submission_id");
      expect(body).not.toContain("request_id");
    });
  });

  it("fails closed when the bearer file is unavailable", () => {
    const response = createDemoMetricsHandler({
      config: { enabled: true, bearerFile: "/missing" },
      secretReader: () => {
        throw new Error("secret value must not leak");
      }
    })(new Request("https://defense.example.test/metrics"));
    expect(response.status).toBe(503);
  });

  it("does not accept malformed, prefixed, or differently sized credentials", () => {
    const handler = createDemoMetricsHandler({
      config: { enabled: true, bearerFile: "/secret" },
      secretReader: () => Buffer.from(token, "utf8")
    });
    for (const authorization of [
      token,
      `Basic ${token}`,
      `Bearer ${token} extra`,
      "Bearer short"
    ]) {
      expect(
        handler(
          new Request("https://defense.example.test/metrics", {
            headers: { authorization }
          })
        ).status
      ).toBe(401);
    }
  });
});
