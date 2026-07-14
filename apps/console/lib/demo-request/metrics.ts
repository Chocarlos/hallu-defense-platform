export const DEMO_RESULT_OUTCOMES = [
  "accepted",
  "invalid",
  "rate_limited",
  "unavailable"
] as const;
export const WEBHOOK_OUTCOMES = [
  "success",
  "http_error",
  "timeout",
  "network_error"
] as const;

export type DemoResultOutcome = (typeof DEMO_RESULT_OUTCOMES)[number];
export type WebhookOutcome = (typeof WEBHOOK_OUTCOMES)[number];

const WEBHOOK_DURATION_BUCKETS = [0.1, 0.25, 0.5, 1, 2.5, 5] as const;

export interface DemoMetricsRecorder {
  recordDemoResult(outcome: DemoResultOutcome): void;
  recordWebhook(outcome: WebhookOutcome, durationSeconds: number): void;
}

export class DemoMetrics implements DemoMetricsRecorder {
  private readonly resultTotals = new Map<DemoResultOutcome, number>();
  private readonly webhookTotals = new Map<WebhookOutcome, number>();
  private readonly webhookBucketTotals = new Map<number, number>();
  private webhookDurationCount = 0;
  private webhookDurationSum = 0;

  recordDemoResult(outcome: DemoResultOutcome): void {
    assertDemoOutcome(outcome);
    this.resultTotals.set(outcome, (this.resultTotals.get(outcome) ?? 0) + 1);
  }

  recordWebhook(outcome: WebhookOutcome, durationSeconds: number): void {
    assertWebhookOutcome(outcome);
    if (!Number.isFinite(durationSeconds) || durationSeconds < 0) {
      throw new TypeError("Webhook duration must be a finite non-negative number.");
    }
    this.webhookTotals.set(outcome, (this.webhookTotals.get(outcome) ?? 0) + 1);
    this.webhookDurationCount += 1;
    this.webhookDurationSum += durationSeconds;
    for (const bucket of WEBHOOK_DURATION_BUCKETS) {
      if (durationSeconds <= bucket) {
        this.webhookBucketTotals.set(
          bucket,
          (this.webhookBucketTotals.get(bucket) ?? 0) + 1
        );
      }
    }
  }

  render(): string {
    const lines = [
      "# HELP hallu_demo_requests_total Demo request results by bounded outcome.",
      "# TYPE hallu_demo_requests_total counter"
    ];
    for (const outcome of DEMO_RESULT_OUTCOMES) {
      lines.push(
        `hallu_demo_requests_total{outcome="${outcome}"} ${this.resultTotals.get(outcome) ?? 0}`
      );
    }
    lines.push(
      "# HELP hallu_demo_webhook_requests_total Demo webhook results by bounded outcome.",
      "# TYPE hallu_demo_webhook_requests_total counter"
    );
    for (const outcome of WEBHOOK_OUTCOMES) {
      lines.push(
        `hallu_demo_webhook_requests_total{outcome="${outcome}"} ${this.webhookTotals.get(outcome) ?? 0}`
      );
    }
    lines.push(
      "# HELP hallu_demo_webhook_duration_seconds Demo webhook request duration.",
      "# TYPE hallu_demo_webhook_duration_seconds histogram"
    );
    for (const bucket of WEBHOOK_DURATION_BUCKETS) {
      lines.push(
        `hallu_demo_webhook_duration_seconds_bucket{le="${bucket}"} ${this.webhookBucketTotals.get(bucket) ?? 0}`
      );
    }
    lines.push(
      `hallu_demo_webhook_duration_seconds_bucket{le="+Inf"} ${this.webhookDurationCount}`,
      `hallu_demo_webhook_duration_seconds_sum ${this.webhookDurationSum}`,
      `hallu_demo_webhook_duration_seconds_count ${this.webhookDurationCount}`
    );
    return `${lines.join("\n")}\n`;
  }
}

export const demoMetrics = new DemoMetrics();

function assertDemoOutcome(value: string): asserts value is DemoResultOutcome {
  if (!(DEMO_RESULT_OUTCOMES as readonly string[]).includes(value)) {
    throw new TypeError("Unsupported demo request metric outcome.");
  }
}

function assertWebhookOutcome(value: string): asserts value is WebhookOutcome {
  if (!(WEBHOOK_OUTCOMES as readonly string[]).includes(value)) {
    throw new TypeError("Unsupported demo webhook metric outcome.");
  }
}

