export const DEMO_REQUEST_MAX_BYTES = 8 * 1024;
export const DEMO_PRIVACY_VERSION = "privacy.v1" as const;
export const DEMO_WEBHOOK_SCHEMA_VERSION = "demo-request.v1" as const;
export const DEMO_RETENTION_DAYS = 90 as const;

export const DEMO_USE_CASES = [
  "rag_verification",
  "high_risk_tools",
  "code_agents",
  "enterprise_governance"
] as const;

export type DemoLocale = "es" | "en";
export type DemoUseCase = (typeof DEMO_USE_CASES)[number];

export interface NormalizedDemoRequest {
  readonly submissionId: string;
  readonly locale: DemoLocale;
  readonly email: string;
  readonly name?: string;
  readonly company?: string;
  readonly useCase: DemoUseCase;
  readonly consent: true;
  readonly privacyVersion: typeof DEMO_PRIVACY_VERSION;
  readonly honeypot: boolean;
}

export interface DemoWebhookPayload {
  readonly schema_version: typeof DEMO_WEBHOOK_SCHEMA_VERSION;
  readonly submitted_at: string;
  readonly locale: DemoLocale;
  readonly contact: {
    readonly email: string;
    readonly name?: string;
    readonly company?: string;
  };
  readonly use_case: DemoUseCase;
  readonly consent: {
    readonly accepted: true;
    readonly privacy_version: typeof DEMO_PRIVACY_VERSION;
    readonly accepted_at: string;
  };
  readonly retention_days: typeof DEMO_RETENTION_DAYS;
}

export type DemoHttpStatus = 400 | 415 | 422 | 429 | 503;

export class DemoRequestError extends Error {
  constructor(
    readonly status: DemoHttpStatus,
    readonly publicMessage: string,
    readonly outcome: "invalid" | "rate_limited" | "unavailable",
    readonly retryAfterSeconds?: number
  ) {
    super(publicMessage);
    this.name = "DemoRequestError";
  }
}

