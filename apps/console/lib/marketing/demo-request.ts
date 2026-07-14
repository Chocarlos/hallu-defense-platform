import {
  DEMO_PRIVACY_VERSION,
  DEMO_REQUEST_MAX_BYTES,
  DEMO_USE_CASES,
  type DemoUseCase
} from "../demo-request/contracts";
import type { MarketingLocale } from "./content";

export interface DemoRequestDraft {
  readonly submissionId: string;
  readonly locale: MarketingLocale;
  readonly email: string;
  readonly name: string;
  readonly company: string;
  readonly useCase: DemoUseCase;
  readonly consent: boolean;
  readonly website: string;
}

export interface DemoRequestPayload {
  readonly submission_id: string;
  readonly locale: MarketingLocale;
  readonly email: string;
  readonly name?: string;
  readonly company?: string;
  readonly use_case: DemoUseCase;
  readonly consent: true;
  readonly privacy_version: typeof DEMO_PRIVACY_VERSION;
  readonly website: string;
}

export function buildDemoRequestPayload(draft: DemoRequestDraft): DemoRequestPayload {
  if (!draft.consent) {
    throw new Error("Demo request consent is required.");
  }
  if (!DEMO_USE_CASES.includes(draft.useCase)) {
    throw new Error("Demo request use case is invalid.");
  }
  const name = draft.name.trim();
  const company = draft.company.trim();
  const payload: DemoRequestPayload = {
    submission_id: draft.submissionId,
    locale: draft.locale,
    email: draft.email.trim(),
    use_case: draft.useCase,
    consent: true,
    privacy_version: DEMO_PRIVACY_VERSION,
    website: draft.website
  };
  return {
    ...payload,
    ...(name === "" ? {} : { name }),
    ...(company === "" ? {} : { company })
  };
}

export function serializeDemoRequest(payload: DemoRequestPayload): string {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).byteLength > DEMO_REQUEST_MAX_BYTES) {
    throw new Error("Demo request exceeds the maximum JSON size.");
  }
  return body;
}
