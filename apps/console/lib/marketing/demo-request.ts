import {
  DEMO_PRIVACY_VERSION,
  DEMO_REQUEST_MAX_BYTES,
  DEMO_USE_CASES,
  type DemoUseCase
} from "../demo-request/contracts";
import {
  isDemoRequestAcceptedResponseV1,
  type DemoRequestPayloadV1
} from "../demo-request/public-contract";
import type { MarketingLocale } from "./content";

export const DEMO_EMAIL_MAX_LENGTH = 254;

export const DEMO_REQUEST_FORM_FALLBACK = Object.freeze({
  action: "/demo-request",
  method: "post" as const
});

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

export function buildDemoRequestPayload(draft: DemoRequestDraft): DemoRequestPayloadV1 {
  if (!draft.consent) {
    throw new Error("Demo request consent is required.");
  }
  if (!DEMO_USE_CASES.includes(draft.useCase)) {
    throw new Error("Demo request use case is invalid.");
  }
  const name = draft.name.trim();
  const company = draft.company.trim();
  const payload: DemoRequestPayloadV1 = {
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

export function serializeDemoRequest(payload: DemoRequestPayloadV1): string {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).byteLength > DEMO_REQUEST_MAX_BYTES) {
    throw new Error("Demo request exceeds the maximum JSON size.");
  }
  return body;
}

export async function parseAcceptedDemoResponse(response: Response): Promise<string> {
  const mediaType = response.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (response.status !== 202 || mediaType !== "application/json") {
    throw new Error("Demo request response is invalid.");
  }

  let value: unknown;
  try {
    value = (await response.json()) as unknown;
  } catch {
    throw new Error("Demo request response is invalid.");
  }
  if (!isDemoRequestAcceptedResponseV1(value)) {
    throw new Error("Demo request response is invalid.");
  }
  return value.request_id;
}
