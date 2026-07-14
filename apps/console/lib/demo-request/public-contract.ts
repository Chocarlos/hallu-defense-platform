import {
  DEMO_PRIVACY_VERSION,
  type DemoLocale,
  type DemoUseCase
} from "./contracts";

export const DEMO_REQUEST_PAYLOAD_FIELDS_V1 = [
  "submission_id",
  "locale",
  "email",
  "name",
  "company",
  "use_case",
  "consent",
  "privacy_version",
  "website"
] as const;

export const DEMO_REQUEST_ID_PATTERN = /^dr_[A-Za-z0-9_-]{24}$/u;

export interface DemoRequestPayloadV1 {
  readonly submission_id: string;
  readonly locale: DemoLocale;
  readonly email: string;
  readonly name?: string;
  readonly company?: string;
  readonly use_case: DemoUseCase;
  readonly consent: true;
  readonly privacy_version: typeof DEMO_PRIVACY_VERSION;
  readonly website: string;
}

export interface DemoRequestAcceptedResponseV1 {
  readonly request_id: string;
}

export interface DemoRequestErrorResponseV1 {
  readonly error: string;
}

export function isDemoRequestAcceptedResponseV1(
  value: unknown
): value is DemoRequestAcceptedResponseV1 {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    "request_id" in value &&
    typeof value.request_id === "string" &&
    DEMO_REQUEST_ID_PATTERN.test(value.request_id)
  );
}
