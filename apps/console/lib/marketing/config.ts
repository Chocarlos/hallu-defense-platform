const LOCAL_MARKETING_ORIGIN = "http://localhost:3000";
const SIMPLE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

export interface MarketingPublicConfig {
  readonly demoRequestsEnabled: boolean;
  readonly privacyContactEmail: string | null;
  readonly siteOrigin: string;
}

export function loadMarketingPublicConfig(
  env: Readonly<Record<string, string | undefined>> = process.env
): MarketingPublicConfig {
  return Object.freeze({
    demoRequestsEnabled: env.HALLU_DEFENSE_DEMO_REQUESTS_ENABLED === "true",
    privacyContactEmail: safeContactEmail(
      env.HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL
    ),
    siteOrigin: resolveMarketingOrigin(env.HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN)
  });
}

export function resolveMarketingOrigin(value: string | undefined): string {
  if (value === undefined || value === "" || value.trim() !== value) {
    return LOCAL_MARKETING_ORIGIN;
  }
  try {
    const url = new URL(value);
    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.origin !== value
    ) {
      return LOCAL_MARKETING_ORIGIN;
    }
    return url.origin;
  } catch {
    return LOCAL_MARKETING_ORIGIN;
  }
}

function safeContactEmail(value: string | undefined): string | null {
  if (
    value === undefined ||
    value === "" ||
    value.length > 254 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    !SIMPLE_EMAIL.test(value)
  ) {
    return null;
  }
  return value;
}
