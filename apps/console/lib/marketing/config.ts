import {
  isDemoRequestIntakeEnabled,
  normalizePrivacyContactEmail,
  type EnvironmentSource
} from "../demo-request/config";

const LOCAL_MARKETING_ORIGIN = "http://localhost:3000";
const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);
const PRODUCTION_LIKE_ENVIRONMENTS = new Set(["production", "staging"]);

export interface MarketingPublicConfig {
  readonly demoRequestsEnabled: boolean;
  readonly privacyContactEmail: string | null;
  readonly siteOrigin: string;
}

export class MarketingConfigurationError extends Error {
  constructor() {
    super("Public marketing configuration is invalid.");
    this.name = "MarketingConfigurationError";
  }
}

export function loadMarketingPublicConfig(
  env: EnvironmentSource = process.env
): MarketingPublicConfig {
  const environment = env.HALLU_DEFENSE_ENV?.trim().toLowerCase() ?? "local";
  const productionLike =
    PRODUCTION_LIKE_ENVIRONMENTS.has(environment) ||
    (env.NODE_ENV?.trim().toLowerCase() === "production" && environment !== "test");
  const runtimeEnabled = isDemoRequestIntakeEnabled(env);
  const privacyContactEmail = safeContactEmail(
    env.HALLU_DEFENSE_PRIVACY_CONTACT_EMAIL
  );
  return Object.freeze({
    demoRequestsEnabled: runtimeEnabled && privacyContactEmail !== null,
    privacyContactEmail,
    siteOrigin: resolveMarketingOrigin(
      env.HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN,
      productionLike
    )
  });
}

export function resolveMarketingOrigin(
  value: string | undefined,
  productionLike = false
): string {
  try {
    if (
      value === undefined ||
      value === "" ||
      value.trim() !== value ||
      /[\u0000-\u001f\u007f]/u.test(value)
    ) {
      throw new MarketingConfigurationError();
    }
    const url = new URL(value);
    const loopback = LOCAL_HOSTNAMES.has(url.hostname);
    if (
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.origin !== value ||
      (url.protocol !== "https:" &&
        !(url.protocol === "http:" && !productionLike && loopback))
    ) {
      throw new MarketingConfigurationError();
    }
    return url.origin;
  } catch {
    if (productionLike) {
      throw new MarketingConfigurationError();
    }
    return LOCAL_MARKETING_ORIGIN;
  }
}

export function safeContactEmail(value: string | undefined): string | null {
  return normalizePrivacyContactEmail(value);
}
