export const CONSOLE_AUTH_MODE_OIDC = "oidc" as const;
export const CONSOLE_AUTH_MODE_UNSIGNED_LOCAL = "unsigned-local" as const;

const PRODUCTION_LIKE_ENVIRONMENTS = new Set(["production", "staging"]);
const LOCAL_ENVIRONMENTS = new Set(["ci", "dev", "development", "local", "test"]);
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_:-]{0,63}$/;
const CLAIM_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const SUBJECT_RE = /^[^\u0000-\u001f\u007f]{1,256}$/;

export class ConsoleRuntimeConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConsoleRuntimeConfigError";
  }
}

export interface ConsoleIdentity {
  readonly tenantId: string;
  readonly subjectId: string;
  readonly roles: readonly string[];
}

interface ConsoleRuntimeBase {
  readonly environment: string;
  readonly productionLike: boolean;
  readonly publicOrigin: string;
  readonly apiOrigin: string;
  readonly allowInsecureLocalHttp: boolean;
}

export interface ConsoleOidcRuntimeConfig extends ConsoleRuntimeBase {
  readonly authMode: typeof CONSOLE_AUTH_MODE_OIDC;
  readonly issuer: string;
  readonly clientId: string;
  readonly apiAudience: string;
  readonly tenantClaim: string;
  readonly rolesClaim: string;
  readonly requiredRoles: readonly string[];
  readonly clockSkewSeconds: number;
  readonly httpTimeoutMs: number;
  readonly discoveryCacheTtlSeconds: number;
  readonly jwksCacheTtlSeconds: number;
  readonly providerFailureCooldownSeconds: number;
  readonly transactionTtlSeconds: number;
  readonly sessionMaxSeconds: number;
  readonly authRateLimitWindowSeconds: number;
  readonly loginRateLimitMax: number;
  readonly callbackRateLimitMax: number;
  readonly trustedProxyHops: number;
}

export interface ConsoleUnsignedLocalRuntimeConfig extends ConsoleRuntimeBase {
  readonly authMode: typeof CONSOLE_AUTH_MODE_UNSIGNED_LOCAL;
  readonly localIdentity: ConsoleIdentity;
}

export type ConsoleRuntimeConfig =
  | ConsoleOidcRuntimeConfig
  | ConsoleUnsignedLocalRuntimeConfig;

export type BrowserRuntimeConfig =
  | {
      readonly authMode: typeof CONSOLE_AUTH_MODE_OIDC;
    }
  | {
      readonly authMode: typeof CONSOLE_AUTH_MODE_UNSIGNED_LOCAL;
    };

export function loadConsoleRuntimeConfig(
  env: Readonly<Record<string, string | undefined>> = process.env
): ConsoleRuntimeConfig {
  const environment = required(env, "HALLU_DEFENSE_ENV").toLowerCase();
  const productionLike = PRODUCTION_LIKE_ENVIRONMENTS.has(environment);
  if (!productionLike && !LOCAL_ENVIRONMENTS.has(environment)) {
    throw new ConsoleRuntimeConfigError("Console environment is not approved.");
  }
  const allowInsecureLocalHttp = strictBoolean(
    env,
    "HALLU_DEFENSE_CONSOLE_ALLOW_INSECURE_LOCAL_HTTP",
    false
  );
  if (productionLike && allowInsecureLocalHttp) {
    throw new ConsoleRuntimeConfigError(
      "Production console cannot enable insecure local HTTP."
    );
  }
  const demoFixtureRequested = strictBoolean(
    env,
    "HALLU_DEFENSE_CONSOLE_DEMO_FIXTURE_ENABLED",
    false
  );
  if (demoFixtureRequested) {
    throw new ConsoleRuntimeConfigError(
      "Console demo verification fixtures are not supported."
    );
  }
  const publicOrigin = parseOrigin(
    required(env, "HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN"),
    "console public origin",
    allowInsecureLocalHttp
  );
  const apiOrigin = parseOrigin(
    required(env, "HALLU_DEFENSE_CONSOLE_API_ORIGIN"),
    "console API origin",
    allowInsecureLocalHttp
  );
  const authMode = required(env, "HALLU_DEFENSE_CONSOLE_AUTH_MODE").toLowerCase();

  const base: ConsoleRuntimeBase = {
    environment,
    productionLike,
    publicOrigin,
    apiOrigin,
    allowInsecureLocalHttp
  };
  if (authMode === CONSOLE_AUTH_MODE_UNSIGNED_LOCAL) {
    if (
      productionLike ||
      !strictBoolean(env, "HALLU_DEFENSE_CONSOLE_ALLOW_UNSIGNED_LOCAL", false)
    ) {
      throw new ConsoleRuntimeConfigError(
        "Unsigned console identity is restricted to explicit local fixtures."
      );
    }
    const tenantId = required(env, "HALLU_DEFENSE_CONSOLE_LOCAL_TENANT_ID");
    const subjectId = required(env, "HALLU_DEFENSE_CONSOLE_LOCAL_SUBJECT_ID");
    if (!TENANT_RE.test(tenantId)) {
      throw new ConsoleRuntimeConfigError("Local console tenant is invalid.");
    }
    if (!SUBJECT_RE.test(subjectId) || subjectId.trim() !== subjectId) {
      throw new ConsoleRuntimeConfigError("Local console subject is invalid.");
    }
    return {
      ...base,
      authMode,
      localIdentity: {
        tenantId,
        subjectId,
        roles: parseRoles(required(env, "HALLU_DEFENSE_CONSOLE_LOCAL_ROLES"))
      }
    };
  }
  if (authMode !== CONSOLE_AUTH_MODE_OIDC) {
    throw new ConsoleRuntimeConfigError("Console auth mode is invalid.");
  }
  const issuer = parseIssuer(
    required(env, "HALLU_DEFENSE_CONSOLE_OIDC_ISSUER"),
    allowInsecureLocalHttp
  );
  const clientId = safeIdentifier(
    required(env, "HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID"),
    "OIDC client id"
  );
  const apiAudience = safeIdentifier(
    required(env, "HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE"),
    "OIDC API audience"
  );
  const tenantClaim = claimName(
    env.HALLU_DEFENSE_CONSOLE_OIDC_TENANT_CLAIM ?? "tenant_id",
    "OIDC tenant claim"
  );
  const rolesClaim = claimName(
    env.HALLU_DEFENSE_CONSOLE_OIDC_ROLES_CLAIM ?? "roles",
    "OIDC roles claim"
  );
  return {
    ...base,
    authMode,
    issuer,
    clientId,
    apiAudience,
    tenantClaim,
    rolesClaim,
    requiredRoles: parseRoles(
      required(env, "HALLU_DEFENSE_CONSOLE_OIDC_REQUIRED_ROLES")
    ),
    clockSkewSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_CLOCK_SKEW_SECONDS",
      30,
      0,
      120
    ),
    httpTimeoutMs: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_HTTP_TIMEOUT_MS",
      5000,
      500,
      15000
    ),
    discoveryCacheTtlSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_DISCOVERY_CACHE_TTL_SECONDS",
      300,
      30,
      86400
    ),
    jwksCacheTtlSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_JWKS_CACHE_TTL_SECONDS",
      300,
      30,
      86400
    ),
    providerFailureCooldownSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_FAILURE_COOLDOWN_SECONDS",
      5,
      1,
      300
    ),
    transactionTtlSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_OIDC_TRANSACTION_TTL_SECONDS",
      300,
      60,
      600
    ),
    sessionMaxSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_SESSION_MAX_SECONDS",
      3600,
      60,
      86400
    ),
    authRateLimitWindowSeconds: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_AUTH_RATE_LIMIT_WINDOW_SECONDS",
      60,
      10,
      600
    ),
    loginRateLimitMax: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_LOGIN_RATE_LIMIT_MAX",
      20,
      1,
      1000
    ),
    callbackRateLimitMax: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_CALLBACK_RATE_LIMIT_MAX",
      30,
      1,
      1000
    ),
    trustedProxyHops: boundedInteger(
      env,
      "HALLU_DEFENSE_CONSOLE_TRUSTED_PROXY_HOPS",
      0,
      0,
      8
    )
  };
}

export function browserRuntimeConfig(config: ConsoleRuntimeConfig): BrowserRuntimeConfig {
  return { authMode: config.authMode };
}

export function parseOrigin(
  value: string,
  label: string,
  allowInsecureLocalHttp: boolean
): string {
  const url = absoluteUrl(value, label);
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new ConsoleRuntimeConfigError(
      `${label} must not contain credentials, path, query, or fragment.`
    );
  }
  validateSchemeAndHost(url, label, allowInsecureLocalHttp);
  if (value !== url.origin) {
    throw new ConsoleRuntimeConfigError(`${label} must use its canonical origin form.`);
  }
  return url.origin;
}

export function parseIssuer(value: string, allowInsecureLocalHttp: boolean): string {
  const url = absoluteUrl(value, "OIDC issuer");
  const pathSegments = url.pathname.split("/").slice(1);
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname === "/" ||
    url.pathname.endsWith("/") ||
    url.pathname.includes("%") ||
    url.pathname.includes("\\") ||
    pathSegments.some(
      (segment) =>
        segment === "" ||
        segment === "." ||
        segment === ".." ||
        !/^[A-Za-z0-9._~-]+$/u.test(segment)
    )
  ) {
    throw new ConsoleRuntimeConfigError(
      "OIDC issuer must be a canonical absolute realm URL without credentials, query, or fragment."
    );
  }
  validateSchemeAndHost(url, "OIDC issuer", allowInsecureLocalHttp);
  const canonical = `${url.origin}${url.pathname}`;
  if (value !== canonical) {
    throw new ConsoleRuntimeConfigError("OIDC issuer must use canonical URL form.");
  }
  return canonical;
}

function validateSchemeAndHost(
  url: URL,
  label: string,
  allowInsecureLocalHttp: boolean
): void {
  if (url.protocol === "https:") {
    return;
  }
  if (
    url.protocol !== "http:" ||
    !allowInsecureLocalHttp ||
    !isLoopbackHostname(url.hostname)
  ) {
    throw new ConsoleRuntimeConfigError(
      `${label} must use HTTPS; HTTP is limited to an explicit loopback fixture.`
    );
  }
}

function absoluteUrl(value: string, label: string): URL {
  if (value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ConsoleRuntimeConfigError(`${label} is invalid.`);
  }
  try {
    return new URL(value);
  } catch {
    throw new ConsoleRuntimeConfigError(`${label} must be an absolute URL.`);
  }
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function required(
  env: Readonly<Record<string, string | undefined>>,
  name: string
): string {
  const value = env[name];
  if (value === undefined || value.trim() === "") {
    throw new ConsoleRuntimeConfigError(`${name} is required.`);
  }
  if (value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ConsoleRuntimeConfigError(`${name} is invalid.`);
  }
  return value;
}

function strictBoolean(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  defaultValue: boolean
): boolean {
  const raw = env[name];
  if (raw === undefined || raw === "") {
    return defaultValue;
  }
  if (raw === "true") {
    return true;
  }
  if (raw === "false") {
    return false;
  }
  throw new ConsoleRuntimeConfigError(`${name} must be true or false.`);
}

function boundedInteger(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  defaultValue: number,
  minimum: number,
  maximum: number
): number {
  const raw = env[name];
  if (raw === undefined || raw === "") {
    return defaultValue;
  }
  if (!/^(0|[1-9][0-9]*)$/u.test(raw)) {
    throw new ConsoleRuntimeConfigError(`${name} must be an integer.`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new ConsoleRuntimeConfigError(`${name} is outside its allowed bounds.`);
  }
  return value;
}

function safeIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) {
    throw new ConsoleRuntimeConfigError(`${label} is invalid.`);
  }
  return value;
}

function claimName(value: string, label: string): string {
  if (!CLAIM_RE.test(value)) {
    throw new ConsoleRuntimeConfigError(`${label} is invalid.`);
  }
  return value;
}

function parseRoles(value: string): readonly string[] {
  const roles = value.split(",").map((role) => role.trim());
  if (
    roles.length === 0 ||
    roles.some((role) => !ROLE_RE.test(role)) ||
    new Set(roles).size !== roles.length
  ) {
    throw new ConsoleRuntimeConfigError("Console roles must be unique canonical names.");
  }
  return Object.freeze([...roles].sort());
}
