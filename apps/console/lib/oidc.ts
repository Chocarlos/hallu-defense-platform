import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import type { ConsoleOidcRuntimeConfig } from "./runtime-config";

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_JWT_SEGMENT_BYTES = 16 * 1024;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_:-]{0,63}$/u;
const MAX_PROVIDER_CACHE_ENTRIES = 8;

export class OidcSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidcSecurityError";
  }
}

class OidcSigningKeyNotFoundError extends OidcSecurityError {
  constructor() {
    super("OIDC signing key is unavailable.");
    this.name = "OidcSigningKeyNotFoundError";
  }
}

export interface OidcDiscovery {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
}

export interface PkceMaterial {
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
  readonly challenge: string;
}

export interface OidcTokenResponse {
  readonly accessToken: string;
  readonly idToken: string;
  readonly tokenType: "Bearer";
}

export interface AuthenticatedTokenSet {
  readonly accessToken: string;
  readonly expiresAtSeconds: number;
  readonly tenantId: string;
  readonly subjectId: string;
  readonly roles: readonly string[];
}

interface JwtPayload {
  readonly [name: string]: unknown;
}

type FetchImplementation = typeof fetch;

interface OidcCacheEntry<T> {
  value: T | undefined;
  expiresAtMs: number;
  failureUntilMs: number;
  forcedRefreshAfterMs: number;
  inFlight: Promise<T> | undefined;
}

interface OidcProviderCache {
  readonly discoveries: Map<string, OidcCacheEntry<OidcDiscovery>>;
  readonly jwks: Map<string, OidcCacheEntry<Readonly<Record<string, unknown>>>>;
}

export interface OidcCacheReadOptions {
  readonly currentTimeMs?: number;
}

declare global {
  var __halluConsoleOidcProviderCache: OidcProviderCache | undefined;
}

export function createPkceMaterial(): PkceMaterial {
  const verifier = randomBase64Url();
  return {
    state: randomBase64Url(),
    nonce: randomBase64Url(),
    verifier,
    challenge: createHash("sha256").update(verifier, "ascii").digest("base64url")
  };
}

export function buildAuthorizationUrl(
  config: ConsoleOidcRuntimeConfig,
  discovery: OidcDiscovery,
  material: PkceMaterial
): string {
  const url = new URL(discovery.authorizationEndpoint);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", callbackUrl(config));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid profile");
  url.searchParams.set("state", material.state);
  url.searchParams.set("nonce", material.nonce);
  url.searchParams.set("code_challenge", material.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function discoverOidc(
  config: ConsoleOidcRuntimeConfig,
  fetchImpl: FetchImplementation = globalThis.fetch,
  options: OidcCacheReadOptions = {}
): Promise<OidcDiscovery> {
  const nowMs = options.currentTimeMs ?? Date.now();
  return cachedOidcResource(
    providerCache().discoveries,
    config.issuer,
    config.discoveryCacheTtlSeconds * 1000,
    config.providerFailureCooldownSeconds * 1000,
    nowMs,
    async () => fetchDiscoveryDocument(config, fetchImpl),
    false
  );
}

async function fetchDiscoveryDocument(
  config: ConsoleOidcRuntimeConfig,
  fetchImpl: FetchImplementation
): Promise<OidcDiscovery> {
  const document = await fetchJson(
    `${config.issuer}/.well-known/openid-configuration`,
    { method: "GET" },
    config.httpTimeoutMs,
    fetchImpl
  );
  if (document.issuer !== config.issuer) {
    throw new OidcSecurityError("OIDC discovery issuer does not match configuration.");
  }
  const authorizationEndpoint = discoveryEndpoint(
    document.authorization_endpoint,
    "authorization endpoint",
    config
  );
  const tokenEndpoint = discoveryEndpoint(document.token_endpoint, "token endpoint", config);
  const jwksUri = discoveryEndpoint(document.jwks_uri, "JWKS endpoint", config);
  const challengeMethods = document.code_challenge_methods_supported;
  if (!stringArray(challengeMethods).includes("S256")) {
    throw new OidcSecurityError("OIDC provider does not advertise PKCE S256.");
  }
  const responseTypes = stringArray(document.response_types_supported);
  if (!responseTypes.includes("code")) {
    throw new OidcSecurityError("OIDC provider does not advertise authorization code flow.");
  }
  return Object.freeze({
    issuer: config.issuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri
  });
}

export async function exchangeAuthorizationCode(
  config: ConsoleOidcRuntimeConfig,
  discovery: OidcDiscovery,
  code: string,
  verifier: string,
  fetchImpl: FetchImplementation = globalThis.fetch
): Promise<OidcTokenResponse> {
  if (!isOpaqueCallbackValue(code, 4096) || !isPkceVerifier(verifier)) {
    throw new OidcSecurityError("OIDC callback values are invalid.");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    redirect_uri: callbackUrl(config),
    code,
    code_verifier: verifier
  });
  const payload = await fetchJson(
    discovery.tokenEndpoint,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    },
    config.httpTimeoutMs,
    fetchImpl
  );
  if (payload.token_type !== "Bearer") {
    throw new OidcSecurityError("OIDC token response must use Bearer token type.");
  }
  const accessToken = tokenString(payload.access_token, "access token");
  const idToken = tokenString(payload.id_token, "ID token");
  return { accessToken, idToken, tokenType: "Bearer" };
}

export async function validateTokenSet(
  config: ConsoleOidcRuntimeConfig,
  discovery: OidcDiscovery,
  tokenResponse: OidcTokenResponse,
  expectedNonce: string,
  options: {
    readonly currentTimeSeconds?: number;
    readonly currentTimeMs?: number;
    readonly fetchImpl?: FetchImplementation;
  } = {}
): Promise<AuthenticatedTokenSet> {
  if (!isOpaqueCallbackValue(expectedNonce, 128)) {
    throw new OidcSecurityError("OIDC nonce is invalid.");
  }
  const now = options.currentTimeSeconds ?? Math.floor(Date.now() / 1000);
  const cacheNowMs = options.currentTimeMs ?? now * 1000;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  let jwks = await cachedJwks(config, discovery, fetchImpl, cacheNowMs, false);
  let payloads: readonly [JwtPayload, JwtPayload];
  try {
    payloads = await verifyTokenPair(tokenResponse, jwks);
  } catch (error) {
    if (!(error instanceof OidcSigningKeyNotFoundError)) {
      throw error;
    }
    jwks = await cachedJwks(config, discovery, fetchImpl, cacheNowMs, true);
    payloads = await verifyTokenPair(tokenResponse, jwks);
  }
  const [idPayload, accessPayload] = payloads;
  validateRegisteredClaims(idPayload, config.issuer, config.clientId, now, config.clockSkewSeconds);
  if (!constantTimeEqual(stringClaim(idPayload, "nonce"), expectedNonce)) {
    throw new OidcSecurityError("OIDC ID token nonce is invalid.");
  }
  validateAuthorizedParty(idPayload, config.clientId);
  validateAtHash(idPayload, tokenResponse.accessToken);

  const accessExpiry = validateRegisteredClaims(
    accessPayload,
    config.issuer,
    config.apiAudience,
    now,
    config.clockSkewSeconds
  );
  validateAuthorizedParty(accessPayload, config.clientId);
  const subjectId = stringClaim(accessPayload, "sub");
  if (subjectId.length > 256) {
    throw new OidcSecurityError("OIDC access token subject is invalid.");
  }
  if (!constantTimeEqual(subjectId, stringClaim(idPayload, "sub"))) {
    throw new OidcSecurityError("OIDC token subjects do not match.");
  }
  const tenantId = stringClaim(accessPayload, config.tenantClaim);
  if (!TENANT_RE.test(tenantId)) {
    throw new OidcSecurityError("OIDC access token tenant is invalid.");
  }
  const roles = rolesClaim(accessPayload[config.rolesClaim]);
  const roleSet = new Set(roles);
  if (config.requiredRoles.some((role) => !roleSet.has(role))) {
    throw new OidcSecurityError("OIDC access token is missing a required console role.");
  }
  const idTenant = idPayload[config.tenantClaim];
  if (idTenant !== undefined && idTenant !== tenantId) {
    throw new OidcSecurityError("OIDC token tenant claims do not match.");
  }
  return {
    accessToken: tokenResponse.accessToken,
    expiresAtSeconds: Math.min(accessExpiry, now + config.sessionMaxSeconds),
    tenantId,
    subjectId,
    roles
  };
}

export function resetOidcProviderCacheForTests(): void {
  globalThis.__halluConsoleOidcProviderCache = undefined;
}

async function cachedJwks(
  config: ConsoleOidcRuntimeConfig,
  discovery: OidcDiscovery,
  fetchImpl: FetchImplementation,
  nowMs: number,
  forceRefresh: boolean
): Promise<Readonly<Record<string, unknown>>> {
  return cachedOidcResource(
    providerCache().jwks,
    discovery.jwksUri,
    config.jwksCacheTtlSeconds * 1000,
    config.providerFailureCooldownSeconds * 1000,
    nowMs,
    async () => {
      const document = await fetchJson(
        discovery.jwksUri,
        { method: "GET" },
        config.httpTimeoutMs,
        fetchImpl
      );
      return normalizeJwksDocument(document);
    },
    forceRefresh
  );
}

async function verifyTokenPair(
  tokenResponse: OidcTokenResponse,
  jwks: Readonly<Record<string, unknown>>
): Promise<readonly [JwtPayload, JwtPayload]> {
  return Promise.all([
    verifyJwt(tokenResponse.idToken, jwks),
    verifyJwt(tokenResponse.accessToken, jwks)
  ]);
}

export function callbackUrl(config: ConsoleOidcRuntimeConfig): string {
  return `${config.publicOrigin}/auth/callback`;
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export function isOpaqueCallbackValue(value: string, maximumLength: number): boolean {
  return (
    value.length >= 16 &&
    value.length <= maximumLength &&
    /^[A-Za-z0-9._~-]+$/u.test(value)
  );
}

async function verifyJwt(token: string, jwks: Readonly<Record<string, unknown>>): Promise<JwtPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new OidcSecurityError("OIDC JWT must have three segments.");
  }
  const encodedHeader = parts[0];
  const encodedPayload = parts[1];
  const encodedSignature = parts[2];
  if (
    encodedHeader === undefined ||
    encodedPayload === undefined ||
    encodedSignature === undefined
  ) {
    throw new OidcSecurityError("OIDC JWT is invalid.");
  }
  const header = jsonObject(decodeBase64Url(encodedHeader), "OIDC JWT header");
  const payload = jsonObject(decodeBase64Url(encodedPayload), "OIDC JWT payload");
  if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid === "") {
    throw new OidcSecurityError("OIDC JWT signing metadata is invalid.");
  }
  if (header.typ !== undefined && header.typ !== "JWT" && header.typ !== "at+jwt") {
    throw new OidcSecurityError("OIDC JWT type is invalid.");
  }
  const jwk = rsaSigningKey(jwks, header.kid);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch {
    throw new OidcSecurityError("OIDC signing key could not be imported.");
  }
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    ownedArrayBuffer(decodeBase64Url(encodedSignature)),
    ownedArrayBuffer(Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"))
  );
  if (!verified) {
    throw new OidcSecurityError("OIDC JWT signature is invalid.");
  }
  return payload;
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned.buffer;
}

function validateRegisteredClaims(
  payload: JwtPayload,
  issuer: string,
  audience: string,
  now: number,
  skew: number
): number {
  if (payload.iss !== issuer) {
    throw new OidcSecurityError("OIDC JWT issuer is invalid.");
  }
  if (!audiences(payload.aud).includes(audience)) {
    throw new OidcSecurityError("OIDC JWT audience is invalid.");
  }
  const expiry = integerClaim(payload, "exp", true);
  if (expiry === undefined || now > expiry + skew) {
    throw new OidcSecurityError("OIDC JWT is expired.");
  }
  const notBefore = integerClaim(payload, "nbf", false);
  if (notBefore !== undefined && now + skew < notBefore) {
    throw new OidcSecurityError("OIDC JWT is not valid yet.");
  }
  const issuedAt = integerClaim(payload, "iat", false);
  if (issuedAt !== undefined && now + skew < issuedAt) {
    throw new OidcSecurityError("OIDC JWT issued-at time is invalid.");
  }
  return expiry;
}

function validateAuthorizedParty(payload: JwtPayload, clientId: string): void {
  const audience = audiences(payload.aud);
  const authorizedParty = payload.azp;
  if (audience.length > 1 && authorizedParty !== clientId) {
    throw new OidcSecurityError("OIDC JWT authorized party is invalid.");
  }
  if (authorizedParty !== undefined && authorizedParty !== clientId) {
    throw new OidcSecurityError("OIDC JWT authorized party is invalid.");
  }
}

function validateAtHash(payload: JwtPayload, accessToken: string): void {
  if (payload.at_hash === undefined) {
    return;
  }
  const supplied = stringClaim(payload, "at_hash");
  const expected = createHash("sha256")
    .update(accessToken, "ascii")
    .digest()
    .subarray(0, 16)
    .toString("base64url");
  if (!constantTimeEqual(supplied, expected)) {
    throw new OidcSecurityError("OIDC ID token access-token hash is invalid.");
  }
}

function rsaSigningKey(jwks: Readonly<Record<string, unknown>>, kid: string): JsonWebKey {
  const keys = jwks.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 32) {
    throw new OidcSecurityError("OIDC JWKS keys are invalid.");
  }
  const matches = keys.filter(
    (candidate): candidate is Readonly<Record<string, unknown>> =>
      isRecord(candidate) && candidate.kid === kid
  );
  if (matches.length === 0) {
    throw new OidcSigningKeyNotFoundError();
  }
  if (matches.length !== 1) {
    throw new OidcSecurityError("OIDC signing key is ambiguous.");
  }
  const key = matches[0];
  if (
    key === undefined ||
    key.kty !== "RSA" ||
    (key.use !== undefined && key.use !== "sig") ||
    (key.alg !== undefined && key.alg !== "RS256") ||
    typeof key.n !== "string" ||
    typeof key.e !== "string" ||
    !BASE64URL_RE.test(key.n) ||
    !BASE64URL_RE.test(key.e)
  ) {
    throw new OidcSecurityError("OIDC signing key is invalid.");
  }
  return { kty: "RSA", n: key.n, e: key.e, alg: "RS256", ext: true };
}

async function fetchJson(
  url: string,
  init: Readonly<RequestInit>,
  timeoutMs: number,
  fetchImpl: FetchImplementation
): Promise<Readonly<Record<string, unknown>>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      ...init,
      redirect: "error",
      cache: "no-store",
      headers: {
        accept: "application/json",
        ...headersRecord(init.headers)
      },
      signal: controller.signal
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new OidcSecurityError("OIDC endpoint rejected the request.");
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/json") {
      await response.body?.cancel();
      throw new OidcSecurityError("OIDC endpoint returned an invalid content type.");
    }
    const raw = await readBoundedBody(response, MAX_JSON_BYTES);
    return jsonObject(raw, "OIDC JSON response");
  } catch (error) {
    if (error instanceof OidcSecurityError) {
      throw error;
    }
    throw new OidcSecurityError("OIDC request failed.");
  } finally {
    clearTimeout(timeout);
  }
}

async function readBoundedBody(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > maximumBytes)
  ) {
    await response.body?.cancel();
    throw new OidcSecurityError("OIDC JSON response exceeded its byte limit.");
  }
  if (response.body === null) {
    throw new OidcSecurityError("OIDC endpoint returned an empty response.");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new OidcSecurityError("OIDC JSON response exceeded its byte limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

function discoveryEndpoint(
  raw: unknown,
  label: string,
  config: ConsoleOidcRuntimeConfig
): string {
  if (typeof raw !== "string" || raw.trim() !== raw) {
    throw new OidcSecurityError(`OIDC ${label} is invalid.`);
  }
  let endpoint: URL;
  try {
    endpoint = new URL(raw);
  } catch {
    throw new OidcSecurityError(`OIDC ${label} is invalid.`);
  }
  const issuer = new URL(config.issuer);
  if (
    endpoint.origin !== issuer.origin ||
    !endpoint.pathname.startsWith(`${issuer.pathname}/`) ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    endpoint.protocol !== issuer.protocol ||
    endpoint.pathname.includes("%") ||
    raw !== `${endpoint.origin}${endpoint.pathname}`
  ) {
    throw new OidcSecurityError(`OIDC ${label} escaped the configured issuer boundary.`);
  }
  return raw;
}

function tokenString(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 32 ||
    value.length > 32768 ||
    /[\u0000-\u0020\u007f]/u.test(value)
  ) {
    throw new OidcSecurityError(`OIDC ${label} is invalid.`);
  }
  return value;
}

function isPkceVerifier(value: string): boolean {
  return value.length >= 43 && value.length <= 128 && BASE64URL_RE.test(value);
}

function randomBase64Url(): string {
  return randomBytes(32).toString("base64url");
}

function jsonObject(raw: Uint8Array, label: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    throw new OidcSecurityError(`${label} is not valid JSON.`);
  }
  if (!isRecord(parsed)) {
    throw new OidcSecurityError(`${label} must be an object.`);
  }
  return parsed;
}

function decodeBase64Url(value: string): Uint8Array {
  if (
    value.length === 0 ||
    value.length > MAX_JWT_SEGMENT_BYTES ||
    !BASE64URL_RE.test(value)
  ) {
    throw new OidcSecurityError("OIDC JWT contains invalid base64url data.");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new OidcSecurityError("OIDC JWT contains non-canonical base64url data.");
  }
  return decoded;
}

function audiences(value: unknown): readonly string[] {
  if (typeof value === "string" && value !== "") {
    return [value];
  }
  if (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 16 &&
    value.every((entry) => typeof entry === "string" && entry !== "") &&
    new Set(value).size === value.length
  ) {
    return value;
  }
  throw new OidcSecurityError("OIDC JWT audience claim is invalid.");
}

function integerClaim(payload: JwtPayload, name: string, required: boolean): number | undefined {
  const value = payload[name];
  if (value === undefined && !required) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new OidcSecurityError(`OIDC JWT ${name} claim is invalid.`);
  }
  return value as number;
}

function stringClaim(payload: JwtPayload, name: string): string {
  const value = payload[name];
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new OidcSecurityError(`OIDC JWT ${name} claim is invalid.`);
  }
  return value;
}

function rolesClaim(value: unknown): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > 64 ||
    value.some((role) => typeof role !== "string" || !ROLE_RE.test(role)) ||
    new Set(value).size !== value.length
  ) {
    throw new OidcSecurityError("OIDC access token roles claim is invalid.");
  }
  return Object.freeze([...value].sort());
}

function stringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    return [];
  }
  return value;
}

function headersRecord(headers: HeadersInit | undefined): Readonly<Record<string, string>> {
  if (headers === undefined) {
    return {};
  }
  const output: Record<string, string> = {};
  new Headers(headers).forEach((value, name) => {
    output[name] = value;
  });
  return output;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerCache(): OidcProviderCache {
  globalThis.__halluConsoleOidcProviderCache ??= {
    discoveries: new Map(),
    jwks: new Map()
  };
  return globalThis.__halluConsoleOidcProviderCache;
}

async function cachedOidcResource<T>(
  entries: Map<string, OidcCacheEntry<T>>,
  key: string,
  ttlMs: number,
  failureCooldownMs: number,
  nowMs: number,
  loader: () => Promise<T>,
  forceRefresh: boolean
): Promise<T> {
  let entry = entries.get(key);
  if (
    entry?.value !== undefined &&
    entry.expiresAtMs > nowMs &&
    (!forceRefresh || entry.forcedRefreshAfterMs > nowMs)
  ) {
    return entry.value;
  }
  if (entry?.inFlight !== undefined) {
    return entry.inFlight;
  }
  if (entry !== undefined && entry.failureUntilMs > nowMs) {
    throw new OidcSecurityError("OIDC provider metadata is temporarily unavailable.");
  }
  if (entry === undefined) {
    purgeProviderCache(entries, nowMs);
    if (entries.size >= MAX_PROVIDER_CACHE_ENTRIES) {
      throw new OidcSecurityError("OIDC provider cache capacity is unavailable.");
    }
    entry = {
      value: undefined,
      expiresAtMs: 0,
      failureUntilMs: 0,
      forcedRefreshAfterMs: 0,
      inFlight: undefined
    };
    entries.set(key, entry);
  }

  const target = entry;
  const inFlight = (async (): Promise<T> => {
    try {
      const value = await loader();
      target.value = value;
      target.expiresAtMs = nowMs + ttlMs;
      target.failureUntilMs = 0;
      target.forcedRefreshAfterMs = nowMs + failureCooldownMs;
      return value;
    } catch (error) {
      target.failureUntilMs = nowMs + failureCooldownMs;
      if (error instanceof OidcSecurityError) {
        throw error;
      }
      throw new OidcSecurityError("OIDC provider metadata request failed.");
    } finally {
      target.inFlight = undefined;
    }
  })();
  target.inFlight = inFlight;
  return inFlight;
}

function purgeProviderCache<T>(entries: Map<string, OidcCacheEntry<T>>, nowMs: number): void {
  for (const [key, entry] of entries) {
    if (
      entry.inFlight === undefined &&
      entry.expiresAtMs <= nowMs &&
      entry.failureUntilMs <= nowMs
    ) {
      entries.delete(key);
    }
  }
}

function normalizeJwksDocument(
  document: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> {
  const keys = document.keys;
  if (
    !Array.isArray(keys) ||
    keys.length === 0 ||
    keys.length > 32 ||
    keys.some((candidate) => !isRecord(candidate))
  ) {
    throw new OidcSecurityError("OIDC JWKS keys are invalid.");
  }
  return Object.freeze({
    keys: Object.freeze(
      keys.map((candidate) => {
        const key = candidate as Readonly<Record<string, unknown>>;
        return Object.freeze({
          kid: key.kid,
          kty: key.kty,
          use: key.use,
          alg: key.alg,
          n: key.n,
          e: key.e
        });
      })
    )
  });
}
