import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";

import type { ConsoleOidcRuntimeConfig } from "./runtime-config";

export const AUTH_RATE_LIMIT_BUCKET_CAPACITY = 4096;

export type AuthRateLimitScope = "login" | "callback";

export interface AuthRateLimitRequest {
  readonly headers: Pick<Headers, "get">;
}

export interface AuthRateLimitDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

interface RateLimitBucket {
  count: number;
  windowEndsAtMs: number;
}

interface AuthRateLimitStore {
  readonly key: Uint8Array;
  readonly buckets: Map<string, RateLimitBucket>;
}

declare global {
  var __halluConsoleAuthRateLimitStore: AuthRateLimitStore | undefined;
}

export function consumeAuthRateLimit(
  scope: AuthRateLimitScope,
  request: AuthRateLimitRequest,
  config: ConsoleOidcRuntimeConfig,
  nowMs: number = Date.now()
): AuthRateLimitDecision {
  const store = rateLimitStore();
  const source = clientSource(request.headers, config.trustedProxyHops);
  const key = createHmac("sha256", store.key)
    .update(scope, "utf8")
    .update("\0", "utf8")
    .update(source, "utf8")
    .digest("base64url");
  const maximum = scope === "login" ? config.loginRateLimitMax : config.callbackRateLimitMax;
  const windowMs = config.authRateLimitWindowSeconds * 1000;

  purgeExpiredBuckets(store.buckets, nowMs);
  const existing = store.buckets.get(key);
  if (existing !== undefined && existing.windowEndsAtMs > nowMs) {
    if (existing.count >= maximum) {
      return denied(existing.windowEndsAtMs, nowMs);
    }
    existing.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }
  if (existing === undefined && store.buckets.size >= AUTH_RATE_LIMIT_BUCKET_CAPACITY) {
    return { allowed: false, retryAfterSeconds: 1 };
  }
  store.buckets.set(key, { count: 1, windowEndsAtMs: nowMs + windowMs });
  return { allowed: true, retryAfterSeconds: 0 };
}

export function resetAuthRateLimitForTests(): void {
  globalThis.__halluConsoleAuthRateLimitStore = undefined;
}

function clientSource(
  headers: Pick<Headers, "get">,
  trustedProxyHops: number
): string {
  if (trustedProxyHops > 0) {
    const address = trustedProxyAddress(headers.get("x-forwarded-for"), trustedProxyHops);
    return address === null ? "proxy-unattributed" : `ip:${address}`;
  }
  return "client-unattributed";
}

function trustedProxyAddress(raw: string | null, trustedProxyHops: number): string | null {
  if (raw === null || raw.length === 0 || raw.length > 512) {
    return null;
  }
  const addresses = raw.split(",").map((part) => part.trim());
  if (
    addresses.length < trustedProxyHops ||
    addresses.length > 16 ||
    addresses.some((address) => isIP(address) === 0)
  ) {
    return null;
  }
  const selected = addresses[addresses.length - trustedProxyHops];
  return selected === undefined ? null : selected.toLowerCase();
}

function rateLimitStore(): AuthRateLimitStore {
  globalThis.__halluConsoleAuthRateLimitStore ??= {
    key: randomBytes(32),
    buckets: new Map()
  };
  return globalThis.__halluConsoleAuthRateLimitStore;
}

function purgeExpiredBuckets(buckets: Map<string, RateLimitBucket>, nowMs: number): void {
  for (const [key, bucket] of buckets) {
    if (bucket.windowEndsAtMs <= nowMs) {
      buckets.delete(key);
    }
  }
}

function denied(
  windowEndsAtMs: number,
  nowMs: number
): AuthRateLimitDecision {
  return {
    allowed: false,
    retryAfterSeconds: Math.max(1, Math.ceil((windowEndsAtMs - nowMs) / 1000))
  };
}
