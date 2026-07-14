import { readFileSync } from "node:fs";

import { createClient } from "redis";

import type { EnabledDemoRuntimeConfig } from "./config";

const GLOBAL_LIMIT = 60;
const GLOBAL_WINDOW_MILLISECONDS = 60_000;
const EMAIL_LIMIT = 3;
const EMAIL_WINDOW_MILLISECONDS = 3_600_000;
const IDEMPOTENCY_TTL_MILLISECONDS = 86_400_000;
const RESERVATION_LEASE_MILLISECONDS = 15_000;
const KEY_PREFIX = "hallu-defense:demo-request:v1";

export const RESERVE_SCRIPT = `
local state = redis.call('HMGET', KEYS[3], 'status', 'request_id', 'lease_until')
if state[2] then
  if state[1] == 'completed' then
    return {'duplicate', state[2]}
  end
  local lease_until = tonumber(state[3] or '0')
  if state[1] == 'processing' and lease_until > tonumber(ARGV[8]) then
    return {'pending', state[2]}
  end
  if state[1] ~= 'processing' and state[1] ~= 'retryable' then
    return {'invalid', ''}
  end
  redis.call('HSET', KEYS[3],
    'status', 'processing',
    'request_id', state[2],
    'lease_token', ARGV[6],
    'lease_until', tonumber(ARGV[8]) + tonumber(ARGV[7]))
  redis.call('PEXPIRE', KEYS[3], ARGV[5])
  return {'reserved', state[2]}
end

local global_count = redis.call('INCR', KEYS[1])
if global_count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if global_count > tonumber(ARGV[1]) then return {'rate_global', ''} end

local email_count = redis.call('INCR', KEYS[2])
if email_count == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[4]) end
if email_count > tonumber(ARGV[3]) then return {'rate_email', ''} end

redis.call('HSET', KEYS[3],
  'status', 'processing',
  'request_id', ARGV[9],
  'lease_token', ARGV[6],
  'lease_until', tonumber(ARGV[8]) + tonumber(ARGV[7]))
redis.call('PEXPIRE', KEYS[3], ARGV[5])
return {'reserved', ARGV[9]}
`.trim();

export const FINALIZE_SCRIPT = `
if redis.call('HGET', KEYS[1], 'status') ~= 'processing' then return 0 end
if redis.call('HGET', KEYS[1], 'lease_token') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'status', 'completed')
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until')
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`.trim();

export const RELEASE_SCRIPT = `
if redis.call('HGET', KEYS[1], 'status') ~= 'processing' then return 0 end
if redis.call('HGET', KEYS[1], 'lease_token') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'status', 'retryable')
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until')
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`.trim();

export type ReservationStatus =
  | "reserved"
  | "duplicate"
  | "pending"
  | "rate_global"
  | "rate_email";

export interface DemoReservation {
  readonly status: ReservationStatus;
  readonly requestId?: string;
}

export interface DemoReservationInput {
  readonly submissionIdDigest: string;
  readonly emailDigest: string;
  readonly requestId: string;
  readonly leaseToken: string;
  readonly nowMilliseconds: number;
}

export interface DemoStore {
  reserve(input: DemoReservationInput): Promise<DemoReservation>;
  finalize(submissionIdDigest: string, leaseToken: string): Promise<boolean>;
  release(submissionIdDigest: string, leaseToken: string): Promise<boolean>;
}

export interface RedisCommandClient {
  readonly isOpen: boolean;
  connect(): Promise<unknown>;
  sendCommand(arguments_: readonly string[]): Promise<unknown>;
}

export class DemoStoreUnavailableError extends Error {
  constructor() {
    super("Demo request state is unavailable.");
    this.name = "DemoStoreUnavailableError";
  }
}

export class RedisDemoStore implements DemoStore {
  private connectPromise: Promise<unknown> | undefined;

  constructor(private readonly client: RedisCommandClient) {}

  async reserve(input: DemoReservationInput): Promise<DemoReservation> {
    const idempotencyKey = idempotencyRedisKey(input.submissionIdDigest);
    const result = await this.command([
      "EVAL",
      RESERVE_SCRIPT,
      "3",
      `${KEY_PREFIX}:global`,
      `${KEY_PREFIX}:email:${input.emailDigest}`,
      idempotencyKey,
      String(GLOBAL_LIMIT),
      String(GLOBAL_WINDOW_MILLISECONDS),
      String(EMAIL_LIMIT),
      String(EMAIL_WINDOW_MILLISECONDS),
      String(IDEMPOTENCY_TTL_MILLISECONDS),
      input.leaseToken,
      String(RESERVATION_LEASE_MILLISECONDS),
      String(input.nowMilliseconds),
      input.requestId
    ]);
    return parseReservation(result);
  }

  async finalize(submissionIdDigest: string, leaseToken: string): Promise<boolean> {
    const result = await this.command([
      "EVAL",
      FINALIZE_SCRIPT,
      "1",
      idempotencyRedisKey(submissionIdDigest),
      leaseToken,
      String(IDEMPOTENCY_TTL_MILLISECONDS)
    ]);
    return parseCasResult(result);
  }

  async release(submissionIdDigest: string, leaseToken: string): Promise<boolean> {
    const result = await this.command([
      "EVAL",
      RELEASE_SCRIPT,
      "1",
      idempotencyRedisKey(submissionIdDigest),
      leaseToken,
      String(IDEMPOTENCY_TTL_MILLISECONDS)
    ]);
    return parseCasResult(result);
  }

  private async command(arguments_: readonly string[]): Promise<unknown> {
    try {
      if (!this.client.isOpen) {
        this.connectPromise ??= this.client.connect();
        await this.connectPromise;
      }
      return await this.client.sendCommand(arguments_);
    } catch {
      this.connectPromise = undefined;
      throw new DemoStoreUnavailableError();
    }
  }
}

export function createRedisDemoStore(config: EnabledDemoRuntimeConfig): RedisDemoStore {
  const socket = config.redisUrl.startsWith("rediss:")
    ? {
        connectTimeout: 1_000,
        reconnectStrategy: false as const,
        tls: true as const,
        ca: config.redisCaPath === undefined ? undefined : readFileSync(config.redisCaPath)
      }
    : { connectTimeout: 1_000, reconnectStrategy: false as const };
  const client = createClient({ url: config.redisUrl, socket });
  client.on("error", () => undefined);
  return new RedisDemoStore(client);
}

function parseReservation(value: unknown): DemoReservation {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new DemoStoreUnavailableError();
  }
  const [rawStatus, rawRequestId] = value;
  const status = decodeRedisString(rawStatus);
  const requestId = decodeRedisString(rawRequestId);
  if (!isReservationStatus(status)) {
    throw new DemoStoreUnavailableError();
  }
  if (status === "rate_global" || status === "rate_email") {
    if (requestId !== "") {
      throw new DemoStoreUnavailableError();
    }
    return { status };
  }
  if (!/^dr_[A-Za-z0-9_-]{24}$/u.test(requestId)) {
    throw new DemoStoreUnavailableError();
  }
  return { status, requestId };
}

function parseCasResult(value: unknown): boolean {
  if (value === 0) {
    return false;
  }
  if (value === 1) {
    return true;
  }
  throw new DemoStoreUnavailableError();
}

function decodeRedisString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  }
  throw new DemoStoreUnavailableError();
}

function isReservationStatus(value: string): value is ReservationStatus {
  return ["reserved", "duplicate", "pending", "rate_global", "rate_email"].includes(
    value
  );
}

function idempotencyRedisKey(submissionIdDigest: string): string {
  if (!/^[0-9a-f]{64}$/u.test(submissionIdDigest)) {
    throw new TypeError("Submission id digest must be canonical SHA-256 hex.");
  }
  return `${KEY_PREFIX}:idempotency:${submissionIdDigest}`;
}
