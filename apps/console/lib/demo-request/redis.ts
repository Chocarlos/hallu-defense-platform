import { createClient } from "redis";

import { readSecretBytes, type EnabledDemoRuntimeConfig } from "./config";

const GLOBAL_LIMIT = 60;
const GLOBAL_WINDOW_MILLISECONDS = 60_000;
const EMAIL_LIMIT = 3;
const EMAIL_WINDOW_MILLISECONDS = 3_600_000;
const IDEMPOTENCY_TTL_MILLISECONDS = 86_400_000;
const RESERVATION_LEASE_MILLISECONDS = 15_000;
const REDIS_COMMAND_TIMEOUT_MILLISECONDS = 1_000;
const KEY_PREFIX = "hallu-defense:demo-request:v1";

export const RESERVE_SCRIPT = `
local global_count = redis.call('INCR', KEYS[1])
if global_count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if global_count > tonumber(ARGV[1]) then return {'rate_global', ''} end

local redis_time = redis.call('TIME')
local now_milliseconds = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state = redis.call('HMGET', KEYS[3], 'status', 'request_id', 'lease_until', 'payload_digest')
if redis.call('EXISTS', KEYS[3]) == 1 then
  if not state[1] or not state[2] or not state[4] or state[4] ~= ARGV[9] then
    return {'conflict', ''}
  end
  if state[1] == 'completed' then
    return {'duplicate', state[2]}
  end
  local lease_until = tonumber(state[3] or '0')
  if state[1] == 'processing' and lease_until > now_milliseconds then
    return {'pending', state[2]}
  end
  if state[1] ~= 'processing' and state[1] ~= 'retryable' then
    return {'invalid', ''}
  end
  redis.call('HSET', KEYS[3],
    'status', 'processing',
    'request_id', state[2],
    'lease_token', ARGV[6],
    'lease_until', now_milliseconds + tonumber(ARGV[7]))
  redis.call('PEXPIRE', KEYS[3], ARGV[5])
  return {'reserved', state[2]}
end

local email_count = redis.call('INCR', KEYS[2])
if email_count == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[4]) end
if email_count > tonumber(ARGV[3]) then return {'rate_email', ''} end

redis.call('HSET', KEYS[3],
  'status', 'processing',
  'request_id', ARGV[8],
  'payload_digest', ARGV[9],
  'lease_token', ARGV[6],
  'lease_until', now_milliseconds + tonumber(ARGV[7]))
redis.call('PEXPIRE', KEYS[3], ARGV[5])
return {'reserved', ARGV[8]}
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
  | "conflict"
  | "rate_global"
  | "rate_email";

export interface DemoReservation {
  readonly status: ReservationStatus;
  readonly requestId?: string;
}

export interface DemoReservationInput {
  readonly submissionIdDigest: string;
  readonly emailDigest: string;
  readonly payloadDigest: string;
  readonly requestId: string;
  readonly leaseToken: string;
}

export interface DemoStore {
  reserve(input: DemoReservationInput): Promise<DemoReservation>;
  finalize(submissionIdDigest: string, leaseToken: string): Promise<boolean>;
  release(submissionIdDigest: string, leaseToken: string): Promise<boolean>;
}

export interface RedisCommandClient {
  readonly isOpen: boolean;
  connect(): Promise<unknown>;
  sendCommand(
    arguments_: readonly string[],
    options?: { readonly abortSignal?: AbortSignal }
  ): Promise<unknown>;
}

export class DemoStoreUnavailableError extends Error {
  constructor() {
    super("Demo request state is unavailable.");
    this.name = "DemoStoreUnavailableError";
  }
}

export class RedisDemoStore implements DemoStore {
  private connectPromise: Promise<unknown> | undefined;

  constructor(
    private readonly client: RedisCommandClient,
    private readonly commandTimeoutMilliseconds = REDIS_COMMAND_TIMEOUT_MILLISECONDS
  ) {
    if (
      !Number.isFinite(commandTimeoutMilliseconds) ||
      commandTimeoutMilliseconds <= 0
    ) {
      throw new TypeError("Redis command timeout must be positive and finite.");
    }
  }

  async reserve(input: DemoReservationInput): Promise<DemoReservation> {
    assertCanonicalDigest(input.emailDigest, "Email");
    assertCanonicalDigest(input.payloadDigest, "Payload");
    if (!/^dr_[A-Za-z0-9_-]{24}$/u.test(input.requestId)) {
      throw new TypeError("Request id must be canonical.");
    }
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
      input.requestId,
      input.payloadDigest
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
        const activeConnect = (this.connectPromise ??= this.client.connect());
        try {
          await activeConnect;
        } finally {
          if (this.connectPromise === activeConnect) {
            this.connectPromise = undefined;
          }
        }
      }
      return await this.client.sendCommand(arguments_, {
        abortSignal: AbortSignal.timeout(this.commandTimeoutMilliseconds)
      });
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
        socketTimeout: 1_000,
        reconnectStrategy: false as const,
        tls: true as const,
        ca:
          config.redisCaPath === undefined
            ? undefined
            : readSecretBytes(config.redisCaPath)
      }
    : {
        connectTimeout: 1_000,
        socketTimeout: 1_000,
        reconnectStrategy: false as const
      };
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
  if (status === "conflict" || status === "rate_global" || status === "rate_email") {
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
  return [
    "reserved",
    "duplicate",
    "pending",
    "conflict",
    "rate_global",
    "rate_email"
  ].includes(value);
}

function idempotencyRedisKey(submissionIdDigest: string): string {
  assertCanonicalDigest(submissionIdDigest, "Submission id");
  return `${KEY_PREFIX}:idempotency:${submissionIdDigest}`;
}

function assertCanonicalDigest(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${label} digest must be canonical SHA-256 hex.`);
  }
}
