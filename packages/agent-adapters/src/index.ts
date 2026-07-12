import type {
  ApprovalExecutionGrant,
  RiskLevel,
  ToolCallEnvelope,
  ToolValidationResponse,
  VerdictAction
} from "@hallu-defense/contracts";
import type { HalluDefenseClient } from "@hallu-defense/sdk";

export type JsonObject = Readonly<Record<string, unknown>>;
export type JsonSchemaObject<TValue extends object = JsonObject> =
  TValue extends object ? JsonObject : never;
export type JsonSchemaScalarType =
  | "array"
  | "boolean"
  | "integer"
  | "null"
  | "number"
  | "object"
  | "string";
export type StrictJsonSchema = JsonObject & {
  readonly type: JsonSchemaScalarType;
};
export type StrictJsonObjectSchema<TValue extends object = JsonObject> = JsonObject & {
  readonly type: "object";
  readonly properties: Readonly<
    Record<Extract<keyof TValue, string>, StrictJsonSchema>
  >;
  readonly required: readonly Extract<keyof TValue, string>[];
  readonly additionalProperties: false;
};
export type ToolValidationPhase = "input" | "output";
export type ToolValidationBlockedCode =
  | "TOOL_INPUT_VALIDATION_BLOCKED"
  | "TOOL_OUTPUT_VALIDATION_BLOCKED";

export type ToolValidationClient = Pick<
  HalluDefenseClient,
  "validateToolInput" | "validateToolOutput"
>;

export interface AgentToolDefinition<
  TInput extends object = JsonObject,
  TOutput extends object = JsonObject
> {
  readonly name: string;
  readonly inputSchema: JsonSchemaObject<TInput>;
  readonly outputSchema: StrictJsonObjectSchema<TOutput>;
  readonly riskLevel?: RiskLevel;
  readonly approvalRequired?: boolean;
}

export interface BuildToolCallEnvelopeInput<TInput extends object = JsonObject> {
  readonly toolName: string;
  readonly input: TInput;
  readonly schema: JsonSchemaObject;
  readonly riskLevel?: RiskLevel;
  readonly approvalRequired?: boolean;
  readonly callerContext?: JsonObject;
  readonly approvalGrant?: AgentApprovalExecutionGrant;
}

export interface AgentApprovalExecutionGrant {
  readonly approvalId: ApprovalExecutionGrant["approval_id"];
  readonly executionToken: ApprovalExecutionGrant["execution_token"];
}

export interface AgentToolCallInput<
  TInput extends object = JsonObject,
  TOutput extends object = JsonObject
> {
  readonly tool: AgentToolDefinition<TInput, TOutput>;
  readonly input: TInput;
  readonly callerContext?: JsonObject;
  readonly approvalGrant?: AgentApprovalExecutionGrant;
}

export interface AgentToolExecutionContext {
  readonly inputEnvelope: ToolCallEnvelope;
  readonly inputValidation: ToolValidationResponse;
}

export interface ExecuteAgentToolOptions<
  TInput extends object = JsonObject,
  TOutput extends object = JsonObject
> extends AgentToolCallInput<TInput, TOutput> {
  readonly execute: (
    input: TInput,
    context: AgentToolExecutionContext
  ) => Promise<TOutput> | TOutput;
}

export interface AgentToolCallResult<TOutput extends object = JsonObject> {
  readonly output: TOutput;
  readonly verdict: AgentToolValidationVerdict;
  readonly trace: AgentToolCallTrace;
}

export interface AgentToolValidationVerdict {
  readonly allowed: boolean;
  readonly action: VerdictAction;
  readonly approvalRequired: boolean;
  readonly approvalId?: string | null;
}

export interface AgentToolValidationTraceEntry extends AgentToolValidationVerdict {
  readonly phase: ToolValidationPhase;
}

export interface AgentToolCallTrace {
  readonly toolName: string;
  readonly riskLevel: RiskLevel;
  readonly phases: readonly [
    AgentToolValidationTraceEntry,
    AgentToolValidationTraceEntry
  ];
}

export interface AgentToolAdapterOptions {
  readonly client: ToolValidationClient;
  readonly defaultRiskLevel?: RiskLevel;
  readonly defaultCallerContext?: JsonObject;
}

export interface AgentToolAdapter {
  readonly buildEnvelope: <TInput extends object>(
    input: BuildToolCallEnvelopeInput<TInput>
  ) => ToolCallEnvelope;
  readonly validateInput: (
    envelope: ToolCallEnvelope
  ) => Promise<ToolValidationResponse>;
  readonly validateOutput: (
    envelope: ToolCallEnvelope
  ) => Promise<ToolValidationResponse>;
  readonly execute: <
    TInput extends object,
    TOutput extends object
  >(
    options: ExecuteAgentToolOptions<TInput, TOutput>
  ) => Promise<AgentToolCallResult<TOutput>>;
}

export class ToolValidationBlockedError extends Error {
  constructor(
    readonly code: ToolValidationBlockedCode,
    readonly phase: ToolValidationPhase,
    readonly toolName: string,
    readonly verdict: AgentToolValidationVerdict
  ) {
    super(`${phase} validation blocked tool '${toolName}'`);
    this.name = "ToolValidationBlockedError";
  }

  get action(): ToolValidationResponse["action"] {
    return this.verdict.action;
  }

  get approvalId(): string | null | undefined {
    return this.verdict.approvalId;
  }
}

export class ToolInputValidationBlockedError extends ToolValidationBlockedError {
  constructor(toolName: string, validation: ToolValidationResponse) {
    super(
      "TOOL_INPUT_VALIDATION_BLOCKED",
      "input",
      toolName,
      safeVerdict(validation, true)
    );
    this.name = "ToolInputValidationBlockedError";
  }
}

export class ToolOutputValidationBlockedError extends ToolValidationBlockedError {
  constructor(toolName: string, validation: ToolValidationResponse) {
    super(
      "TOOL_OUTPUT_VALIDATION_BLOCKED",
      "output",
      toolName,
      safeVerdict(validation)
    );
    this.name = "ToolOutputValidationBlockedError";
  }
}

export class ToolOutputSchemaError extends Error {
  readonly code = "TOOL_OUTPUT_SCHEMA_INVALID" as const;
  readonly phase = "output" as const;

  constructor(readonly toolName: string, detail: string) {
    super(`output schema for tool '${toolName}' is invalid: ${detail}`);
    this.name = "ToolOutputSchemaError";
  }
}

export class ToolInputValidationContractError extends Error {
  readonly code = "TOOL_INPUT_VALIDATION_CONTRACT_INVALID" as const;
  readonly phase = "input" as const;

  constructor(readonly toolName: string, detail: string) {
    super(`input validation for tool '${toolName}' failed closed: ${detail}`);
    this.name = "ToolInputValidationContractError";
  }
}

export class ToolOutputValidationContractError extends Error {
  readonly code = "TOOL_OUTPUT_VALIDATION_CONTRACT_INVALID" as const;
  readonly phase = "output" as const;

  constructor(readonly toolName: string, detail: string) {
    super(`output validation for tool '${toolName}' failed closed: ${detail}`);
    this.name = "ToolOutputValidationContractError";
  }
}

export function buildToolCallEnvelope<TInput extends object>(
  input: BuildToolCallEnvelopeInput<TInput>
): ToolCallEnvelope {
  return {
    tool_name: input.toolName,
    input: requirePayload(input.input, `${input.toolName} input`),
    schema: input.schema,
    risk_level: input.riskLevel ?? "medium",
    approval_required: input.approvalRequired ?? false,
    caller_context: input.callerContext ?? {},
    ...(input.approvalGrant !== undefined
      ? {
          approval_id: input.approvalGrant.approvalId,
          approval_execution_token: input.approvalGrant.executionToken
        }
      : {})
  };
}

export async function validateToolInputOrThrow(
  client: ToolValidationClient,
  envelope: ToolCallEnvelope
): Promise<ToolValidationResponse> {
  const validation = await client.validateToolInput(envelope);
  assertValidationResponseContract(validation, "input", envelope.tool_name);
  if (!validation.allowed) {
    throw new ToolInputValidationBlockedError(envelope.tool_name, validation);
  }
  return validation;
}

export async function validateToolOutputOrThrow(
  client: ToolValidationClient,
  envelope: ToolCallEnvelope
): Promise<ToolValidationResponse> {
  const validation = await client.validateToolOutput(envelope);
  assertValidationResponseContract(validation, "output", envelope.tool_name);
  if (!validation.allowed) {
    throw new ToolOutputValidationBlockedError(envelope.tool_name, validation);
  }
  return validation;
}

export function createAgentToolAdapter(options: AgentToolAdapterOptions): AgentToolAdapter {
  return {
    buildEnvelope: buildToolCallEnvelope,
    validateInput: (envelope) => validateToolInputOrThrow(options.client, envelope),
    validateOutput: (envelope) => validateToolOutputOrThrow(options.client, envelope),
    execute: (request) => executeAgentTool(options, request)
  };
}

export async function executeAgentTool<
  TInput extends object,
  TOutput extends object
>(
  adapterOptions: AgentToolAdapterOptions,
  request: ExecuteAgentToolOptions<TInput, TOutput>
): Promise<AgentToolCallResult<TOutput>> {
  const riskLevel = request.tool.riskLevel ?? adapterOptions.defaultRiskLevel ?? "medium";
  const callerContext = mergeContext(adapterOptions.defaultCallerContext, request.callerContext);
  assertStrictOutputSchema(request.tool.outputSchema, request.tool.name);
  const inputEnvelope = buildToolCallEnvelope({
    toolName: request.tool.name,
    input: request.input,
    schema: request.tool.inputSchema,
    riskLevel,
    approvalRequired: request.tool.approvalRequired ?? false,
    callerContext,
    ...(request.approvalGrant !== undefined ? { approvalGrant: request.approvalGrant } : {})
  });
  const inputValidation = await validateToolInputOrThrow(adapterOptions.client, inputEnvelope);

  const outputValidation = await (async (): Promise<ToolValidationResponse> => {
    const rawOutput = requirePayload(
      await request.execute(request.input, { inputEnvelope, inputValidation }),
      `${request.tool.name} output`
    );
    return validateToolOutputOrThrow(
      adapterOptions.client,
      buildToolCallEnvelope({
        toolName: request.tool.name,
        input: rawOutput,
        schema: request.tool.outputSchema,
        riskLevel,
        // Output validation keeps the canonical definition assertion. The API
        // uses the output phase to avoid requesting a second approval.
        approvalRequired: request.tool.approvalRequired ?? false,
        callerContext
      })
    );
  })();
  const safeOutput = requireSanitizedOutput(outputValidation, request.tool.name);
  assertPayloadMatchesStrictSchema(safeOutput, request.tool.outputSchema, request.tool.name);
  const verdict = safeVerdict(outputValidation);

  return {
    output: safeOutput as TOutput,
    verdict,
    trace: {
      toolName: request.tool.name,
      riskLevel,
      phases: [
        { phase: "input", ...safeVerdict(inputValidation) },
        { phase: "output", ...verdict }
      ]
    }
  };
}

function requireSanitizedOutput(
  validation: ToolValidationResponse,
  toolName: string
): JsonObject {
  if (validation.sanitized_output === undefined || validation.sanitized_output === null) {
    throw new ToolOutputValidationContractError(
      toolName,
      "the API did not return sanitized_output"
    );
  }
  try {
    return materializeSafeJsonObject(validation.sanitized_output, "sanitized_output");
  } catch (error) {
    throw new ToolOutputValidationContractError(
      toolName,
      error instanceof Error ? error.message : "sanitized_output is not safe JSON"
    );
  }
}

function safeVerdict(
  validation: ToolValidationResponse,
  includeApprovalId = false
): AgentToolValidationVerdict {
  return {
    allowed: validation.allowed,
    action: validation.action,
    approvalRequired: validation.approval_required,
    ...(includeApprovalId && validation.approval_id !== undefined
      ? { approvalId: validation.approval_id }
      : {})
  };
}

function assertValidationResponseContract(
  validation: ToolValidationResponse,
  phase: ToolValidationPhase,
  toolName: string
): void {
  const validShape =
    isPlainDataObject(validation) &&
    typeof validation.allowed === "boolean" &&
    isVerdictAction(validation.action) &&
    typeof validation.reason === "string" &&
    typeof validation.approval_required === "boolean" &&
    (validation.approval_id === undefined ||
      validation.approval_id === null ||
      (typeof validation.approval_id === "string" &&
        validation.approval_id.length > 0 &&
        validation.approval_id.length <= 512));
  const allowedAction =
    validation.action === "allow" || (phase === "output" && validation.action === "rewrite");
  if (!validShape || validation.allowed !== allowedAction) {
    if (phase === "output") {
      throw new ToolOutputValidationContractError(
        toolName,
        "the API returned inconsistent verdict metadata"
      );
    }
    throw new ToolInputValidationContractError(
      toolName,
      "the API returned inconsistent verdict metadata"
    );
  }
}

function mergeContext(
  defaultContext: JsonObject | undefined,
  callerContext: JsonObject | undefined
): JsonObject {
  if (defaultContext === undefined) {
    return callerContext ?? {};
  }
  if (callerContext === undefined) {
    return defaultContext;
  }
  return { ...defaultContext, ...callerContext };
}

function requirePayload(value: object, context: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${context} must be a JSON object payload`);
  }
  return value as JsonObject;
}

function assertStrictOutputSchema(
  schema: unknown,
  toolName: string
): asserts schema is StrictJsonObjectSchema {
  if (!isPlainDataObject(schema)) {
    throw new ToolOutputSchemaError(toolName, "schema must be a plain object");
  }
  if (schema.type !== "object") {
    throw new ToolOutputSchemaError(toolName, "type must be 'object'");
  }
  assertSupportedSchemaKeywords(schema, "object", toolName, "schema");
  if (!isPlainDataObject(schema.properties)) {
    throw new ToolOutputSchemaError(toolName, "properties must be a plain object");
  }
  if (!Array.isArray(schema.required)) {
    throw new ToolOutputSchemaError(toolName, "required must be an array");
  }
  if (schema.additionalProperties !== false) {
    throw new ToolOutputSchemaError(toolName, "additionalProperties must be false");
  }

  const propertyNames = new Set(Object.keys(schema.properties));
  const requiredNames = new Set<string>();
  for (const key of schema.required) {
    if (typeof key !== "string" || key.length === 0) {
      throw new ToolOutputSchemaError(toolName, "required entries must be non-empty strings");
    }
    if (!propertyNames.has(key)) {
      throw new ToolOutputSchemaError(toolName, `required property '${key}' is not declared`);
    }
    if (requiredNames.has(key)) {
      throw new ToolOutputSchemaError(toolName, `required property '${key}' is duplicated`);
    }
    requiredNames.add(key);
  }

  for (const [key, propertySchema] of Object.entries(schema.properties)) {
    assertStrictSchemaNode(propertySchema, toolName, `properties.${key}`);
  }
}

function assertStrictSchemaNode(value: unknown, toolName: string, path: string): void {
  if (!isPlainDataObject(value)) {
    throw new ToolOutputSchemaError(toolName, `${path} must be a plain object`);
  }
  if (!isJsonSchemaScalarType(value.type)) {
    throw new ToolOutputSchemaError(toolName, `${path}.type is unsupported`);
  }
  assertSupportedSchemaKeywords(value, value.type, toolName, path);
  if (value.type === "object") {
    if (!isPlainDataObject(value.properties)) {
      throw new ToolOutputSchemaError(toolName, `${path}.properties must be a plain object`);
    }
    if (!Array.isArray(value.required)) {
      throw new ToolOutputSchemaError(toolName, `${path}.required must be an array`);
    }
    if (value.additionalProperties !== false) {
      throw new ToolOutputSchemaError(
        toolName,
        `${path}.additionalProperties must be false`
      );
    }
    const nestedNames = new Set(Object.keys(value.properties));
    const nestedRequired = new Set<string>();
    for (const key of value.required) {
      if (typeof key !== "string" || !nestedNames.has(key) || nestedRequired.has(key)) {
        throw new ToolOutputSchemaError(toolName, `${path}.required is invalid`);
      }
      nestedRequired.add(key);
    }
    for (const [key, nested] of Object.entries(value.properties)) {
      assertStrictSchemaNode(nested, toolName, `${path}.properties.${key}`);
    }
  }
  if (value.type === "array") {
    assertStrictSchemaNode(value.items, toolName, `${path}.items`);
  }
}

function assertPayloadMatchesStrictSchema(
  payload: JsonObject,
  schema: StrictJsonObjectSchema,
  toolName: string
): void {
  const mismatch = firstSchemaMismatch(payload, schema, "output");
  if (mismatch !== undefined) {
    throw new ToolOutputValidationContractError(toolName, mismatch);
  }
}

function firstSchemaMismatch(
  value: unknown,
  schema: StrictJsonSchema,
  path: string
): string | undefined {
  if (!matchesSchemaType(value, schema.type)) {
    return `${path} must have type ${schema.type}`;
  }
  if (schema.type === "object") {
    if (!isPlainDataObject(value)) {
      return `${path} must be a plain object`;
    }
    const properties = schema.properties as Readonly<Record<string, StrictJsonSchema>>;
    const required = schema.required as readonly string[];
    for (const key of required) {
      if (!Object.hasOwn(value, key)) {
        return `${path}.${key} is required`;
      }
    }
    for (const [key, item] of Object.entries(value)) {
      const propertySchema = properties[key];
      if (propertySchema === undefined) {
        return `${path}.${key} is not allowed`;
      }
      const mismatch = firstSchemaMismatch(item, propertySchema, `${path}.${key}`);
      if (mismatch !== undefined) {
        return mismatch;
      }
    }
  }
  if (schema.type === "array") {
    const items = schema.items as StrictJsonSchema;
    for (const [index, item] of (value as readonly unknown[]).entries()) {
      const mismatch = firstSchemaMismatch(item, items, `${path}[${index}]`);
      if (mismatch !== undefined) {
        return mismatch;
      }
    }
  }
  return undefined;
}

function matchesSchemaType(value: unknown, type: JsonSchemaScalarType): boolean {
  switch (type) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return typeof value === "number" && Number.isSafeInteger(value);
    case "null":
      return value === null;
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "object":
      return isPlainDataObject(value);
    case "string":
      return typeof value === "string";
  }
}

function materializeSafeJsonObject(value: unknown, path: string): JsonObject {
  const materialized = materializeSafeJson(value, path);
  if (!isPlainDataObject(materialized)) {
    throw new TypeError(`${path} must be a plain JSON object`);
  }
  return materialized;
}

function materializeSafeJson(value: unknown, path: string): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.map((item, index) => materializeSafeJson(item, `${path}[${index}]`))
    );
  }
  if (!isPlainDataObject(value)) {
    throw new TypeError(`${path} contains a non-JSON value`);
  }
  const copy = Object.create(null) as Record<string, unknown>;
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!descriptor.enumerable) {
      continue;
    }
    if (!("value" in descriptor)) {
      throw new TypeError(`${path}.${key} must not be an accessor`);
    }
    copy[key] = materializeSafeJson(descriptor.value, `${path}.${key}`);
  }
  return Object.freeze(copy);
}

function isPlainDataObject(value: unknown): value is Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function isJsonSchemaScalarType(value: unknown): value is JsonSchemaScalarType {
  return (
    value === "array" ||
    value === "boolean" ||
    value === "integer" ||
    value === "null" ||
    value === "number" ||
    value === "object" ||
    value === "string"
  );
}

function isVerdictAction(value: unknown): value is VerdictAction {
  return (
    value === "allow" ||
    value === "allow_with_citation" ||
    value === "rewrite" ||
    value === "abstain" ||
    value === "ask_clarification" ||
    value === "block" ||
    value === "require_human_review"
  );
}

function assertSupportedSchemaKeywords(
  schema: Readonly<Record<string, unknown>>,
  type: JsonSchemaScalarType,
  toolName: string,
  path: string
): void {
  const structural =
    type === "object"
      ? ["type", "properties", "required", "additionalProperties"]
      : type === "array"
        ? ["type", "items"]
        : ["type"];
  const allowed = new Set([
    ...structural,
    "$comment",
    "$id",
    "$schema",
    "default",
    "deprecated",
    "description",
    "examples",
    "readOnly",
    "title",
    "writeOnly"
  ]);
  for (const keyword of Object.keys(schema)) {
    if (!allowed.has(keyword)) {
      throw new ToolOutputSchemaError(
        toolName,
        `${path}.${keyword} is not supported by strict local validation`
      );
    }
  }
}
