import type {
  ApprovalExecutionGrant,
  RiskLevel,
  ToolCallEnvelope,
  ToolValidationResponse
} from "@hallu-defense/contracts";
import type { HalluDefenseClient } from "@hallu-defense/sdk";

export type JsonObject = Readonly<Record<string, unknown>>;
export type JsonSchemaObject = JsonObject;
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
  readonly inputSchema: JsonSchemaObject;
  readonly outputSchema?: JsonSchemaObject;
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
  readonly rawOutput: TOutput;
  readonly inputEnvelope: ToolCallEnvelope;
  readonly outputEnvelope: ToolCallEnvelope;
  readonly inputValidation: ToolValidationResponse;
  readonly outputValidation: ToolValidationResponse;
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
    readonly envelope: ToolCallEnvelope,
    readonly validation: ToolValidationResponse
  ) {
    super(`${phase} validation blocked tool '${envelope.tool_name}': ${validation.reason}`);
    this.name = "ToolValidationBlockedError";
  }

  get action(): ToolValidationResponse["action"] {
    return this.validation.action;
  }

  get approvalId(): string | null | undefined {
    return this.validation.approval_id;
  }
}

export class ToolInputValidationBlockedError extends ToolValidationBlockedError {
  constructor(envelope: ToolCallEnvelope, validation: ToolValidationResponse) {
    super("TOOL_INPUT_VALIDATION_BLOCKED", "input", envelope, validation);
    this.name = "ToolInputValidationBlockedError";
  }
}

export class ToolOutputValidationBlockedError extends ToolValidationBlockedError {
  constructor(envelope: ToolCallEnvelope, validation: ToolValidationResponse) {
    super("TOOL_OUTPUT_VALIDATION_BLOCKED", "output", envelope, validation);
    this.name = "ToolOutputValidationBlockedError";
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
  if (!validation.allowed) {
    throw new ToolInputValidationBlockedError(envelope, validation);
  }
  return validation;
}

export async function validateToolOutputOrThrow(
  client: ToolValidationClient,
  envelope: ToolCallEnvelope
): Promise<ToolValidationResponse> {
  const validation = await client.validateToolOutput(envelope);
  if (!validation.allowed) {
    throw new ToolOutputValidationBlockedError(envelope, validation);
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

  const rawOutput = await request.execute(request.input, { inputEnvelope, inputValidation });
  const outputPayload = requirePayload(rawOutput, `${request.tool.name} output`);
  const outputEnvelope = buildToolCallEnvelope({
    toolName: request.tool.name,
    input: outputPayload,
    schema: request.tool.outputSchema ?? { type: "object" },
    riskLevel,
    approvalRequired: false,
    callerContext
  });
  const outputValidation = await validateToolOutputOrThrow(adapterOptions.client, outputEnvelope);

  return {
    output: sanitizedOutputOrRaw(outputValidation, rawOutput),
    rawOutput,
    inputEnvelope,
    outputEnvelope,
    inputValidation,
    outputValidation
  };
}

function sanitizedOutputOrRaw<TOutput extends object>(
  validation: ToolValidationResponse,
  rawOutput: TOutput
): TOutput {
  if (validation.sanitized_output === undefined || validation.sanitized_output === null) {
    return rawOutput;
  }
  return validation.sanitized_output as TOutput;
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
