import { describe, expect, it, vi } from "vitest";

import type {
  AgentToolDefinition,
  JsonSchemaObject,
  ToolValidationClient
} from "../src/index.js";
import {
  buildToolCallEnvelope,
  createAgentToolAdapter,
  ToolInputValidationBlockedError,
  ToolOutputSchemaError,
  ToolOutputValidationBlockedError,
  ToolOutputValidationContractError
} from "../src/index.js";

describe("agent tool adapters", () => {
  it("keeps typed schemas structurally assignable without runtime branding", () => {
    interface ReadInput {
      readonly document_id: string;
    }
    interface ReadOutput {
      readonly content: string;
    }
    const inputSchema: JsonSchemaObject<ReadInput> = {
      type: "object",
      required: ["document_id"]
    };
    const definition: AgentToolDefinition<ReadInput, ReadOutput> = {
      name: "read_document",
      inputSchema,
      outputSchema: {
        type: "object",
        properties: { content: { type: "string" } },
        required: ["content"],
        additionalProperties: false
      }
    };

    expect(definition.inputSchema).toEqual(inputSchema);
  });

  it("builds ToolCallEnvelope values from typed adapter input", () => {
    const envelope = buildToolCallEnvelope({
      toolName: "read_document",
      input: { document_id: "hr-manual-v7" },
      schema: { type: "object", required: ["document_id"] },
      riskLevel: "low",
      callerContext: { subject: "agent-a" }
    });

    expect(envelope).toEqual({
      tool_name: "read_document",
      input: { document_id: "hr-manual-v7" },
      schema: { type: "object", required: ["document_id"] },
      risk_level: "low",
      approval_required: false,
      caller_context: { subject: "agent-a" }
    });
  });

  it("adds approval execution grants to ToolCallEnvelope values", () => {
    const envelope = buildToolCallEnvelope({
      toolName: "delete_repository",
      input: { repo: "core" },
      schema: { type: "object", required: ["repo"] },
      riskLevel: "high",
      approvalGrant: {
        approvalId: "apr_test",
        executionToken: "fixture-execution-grant-token"
      }
    });

    expect(envelope.approval_id).toBe("apr_test");
    expect(envelope.approval_execution_token).toBe("fixture-execution-grant-token");
  });

  it("returns only sanitized output and safe verdict metadata", async () => {
    const calls: string[] = [];
    const rawSecrets = {
      apiKey: "raw-api-key-value",
      password: "raw-password-value",
      bearer: "Bearer raw-bearer-token",
      email: "person@example.test",
      phone: "+1 415-555-0199",
      ssn: "123-45-6789",
      approvalToken: "fixture-execution-grant-token"
    } as const;
    const client: ToolValidationClient = {
      validateToolInput: async (envelope) => {
        calls.push(`input:${String(envelope.input.document_id)}`);
        return {
          allowed: true,
          action: "allow",
          reason: "input ok",
          approval_required: false
        };
      },
      validateToolOutput: async (envelope) => {
        calls.push(`output:${String(envelope.input.api_key)}`);
        expect(envelope.schema).toMatchObject({
          type: "object",
          additionalProperties: false
        });
        expect(envelope.schema.required).toContain("api_key");
        return {
          allowed: true,
          action: "rewrite",
          reason: "output sanitized",
          approval_required: false,
          sanitized_output: {
            api_key: "[REDACTED]",
            password: "[REDACTED]",
            authorization: "[REDACTED]",
            email: "[REDACTED_EMAIL]",
            phone: "[REDACTED_PHONE]",
            ssn: "[REDACTED_SSN]",
            safe: envelope.input.safe
          }
        };
      }
    };
    const adapter = createAgentToolAdapter({
      client,
      defaultCallerContext: { tenant_id: "tenant-a" }
    });

    const result = await adapter.execute({
      tool: {
        name: "fetch_config",
        inputSchema: { type: "object", required: ["document_id"] },
        outputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string" },
            password: { type: "string" },
            authorization: { type: "string" },
            email: { type: "string" },
            phone: { type: "string" },
            ssn: { type: "string" },
            safe: { type: "string" }
          },
          required: [
            "api_key",
            "password",
            "authorization",
            "email",
            "phone",
            "ssn",
            "safe"
          ],
          additionalProperties: false
        },
        riskLevel: "low"
      },
      input: { document_id: "hr-manual-v7" },
      callerContext: { subject: "agent-a" },
      approvalGrant: {
        approvalId: "apr_allowed",
        executionToken: rawSecrets.approvalToken
      },
      execute: async (input, context) => {
        calls.push("execute");
        expect(context.inputValidation.allowed).toBe(true);
        return {
          api_key: rawSecrets.apiKey,
          password: rawSecrets.password,
          authorization: rawSecrets.bearer,
          email: rawSecrets.email,
          phone: rawSecrets.phone,
          ssn: rawSecrets.ssn,
          safe: input.document_id
        };
      }
    });

    expect(calls).toEqual([
      "input:hr-manual-v7",
      "execute",
      `output:${rawSecrets.apiKey}`
    ]);
    expect(result).toEqual({
      output: {
        api_key: "[REDACTED]",
        password: "[REDACTED]",
        authorization: "[REDACTED]",
        email: "[REDACTED_EMAIL]",
        phone: "[REDACTED_PHONE]",
        ssn: "[REDACTED_SSN]",
        safe: "hr-manual-v7"
      },
      verdict: {
        allowed: true,
        action: "rewrite",
        approvalRequired: false
      },
      trace: {
        toolName: "fetch_config",
        riskLevel: "low",
        phases: [
          {
            phase: "input",
            allowed: true,
            action: "allow",
            approvalRequired: false
          },
          {
            phase: "output",
            allowed: true,
            action: "rewrite",
            approvalRequired: false
          }
        ]
      }
    });

    const serialized = JSON.stringify(result);
    for (const secret of Object.values(rawSecrets)) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).not.toContain("rawOutput");
    expect(serialized).not.toContain("inputEnvelope");
    expect(serialized).not.toContain("outputEnvelope");
  });

  it("throws a typed input validation error and does not execute blocked tools", async () => {
    const execute = vi.fn(async () => ({ ok: true }));
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput: async () => ({
          allowed: false,
          action: "require_human_review",
          reason: "Tool call is high-risk and requires approval.",
          approval_required: true,
          approval_id: "apr_test"
        }),
        validateToolOutput: async () => {
          throw new Error("output validation should not run");
        }
      }
    });

    await expect(
      adapter.execute({
        tool: {
          name: "delete_repository",
          inputSchema: { type: "object", required: ["repo"] },
          outputSchema: {
            type: "object",
            properties: { ok: { type: "boolean" } },
            required: ["ok"],
            additionalProperties: false
          },
          riskLevel: "high"
        },
        input: { repo: "core" },
        execute
      })
    ).rejects.toMatchObject({
      code: "TOOL_INPUT_VALIDATION_BLOCKED",
      phase: "input",
      approvalId: "apr_test"
    });
    await expect(
      adapter.execute({
        tool: {
          name: "delete_repository",
          inputSchema: { type: "object", required: ["repo"] },
          outputSchema: {
            type: "object",
            properties: { ok: { type: "boolean" } },
            required: ["ok"],
            additionalProperties: false
          },
          riskLevel: "high"
        },
        input: { repo: "core" },
        execute
      })
    ).rejects.toBeInstanceOf(ToolInputValidationBlockedError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("blocks post-tool output without retaining raw secrets in the error", async () => {
    const rawSecrets = [
      "Bearer blocked-bearer-token",
      "blocked-api-key",
      "blocked-password",
      "blocked.person@example.test",
      "123-45-6789"
    ] as const;
    const execute = vi.fn(async () => ({
      authorization: rawSecrets[0],
      api_key: rawSecrets[1],
      password: rawSecrets[2],
      email: rawSecrets[3],
      ssn: rawSecrets[4]
    }));
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput: async () => ({
          allowed: true,
          action: "allow",
          reason: "input ok",
          approval_required: false
        }),
        validateToolOutput: async () => ({
          allowed: false,
          action: "block",
          reason: `blocked raw output ${rawSecrets.join(" ")}`,
          approval_required: false,
          approval_id: rawSecrets[0],
          sanitized_output: {
            authorization: rawSecrets[0],
            api_key: rawSecrets[1],
            password: rawSecrets[2],
            email: rawSecrets[3],
            ssn: rawSecrets[4]
          }
        })
      }
    });

    let captured: unknown;
    try {
      await adapter.execute({
        tool: {
          name: "read_secret",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: {
              authorization: { type: "string" },
              api_key: { type: "string" },
              password: { type: "string" },
              email: { type: "string" },
              ssn: { type: "string" }
            },
            required: ["authorization", "api_key", "password", "email", "ssn"],
            additionalProperties: false
          },
          riskLevel: "medium"
        },
        input: {},
        execute
      });
    } catch (error) {
      captured = error;
    }

    expect(captured).toBeInstanceOf(ToolOutputValidationBlockedError);
    const serialized = `${JSON.stringify(captured)} ${String(captured)}`;
    for (const secret of rawSecrets) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).not.toContain("envelope");
    expect(serialized).not.toContain("sanitized_output");
    expect(execute).toHaveBeenCalledOnce();
  });

  it("rejects permissive or missing output schemas before tool execution", async () => {
    const execute = vi.fn(async () => ({ ok: true }));
    const validateToolInput = vi.fn(async () => ({
      allowed: true,
      action: "allow" as const,
      reason: "input ok",
      approval_required: false
    }));
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput,
        validateToolOutput: async () => ({
          allowed: true,
          action: "allow",
          reason: "output ok",
          approval_required: false,
          sanitized_output: { ok: true }
        })
      }
    });

    const permissiveRequest = {
      tool: {
        name: "permissive_tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" }
      },
      input: {},
      execute
    } as unknown as Parameters<typeof adapter.execute>[0];
    await expect(adapter.execute(permissiveRequest)).rejects.toBeInstanceOf(
      ToolOutputSchemaError
    );

    const missingRequest = {
      tool: {
        name: "missing_schema_tool",
        inputSchema: { type: "object" }
      },
      input: {},
      execute
    } as unknown as Parameters<typeof adapter.execute>[0];
    await expect(adapter.execute(missingRequest)).rejects.toBeInstanceOf(
      ToolOutputSchemaError
    );
    expect(validateToolInput).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("fails closed when validate-output omits sanitized_output", async () => {
    const rawSecret = "Bearer must-not-escape";
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput: async () => ({
          allowed: true,
          action: "allow",
          reason: "input ok",
          approval_required: false
        }),
        validateToolOutput: async () => ({
          allowed: true,
          action: "allow",
          reason: `unsafe echo ${rawSecret}`,
          approval_required: false
        })
      }
    });

    let captured: unknown;
    try {
      await adapter.execute({
        tool: {
          name: "missing_sanitized_output",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { authorization: { type: "string" } },
            required: ["authorization"],
            additionalProperties: false
          }
        },
        input: {},
        execute: async () => ({ authorization: rawSecret })
      });
    } catch (error) {
      captured = error;
    }

    expect(captured).toBeInstanceOf(ToolOutputValidationContractError);
    expect(`${JSON.stringify(captured)} ${String(captured)}`).not.toContain(rawSecret);
  });

  it("fails closed on inconsistent validate-output metadata without echoing it", async () => {
    const rawSecret = "Bearer malformed-validator-secret";
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput: async () => ({
          allowed: true,
          action: "allow",
          reason: "input ok",
          approval_required: false
        }),
        validateToolOutput: async () =>
          ({
            allowed: true,
            action: rawSecret,
            reason: rawSecret,
            approval_required: false,
            sanitized_output: { value: rawSecret }
          }) as unknown as Awaited<ReturnType<ToolValidationClient["validateToolOutput"]>>
      }
    });

    let captured: unknown;
    try {
      await adapter.execute({
        tool: {
          name: "malformed_validator_tool",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { value: { type: "string" } },
            required: ["value"],
            additionalProperties: false
          }
        },
        input: {},
        execute: async () => ({ value: rawSecret })
      });
    } catch (error) {
      captured = error;
    }

    expect(captured).toBeInstanceOf(ToolOutputValidationContractError);
    expect(`${JSON.stringify(captured)} ${String(captured)}`).not.toContain(rawSecret);
  });

  it("validates the sanitized response against the closed output schema", async () => {
    const adapter = createAgentToolAdapter({
      client: {
        validateToolInput: async () => ({
          allowed: true,
          action: "allow",
          reason: "input ok",
          approval_required: false
        }),
        validateToolOutput: async () => ({
          allowed: true,
          action: "rewrite",
          reason: "rewritten",
          approval_required: false,
          sanitized_output: { value: "safe", undeclared: "must not pass" }
        })
      }
    });

    await expect(
      adapter.execute({
        tool: {
          name: "closed_schema_tool",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { value: { type: "string" } },
            required: ["value"],
            additionalProperties: false
          }
        },
        input: {},
        execute: async () => ({ value: "safe" })
      })
    ).rejects.toMatchObject({
      code: "TOOL_OUTPUT_VALIDATION_CONTRACT_INVALID",
      phase: "output"
    });
  });
});
