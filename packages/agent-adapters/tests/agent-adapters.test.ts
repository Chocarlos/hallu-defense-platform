import { describe, expect, it, vi } from "vitest";

import type { ToolValidationClient } from "../src/index.js";
import {
  buildToolCallEnvelope,
  createAgentToolAdapter,
  ToolInputValidationBlockedError,
  ToolOutputValidationBlockedError
} from "../src/index.js";

describe("agent tool adapters", () => {
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

  it("validates input before execution and validates output after execution", async () => {
    const calls: string[] = [];
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
        return {
          allowed: true,
          action: "rewrite",
          reason: "output sanitized",
          approval_required: false,
          sanitized_output: { api_key: "[REDACTED]", safe: envelope.input.safe }
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
        outputSchema: { type: "object" },
        riskLevel: "low"
      },
      input: { document_id: "hr-manual-v7" },
      callerContext: { subject: "agent-a" },
      approvalGrant: {
        approvalId: "apr_allowed",
        executionToken: "fixture-execution-grant-token"
      },
      execute: async (input, context) => {
        calls.push("execute");
        expect(context.inputValidation.allowed).toBe(true);
        return { api_key: "secret-value", safe: input.document_id };
      }
    });

    expect(calls).toEqual(["input:hr-manual-v7", "execute", "output:secret-value"]);
    expect(result.inputEnvelope.caller_context).toEqual({
      tenant_id: "tenant-a",
      subject: "agent-a"
    });
    expect(result.inputEnvelope.approval_id).toBe("apr_allowed");
    expect(result.inputEnvelope.approval_execution_token).toBe(
      "fixture-execution-grant-token"
    );
    expect(result.rawOutput).toEqual({ api_key: "secret-value", safe: "hr-manual-v7" });
    expect(result.output).toEqual({ api_key: "[REDACTED]", safe: "hr-manual-v7" });
    expect(result.outputValidation.action).toBe("rewrite");
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
          riskLevel: "high"
        },
        input: { repo: "core" },
        execute
      })
    ).rejects.toBeInstanceOf(ToolInputValidationBlockedError);
    expect(execute).not.toHaveBeenCalled();
  });

  it("throws a typed output validation error after execution when output is blocked", async () => {
    const execute = vi.fn(async () => ({ unsafe: "payload" }));
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
          reason: "output failed safety checks",
          approval_required: false
        })
      }
    });

    await expect(
      adapter.execute({
        tool: {
          name: "read_secret",
          inputSchema: { type: "object" },
          outputSchema: { type: "object" },
          riskLevel: "medium"
        },
        input: {},
        execute
      })
    ).rejects.toBeInstanceOf(ToolOutputValidationBlockedError);
    expect(execute).toHaveBeenCalledOnce();
  });
});
