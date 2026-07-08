import { describe, expect, it } from "vitest";

import { HalluDefenseClient, HalluDefenseError } from "../src/index.js";

describe("HalluDefenseClient", () => {
  it("sends tenant headers and returns verification runs", async () => {
    const requests: RequestInit[] = [];
    const fakeFetch: typeof fetch = async (_input, init) => {
      requests.push(init ?? {});
      return new Response(
        JSON.stringify({
          trace_id: "tr_test",
          tenant_id: "tenant-a",
          input: {},
          claims: [],
          evidence: [],
          verdicts: [],
          final_decision: "allow",
          final_text: "ok",
          policy_version: "test",
          created_at: "2026-07-07T00:00:00Z"
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local/",
      tenantId: "tenant-a",
      traceId: "tr_sdk_unit",
      subjectId: "sdk-user",
      roles: ["reader", "approval_reviewer"],
      fetchImpl: fakeFetch
    });

    const run = await client.runVerification({ message_text: "A supported claim." });

    expect(run.trace_id).toBe("tr_test");
    expect(requests).toHaveLength(1);
    expect(requests[0]?.headers).toMatchObject({
      "content-type": "application/json",
      "x-tenant-id": "tenant-a",
      "x-trace-id": "tr_sdk_unit",
      "x-subject-id": "sdk-user",
      "x-roles": "reader,approval_reviewer"
    });
  });

  it("throws typed errors for API failures", async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ detail: "blocked" }), {
        status: 403,
        headers: { "content-type": "application/json" }
      });

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      fetchImpl: fakeFetch
    });

    await expect(client.extractClaims("hello world claim")).rejects.toBeInstanceOf(
      HalluDefenseError
    );
  });

  it("exports audit runs and events through the typed API", async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          trace_id: "tr_audit",
          runs: [],
          events: [
            {
              event_id: "evt_1",
              trace_id: "tr_previous",
              tenant_id: "tenant-a",
              event_type: "http_request",
              method: "POST",
              path: "/claims/extract",
              status_code: 200,
              outcome: "success",
              metadata: {},
              created_at: "2026-07-07T00:00:00Z"
            }
          ]
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      fetchImpl: fakeFetch
    });

    const audit = await client.exportAudit({ tenant_id: "tenant-a" });

    expect(audit.trace_id).toBe("tr_audit");
    expect(audit.events[0]?.path).toBe("/claims/extract");
  });

  it("ingests documents through the typed API", async () => {
    const endpoints: string[] = [];
    const fakeFetch: typeof fetch = async (input) => {
      endpoints.push(String(input));
      return new Response(
        JSON.stringify({
          trace_id: "tr_ingest",
          tenant_id: "tenant-a",
          corpus_id: "hr",
          backend: "local",
          document_count: 1,
          indexed_count: 0,
          evidence_ids: [],
          warnings: ["No persistent RAG index backend is configured; documents were validated but not persisted."]
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      subjectId: "sdk-reviewer",
      roles: ["approval_reviewer"],
      fetchImpl: fakeFetch
    });

    const result = await client.ingestDocuments({
      corpus_id: "hr",
      documents: [
        {
          source_ref: "hr-manual-v7",
          content: "Full-time employees receive 15 days of paid vacation per year.",
          authority: "internal"
        }
      ]
    });

    expect(endpoints).toEqual(["http://api.local/documents/ingest"]);
    expect(result.trace_id).toBe("tr_ingest");
    expect(result.backend).toBe("local");
  });

  it("manages corpus grants through typed endpoints", async () => {
    const endpoints: string[] = [];
    const bodies: unknown[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      endpoints.push(String(input));
      bodies.push(JSON.parse(String(init?.body)));
      if (String(input).endsWith("/rag/corpus-grants/upsert")) {
        return new Response(
          JSON.stringify({
            grant: {
              tenant_id: "tenant-a",
              corpus_id: "hr",
              reader_roles: ["hr_reader"],
              writer_roles: ["hr_writer"],
              version: 1,
              created_by: "sdk-admin",
              updated_by: "sdk-admin",
              created_at: "2026-07-08T00:00:00Z",
              updated_at: "2026-07-08T00:00:00Z",
              disabled_by: null,
              disabled_at: null
            }
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (String(input).endsWith("/rag/corpus-grants/disable")) {
        return new Response(
          JSON.stringify({
            grant: {
              tenant_id: "tenant-a",
              corpus_id: "hr",
              reader_roles: ["hr_reader"],
              writer_roles: ["hr_writer"],
              version: 2,
              created_by: "sdk-admin",
              updated_by: "sdk-admin",
              created_at: "2026-07-08T00:00:00Z",
              updated_at: "2026-07-08T00:05:00Z",
              disabled_by: "sdk-admin",
              disabled_at: "2026-07-08T00:05:00Z"
            }
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (String(input).endsWith("/rag/corpus-grants/history")) {
        return new Response(
          JSON.stringify({
            grants: [
              {
                tenant_id: "tenant-a",
                corpus_id: "hr",
                reader_roles: ["hr_reader"],
                writer_roles: ["hr_writer"],
                version: 1,
                created_by: "sdk-admin",
                updated_by: "sdk-admin",
                created_at: "2026-07-08T00:00:00Z",
                updated_at: "2026-07-08T00:00:00Z",
                disabled_by: null,
                disabled_at: null
              },
              {
                tenant_id: "tenant-a",
                corpus_id: "hr",
                reader_roles: ["hr_reader"],
                writer_roles: ["hr_writer"],
                version: 2,
                created_by: "sdk-admin",
                updated_by: "sdk-admin",
                created_at: "2026-07-08T00:00:00Z",
                updated_at: "2026-07-08T00:05:00Z",
                disabled_by: "sdk-admin",
                disabled_at: "2026-07-08T00:05:00Z"
              }
            ],
            next_cursor: null
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (String(input).endsWith("/rag/corpus-grants/history/diff")) {
        return new Response(
          JSON.stringify({
            diffs: [
              {
                tenant_id: "tenant-a",
                corpus_id: "hr",
                version: 1,
                previous_version: null,
                action: "create",
                changed_fields: ["reader_roles", "writer_roles"],
                reader_roles_added: ["hr_reader"],
                reader_roles_removed: [],
                writer_roles_added: ["hr_writer"],
                writer_roles_removed: [],
                updated_by: "sdk-admin",
                updated_at: "2026-07-08T00:00:00Z"
              },
              {
                tenant_id: "tenant-a",
                corpus_id: "hr",
                version: 2,
                previous_version: 1,
                action: "disable",
                changed_fields: ["disabled_state"],
                reader_roles_added: [],
                reader_roles_removed: [],
                writer_roles_added: [],
                writer_roles_removed: [],
                updated_by: "sdk-admin",
                updated_at: "2026-07-08T00:05:00Z"
              }
            ],
            next_cursor: null
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          grants: [
            {
              tenant_id: "tenant-a",
              corpus_id: "hr",
              reader_roles: ["hr_reader"],
              writer_roles: ["hr_writer"],
              version: 2,
              created_by: "sdk-admin",
              updated_by: "sdk-admin",
              created_at: "2026-07-08T00:00:00Z",
              updated_at: "2026-07-08T00:05:00Z",
              disabled_by: "sdk-admin",
              disabled_at: "2026-07-08T00:05:00Z"
            }
          ],
          next_cursor: null
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      subjectId: "sdk-admin",
      roles: ["rag_writer"],
      fetchImpl: fakeFetch
    });

    const upsert = await client.upsertCorpusGrant({
      corpus_id: "hr",
      reader_roles: ["hr_reader"],
      writer_roles: ["hr_writer"],
      expected_version: 0
    });
    const disabled = await client.disableCorpusGrant({ corpus_id: "hr", expected_version: 1 });
    const list = await client.listCorpusGrants({ corpus_id: "hr", include_disabled: true });
    const history = await client.corpusGrantHistory({
      corpus_id: "hr",
      actor_id: "sdk-admin",
      updated_at_from: "2026-07-08T00:00:00Z",
      updated_at_to: "2026-07-08T00:10:00Z"
    });
    const historyDiff = await client.corpusGrantHistoryDiff({
      corpus_id: "hr",
      actor_id: "sdk-admin"
    });

    expect(upsert.grant.corpus_id).toBe("hr");
    expect(disabled.grant.disabled_by).toBe("sdk-admin");
    expect(list.grants[0]?.reader_roles).toEqual(["hr_reader"]);
    expect(history.grants.map((grant) => grant.version)).toEqual([1, 2]);
    expect(historyDiff.diffs.map((diff) => diff.action)).toEqual(["create", "disable"]);
    expect(list.next_cursor).toBeNull();
    expect(endpoints).toEqual([
      "http://api.local/rag/corpus-grants/upsert",
      "http://api.local/rag/corpus-grants/disable",
      "http://api.local/rag/corpus-grants/list",
      "http://api.local/rag/corpus-grants/history",
      "http://api.local/rag/corpus-grants/history/diff"
    ]);
    expect(bodies).toEqual([
      {
        corpus_id: "hr",
        reader_roles: ["hr_reader"],
        writer_roles: ["hr_writer"],
        expected_version: 0
      },
      { corpus_id: "hr", expected_version: 1 },
      { corpus_id: "hr", include_disabled: true },
      {
        corpus_id: "hr",
        actor_id: "sdk-admin",
        updated_at_from: "2026-07-08T00:00:00Z",
        updated_at_to: "2026-07-08T00:10:00Z"
      },
      {
        corpus_id: "hr",
        actor_id: "sdk-admin"
      }
    ]);
  });

  it("lists and decides approvals through typed endpoints", async () => {
    const endpoints: string[] = [];
    const fakeFetch: typeof fetch = async (input) => {
      endpoints.push(String(input));
      if (String(input).endsWith("/approvals/list")) {
        return new Response(
          JSON.stringify({
            approvals: [
              {
                approval_id: "apr_sdk",
                tenant_id: "tenant-a",
                trace_id: "tr_sdk",
                tool_call: {
                  tool_name: "delete_repository",
                  input: { repo: "core" },
                  schema: { type: "object" },
                  risk_level: "high",
                  approval_required: false,
                  caller_context: {}
                },
                status: "pending",
                risk_level: "high",
                reason: "Tool call is high-risk and requires approval.",
                requested_by: "agent",
                decided_by: null,
                decision_reason: null,
                created_at: "2026-07-08T00:00:00Z",
                decided_at: null
              }
            ]
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          approval: {
            approval_id: "apr_sdk",
            tenant_id: "tenant-a",
            trace_id: "tr_sdk",
            tool_call: {
              tool_name: "delete_repository",
              input: { repo: "core" },
              schema: { type: "object" },
              risk_level: "high",
              approval_required: false,
              caller_context: {}
            },
            status: "approved",
            risk_level: "high",
            reason: "Tool call is high-risk and requires approval.",
            requested_by: "agent",
            decided_by: "reviewer",
            decision_reason: "Approved.",
            created_at: "2026-07-08T00:00:00Z",
            decided_at: "2026-07-08T00:01:00Z"
          },
          execution_grant: {
            approval_id: "apr_sdk",
            tenant_id: "tenant-a",
            tool_name: "delete_repository",
            execution_token: "fixture-execution-grant-token",
            expires_at: "2026-07-08T00:16:00Z"
          }
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      fetchImpl: fakeFetch
    });

    const list = await client.listApprovals({ status: "pending" });
    const decision = await client.decideApproval({
      approval_id: "apr_sdk",
      decision: "approve",
      reason: "Approved."
    });

    expect(list.approvals[0]?.approval_id).toBe("apr_sdk");
    expect(decision.approval.status).toBe("approved");
    expect(decision.execution_grant?.approval_id).toBe("apr_sdk");
    expect(decision.execution_grant?.execution_token).toBe("fixture-execution-grant-token");
    expect(endpoints).toEqual([
      "http://api.local/approvals/list",
      "http://api.local/approvals/decide"
    ]);
  });
});
