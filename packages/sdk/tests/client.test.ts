import { afterEach, describe, expect, it, vi } from "vitest";

import { HalluDefenseClient, HalluDefenseError } from "../src/index.js";

describe("HalluDefenseClient", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

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

  it("uses Bearer as the sole identity authority when a token is configured", async () => {
    let capturedHeaders: HeadersInit | undefined;
    const fakeFetch: typeof fetch = async (_input, init) => {
      capturedHeaders = init?.headers;
      return new Response(JSON.stringify({ claims: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    };
    const client = new HalluDefenseClient({
      baseUrl: "https://api.example.test",
      token: "signed.access.token",
      tenantId: "spoofed-tenant",
      subjectId: "spoofed-subject",
      roles: ["spoofed-role"],
      traceId: "tr_bearer",
      fetchImpl: fakeFetch
    });

    await client.extractClaims("A supported claim.");

    expect(capturedHeaders).toMatchObject({
      authorization: "Bearer signed.access.token",
      "content-type": "application/json",
      "x-trace-id": "tr_bearer"
    });
    expect(capturedHeaders).not.toHaveProperty("x-tenant-id");
    expect(capturedHeaders).not.toHaveProperty("x-subject-id");
    expect(capturedHeaders).not.toHaveProperty("x-roles");
  });

  it("rejects malformed Bearer material before making a request", () => {
    expect(
      () =>
        new HalluDefenseClient({
          baseUrl: "https://api.example.test",
          token: "valid-part\r\ninjected-header"
        })
    ).toThrow(TypeError);
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

  it("supports a bounded per-call timeout for long-running sandbox batches", async () => {
    vi.useFakeTimers();
    let capturedSignal: AbortSignal | null = null;
    const fakeFetch: typeof fetch = (_input, init) => {
      capturedSignal = init?.signal ?? null;
      return new Promise((_resolve, reject) => {
        capturedSignal?.addEventListener("abort", () => {
          reject(new DOMException("request aborted", "AbortError"));
        });
      });
    };
    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      timeoutMs: 10,
      fetchImpl: fakeFetch
    });

    const pending = client.runRepoChecks(
      {
        repo_ref: ".",
        commands: ["python --version"],
        network_policy: "deny"
      },
      { timeoutMs: 40 }
    );
    const rejection = expect(pending).rejects.toMatchObject({
      status: 408,
      endpoint: "/repo/checks/run",
      message: "Request timed out"
    });

    await vi.advanceTimersByTimeAsync(11);
    expect(capturedSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(29);
    await rejection;
    expect(capturedSignal?.aborted).toBe(true);
  });

  it("rejects invalid request timeout overrides before sending a request", async () => {
    const fakeFetch = vi.fn<typeof fetch>();
    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      fetchImpl: fakeFetch
    });

    await expect(
      client.runRepoChecks(
        {
          repo_ref: ".",
          commands: ["python --version"],
          network_policy: "deny"
        },
        { timeoutMs: 0 }
      )
    ).rejects.toThrow(TypeError);
    expect(fakeFetch).not.toHaveBeenCalled();
  });

  it("lists paginated verification summaries without a client-controlled tenant", async () => {
    let endpoint = "";
    let body: unknown;
    const fakeFetch: typeof fetch = async (input, init) => {
      endpoint = String(input);
      body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          trace_id: "tr_history_list",
          runs: [
            {
              trace_id: "tr_completed_run",
              final_decision: "repaired",
              created_at: "2026-07-10T12:00:00Z"
            }
          ],
          next_cursor: "eyJ2ZXJzaW9uIjoxfQ"
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };
    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      fetchImpl: fakeFetch
    });

    const history = await client.listVerificationRuns({ limit: 10 });

    expect(endpoint).toBe("http://api.local/verification/runs/list");
    expect(body).toEqual({ limit: 10 });
    expect(history.runs[0]?.trace_id).toBe("tr_completed_run");
    expect(history.next_cursor).toBe("eyJ2ZXJzaW9uIjoxfQ");
  });

  it("publishes and lists eval reports through typed endpoints", async () => {
    const endpoints: string[] = [];
    const bodies: unknown[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      endpoints.push(String(input));
      bodies.push(JSON.parse(String(init?.body)));
      if (String(input).endsWith("/evals/reports/publish")) {
        return new Response(
          JSON.stringify({
            trace_id: "tr_eval_publish_sdk",
            report: {
              report_id: "evr_sdk",
              tenant_id: "tenant-a",
              suite: "scenarios",
              run_id: "sdk-run",
              source: "sdk-test",
              metrics: {
                scenario_count: 21,
                pass_rate: 1,
                p95_latency_ms: 4.79,
                groundedness: 0.98,
                faithfulness: 0.99
              },
              payload: { report_path: "evals/reports/scenario-metrics.json" },
              published_by: "sdk-publisher",
              published_at: "2026-07-09T15:00:00Z"
            }
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          trace_id: "tr_eval_list_sdk",
          reports: [
            {
              report_id: "evr_sdk",
              tenant_id: "tenant-a",
              suite: "scenarios",
              run_id: "sdk-run",
              source: "sdk-test",
              metrics: {
                scenario_count: 21,
                pass_rate: 1,
                p95_latency_ms: 4.79,
                groundedness: 0.98,
                faithfulness: 0.99
              },
              payload: { report_path: "evals/reports/scenario-metrics.json" },
              published_by: "sdk-publisher",
              published_at: "2026-07-09T15:00:00Z"
            }
          ]
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      subjectId: "sdk-publisher",
      roles: ["eval_publisher"],
      fetchImpl: fakeFetch
    });

    const published = await client.publishEvalReport({
      suite: "scenarios",
      run_id: "sdk-run",
      source: "sdk-test",
      metrics: {
        scenario_count: 21,
        pass_rate: 1,
        p95_latency_ms: 4.79,
        groundedness: 0.98,
        faithfulness: 0.99
      },
      payload: { report_path: "evals/reports/scenario-metrics.json" }
    });
    const listed = await client.listEvalReports({ suite: "scenarios", limit: 5 });

    expect(published.report.report_id).toBe("evr_sdk");
    expect(listed.reports[0]?.report_id).toBe("evr_sdk");
    expect(endpoints).toEqual([
      "http://api.local/evals/reports/publish",
      "http://api.local/evals/reports/list"
    ]);
    expect(bodies).toEqual([
      {
        suite: "scenarios",
        run_id: "sdk-run",
        source: "sdk-test",
        metrics: {
          scenario_count: 21,
          pass_rate: 1,
          p95_latency_ms: 4.79,
          groundedness: 0.98,
          faithfulness: 0.99
        },
        payload: { report_path: "evals/reports/scenario-metrics.json" }
      },
      { suite: "scenarios", limit: 5 }
    ]);
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

  it("fetches document ingestion status through the typed API", async () => {
    const endpoints: string[] = [];
    const bodies: unknown[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      endpoints.push(String(input));
      bodies.push(JSON.parse(String(init?.body)));
      return new Response(
        JSON.stringify({
          trace_id: "tr_status",
          tenant_id: "tenant-a",
          job_id: "ing_123",
          corpus_id: "hr",
          job_type: "ingest",
          job_status: "queued",
          attempts: 0,
          available_at: "2026-07-09T12:00:00Z",
          created_at: "2026-07-09T12:00:00Z",
          updated_at: "2026-07-09T12:00:00Z"
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      fetchImpl: fakeFetch
    });

    const result = await client.getDocumentIngestionStatus({ job_id: "ing_123" });

    expect(endpoints).toEqual(["http://api.local/documents/ingest/status"]);
    expect(bodies).toEqual([{ job_id: "ing_123" }]);
    expect(result.job_status).toBe("queued");
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

  it("replays verification runs through the typed endpoint", async () => {
    const endpoints: string[] = [];
    const bodies: unknown[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      endpoints.push(String(input));
      bodies.push(JSON.parse(String(init?.body)));
      return new Response(
        JSON.stringify({
          trace_id: "tr_replay_call",
          source_trace_id: "tr_replay_source",
          source_created_at: "2026-07-08T00:00:00Z",
          source_final_decision: "allow",
          decision_changed: false,
          replayed_run: {
            trace_id: "tr_replay_call",
            tenant_id: "tenant-a",
            input: { replay_of: "tr_replay_source" },
            claims: [],
            evidence: [],
            verdicts: [],
            final_decision: "allow",
            final_text: "ok",
            policy_version: "test",
            created_at: "2026-07-08T00:01:00Z"
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

    const replay = await client.replayVerification({ trace_id: "tr_replay_source" });

    expect(endpoints).toEqual(["http://api.local/verification/replay"]);
    expect(bodies).toEqual([{ trace_id: "tr_replay_source" }]);
    expect(replay.source_trace_id).toBe("tr_replay_source");
    expect(replay.decision_changed).toBe(false);
    expect(replay.replayed_run.input["replay_of"]).toBe("tr_replay_source");
  });

  it("uses explicit v2 contracts for verification and claim verdicts", async () => {
    const endpoints: string[] = [];
    const bodies: unknown[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      const endpoint = String(input);
      endpoints.push(endpoint);
      bodies.push(JSON.parse(String(init?.body)));
      if (endpoint.endsWith("/v2/claims/verify")) {
        return new Response(
          JSON.stringify({
            schema_version: "2.0",
            verdicts: [
              {
                schema_version: "2.0",
                claim_id: "clm_v2",
                status: "unsupported",
                confidence: 0.4,
                evidence_ids: [],
                action: "abstain",
                reason: "No evidence was found.",
                validator_trace: {}
              }
            ]
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          schema_version: "2.0",
          trace_id: "tr_sdk_v2",
          tenant_id: "tenant-a",
          input: {},
          claims: [],
          evidence: [],
          verdicts: [],
          final_decision: "allow",
          final_text: "ok",
          policy_version: "test",
          created_at: "2026-07-09T00:00:00Z"
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };
    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      tenantId: "tenant-a",
      fetchImpl: fakeFetch
    });

    const run = await client.runVerificationV2({
      schema_version: "2.0",
      message_text: "A versioned response."
    });
    const response = await client.verifyClaimsV2({
      schema_version: "2.0",
      claims: [],
      evidence: []
    });

    expect(run.schema_version).toBe("2.0");
    expect(response.verdicts[0]?.status).toBe("unsupported");
    expect(endpoints).toEqual([
      "http://api.local/v2/verification/run",
      "http://api.local/v2/claims/verify"
    ]);
    expect(bodies).toEqual([
      { schema_version: "2.0", message_text: "A versioned response." },
      { schema_version: "2.0", claims: [], evidence: [] }
    ]);
  });

  it("binds injected browser fetch implementations", async () => {
    let invokedWithGlobalThis = false;
    const browserFetch = async function (
      this: unknown,
      _input: RequestInfo | URL,
      _init?: RequestInit
    ): Promise<Response> {
      invokedWithGlobalThis = this === globalThis;
      if (!invokedWithGlobalThis) {
        throw new TypeError("Illegal invocation");
      }
      return new Response(JSON.stringify({ claims: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    } as typeof fetch;

    const client = new HalluDefenseClient({
      baseUrl: "http://api.local",
      fetchImpl: browserFetch
    });

    await expect(client.extractClaims("hello world claim")).resolves.toEqual([]);
    expect(invokedWithGlobalThis).toBe(true);
  });
});
