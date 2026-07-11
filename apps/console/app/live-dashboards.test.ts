import { describe, expect, it } from "vitest";

import type { CorpusGrant, EvalReport, VerificationRunSummary } from "@hallu-defense/contracts";
import { newestEvalReports, newestGrants, newestRuns } from "./live-dashboards";

describe("live dashboard ordering", () => {
  it("orders event-backed run summaries newest first without mutating input", () => {
    const input: readonly VerificationRunSummary[] = Object.freeze([
      {
        trace_id: "tr_old",
        final_decision: "allow",
        created_at: "2026-07-10T10:00:00Z"
      },
      {
        trace_id: "tr_new",
        final_decision: "blocked",
        created_at: "2026-07-10T11:00:00Z"
      }
    ]);

    expect(newestRuns(input).map((item) => item.trace_id)).toEqual(["tr_new", "tr_old"]);
    expect(input.map((item) => item.trace_id)).toEqual(["tr_old", "tr_new"]);
  });

  it("orders real corpus grants and eval reports by their persisted timestamps", () => {
    const grants: readonly CorpusGrant[] = [grant("older", "2026-07-10T09:00:00Z"), grant("newer", "2026-07-10T12:00:00Z")];
    const reports: readonly EvalReport[] = [
      report("evr_old", "2026-07-10T08:00:00Z"),
      report("evr_new", "2026-07-10T13:00:00Z")
    ];

    expect(newestGrants(grants).map((item) => item.corpus_id)).toEqual(["newer", "older"]);
    expect(newestEvalReports(reports).map((item) => item.report_id)).toEqual([
      "evr_new",
      "evr_old"
    ]);
  });
});

function grant(corpusId: string, updatedAt: string): CorpusGrant {
  return {
    tenant_id: "tenant-a",
    corpus_id: corpusId,
    reader_roles: [],
    writer_roles: [],
    version: 1,
    created_by: "writer",
    updated_by: "writer",
    created_at: updatedAt,
    updated_at: updatedAt,
    disabled_by: null,
    disabled_at: null
  };
}

function report(reportId: string, publishedAt: string): EvalReport {
  return {
    report_id: reportId,
    tenant_id: "tenant-a",
    suite: "scenarios",
    run_id: reportId,
    source: "e2e",
    metrics: { scenario_count: 1, pass_rate: 1, p95_latency_ms: 2 },
    payload: {},
    published_by: "publisher",
    published_at: publishedAt
  };
}
