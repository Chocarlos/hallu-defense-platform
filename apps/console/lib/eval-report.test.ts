import { describe, expect, it } from "vitest";

import {
  loadEvalScenarioHistoryReport,
  loadEvalScenarioReport,
  loadEvalSmokeReport,
  parseEvalScenarioHistoryReport,
  parseEvalScenarioReport,
  parseEvalSmokeReport
} from "./eval-report";

describe("eval smoke report loading", () => {
  it("loads the real eval smoke report artifact", async () => {
    const report = await loadEvalSmokeReport();

    expect(report).not.toBeNull();
    expect(report?.metrics.scenario_count).toBe(report?.scenarios.length);
    expect(report?.metrics.final_decision_accuracy).toBeGreaterThanOrEqual(1);
    expect(report?.scenarios.map((scenario) => scenario.id)).toContain("doc_supported");
  });

  it("rejects malformed report payloads instead of rendering fake data", () => {
    expect(parseEvalSmokeReport({ metrics: { scenario_count: 1 }, scenarios: [] })).toBeNull();
    expect(
      parseEvalSmokeReport({
        metrics: {
          scenario_count: 1,
          final_decision_accuracy: 1,
          trace_coverage: 1,
          claim_ledger_coverage: 1,
          verdict_ledger_coverage: 1,
          claim_precision: 1,
          claim_recall: 1,
          unsupported_claim_recall: 1,
          groundedness: 1,
          faithfulness: 1,
          false_positive_blocking: 0,
          critical_pass_through: 0,
          p95_latency_ms: 10,
          cost_per_run_usd: 0
        },
        scenarios: []
      })
    ).toBeNull();
  });
});

describe("expanded eval scenario report loading", () => {
  it("loads the real expanded eval scenario report artifact", async () => {
    const report = await loadEvalScenarioReport();

    expect(report).not.toBeNull();
    expect(report?.metrics.scenario_count).toBe(report?.scenarios.length);
    expect(report?.metrics.pass_rate).toBe(1);
    expect(report?.metrics.repo_semantic_claim_decision_accuracy).toBe(1);
    expect(report?.scenarios.map((scenario) => scenario.id)).toContain(
      "code_fix_claim_supported_by_targeted_command"
    );
  });

  it("rejects malformed expanded scenario reports instead of rendering fake data", () => {
    expect(parseEvalScenarioReport({ metrics: { scenario_count: 1 }, scenarios: [] })).toBeNull();
    expect(
      parseEvalScenarioReport({
        metrics: {
          scenario_count: 1,
          passed_count: 0,
          pass_rate: 1,
          category_pass_rate: { code_agents: 1 },
          verification_decision_accuracy: 1,
          blocked_high_risk_rate: 1,
          secret_redaction_rate: 1,
          prompt_injection_block_rate: 1,
          data_poisoning_block_rate: 1,
          tool_contradiction_guard_rate: 1,
          repo_false_claim_block_rate: 1,
          repo_semantic_claim_decision_accuracy: 1,
          blocking_precision: 1,
          sandbox_block_rate: 1,
          p95_latency_ms: 4.42
        },
        scenarios: [
          {
            id: "scenario",
            kind: "verification_run",
            category: "code_agents",
            latency_ms: 1,
            expected: {},
            observed: {},
            passed: true,
            failures: []
          }
        ]
      })
    ).toBeNull();
  });
});

describe("expanded eval scenario history loading", () => {
  it("loads the real expanded eval scenario history artifact", async () => {
    const report = await loadEvalScenarioHistoryReport();

    expect(report).not.toBeNull();
    expect(report?.runs.length).toBeGreaterThanOrEqual(1);
    expect(report?.runs.at(-1)?.metrics.scenario_count).toBe(21);
    expect(report?.runs.at(-1)?.metrics.pass_rate).toBe(1);
  });

  it("rejects malformed expanded scenario history reports", () => {
    const metrics = {
      scenario_count: 21,
      passed_count: 21,
      pass_rate: 1,
      category_pass_rate: { code_agents: 1 },
      verification_decision_accuracy: 1,
      blocked_high_risk_rate: 1,
      secret_redaction_rate: 1,
      prompt_injection_block_rate: 1,
      data_poisoning_block_rate: 1,
      tool_contradiction_guard_rate: 1,
      repo_false_claim_block_rate: 1,
      repo_semantic_claim_decision_accuracy: 1,
      blocking_precision: 1,
      sandbox_block_rate: 1,
      p95_latency_ms: 4.42
    };

    expect(parseEvalScenarioHistoryReport({ runs: [{ run_id: "", created_at: "bad", metrics }] })).toBeNull();
    expect(
      parseEvalScenarioHistoryReport({
        runs: [
          { run_id: "scenario-one", created_at: "2026-07-08T15:30:00Z", metrics },
          { run_id: "scenario-one", created_at: "2026-07-08T15:31:00Z", metrics }
        ]
      })
    ).toBeNull();
  });
});
