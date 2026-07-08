import { access, readFile } from "node:fs/promises";
import path from "node:path";

import type {
  EvalScenarioHistoryEntry,
  EvalScenarioHistoryReport,
  EvalScenarioMetrics,
  EvalScenarioReport,
  EvalScenarioResult,
  EvalSmokeMetrics,
  EvalSmokeReport,
  EvalSmokeScenarioResult,
  FinalDecision
} from "@hallu-defense/contracts";

export const EVAL_SMOKE_REPORT_RELATIVE_PATH = path.join(
  "evals",
  "reports",
  "smoke-metrics.json"
);
export const EVAL_SCENARIO_REPORT_RELATIVE_PATH = path.join(
  "evals",
  "reports",
  "scenario-metrics.json"
);
export const EVAL_SCENARIO_HISTORY_RELATIVE_PATH = path.join(
  "evals",
  "reports",
  "scenario-history.json"
);

const FINAL_DECISIONS = new Set<FinalDecision>([
  "allow",
  "repaired",
  "abstained",
  "blocked",
  "require_human_review"
]);

const METRIC_KEYS = [
  "scenario_count",
  "final_decision_accuracy",
  "trace_coverage",
  "claim_ledger_coverage",
  "verdict_ledger_coverage",
  "claim_precision",
  "claim_recall",
  "unsupported_claim_recall",
  "groundedness",
  "faithfulness",
  "false_positive_blocking",
  "critical_pass_through",
  "p95_latency_ms",
  "cost_per_run_usd"
] as const satisfies readonly (keyof EvalSmokeMetrics)[];

const SCENARIO_NUMBER_KEYS = [
  "latency_ms",
  "unsupported_hits",
  "supported_verdicts",
  "supported_verdicts_with_evidence",
  "verdict_count",
  "cost_usd"
] as const satisfies readonly (keyof EvalSmokeScenarioResult)[];

const SCENARIO_BOOLEAN_KEYS = [
  "trace_present",
  "claim_ledger_present",
  "verdict_ledger_present"
] as const satisfies readonly (keyof EvalSmokeScenarioResult)[];

const EXPANDED_METRIC_KEYS = [
  "scenario_count",
  "passed_count",
  "pass_rate",
  "verification_decision_accuracy",
  "blocked_high_risk_rate",
  "secret_redaction_rate",
  "prompt_injection_block_rate",
  "data_poisoning_block_rate",
  "tool_contradiction_guard_rate",
  "repo_false_claim_block_rate",
  "repo_semantic_claim_decision_accuracy",
  "sandbox_block_rate",
  "p95_latency_ms"
] as const satisfies readonly (keyof EvalScenarioMetrics)[];

export async function loadEvalSmokeReport(startDir = process.cwd()): Promise<EvalSmokeReport | null> {
  const reportPath = await findReportPath(startDir, EVAL_SMOKE_REPORT_RELATIVE_PATH);
  if (reportPath === null) {
    return null;
  }

  try {
    const raw = await readFile(reportPath, "utf-8");
    return parseEvalSmokeReport(JSON.parse(raw) as unknown);
  } catch {
    return null;
  }
}

export async function loadEvalScenarioReport(startDir = process.cwd()): Promise<EvalScenarioReport | null> {
  const reportPath = await findReportPath(startDir, EVAL_SCENARIO_REPORT_RELATIVE_PATH);
  if (reportPath === null) {
    return null;
  }

  try {
    const raw = await readFile(reportPath, "utf-8");
    return parseEvalScenarioReport(JSON.parse(raw) as unknown);
  } catch {
    return null;
  }
}

export async function loadEvalScenarioHistoryReport(
  startDir = process.cwd()
): Promise<EvalScenarioHistoryReport | null> {
  const reportPath = await findReportPath(startDir, EVAL_SCENARIO_HISTORY_RELATIVE_PATH);
  if (reportPath === null) {
    return null;
  }

  try {
    const raw = await readFile(reportPath, "utf-8");
    return parseEvalScenarioHistoryReport(JSON.parse(raw) as unknown);
  } catch {
    return null;
  }
}

export function parseEvalSmokeReport(value: unknown): EvalSmokeReport | null {
  if (!isRecord(value)) {
    return null;
  }
  const metrics = parseMetrics(value["metrics"]);
  const scenarios = parseScenarios(value["scenarios"]);
  if (metrics === null || scenarios === null || scenarios.length !== metrics.scenario_count) {
    return null;
  }
  return { metrics, scenarios };
}

export function parseEvalScenarioReport(value: unknown): EvalScenarioReport | null {
  if (!isRecord(value)) {
    return null;
  }
  const metrics = parseExpandedMetrics(value["metrics"]);
  const scenarios = parseExpandedScenarios(value["scenarios"]);
  if (
    metrics === null ||
    scenarios === null ||
    scenarios.length !== metrics.scenario_count ||
    scenarios.filter((scenario) => scenario.passed).length !== metrics.passed_count
  ) {
    return null;
  }
  return { metrics, scenarios };
}

export function parseEvalScenarioHistoryReport(value: unknown): EvalScenarioHistoryReport | null {
  if (!isRecord(value) || !Array.isArray(value["runs"])) {
    return null;
  }
  const seen = new Set<string>();
  const runs: EvalScenarioHistoryEntry[] = [];
  for (const item of value["runs"]) {
    const entry = parseEvalScenarioHistoryEntry(item);
    if (entry === null || seen.has(entry.run_id)) {
      return null;
    }
    seen.add(entry.run_id);
    runs.push(entry);
  }
  return { runs };
}

async function findReportPath(startDir: string, relativePath: string): Promise<string | null> {
  let current = path.resolve(startDir);
  while (true) {
    const candidate = path.join(current, relativePath);
    if (await exists(candidate)) {
      return candidate;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function parseMetrics(value: unknown): EvalSmokeMetrics | null {
  if (!isRecord(value)) {
    return null;
  }
  for (const key of METRIC_KEYS) {
    if (!isFiniteNumber(value[key])) {
      return null;
    }
  }
  const scenarioCount = value["scenario_count"];
  if (typeof scenarioCount !== "number" || !Number.isInteger(scenarioCount) || scenarioCount < 0) {
    return null;
  }
  return value as unknown as EvalSmokeMetrics;
}

function parseExpandedMetrics(value: unknown): EvalScenarioMetrics | null {
  if (!isRecord(value)) {
    return null;
  }
  for (const key of EXPANDED_METRIC_KEYS) {
    if (!isFiniteNumber(value[key])) {
      return null;
    }
  }
  const scenarioCount = value["scenario_count"];
  const passedCount = value["passed_count"];
  const categoryPassRate = value["category_pass_rate"];
  if (
    typeof scenarioCount !== "number" ||
    !Number.isInteger(scenarioCount) ||
    scenarioCount < 0 ||
    typeof passedCount !== "number" ||
    !Number.isInteger(passedCount) ||
    passedCount < 0 ||
    passedCount > scenarioCount ||
    !isRateRecord(categoryPassRate)
  ) {
    return null;
  }
  for (const key of EXPANDED_METRIC_KEYS) {
    const metricValue = value[key];
    if (
      key !== "scenario_count" &&
      key !== "passed_count" &&
      key !== "p95_latency_ms" &&
      (typeof metricValue !== "number" || metricValue < 0 || metricValue > 1)
    ) {
      return null;
    }
  }
  return value as unknown as EvalScenarioMetrics;
}

function parseScenarios(value: unknown): readonly EvalSmokeScenarioResult[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const scenarios = value.map(parseScenario);
  if (scenarios.some((scenario) => scenario === null)) {
    return null;
  }
  return scenarios as readonly EvalSmokeScenarioResult[];
}

function parseScenario(value: unknown): EvalSmokeScenarioResult | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    !isNonEmptyString(value["id"]) ||
    !isFinalDecision(value["expected_final_decision"]) ||
    !isFinalDecision(value["final_decision"]) ||
    !isStringArray(value["expected_claims"]) ||
    !isStringArray(value["actual_claims"]) ||
    !isStringArray(value["expected_unsupported_claims"])
  ) {
    return null;
  }
  for (const key of SCENARIO_NUMBER_KEYS) {
    if (!isFiniteNumber(value[key])) {
      return null;
    }
  }
  for (const key of SCENARIO_BOOLEAN_KEYS) {
    if (typeof value[key] !== "boolean") {
      return null;
    }
  }
  return value as unknown as EvalSmokeScenarioResult;
}

function parseExpandedScenarios(value: unknown): readonly EvalScenarioResult[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const scenarios = value.map(parseExpandedScenario);
  if (scenarios.some((scenario) => scenario === null)) {
    return null;
  }
  return scenarios as readonly EvalScenarioResult[];
}

function parseEvalScenarioHistoryEntry(value: unknown): EvalScenarioHistoryEntry | null {
  if (!isRecord(value)) {
    return null;
  }
  const metrics = parseExpandedMetrics(value["metrics"]);
  if (
    !isNonEmptyString(value["run_id"]) ||
    !isValidDateTime(value["created_at"]) ||
    metrics === null
  ) {
    return null;
  }
  return {
    run_id: value["run_id"],
    created_at: value["created_at"],
    metrics
  };
}

function parseExpandedScenario(value: unknown): EvalScenarioResult | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    !isNonEmptyString(value["id"]) ||
    !isNonEmptyString(value["kind"]) ||
    !isNonEmptyString(value["category"]) ||
    !isFiniteNumber(value["latency_ms"]) ||
    !isRecord(value["expected"]) ||
    !isRecord(value["observed"]) ||
    typeof value["passed"] !== "boolean" ||
    !isStringArray(value["failures"])
  ) {
    return null;
  }
  return value as unknown as EvalScenarioResult;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isRateRecord(value: unknown): value is Readonly<Record<string, number>> {
  return (
    isRecord(value) &&
    Object.values(value).every(
      (item) => typeof item === "number" && Number.isFinite(item) && item >= 0 && item <= 1
    )
  );
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isFinalDecision(value: unknown): value is FinalDecision {
  return typeof value === "string" && FINAL_DECISIONS.has(value as FinalDecision);
}

function isValidDateTime(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}
