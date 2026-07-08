import { RunConsole } from "./run-console";
import { demoRun } from "../lib/demo-run";
import {
  loadEvalScenarioHistoryReport,
  loadEvalScenarioReport,
  loadEvalSmokeReport
} from "../lib/eval-report";

export default async function Page() {
  const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";
  const [evalSmokeReport, evalScenarioReport, evalScenarioHistoryReport] = await Promise.all([
    loadEvalSmokeReport(),
    loadEvalScenarioReport(),
    loadEvalScenarioHistoryReport()
  ]);
  return (
    <RunConsole
      apiBaseUrl={apiBaseUrl}
      initialRun={demoRun}
      initialEvalSmokeReport={evalSmokeReport}
      initialEvalScenarioReport={evalScenarioReport}
      initialEvalScenarioHistoryReport={evalScenarioHistoryReport}
    />
  );
}
