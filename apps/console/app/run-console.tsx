"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Check,
  CheckCircle2,
  ClipboardCheck,
  FileSearch,
  GitBranch,
  Play,
  RotateCcw,
  ShieldCheck,
  X
} from "lucide-react";

import type {
  ApprovalDecision,
  ApprovalRecord,
  EvalScenarioHistoryEntry,
  EvalScenarioHistoryReport,
  EvalScenarioReport,
  EvalSmokeReport,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  RepoChecksRunRequest,
  RiskLevel,
  SandboxRun,
  VerificationReplayResponse,
  VerificationRun
} from "@hallu-defense/contracts";
import { HalluDefenseClient } from "@hallu-defense/sdk";

interface RunConsoleProps {
  readonly apiBaseUrl: string;
  readonly initialRun: VerificationRun;
  readonly initialEvalSmokeReport: EvalSmokeReport | null;
  readonly initialEvalScenarioReport: EvalScenarioReport | null;
  readonly initialEvalScenarioHistoryReport: EvalScenarioHistoryReport | null;
}

const sampleDocument =
  "Part-time employees accrue PTO pro rata based on scheduled hours.\n\n" +
  "Full-time employees receive 15 days of paid vacation per year.";
const defaultPolicyAttributes = '{\n  "tenant_id": "console",\n  "tool_name": "read_file"\n}';
const defaultSandboxCommands = "python --version";

export function RunConsole({
  apiBaseUrl,
  initialRun,
  initialEvalSmokeReport,
  initialEvalScenarioReport,
  initialEvalScenarioHistoryReport
}: RunConsoleProps) {
  const [messageText, setMessageText] = useState(
    "Los empleados part-time reciben 15 dias de vacaciones pagadas al ano."
  );
  const [documentText, setDocumentText] = useState(sampleDocument);
  const [run, setRun] = useState<VerificationRun>(initialRun);
  const [approvals, setApprovals] = useState<readonly ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [approvalLoading, setApprovalLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [policySubject, setPolicySubject] = useState("console-user");
  const [policyAction, setPolicyAction] = useState("read");
  const [policyResource, setPolicyResource] = useState("repo:local");
  const [policyRisk, setPolicyRisk] = useState<RiskLevel>("medium");
  const [policyAttributes, setPolicyAttributes] = useState(defaultPolicyAttributes);
  const [policyResult, setPolicyResult] = useState<PolicyEvaluationResponse | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [repoRef, setRepoRef] = useState(".");
  const [commandsText, setCommandsText] = useState(defaultSandboxCommands);
  const [networkPolicy, setNetworkPolicy] = useState<SandboxRun["network_policy"]>("deny");
  const [sandboxRun, setSandboxRun] = useState<SandboxRun | null>(null);
  const [sandboxLoading, setSandboxLoading] = useState(false);
  const [sandboxError, setSandboxError] = useState<string | null>(null);
  const [replayTraceId, setReplayTraceId] = useState("");
  const [replayResult, setReplayResult] = useState<VerificationReplayResponse | null>(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayError, setReplayError] = useState<string | null>(null);

  const client = useMemo(
    () =>
      new HalluDefenseClient({
        baseUrl: apiBaseUrl,
        tenantId: "console",
        subjectId: "console-reviewer",
        roles: ["approval_reviewer", "verifier"],
        timeoutMs: 8000
      }),
    [apiBaseUrl]
  );

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const result = await client.listApprovals({ status: "pending" });
        if (!cancelled) {
          setApprovals(result.approvals);
        }
      } catch {
        if (!cancelled) {
          setApprovals([]);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [client]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setErrorMessage(null);
    try {
      const result = await client.runVerification({
        tenant_id: "console",
        message_text: messageText,
        task_type: "document_qa",
        documents: [
          {
            source_ref: "console-document",
            content: documentText,
            authority: "internal"
          }
        ]
      });
      setRun(result);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "No se pudo ejecutar el run");
    } finally {
      setLoading(false);
    }
  }

  function resetDemo() {
    setRun(initialRun);
    setMessageText("Los empleados part-time reciben 15 dias de vacaciones pagadas al ano.");
    setDocumentText(sampleDocument);
    setErrorMessage(null);
  }

  async function refreshApprovals() {
    setApprovalLoading(true);
    setApprovalMessage(null);
    try {
      const result = await client.listApprovals({ status: "pending" });
      setApprovals(result.approvals);
    } catch (error) {
      setApprovalMessage(error instanceof Error ? error.message : "No se pudo cargar la cola");
    } finally {
      setApprovalLoading(false);
    }
  }

  async function enqueueApproval() {
    setApprovalLoading(true);
    setApprovalMessage(null);
    try {
      const validation = await client.validateToolInput({
        tool_name: "delete_repository",
        input: { repo: "core", api_key: "demo" },
        schema: { type: "object", required: ["repo"] },
        risk_level: "high",
        approval_required: false,
        caller_context: { subject: "console-user" }
      });
      const message =
        validation.approval_id !== undefined && validation.approval_id !== null
          ? `Pendiente ${validation.approval_id}`
          : validation.reason;
      await refreshApprovals();
      setApprovalMessage(message);
    } catch (error) {
      setApprovalMessage(error instanceof Error ? error.message : "No se pudo encolar approval");
      setApprovalLoading(false);
    }
  }

  async function decideApproval(approvalId: string, decision: ApprovalDecision) {
    setApprovalLoading(true);
    setApprovalMessage(null);
    try {
      await client.decideApproval({
        approval_id: approvalId,
        decision,
        reason: decision === "approve" ? "Approved in console." : "Rejected in console."
      });
      await refreshApprovals();
      setApprovalMessage(decision === "approve" ? "Aprobado" : "Rechazado");
    } catch (error) {
      setApprovalMessage(error instanceof Error ? error.message : "No se pudo decidir approval");
      setApprovalLoading(false);
    }
  }

  async function handlePolicySubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const action = policyAction.trim();
    const subject = policySubject.trim();
    const resource = policyResource.trim();

    if (action.length === 0) {
      setPolicyError("La accion es obligatoria");
      return;
    }

    setPolicyLoading(true);
    setPolicyError(null);
    try {
      const attributes = parseAttributes(policyAttributes);
      const request = {
        action,
        risk_level: policyRisk,
        ...(subject.length > 0 ? { subject } : {}),
        ...(resource.length > 0 ? { resource } : {}),
        ...(attributes !== undefined ? { attributes } : {})
      } satisfies PolicyEvaluationRequest;
      const result = await client.evaluatePolicy(request);
      setPolicyResult(result);
    } catch (error) {
      setPolicyError(error instanceof Error ? error.message : "No se pudo evaluar policy");
    } finally {
      setPolicyLoading(false);
    }
  }

  async function handleReplaySubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const traceId = replayTraceId.trim();
    if (traceId.length === 0) {
      setReplayError("El trace es obligatorio");
      return;
    }
    setReplayLoading(true);
    setReplayError(null);
    try {
      const result = await client.replayVerification({ trace_id: traceId });
      setReplayResult(result);
    } catch (error) {
      setReplayResult(null);
      setReplayError(error instanceof Error ? error.message : "No se pudo ejecutar replay");
    } finally {
      setReplayLoading(false);
    }
  }

  async function handleSandboxSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const commands = parseCommands(commandsText);
    if (commands.length === 0) {
      setSandboxError("Agrega al menos un comando");
      return;
    }

    setSandboxLoading(true);
    setSandboxError(null);
    try {
      const request = {
        repo_ref: repoRef.trim() || ".",
        commands,
        network_policy: networkPolicy
      } satisfies RepoChecksRunRequest;
      const result = await client.runRepoChecks(request);
      setSandboxRun(result);
    } catch (error) {
      setSandboxError(error instanceof Error ? error.message : "No se pudo ejecutar sandbox");
    } finally {
      setSandboxLoading(false);
    }
  }

  const blockedCount = run.verdicts.filter((verdict) => verdict.action === "block").length;
  const repairedCount = run.verdicts.filter((verdict) => verdict.action === "rewrite").length;
  const supportedCount = run.verdicts.filter((verdict) => verdict.status === "SUPPORTED").length;
  const sandboxSummary = useMemo(() => summarizeSandboxRun(sandboxRun), [sandboxRun]);

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Hallu Defense</p>
          <h1>Consola DevEx</h1>
        </div>
        <div className="status-pill" aria-label={`Decision final ${run.final_decision}`}>
          <ShieldCheck aria-hidden="true" size={18} />
          <span>{run.final_decision}</span>
        </div>
      </header>

      <section className="metrics" aria-label="Metricas del run">
        <Metric icon={<Activity aria-hidden="true" />} label="Trace" value={run.trace_id} />
        <Metric icon={<CheckCircle2 aria-hidden="true" />} label="Soportados" value={supportedCount} />
        <Metric icon={<FileSearch aria-hidden="true" />} label="Reparados" value={repairedCount} />
        <Metric icon={<AlertTriangle aria-hidden="true" />} label="Bloqueados" value={blockedCount} />
      </section>

      <section className="eval-dashboard-grid" aria-label="Eval dashboards">
        <EvalSmokeDashboard report={initialEvalSmokeReport} />
        <EvalScenarioDashboard
          report={initialEvalScenarioReport}
          history={initialEvalScenarioHistoryReport}
        />
      </section>

      <section className="workspace">
        <form className="panel verify-panel" onSubmit={handleSubmit}>
          <div className="panel-header">
            <h2>Verificacion</h2>
            <div className="toolbar">
              <button className="icon-button" type="button" onClick={resetDemo} title="Restaurar demo">
                <RotateCcw aria-hidden="true" size={18} />
              </button>
              <button className="primary-button" type="submit" disabled={loading}>
                <Play aria-hidden="true" size={18} />
                <span>{loading ? "Ejecutando" : "Ejecutar"}</span>
              </button>
            </div>
          </div>

          <label className="field">
            <span>Respuesta candidata</span>
            <textarea
              value={messageText}
              onChange={(event) => setMessageText(event.target.value)}
              rows={5}
              required
            />
          </label>

          <label className="field">
            <span>Evidencia documental</span>
            <textarea
              value={documentText}
              onChange={(event) => setDocumentText(event.target.value)}
              rows={8}
              required
            />
          </label>

          {errorMessage !== null ? (
            <p className="error" role="alert">
              {errorMessage}
            </p>
          ) : null}
        </form>

        <section className="panel result-panel" aria-label="Resultado final">
          <div className="panel-header">
            <h2>Respuesta final</h2>
            <span className="policy">Policy {run.policy_version}</span>
          </div>
          <pre>{safeText(run.final_text)}</pre>
        </section>
      </section>

      <section className="operations-grid" aria-label="Policy y sandbox">
        <section className="panel operation-panel" aria-label="Policy explanation">
          <div className="panel-header">
            <h2>
              <ShieldCheck aria-hidden="true" />
              <span>Policy explanation</span>
            </h2>
            <span className="policy">/policy/evaluate</span>
          </div>

          <form className="operation-form" onSubmit={handlePolicySubmit}>
            <div className="field-grid">
              <label className="field">
                <span>Sujeto</span>
                <input
                  value={policySubject}
                  onChange={(event) => setPolicySubject(event.target.value)}
                  autoComplete="off"
                />
              </label>
              <label className="field">
                <span>Accion</span>
                <input
                  value={policyAction}
                  onChange={(event) => setPolicyAction(event.target.value)}
                  autoComplete="off"
                  required
                />
              </label>
              <label className="field">
                <span>Recurso</span>
                <input
                  value={policyResource}
                  onChange={(event) => setPolicyResource(event.target.value)}
                  autoComplete="off"
                />
              </label>
              <label className="field">
                <span>Riesgo</span>
                <select
                  value={policyRisk}
                  onChange={(event) => setPolicyRisk(event.target.value as RiskLevel)}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
            </div>

            <label className="field">
              <span>Atributos JSON</span>
              <textarea
                value={policyAttributes}
                onChange={(event) => setPolicyAttributes(event.target.value)}
                rows={5}
              />
            </label>

            <div className="form-footer">
              {policyError !== null ? (
                <p className="error compact-error" role="alert">
                  {policyError}
                </p>
              ) : null}
              <button className="primary-button" type="submit" disabled={policyLoading}>
                <Play aria-hidden="true" size={18} />
                <span>{policyLoading ? "Evaluando" : "Evaluar"}</span>
              </button>
            </div>
          </form>

          <PolicyExplanation result={policyResult} loading={policyLoading} />
        </section>

        <section className="panel operation-panel" aria-label="Sandbox evidence">
          <div className="panel-header">
            <h2>
              <GitBranch aria-hidden="true" />
              <span>Sandbox evidence</span>
            </h2>
            <span className="policy">/repo/checks/run</span>
          </div>

          <form className="operation-form" onSubmit={handleSandboxSubmit}>
            <div className="field-grid sandbox-controls">
              <label className="field">
                <span>Repo ref</span>
                <input
                  value={repoRef}
                  onChange={(event) => setRepoRef(event.target.value)}
                  autoComplete="off"
                  required
                />
              </label>
              <label className="field">
                <span>Network</span>
                <select
                  value={networkPolicy}
                  onChange={(event) => setNetworkPolicy(event.target.value as SandboxRun["network_policy"])}
                >
                  <option value="deny">deny</option>
                  <option value="allowlisted">allowlisted</option>
                </select>
              </label>
            </div>

            <label className="field">
              <span>Comandos</span>
              <textarea
                value={commandsText}
                onChange={(event) => setCommandsText(event.target.value)}
                rows={5}
                required
              />
            </label>

            <div className="form-footer">
              {sandboxError !== null ? (
                <p className="error compact-error" role="alert">
                  {sandboxError}
                </p>
              ) : null}
              <button className="primary-button" type="submit" disabled={sandboxLoading}>
                <Play aria-hidden="true" size={18} />
                <span>{sandboxLoading ? "Ejecutando" : "Ejecutar"}</span>
              </button>
            </div>
          </form>

          <SandboxEvidence run={sandboxRun} summary={sandboxSummary} loading={sandboxLoading} />
        </section>
      </section>

      <section className="panel operation-panel replay-panel" aria-label="Replay verification">
        <div className="panel-header">
          <h2>
            <RotateCcw aria-hidden="true" />
            <span>Replay verification</span>
          </h2>
          <span className="policy">/verification/replay</span>
        </div>

        <form className="operation-form" onSubmit={handleReplaySubmit}>
          <label className="field">
            <span>Trace a reproducir</span>
            <input
              value={replayTraceId}
              onChange={(event) => setReplayTraceId(event.target.value)}
              placeholder="tr_..."
              autoComplete="off"
              required
            />
          </label>
          <div className="form-footer">
            {replayError !== null ? (
              <p className="error compact-error" role="alert">
                {replayError}
              </p>
            ) : null}
            <button
              className="secondary-button"
              type="button"
              onClick={() => setReplayTraceId(run.trace_id)}
            >
              <RotateCcw aria-hidden="true" size={16} />
              <span>Usar trace actual</span>
            </button>
            <button className="primary-button" type="submit" disabled={replayLoading}>
              <Play aria-hidden="true" size={18} />
              <span>{replayLoading ? "Reproduciendo" : "Replay"}</span>
            </button>
          </div>
        </form>

        <ReplayResult result={replayResult} loading={replayLoading} />
      </section>

      <section className="grid-three">
        <LedgerPanel title="Claims" icon={<ClipboardCheck aria-hidden="true" />}>
          <ul className="ledger-list">
            {run.claims.map((claim) => (
              <li key={claim.claim_id}>
                <span className="row-title">{claim.claim_id}</span>
                <span>{safeText(claim.text)}</span>
                <small>
                  {claim.type} / {claim.risk_level}
                </small>
              </li>
            ))}
          </ul>
        </LedgerPanel>

        <LedgerPanel title="Veredictos" icon={<ShieldCheck aria-hidden="true" />}>
          <ul className="ledger-list">
            {run.verdicts.map((verdict) => (
              <li key={verdict.claim_id}>
                <span className={`badge badge-${verdict.action}`}>{verdict.action}</span>
                <span>{verdict.status}</span>
                <small>{safeText(verdict.reason)}</small>
              </li>
            ))}
          </ul>
        </LedgerPanel>

        <LedgerPanel title="Evidencia" icon={<GitBranch aria-hidden="true" />}>
          <ul className="ledger-list">
            {run.evidence.map((evidence) => (
              <li key={evidence.evidence_id}>
                <span className="row-title">{safeText(evidence.source_ref)}</span>
                <span>{safeSnippet(evidence.content, 280)}</span>
                <small>
                  {evidence.kind} / {evidence.authority}
                </small>
              </li>
            ))}
          </ul>
        </LedgerPanel>
      </section>

      <section className="panel approval-panel" aria-label="Approval queue">
        <div className="panel-header">
          <h2>
            <ClipboardCheck aria-hidden="true" />
            <span>Approvals</span>
          </h2>
          <div className="toolbar">
            <button
              className="icon-button"
              type="button"
              onClick={refreshApprovals}
              disabled={approvalLoading}
              title="Actualizar approvals"
            >
              <RotateCcw aria-hidden="true" size={18} />
            </button>
            <button
              className="primary-button"
              type="button"
              onClick={enqueueApproval}
              disabled={approvalLoading}
            >
              <Play aria-hidden="true" size={18} />
              <span>Encolar</span>
            </button>
          </div>
        </div>

        {approvalMessage !== null ? (
          <p className="approval-message" role="status" aria-live="polite">
            {approvalMessage}
          </p>
        ) : null}

        <ul className="ledger-list approval-list">
          {approvals.length === 0 ? (
            <li>
              <span className="row-title">Sin pendientes</span>
              <small>tenant console</small>
            </li>
          ) : (
            approvals.map((approval) => (
              <li key={approval.approval_id}>
                <span className="row-title">{approval.tool_call.tool_name}</span>
                <span className={`badge badge-${approval.status}`}>{approval.status}</span>
                <small>
                  {approval.approval_id} / {approval.risk_level} / {approval.requested_by}
                </small>
                <small className="approval-input-snippet">
                  input {safeSnippet(JSON.stringify(approval.tool_call.input), 200)}
                </small>
                <div className="approval-actions">
                  <button
                    className="secondary-button"
                    type="button"
                    onClick={() => decideApproval(approval.approval_id, "approve")}
                    disabled={approvalLoading}
                  >
                    <Check aria-hidden="true" size={16} />
                    <span>Aprobar</span>
                  </button>
                  <button
                    className="danger-button"
                    type="button"
                    onClick={() => decideApproval(approval.approval_id, "reject")}
                    disabled={approvalLoading}
                  >
                    <X aria-hidden="true" size={16} />
                    <span>Rechazar</span>
                  </button>
                </div>
              </li>
            ))
          )}
        </ul>
      </section>
    </main>
  );
}

function EvalSmokeDashboard({ report }: Readonly<{ report: EvalSmokeReport | null }>) {
  if (report === null) {
    return (
      <section className="panel eval-panel" aria-label="Eval smoke dashboard">
        <div className="panel-header">
          <h2>
            <BarChart3 aria-hidden="true" />
            <span>Eval smoke</span>
          </h2>
          <span className="policy">evals/reports/smoke-metrics.json</span>
        </div>
        <article className="evidence-card empty-card">
          <span className="row-title">Sin reporte</span>
          <small>Ejecuta eval smoke para generar metricas</small>
        </article>
      </section>
    );
  }

  const { metrics } = report;
  const passedScenarios = report.scenarios.filter(
    (scenario) => scenario.final_decision === scenario.expected_final_decision
  ).length;

  return (
    <section className="panel eval-panel" aria-label="Eval smoke dashboard">
      <div className="panel-header">
        <h2>
          <BarChart3 aria-hidden="true" />
          <span>Eval smoke</span>
        </h2>
        <span className="policy">evals/reports/smoke-metrics.json</span>
      </div>

      <div className="summary-grid eval-summary">
        <SummaryCell label="scenarios" value={metrics.scenario_count} />
        <SummaryCell label="passed" value={passedScenarios} />
        <SummaryCell label="p95 ms" value={Math.round(metrics.p95_latency_ms)} />
        <SummaryCell label="cost usd" value={metrics.cost_per_run_usd} />
      </div>

      <div className="eval-metric-grid">
        <EvalMetric label="decision accuracy" value={formatPercent(metrics.final_decision_accuracy)} />
        <EvalMetric label="unsupported recall" value={formatPercent(metrics.unsupported_claim_recall)} />
        <EvalMetric label="groundedness" value={formatPercent(metrics.groundedness)} />
        <EvalMetric label="faithfulness" value={formatPercent(metrics.faithfulness)} />
        <EvalMetric label="false positive blocking" value={formatPercent(metrics.false_positive_blocking)} />
        <EvalMetric label="critical pass-through" value={formatPercent(metrics.critical_pass_through)} />
      </div>

      <ul className="ledger-list eval-scenario-list">
        {report.scenarios.map((scenario) => (
          <li key={scenario.id}>
            <span className="row-title">{safeText(scenario.id)}</span>
            <span
              className={
                scenario.final_decision === scenario.expected_final_decision
                  ? "badge badge-allow"
                  : "badge badge-block"
              }
            >
              {scenario.final_decision}
            </span>
            <small>
              expected {scenario.expected_final_decision} / {formatMs(scenario.latency_ms)} /{" "}
              {scenario.actual_claims.length} claims
            </small>
          </li>
        ))}
      </ul>
    </section>
  );
}

function EvalScenarioDashboard({
  report,
  history
}: Readonly<{
  report: EvalScenarioReport | null;
  history: EvalScenarioHistoryReport | null;
}>) {
  if (report === null) {
    return (
      <section className="panel eval-panel" aria-label="Expanded eval dashboard">
        <div className="panel-header">
          <h2>
            <BarChart3 aria-hidden="true" />
            <span>Eval scenarios</span>
          </h2>
          <span className="policy">evals/reports/scenario-metrics.json</span>
        </div>
        <article className="evidence-card empty-card">
          <span className="row-title">Sin reporte</span>
          <small>Ejecuta evals-scenarios para generar metricas</small>
        </article>
      </section>
    );
  }

  const { metrics } = report;
  const failedScenarios = report.scenarios.length - metrics.passed_count;
  const categoryRows = Object.entries(metrics.category_pass_rate).sort(([left], [right]) =>
    left.localeCompare(right)
  );
  const latestHistory = latestScenarioHistory(history);
  const previousHistory = previousScenarioHistory(history);

  return (
    <section className="panel eval-panel" aria-label="Expanded eval dashboard">
      <div className="panel-header">
        <h2>
          <BarChart3 aria-hidden="true" />
          <span>Eval scenarios</span>
        </h2>
        <span className="policy">evals/reports/scenario-metrics.json</span>
      </div>

      <div className="summary-grid eval-summary">
        <SummaryCell label="scenarios" value={metrics.scenario_count} />
        <SummaryCell label="passed" value={metrics.passed_count} />
        <SummaryCell label="failed" value={failedScenarios} />
        <SummaryCell label="p95 ms" value={Math.round(metrics.p95_latency_ms)} />
      </div>

      <div className="eval-metric-grid">
        <EvalMetric label="pass rate" value={formatPercent(metrics.pass_rate)} />
        <EvalMetric label="decision accuracy" value={formatPercent(metrics.verification_decision_accuracy)} />
        <EvalMetric label="high-risk blocks" value={formatPercent(metrics.blocked_high_risk_rate)} />
        <EvalMetric label="repo false claims" value={formatPercent(metrics.repo_false_claim_block_rate)} />
        <EvalMetric
          label="repo semantic claims"
          value={formatPercent(metrics.repo_semantic_claim_decision_accuracy)}
        />
        <EvalMetric label="sandbox blocks" value={formatPercent(metrics.sandbox_block_rate)} />
      </div>

      <div className="eval-category-grid" aria-label="Eval category pass rates">
        {categoryRows.map(([category, value]) => (
          <EvalMetric key={category} label={safeText(category)} value={formatPercent(value)} />
        ))}
      </div>

      {latestHistory !== null ? (
        <section className="eval-history" aria-label="Eval scenario history">
          <div className="eval-history-summary">
            <EvalMetric
              label="latest pass"
              value={`${formatPercent(latestHistory.metrics.pass_rate)} ${formatDelta(
                latestHistory.metrics.pass_rate,
                previousHistory?.metrics.pass_rate,
                "percent"
              )}`}
            />
            <EvalMetric
              label="latest p95"
              value={`${formatMs(latestHistory.metrics.p95_latency_ms)} ${formatDelta(
                latestHistory.metrics.p95_latency_ms,
                previousHistory?.metrics.p95_latency_ms,
                "ms"
              )}`}
            />
          </div>
          <ul className="ledger-list eval-history-list">
            {recentScenarioHistory(history).map((entry) => (
              <li key={entry.run_id}>
                <span className="row-title">{safeText(entry.run_id)}</span>
                <span className="badge badge-allow">{formatPercent(entry.metrics.pass_rate)}</span>
                <small>
                  {formatRunDate(entry.created_at)} / {entry.metrics.passed_count}/
                  {entry.metrics.scenario_count} passed / {formatMs(entry.metrics.p95_latency_ms)}
                </small>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <ul className="ledger-list eval-scenario-list">
        {report.scenarios.map((scenario) => (
          <li key={scenario.id}>
            <span className="row-title">{safeText(scenario.id)}</span>
            <span className={scenario.passed ? "badge badge-allow" : "badge badge-block"}>
              {scenario.passed ? "passed" : "failed"}
            </span>
            <small>
              {safeText(scenario.category)} / expected{" "}
              {formatScenarioValue(scenario.expected, "final_decision")} / observed{" "}
              {formatScenarioValue(scenario.observed, "final_decision")} / {formatMs(scenario.latency_ms)}
            </small>
            {scenario.failures.length > 0 ? (
              <small>{safeSnippet(scenario.failures.join("; "), 240)}</small>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function EvalMetric({ label, value }: Readonly<{ label: string; value: string }>) {
  return (
    <article className="eval-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function Metric({
  icon,
  label,
  value
}: Readonly<{ icon: React.ReactNode; label: string; value: string | number }>) {
  return (
    <article className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </article>
  );
}

function LedgerPanel({
  title,
  icon,
  children
}: Readonly<{ title: string; icon: React.ReactNode; children: React.ReactNode }>) {
  return (
    <section className="panel ledger-panel">
      <div className="panel-header">
        <h2>
          {icon}
          <span>{title}</span>
        </h2>
      </div>
      {children}
    </section>
  );
}

function PolicyExplanation({
  result,
  loading
}: Readonly<{ result: PolicyEvaluationResponse | null; loading: boolean }>) {
  if (result === null) {
    return (
      <article className="evidence-card empty-card" aria-live="polite">
        <span className="row-title">{loading ? "Evaluando policy" : "Sin evaluacion"}</span>
        <small>tenant console</small>
      </article>
    );
  }

  return (
    <article className="evidence-card" aria-live="polite">
      <div className="decision-line">
        <span className={`badge ${result.allowed ? "badge-allow" : "badge-block"}`}>
          {result.allowed ? "allowed" : "blocked"}
        </span>
        <span className={`badge badge-${result.action}`}>{result.action}</span>
        <small>Policy {result.policy_version}</small>
      </div>
      <p className="explanation-text">{safeText(result.explanation)}</p>
      <div className="detail-block">
        <span className="detail-label">Matched rules</span>
        <TagList values={result.matched_rules} emptyLabel="Sin reglas" />
      </div>
    </article>
  );
}

function ReplayResult({
  result,
  loading
}: Readonly<{ result: VerificationReplayResponse | null; loading: boolean }>) {
  if (result === null) {
    return (
      <article className="evidence-card empty-card" aria-live="polite">
        <span className="row-title">{loading ? "Reproduciendo run" : "Sin replay"}</span>
        <small>tenant console</small>
      </article>
    );
  }

  const replayed = result.replayed_run;
  return (
    <article className="evidence-card" aria-live="polite">
      <div className="decision-line">
        <span className={`badge badge-${result.source_final_decision}`}>
          origen {result.source_final_decision}
        </span>
        <span className={`badge badge-${replayed.final_decision}`}>
          replay {replayed.final_decision}
        </span>
        <span className={result.decision_changed ? "badge badge-block" : "badge badge-allow"}>
          {result.decision_changed ? "decision cambiada" : "decision estable"}
        </span>
      </div>
      <p className="explanation-text">
        Fuente {safeText(result.source_trace_id)} creada {formatRunDate(result.source_created_at)}.
        Replay {safeText(result.trace_id)} re-ejecuto verificacion y reparacion sobre el snapshot
        auditado.
      </p>
      <div className="detail-block">
        <span className="detail-label">Respuesta replay</span>
        <pre className="snippet">{safeSnippet(replayed.final_text, 500)}</pre>
      </div>
      <div className="detail-block">
        <span className="detail-label">Veredictos replay</span>
        <TagList
          values={replayed.verdicts.map((verdict) => `${verdict.claim_id}: ${verdict.status}`)}
          emptyLabel="Sin veredictos"
        />
      </div>
    </article>
  );
}

function SandboxEvidence({
  run,
  summary,
  loading
}: Readonly<{
  run: SandboxRun | null;
  summary: SandboxInspectionSummary | null;
  loading: boolean;
}>) {
  if (run === null) {
    return (
      <article className="evidence-card empty-card" aria-live="polite">
        <span className="row-title">{loading ? "Ejecutando sandbox" : "Sin sandbox run"}</span>
        <small>network deny</small>
      </article>
    );
  }

  const commandRows = buildCommandRows(run);

  return (
    <div className="sandbox-result" aria-live="polite">
      <div className="run-strip">
        <span className="row-title">{safeText(run.repo_ref)}</span>
        <span className={`badge badge-${run.verdict === "SUPPORTED" ? "allow" : "block"}`}>{run.verdict}</span>
        <small>
          {run.network_policy} / {run.artifacts.length} artifacts / {run.evidence.length} evidence
        </small>
      </div>

      <section className="detail-block" aria-label="Sandbox commands">
        <span className="detail-label">Commands</span>
        <ul className="command-list">
          {commandRows.map((row) => (
            <li key={`${row.index}-${row.command}`}>
              <div className="command-header">
                <span className="row-title">{safeText(row.command)}</span>
                <span className={row.exitCode === 0 ? "badge badge-allow" : "badge badge-block"}>
                  exit {row.exitCodeText}
                </span>
              </div>
              <small>
                {row.kind} / targets {row.targets.length > 0 ? row.targets.join(", ") : "none"}
              </small>
              <div className="snippet-grid">
                <OutputSnippet label="stdout" value={row.stdout} />
                <OutputSnippet label="stderr" value={row.stderr} />
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="detail-block" aria-label="Sandbox artifacts">
        <span className="detail-label">Artifacts</span>
        <TagList values={run.artifacts} emptyLabel="Sin artifacts" />
      </section>

      <InspectionSummary summary={summary} />
    </div>
  );
}

function InspectionSummary({ summary }: Readonly<{ summary: SandboxInspectionSummary | null }>) {
  if (summary === null) {
    return (
      <section className="detail-block" aria-label="Sandbox inspection">
        <span className="detail-label">Inspection</span>
        <article className="evidence-card empty-card">
          <span className="row-title">Sin reporte</span>
          <small>reports/sandbox-inspection.json</small>
        </article>
      </section>
    );
  }

  return (
    <section className="detail-block" aria-label="Sandbox inspection">
      <span className="detail-label">Inspection</span>
      <small className="inspection-source">{safeText(summary.sourceRef)}</small>
      <div className="summary-grid">
        <SummaryCell label="diff files" value={summary.diffFiles.length} />
        <SummaryCell label="changed symbols" value={summary.changedSymbols.length} />
        <SummaryCell label="changed lines" value={summary.changedLines.length} />
        <SummaryCell label="static files" value={summary.staticFiles.length} />
      </div>

      <div className="inspection-columns">
        <div>
          <span className="detail-label">Diff</span>
          <TagList values={summary.diffFiles} emptyLabel="Sin diff files" />
          {summary.diffStat.length > 0 ? <pre className="snippet">{safeSnippet(summary.diffStat, 500)}</pre> : null}
        </div>
        <div>
          <span className="detail-label">Symbols</span>
          <TagList values={summary.changedSymbols} emptyLabel="Sin changed symbols" />
        </div>
      </div>

      <div className="inspection-columns">
        <div>
          <span className="detail-label">Changed lines</span>
          <TagList values={summary.changedLines} emptyLabel="Sin changed lines" />
        </div>
        <div>
          <span className="detail-label">Git status</span>
          <TagList values={summary.status} emptyLabel="Clean" />
        </div>
      </div>

      {summary.errors.length > 0 || summary.parseErrors.length > 0 ? (
        <div className="detail-block">
          <span className="detail-label">Inspection errors</span>
          <TagList values={[...summary.errors, ...summary.parseErrors]} emptyLabel="Sin errores" />
        </div>
      ) : null}
    </section>
  );
}

function OutputSnippet({ label, value }: Readonly<{ label: string; value: string }>) {
  return (
    <div>
      <span className="detail-label">{label}</span>
      <pre className="snippet">{safeSnippet(value, 700)}</pre>
    </div>
  );
}

function SummaryCell({ label, value }: Readonly<{ label: string; value: number }>) {
  return (
    <article className="summary-cell">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function formatPercent(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

function formatMs(value: number): string {
  return `${Math.round(value * 10) / 10} ms`;
}

function formatScenarioValue(record: Readonly<Record<string, unknown>>, key: string): string {
  const value = record[key];
  if (value === undefined) {
    return "n/a";
  }
  return safeText(formatScalar(value));
}

function latestScenarioHistory(
  history: EvalScenarioHistoryReport | null
): EvalScenarioHistoryEntry | null {
  const runs = recentScenarioHistory(history);
  return runs[0] ?? null;
}

function previousScenarioHistory(
  history: EvalScenarioHistoryReport | null
): EvalScenarioHistoryEntry | null {
  const runs = recentScenarioHistory(history);
  return runs[1] ?? null;
}

function recentScenarioHistory(
  history: EvalScenarioHistoryReport | null
): readonly EvalScenarioHistoryEntry[] {
  if (history === null) {
    return [];
  }
  return [...history.runs]
    .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
    .slice(0, 5);
}

function formatDelta(current: number, previous: number | undefined, mode: "percent" | "ms"): string {
  if (previous === undefined) {
    return "";
  }
  const delta = current - previous;
  if (delta === 0) {
    return "(0)";
  }
  const prefix = delta > 0 ? "+" : "";
  if (mode === "percent") {
    return `(${prefix}${formatPercent(delta)})`;
  }
  return `(${prefix}${formatMs(delta)})`;
}

function formatRunDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "invalid date";
  }
  return date.toISOString().replace(".000Z", "Z");
}

function TagList({
  values,
  emptyLabel
}: Readonly<{ values: readonly string[]; emptyLabel: string }>) {
  const visibleValues = values.slice(0, 12);
  return (
    <ul className="tag-list">
      {visibleValues.length === 0 ? (
        <li>{emptyLabel}</li>
      ) : (
        visibleValues.map((value, index) => <li key={`${value}-${index}`}>{safeText(value)}</li>)
      )}
    </ul>
  );
}

type JsonRecord = Readonly<Record<string, unknown>>;

interface SandboxCommandRow {
  readonly index: number;
  readonly command: string;
  readonly exitCode?: number;
  readonly exitCodeText: string;
  readonly stdout: string;
  readonly stderr: string;
  readonly kind: string;
  readonly targets: readonly string[];
}

interface SandboxInspectionSummary {
  readonly sourceRef: string;
  readonly status: readonly string[];
  readonly diffFiles: readonly string[];
  readonly diffStat: string;
  readonly changedRanges: readonly string[];
  readonly changedLines: readonly string[];
  readonly changedSymbols: readonly string[];
  readonly staticFiles: readonly string[];
  readonly errors: readonly string[];
  readonly parseErrors: readonly string[];
}

function parseAttributes(raw: string): Readonly<Record<string, unknown>> | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  const parsed = JSON.parse(trimmed) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("Atributos debe ser un objeto JSON");
  }
  return parsed;
}

function parseCommands(raw: string): readonly string[] {
  return raw
    .split(/\r?\n/)
    .map((command) => command.trim())
    .filter((command) => command.length > 0);
}

function buildCommandRows(run: SandboxRun): readonly SandboxCommandRow[] {
  const commandEvidence = run.evidence.filter(
    (evidence) => getString(evidence.structured_content["schema_version"]) === "sandbox_command.v1"
  );

  return run.commands.map((command, index) => {
    const metadata = commandEvidence[index]?.structured_content;
    const exitCode = run.exit_codes[index];
    const metadataStdout = metadata !== undefined ? getString(metadata["stdout"]) : "";
    const metadataStderr = metadata !== undefined ? getString(metadata["stderr"]) : "";
    const kind = metadata !== undefined ? getString(metadata["command_kind"]) : "";
    const targets = metadata !== undefined ? getStringArray(metadata["command_target_tokens"]) : [];
    return {
      index: index + 1,
      command,
      ...(typeof exitCode === "number" ? { exitCode } : {}),
      exitCodeText: typeof exitCode === "number" ? String(exitCode) : "n/a",
      stdout: run.stdout[index] ?? metadataStdout,
      stderr: run.stderr[index] ?? metadataStderr,
      kind: kind.length > 0 ? kind : "command",
      targets
    };
  });
}

function summarizeSandboxRun(run: SandboxRun | null): SandboxInspectionSummary | null {
  if (run === null) {
    return null;
  }

  for (const evidence of run.evidence) {
    const report = extractInspectionReport(evidence.structured_content);
    if (report === null) {
      continue;
    }

    const git = getRecord(report["git"]);
    const staticReport = getRecord(report["static"]);
    const diffStat = getString(git["diff_stat"]);
    return {
      sourceRef: evidence.source_ref,
      status: getStringArray(git["status"]),
      diffFiles: getStringArray(git["diff_files"]),
      diffStat,
      changedRanges: getRecordArray(git["changed_ranges"]).map(formatChangedRange),
      changedLines: getRecordArray(git["changed_lines"]).map(formatChangedLine),
      changedSymbols: getRecordArray(git["changed_symbols"]).map(formatChangedSymbol),
      staticFiles: getStringArray(staticReport["files"]),
      errors: getRecordArray(git["errors"]).map(formatRecord),
      parseErrors: getRecordArray(staticReport["parse_errors"]).map(formatRecord)
    };
  }

  return null;
}

function extractInspectionReport(content: JsonRecord): JsonRecord | null {
  if (getString(content["schema_version"]) === "sandbox_inspection.v1") {
    return content;
  }
  const nested = content["sandbox_inspection"];
  if (isRecord(nested) && getString(nested["schema_version"]) === "sandbox_inspection.v1") {
    return nested;
  }
  return null;
}

function formatChangedRange(record: JsonRecord): string {
  const path = getString(record["path"]);
  const start = getNumber(record["new_start"]);
  const lines = getNumber(record["new_lines"]);
  const source = getString(record["source"]);
  return `${path}:${start ?? "?"}+${lines ?? "?"} ${source}`.trim();
}

function formatChangedLine(record: JsonRecord): string {
  const path = getString(record["path"]);
  const line = getNumber(record["lineno"]) ?? getNumber(record["old_lineno"]) ?? "?";
  const kind = getString(record["kind"]);
  const text = getString(record["text"]);
  return `${path}:${line} ${kind} ${text}`.trim();
}

function formatChangedSymbol(record: JsonRecord): string {
  const path = getString(record["path"]);
  const qualifiedName = getString(record["qualified_name"]);
  const kind = getString(record["kind"]);
  const line = getNumber(record["lineno"]);
  return `${qualifiedName || "symbol"} / ${path}:${line ?? "?"} / ${kind || "unknown"}`;
}

function formatRecord(record: JsonRecord): string {
  return Object.entries(record)
    .slice(0, 5)
    .map(([key, value]) => `${key}: ${formatScalar(value)}`)
    .join(" / ");
}

function formatScalar(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null || value === undefined) {
    return "null";
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function getRecord(value: unknown): JsonRecord {
  return isRecord(value) ? value : {};
}

function getRecordArray(value: unknown): readonly JsonRecord[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is JsonRecord => isRecord(item));
}

function getStringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string").map((item) => safeText(item));
}

function getString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function getNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeText(value: string): string {
  return redactSecrets(value);
}

function safeSnippet(value: string, maxLength: number): string {
  const redacted = safeText(value.trim());
  if (redacted.length === 0) {
    return "empty";
  }
  if (redacted.length <= maxLength) {
    return redacted;
  }
  return `${redacted.slice(0, maxLength)}...`;
}

function redactSecrets(value: string): string {
  return value
    .replace(/"(api[_-]?key|token|secret|password|authorization)"\s*:\s*"[^"]*"/gi, '"$1":"[redacted]"')
    .replace(/\b(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*([^\s,;'"`]+)/gi, "$1=[redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[redacted]")
    .replace(/(--(?:api-key|token|secret|password)\s+)([^\s]+)/gi, "$1[redacted]")
    .replace(/\b([A-Za-z0-9_]*(?:API|TOKEN|SECRET|PASSWORD|KEY)[A-Za-z0-9_]*)=([^\s]+)/g, "$1=[redacted]");
}
