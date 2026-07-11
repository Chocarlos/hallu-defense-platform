"use client";

import { useEffect, useMemo, useState } from "react";
import { BarChart3, Database, History, RefreshCw, Upload } from "lucide-react";

import type {
  CorpusGrant,
  DocumentIngestionResponse,
  DocumentIngestionStatusResponse,
  EvalReport,
  VerificationRunSummary
} from "@hallu-defense/contracts";
import { safeConsoleApiError } from "../lib/api-error";
import type { ConsoleApiClientFactory } from "../lib/console-client";
import { createRequestCoordinator } from "../lib/request-coordinator";

interface LiveDashboardsProps {
  readonly createClient: ConsoleApiClientFactory;
  readonly roles: readonly string[];
  readonly historyRevision: number;
  readonly onUseReplayTrace: (traceId: string) => void;
  readonly onUnauthorized: () => void;
}

type LoadState = "loading" | "ready" | "error";

interface ResourceState<T> {
  readonly status: LoadState;
  readonly values: readonly T[];
  readonly error: string | null;
}

interface CorpusMessage {
  readonly kind: "error" | "status";
  readonly text: string;
}

const emptyLoading = <T,>(): ResourceState<T> => ({
  status: "loading",
  values: [],
  error: null
});

export function LiveDashboards({
  createClient,
  roles,
  historyRevision,
  onUseReplayTrace,
  onUnauthorized
}: LiveDashboardsProps) {
  const coordinator = useMemo(() => createRequestCoordinator(), []);
  const [history, setHistory] = useState<ResourceState<VerificationRunSummary>>(
    emptyLoading
  );
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [grants, setGrants] = useState<ResourceState<CorpusGrant>>(emptyLoading);
  const [grantCursor, setGrantCursor] = useState<string | null>(null);
  const [evalReports, setEvalReports] = useState<ResourceState<EvalReport>>(emptyLoading);
  const [corpusId, setCorpusId] = useState("");
  const [sourceRef, setSourceRef] = useState("");
  const [documentText, setDocumentText] = useState("");
  const [corpusMutation, setCorpusMutation] = useState<"grant" | "ingest" | "status" | null>(
    null
  );
  const [corpusMessage, setCorpusMessage] = useState<CorpusMessage | null>(null);
  const [ingestion, setIngestion] = useState<DocumentIngestionResponse | null>(null);
  const [ingestionStatus, setIngestionStatus] =
    useState<DocumentIngestionStatusResponse | null>(null);
  const canWriteRag = roles.includes("rag_writer");

  useEffect(() => {
    return () => coordinator.abortAll();
  }, [coordinator]);

  useEffect(() => {
    setHistory(emptyLoading());
    setHistoryCursor(null);
    void coordinator
      .run("history", `first:${historyRevision}`, (signal) =>
        createClient(signal).listVerificationRuns({ limit: 20 })
      )
      .then((result) => {
        if (result.kind === "current") {
          const response = result.value;
          setHistory({ status: "ready", values: newestRuns(response.runs), error: null });
          setHistoryCursor(response.next_cursor);
        }
      })
      .catch((error: unknown) => {
        setHistory({
          status: "error",
          values: [],
          error: apiError(error, "No se pudo cargar el historial de runs.", onUnauthorized)
        });
      });
    return () => coordinator.abort("history");
  }, [coordinator, createClient, historyRevision, onUnauthorized]);

  useEffect(() => {
    setGrants(emptyLoading());
    setGrantCursor(null);
    void coordinator
      .run("grants", "first", (signal) =>
        createClient(signal).listCorpusGrants({ limit: 50, include_disabled: true })
      )
      .then((result) => {
        if (result.kind === "current") {
          const response = result.value;
          setGrants({ status: "ready", values: newestGrants(response.grants), error: null });
          setGrantCursor(response.next_cursor ?? null);
        }
      })
      .catch((error: unknown) => {
        setGrants({
          status: "error",
          values: [],
          error: apiError(error, "No se pudieron cargar los grants de corpus.", onUnauthorized)
        });
      });

    setEvalReports(emptyLoading());
    void coordinator
      .run("evals", "first", (signal) => createClient(signal).listEvalReports({ limit: 50 }))
      .then((result) => {
        if (result.kind === "current") {
          const response = result.value;
          setEvalReports({
            status: "ready",
            values: newestEvalReports(response.reports),
            error: null
          });
        }
      })
      .catch((error: unknown) => {
        setEvalReports({
          status: "error",
          values: [],
          error: apiError(error, "No se pudieron cargar los reportes de eval.", onUnauthorized)
        });
      });
    return () => {
      coordinator.abort("grants");
      coordinator.abort("evals");
    };
  }, [coordinator, createClient, onUnauthorized]);

  async function refreshHistory() {
    setHistory((current) => ({ ...current, status: "loading", error: null }));
    setHistoryCursor(null);
    try {
      const result = await coordinator.run("history", `first:${historyRevision}`, (signal) =>
        createClient(signal).listVerificationRuns({ limit: 20 })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setHistory({ status: "ready", values: newestRuns(response.runs), error: null });
      setHistoryCursor(response.next_cursor);
    } catch (error) {
      setHistory((current) => ({
        ...current,
        status: "error",
        error: apiError(error, "No se pudo cargar el historial de runs.", onUnauthorized)
      }));
    }
  }

  async function loadMoreHistory() {
    if (historyCursor === null) {
      return;
    }
    setHistory((current) => ({ ...current, status: "loading", error: null }));
    try {
      const cursor = historyCursor;
      const result = await coordinator.run("history", `cursor:${cursor}`, (signal) =>
        createClient(signal).listVerificationRuns({ limit: 20, cursor })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setHistory((current) => ({
        status: "ready",
        values: mergeRuns(current.values, response.runs),
        error: null
      }));
      setHistoryCursor(response.next_cursor);
    } catch (error) {
      setHistory((current) => ({
        ...current,
        status: "error",
        error: apiError(error, "No se pudo cargar la siguiente pagina de runs.", onUnauthorized)
      }));
    }
  }

  async function refreshGrants() {
    setGrants((current) => ({ ...current, status: "loading", error: null }));
    setGrantCursor(null);
    try {
      const result = await coordinator.run("grants", "first", (signal) =>
        createClient(signal).listCorpusGrants({ limit: 50, include_disabled: true })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setGrants({ status: "ready", values: newestGrants(response.grants), error: null });
      setGrantCursor(response.next_cursor ?? null);
    } catch (error) {
      setGrants((current) => ({
        ...current,
        status: "error",
        error: apiError(error, "No se pudieron cargar los grants de corpus.", onUnauthorized)
      }));
    }
  }

  async function loadMoreGrants() {
    if (grantCursor === null) {
      return;
    }
    setGrants((current) => ({ ...current, status: "loading", error: null }));
    try {
      const cursor = grantCursor;
      const result = await coordinator.run("grants", `cursor:${cursor}`, (signal) =>
        createClient(signal).listCorpusGrants({
          limit: 50,
          include_disabled: true,
          cursor
        })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setGrants((current) => ({
        status: "ready",
        values: mergeGrants(current.values, response.grants),
        error: null
      }));
      setGrantCursor(response.next_cursor ?? null);
    } catch (error) {
      setGrants((current) => ({
        ...current,
        status: "error",
        error: apiError(error, "No se pudo cargar la siguiente pagina de grants.", onUnauthorized)
      }));
    }
  }

  async function refreshEvalReports() {
    setEvalReports((current) => ({ ...current, status: "loading", error: null }));
    try {
      const result = await coordinator.run("evals", "first", (signal) =>
        createClient(signal).listEvalReports({ limit: 50 })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setEvalReports({
        status: "ready",
        values: newestEvalReports(response.reports),
        error: null
      });
    } catch (error) {
      setEvalReports((current) => ({
        ...current,
        status: "error",
        error: apiError(error, "No se pudieron cargar los reportes de eval.", onUnauthorized)
      }));
    }
  }

  async function registerCorpus(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedCorpusId = corpusId.trim();
    if (!canWriteRag || normalizedCorpusId.length === 0) {
      return;
    }
    const existing = grants.values.find((grant) => grant.corpus_id === normalizedCorpusId);
    if (existing !== undefined) {
      setCorpusMessage({
        kind: "status",
        text: `El grant ${safeText(normalizedCorpusId)} ya existe en version ${existing.version}.`
      });
      return;
    }
    setCorpusMutation("grant");
    setCorpusMessage(null);
    try {
      const result = await coordinator.run("grant-mutation", normalizedCorpusId, (signal) =>
        createClient(signal).upsertCorpusGrant({
          corpus_id: normalizedCorpusId,
          reader_roles: [],
          writer_roles: [],
          expected_version: 0
        })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setCorpusMessage({
        kind: "status",
        text: `Grant ${safeText(response.grant.corpus_id)} registrado en version ${response.grant.version}.`
      });
      await refreshGrants();
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: apiError(error, "No se pudo registrar el grant de corpus.", onUnauthorized)
      });
    } finally {
      setCorpusMutation(null);
    }
  }

  async function ingestDocument(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedCorpusId = corpusId.trim();
    const normalizedSourceRef = sourceRef.trim();
    if (
      !canWriteRag ||
      normalizedCorpusId.length === 0 ||
      normalizedSourceRef.length === 0 ||
      documentText.trim().length === 0
    ) {
      return;
    }
    setCorpusMutation("ingest");
    setCorpusMessage(null);
    setIngestion(null);
    setIngestionStatus(null);
    try {
      const result = await coordinator.run(
        "ingest-mutation",
        `${normalizedCorpusId}\0${normalizedSourceRef}\0${documentText}`,
        (signal) =>
          createClient(signal).ingestDocuments({
            corpus_id: normalizedCorpusId,
            documents: [
              {
                source_ref: normalizedSourceRef,
                content: documentText,
                authority: "internal"
              }
            ]
          })
      );
      if (result.kind === "superseded") {
        return;
      }
      const response = result.value;
      setIngestion(response);
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: apiError(error, "No se pudo ejecutar la ingesta documental.", onUnauthorized)
      });
    } finally {
      setCorpusMutation(null);
    }
  }

  async function refreshIngestionStatus() {
    if (!canWriteRag || ingestion?.job_id === null || ingestion?.job_id === undefined) {
      return;
    }
    setCorpusMutation("status");
    setCorpusMessage(null);
    try {
      const jobId = ingestion.job_id;
      const result = await coordinator.run("ingestion-status", jobId, (signal) =>
        createClient(signal).getDocumentIngestionStatus({ job_id: jobId })
      );
      if (result.kind === "current") {
        setIngestionStatus(result.value);
      }
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: apiError(error, "No se pudo actualizar el estado de la ingesta.", onUnauthorized)
      });
    } finally {
      setCorpusMutation(null);
    }
  }

  return (
    <section className="live-dashboard-grid" aria-label="Dashboards live">
      <section className="panel live-panel" aria-label="Historial de runs">
        <DashboardHeader
          icon={<History aria-hidden="true" />}
          title="Historial de runs"
          endpoint="/verification/runs/list"
          loading={history.status === "loading"}
          onRefresh={refreshHistory}
        />
        <ResourceStatus
          status={history.status}
          error={history.error}
          empty={history.values.length === 0}
          loadingLabel="Cargando historial de runs"
          emptyLabel="Sin runs completados registrados"
        />
        {history.values.length > 0 ? (
          <ul className="ledger-list live-list">
            {history.values.map((item) => (
              <li key={item.trace_id}>
                <span className="row-title">{safeText(item.trace_id)}</span>
                <span className={`badge badge-${item.final_decision}`}>
                  {item.final_decision}
                </span>
                <small>{formatDate(item.created_at)}</small>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => onUseReplayTrace(item.trace_id)}
                >
                  Usar en replay
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {historyCursor !== null ? (
          <button
            className="secondary-button load-more-button"
            type="button"
            onClick={loadMoreHistory}
            disabled={history.status === "loading"}
          >
            Cargar mas runs
          </button>
        ) : null}
      </section>

      <section className="panel live-panel corpus-panel" aria-label="Corpus e ingesta">
        <DashboardHeader
          icon={<Database aria-hidden="true" />}
          title="Grants de corpus e ingesta"
          endpoint="/rag/corpus-grants/list"
          loading={grants.status === "loading"}
          onRefresh={refreshGrants}
        />
        <ResourceStatus
          status={grants.status}
          error={grants.error}
          empty={grants.values.length === 0}
          loadingLabel="Cargando grants de corpus"
          emptyLabel="Sin grants de corpus registrados"
        />
        {grants.values.length > 0 ? (
          <ul className="ledger-list live-list corpus-grant-list">
            {grants.values.map((grant) => (
              <li key={grant.corpus_id}>
                <span className="row-title">{safeText(grant.corpus_id)}</span>
                <span className={grant.disabled_at === null || grant.disabled_at === undefined ? "badge badge-allow" : "badge badge-rejected"}>
                  {grant.disabled_at === null || grant.disabled_at === undefined
                    ? `active v${grant.version}`
                    : `disabled v${grant.version}`}
                </span>
                <small>
                  readers {formatRoles(grant.reader_roles)} / writers {formatRoles(grant.writer_roles)}
                </small>
                <small>actualizado {formatDate(grant.updated_at)}</small>
              </li>
            ))}
          </ul>
        ) : null}
        {grantCursor !== null ? (
          <button
            className="secondary-button load-more-button"
            type="button"
            onClick={loadMoreGrants}
            disabled={grants.status === "loading"}
          >
            Cargar mas grants
          </button>
        ) : null}

        <div className="corpus-forms">
          <form className="operation-form" onSubmit={registerCorpus}>
            <label className="field" htmlFor="live-corpus-id">
              <span>Corpus ID</span>
              <input
                id="live-corpus-id"
                value={corpusId}
                onChange={(event) => setCorpusId(event.target.value)}
                minLength={1}
                maxLength={120}
                autoComplete="off"
                required
              />
            </label>
            <button
              className="secondary-button"
              type="submit"
              disabled={!canWriteRag || corpusMutation !== null}
            >
              <Database aria-hidden="true" size={16} />
              Registrar grant
            </button>
          </form>

          <form className="operation-form" onSubmit={ingestDocument}>
            <label className="field" htmlFor="live-source-ref">
              <span>Source ref</span>
              <input
                id="live-source-ref"
                value={sourceRef}
                onChange={(event) => setSourceRef(event.target.value)}
                minLength={1}
                maxLength={500}
                autoComplete="off"
                required
              />
            </label>
            <label className="field" htmlFor="live-document-text">
              <span>Documento</span>
              <textarea
                id="live-document-text"
                value={documentText}
                onChange={(event) => setDocumentText(event.target.value)}
                rows={4}
                required
              />
            </label>
            <button
              className="primary-button"
              type="submit"
              disabled={!canWriteRag || corpusMutation !== null}
            >
              <Upload aria-hidden="true" size={16} />
              {corpusMutation === "ingest" ? "Ingestando" : "Ingestar documento"}
            </button>
          </form>
        </div>
        {!canWriteRag ? (
          <p className="resource-note" role="status">
            Lectura disponible. Registrar grants e ingerir requiere el rol rag_writer.
          </p>
        ) : null}
        {corpusMessage !== null ? (
          <p
            className={corpusMessage.kind === "error" ? "error" : "approval-message"}
            role={corpusMessage.kind === "error" ? "alert" : "status"}
            aria-live="polite"
          >
            {safeText(corpusMessage.text)}
          </p>
        ) : null}
        {ingestion !== null ? (
          <article className="evidence-card ingestion-result" aria-live="polite">
            <span className="row-title">Ingesta {safeText(ingestion.trace_id)}</span>
            <small>
              backend {safeText(ingestion.backend)} / {ingestion.indexed_count} indexados de {" "}
              {ingestion.document_count}
            </small>
            {ingestion.job_id !== null && ingestion.job_id !== undefined ? (
              <small>
                job {safeText(ingestion.job_id)} / {ingestionStatus?.job_status ?? ingestion.job_status}
              </small>
            ) : null}
            {ingestion.warnings.length > 0 ? (
              <ul className="tag-list">
                {[...new Set(ingestion.warnings)].map((warning) => (
                  <li key={warning}>{safeText(warning)}</li>
                ))}
              </ul>
            ) : null}
            {ingestion.job_id !== null && ingestion.job_id !== undefined ? (
              <button
                className="secondary-button"
                type="button"
                onClick={refreshIngestionStatus}
                disabled={corpusMutation !== null}
              >
                Actualizar job
              </button>
            ) : null}
          </article>
        ) : null}
      </section>

      <section className="panel live-panel" aria-label="Reportes de eval">
        <DashboardHeader
          icon={<BarChart3 aria-hidden="true" />}
          title="Reportes de eval"
          endpoint="/evals/reports/list"
          loading={evalReports.status === "loading"}
          onRefresh={refreshEvalReports}
        />
        <ResourceStatus
          status={evalReports.status}
          error={evalReports.error}
          empty={evalReports.values.length === 0}
          loadingLabel="Cargando reportes de eval"
          emptyLabel="Sin reportes de eval publicados"
        />
        {evalReports.values.length > 0 ? (
          <ul className="ledger-list live-list eval-report-list">
            {evalReports.values.map((report) => (
              <li key={report.report_id}>
                <span className="row-title">{safeText(report.suite)}</span>
                <span className="badge badge-allow">{formatPercent(report.metrics.pass_rate)}</span>
                <small>
                  run {safeText(report.run_id)} / {report.metrics.scenario_count} escenarios / {" "}
                  {formatMs(report.metrics.p95_latency_ms)}
                </small>
                <small>
                  source {safeText(report.source)} / publicado {formatDate(report.published_at)}
                </small>
                <div className="eval-inline-metrics">
                  {report.metrics.groundedness !== null &&
                  report.metrics.groundedness !== undefined ? (
                    <span>groundedness {formatPercent(report.metrics.groundedness)}</span>
                  ) : null}
                  {report.metrics.faithfulness !== null &&
                  report.metrics.faithfulness !== undefined ? (
                    <span>faithfulness {formatPercent(report.metrics.faithfulness)}</span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </section>
  );
}

function DashboardHeader({
  icon,
  title,
  endpoint,
  loading,
  onRefresh
}: Readonly<{
  icon: React.ReactNode;
  title: string;
  endpoint: string;
  loading: boolean;
  onRefresh: () => Promise<void>;
}>) {
  return (
    <div className="panel-header">
      <h2>
        {icon}
        <span>{title}</span>
      </h2>
      <div className="toolbar">
        <span className="policy">{endpoint}</span>
        <button
          className="icon-button"
          type="button"
          title={`Actualizar ${title}`}
          aria-label={`Actualizar ${title}`}
          onClick={() => void onRefresh()}
          disabled={loading}
        >
          <RefreshCw aria-hidden="true" size={16} />
        </button>
      </div>
    </div>
  );
}

function ResourceStatus({
  status,
  error,
  empty,
  loadingLabel,
  emptyLabel
}: Readonly<{
  status: LoadState;
  error: string | null;
  empty: boolean;
  loadingLabel: string;
  emptyLabel: string;
}>) {
  if (status === "loading" && empty) {
    return (
      <p className="resource-status" role="status" aria-live="polite">
        {loadingLabel}
      </p>
    );
  }
  if (status === "error") {
    return (
      <p className="error resource-status" role="alert">
        {safeText(error ?? "Recurso no disponible.")}
      </p>
    );
  }
  if (empty) {
    return (
      <p className="resource-status" role="status" aria-live="polite">
        {emptyLabel}
      </p>
    );
  }
  return null;
}

export function newestRuns(values: readonly VerificationRunSummary[]): readonly VerificationRunSummary[] {
  const byTrace = new Map<string, VerificationRunSummary>();
  for (const value of values) {
    const current = byTrace.get(value.trace_id);
    if (current === undefined || timestamp(value.created_at) > timestamp(current.created_at)) {
      byTrace.set(value.trace_id, value);
    }
  }
  return [...byTrace.values()].sort(
    (left, right) => timestamp(right.created_at) - timestamp(left.created_at)
  );
}

export function newestGrants(values: readonly CorpusGrant[]): readonly CorpusGrant[] {
  const byCorpus = new Map<string, CorpusGrant>();
  for (const value of values) {
    const current = byCorpus.get(value.corpus_id);
    if (
      current === undefined ||
      value.version > current.version ||
      (value.version === current.version &&
        timestamp(value.updated_at) > timestamp(current.updated_at))
    ) {
      byCorpus.set(value.corpus_id, value);
    }
  }
  return [...byCorpus.values()].sort(
    (left, right) => timestamp(right.updated_at) - timestamp(left.updated_at)
  );
}

export function newestEvalReports(values: readonly EvalReport[]): readonly EvalReport[] {
  const byReport = new Map<string, EvalReport>();
  for (const value of values) {
    const current = byReport.get(value.report_id);
    if (
      current === undefined ||
      timestamp(value.published_at) > timestamp(current.published_at)
    ) {
      byReport.set(value.report_id, value);
    }
  }
  return [...byReport.values()].sort(
    (left, right) => timestamp(right.published_at) - timestamp(left.published_at)
  );
}

export function mergeRuns(
  current: readonly VerificationRunSummary[],
  next: readonly VerificationRunSummary[]
): readonly VerificationRunSummary[] {
  return newestRuns([...current, ...next]);
}

export function mergeGrants(current: readonly CorpusGrant[], next: readonly CorpusGrant[]): readonly CorpusGrant[] {
  return newestGrants([...current, ...next]);
}

export function mergeEvalReports(
  current: readonly EvalReport[],
  next: readonly EvalReport[]
): readonly EvalReport[] {
  return newestEvalReports([...current, ...next]);
}

function apiError(
  error: unknown,
  fallback: string,
  onUnauthorized: () => void
): string {
  return safeConsoleApiError(error, fallback, onUnauthorized).message;
}

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
}

function formatRoles(roles: readonly string[]): string {
  return roles.length === 0 ? "sin restriccion adicional" : roles.map(safeText).join(", ");
}

function formatPercent(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

function formatMs(value: number): string {
  return `${Math.round(value * 10) / 10} ms`;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "fecha invalida" : date.toISOString().replace(".000Z", "Z");
}

function safeText(value: string): string {
  return value
    .replace(/"(api[_-]?key|token|secret|password|authorization)"\s*:\s*"[^"]*"/gi, '"$1":"[redacted]"')
    .replace(/\b(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*([^\s,;'"`]+)/gi, "$1=[redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[redacted]");
}
