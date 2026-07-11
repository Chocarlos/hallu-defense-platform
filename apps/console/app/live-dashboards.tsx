"use client";

import { useEffect, useState } from "react";
import { BarChart3, Database, History, RefreshCw, Upload } from "lucide-react";

import type {
  CorpusGrant,
  DocumentIngestionResponse,
  DocumentIngestionStatusResponse,
  EvalReport,
  VerificationRunSummary
} from "@hallu-defense/contracts";
import { HalluDefenseClient } from "@hallu-defense/sdk";

interface LiveDashboardsProps {
  readonly client: HalluDefenseClient;
  readonly roles: readonly string[];
  readonly historyRevision: number;
  readonly onUseReplayTrace: (traceId: string) => void;
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
  client,
  roles,
  historyRevision,
  onUseReplayTrace
}: LiveDashboardsProps) {
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
    let active = true;
    setHistory(emptyLoading());
    setHistoryCursor(null);
    void client
      .listVerificationRuns({ limit: 20 })
      .then((response) => {
        if (active) {
          setHistory({ status: "ready", values: newestRuns(response.runs), error: null });
          setHistoryCursor(response.next_cursor);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setHistory({
            status: "error",
            values: [],
            error: errorMessage(error, "No se pudo cargar el historial de runs.")
          });
        }
      });
    return () => {
      active = false;
    };
  }, [client, historyRevision]);

  useEffect(() => {
    let active = true;
    setGrants(emptyLoading());
    setGrantCursor(null);
    void client
      .listCorpusGrants({ limit: 50, include_disabled: true })
      .then((response) => {
        if (active) {
          setGrants({ status: "ready", values: newestGrants(response.grants), error: null });
          setGrantCursor(response.next_cursor ?? null);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setGrants({
            status: "error",
            values: [],
            error: errorMessage(error, "No se pudieron cargar los grants de corpus.")
          });
        }
      });

    setEvalReports(emptyLoading());
    void client
      .listEvalReports({ limit: 50 })
      .then((response) => {
        if (active) {
          setEvalReports({
            status: "ready",
            values: newestEvalReports(response.reports),
            error: null
          });
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setEvalReports({
            status: "error",
            values: [],
            error: errorMessage(error, "No se pudieron cargar los reportes de eval.")
          });
        }
      });
    return () => {
      active = false;
    };
  }, [client]);

  async function refreshHistory() {
    setHistory((current) => ({ ...current, status: "loading", error: null }));
    setHistoryCursor(null);
    try {
      const response = await client.listVerificationRuns({ limit: 20 });
      setHistory({ status: "ready", values: newestRuns(response.runs), error: null });
      setHistoryCursor(response.next_cursor);
    } catch (error) {
      setHistory((current) => ({
        ...current,
        status: "error",
        error: errorMessage(error, "No se pudo cargar el historial de runs.")
      }));
    }
  }

  async function loadMoreHistory() {
    if (historyCursor === null) {
      return;
    }
    setHistory((current) => ({ ...current, status: "loading", error: null }));
    try {
      const response = await client.listVerificationRuns({ limit: 20, cursor: historyCursor });
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
        error: errorMessage(error, "No se pudo cargar la siguiente pagina de runs.")
      }));
    }
  }

  async function refreshGrants() {
    setGrants((current) => ({ ...current, status: "loading", error: null }));
    setGrantCursor(null);
    try {
      const response = await client.listCorpusGrants({ limit: 50, include_disabled: true });
      setGrants({ status: "ready", values: newestGrants(response.grants), error: null });
      setGrantCursor(response.next_cursor ?? null);
    } catch (error) {
      setGrants((current) => ({
        ...current,
        status: "error",
        error: errorMessage(error, "No se pudieron cargar los grants de corpus.")
      }));
    }
  }

  async function loadMoreGrants() {
    if (grantCursor === null) {
      return;
    }
    setGrants((current) => ({ ...current, status: "loading", error: null }));
    try {
      const response = await client.listCorpusGrants({
        limit: 50,
        include_disabled: true,
        cursor: grantCursor
      });
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
        error: errorMessage(error, "No se pudo cargar la siguiente pagina de grants.")
      }));
    }
  }

  async function refreshEvalReports() {
    setEvalReports((current) => ({ ...current, status: "loading", error: null }));
    try {
      const response = await client.listEvalReports({ limit: 50 });
      setEvalReports({
        status: "ready",
        values: newestEvalReports(response.reports),
        error: null
      });
    } catch (error) {
      setEvalReports((current) => ({
        ...current,
        status: "error",
        error: errorMessage(error, "No se pudieron cargar los reportes de eval.")
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
      const response = await client.upsertCorpusGrant({
        corpus_id: normalizedCorpusId,
        reader_roles: [],
        writer_roles: [],
        expected_version: 0
      });
      setCorpusMessage({
        kind: "status",
        text: `Grant ${safeText(response.grant.corpus_id)} registrado en version ${response.grant.version}.`
      });
      await refreshGrants();
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: errorMessage(error, "No se pudo registrar el grant de corpus.")
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
      const response = await client.ingestDocuments({
        corpus_id: normalizedCorpusId,
        documents: [
          {
            source_ref: normalizedSourceRef,
            content: documentText,
            authority: "internal"
          }
        ]
      });
      setIngestion(response);
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: errorMessage(error, "No se pudo ejecutar la ingesta documental.")
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
      setIngestionStatus(
        await client.getDocumentIngestionStatus({ job_id: ingestion.job_id })
      );
    } catch (error) {
      setCorpusMessage({
        kind: "error",
        text: errorMessage(error, "No se pudo actualizar el estado de la ingesta.")
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
            {history.values.map((item, index) => (
              <li key={`${item.trace_id}-${item.created_at}-${index}`}>
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
              <li key={`${grant.corpus_id}-${grant.version}`}>
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
                {ingestion.warnings.map((warning, index) => (
                  <li key={`${index}-${warning}`}>{safeText(warning)}</li>
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
  return [...values].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at));
}

export function newestGrants(values: readonly CorpusGrant[]): readonly CorpusGrant[] {
  return [...values].sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at));
}

export function newestEvalReports(values: readonly EvalReport[]): readonly EvalReport[] {
  return [...values].sort((left, right) => Date.parse(right.published_at) - Date.parse(left.published_at));
}

function mergeRuns(
  current: readonly VerificationRunSummary[],
  next: readonly VerificationRunSummary[]
): readonly VerificationRunSummary[] {
  return newestRuns([...current, ...next]);
}

function mergeGrants(current: readonly CorpusGrant[], next: readonly CorpusGrant[]): readonly CorpusGrant[] {
  const byKey = new Map(current.map((item) => [item.corpus_id, item]));
  for (const item of next) {
    byKey.set(item.corpus_id, item);
  }
  return newestGrants([...byKey.values()]);
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message.trim().length > 0 ? error.message : fallback;
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
