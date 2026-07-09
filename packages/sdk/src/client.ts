import type {
  ApprovalDecisionRequest,
  ApprovalDecisionResponse,
  ApprovalListRequest,
  ApprovalListResponse,
  AuditExportRequest,
  AuditExportResponse,
  Claim,
  ClaimVerdict,
  CorpusGrantDisableRequest,
  CorpusGrantHistoryDiffRequest,
  CorpusGrantHistoryDiffResponse,
  CorpusGrantHistoryRequest,
  CorpusGrantHistoryResponse,
  CorpusGrantListRequest,
  CorpusGrantListResponse,
  CorpusGrantResponse,
  CorpusGrantUpsertRequest,
  DocumentIngestionRequest,
  DocumentIngestionResponse,
  DocumentIngestionStatusRequest,
  DocumentIngestionStatusResponse,
  DocumentInput,
  Evidence,
  EvidenceRetrievalRequest,
  EvidenceRetrievalResponse,
  EvalReportListRequest,
  EvalReportListResponse,
  EvalReportPublishRequest,
  EvalReportPublishResponse,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  RepoChecksRunRequest,
  ResponseRepairRequest,
  ResponseRepairResponse,
  SandboxRun,
  ToolCallEnvelope,
  ToolValidationResponse,
  VerificationReplayRequest,
  VerificationReplayResponse,
  VerificationRun,
  VerificationRunRequest
} from "@hallu-defense/contracts";

export interface HalluDefenseClientOptions {
  readonly baseUrl: string;
  readonly tenantId?: string;
  readonly traceId?: string;
  readonly subjectId?: string;
  readonly roles?: readonly string[];
  readonly token?: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

export class HalluDefenseError extends Error {
  constructor(
    readonly status: number,
    readonly endpoint: string,
    message: string
  ) {
    super(message);
    this.name = "HalluDefenseError";
  }
}

export class HalluDefenseClient {
  readonly #baseUrl: string;
  readonly #tenantId: string | undefined;
  readonly #traceId: string | undefined;
  readonly #subjectId: string | undefined;
  readonly #roles: readonly string[] | undefined;
  readonly #token: string | undefined;
  readonly #timeoutMs: number;
  readonly #fetchImpl: typeof fetch;

  constructor(options: HalluDefenseClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#tenantId = options.tenantId;
    this.#traceId = options.traceId;
    this.#subjectId = options.subjectId;
    this.#roles = options.roles;
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 10000;
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    // Wrap fetch so browsers keep the required global binding even when callers
    // pass `window.fetch` explicitly.
    this.#fetchImpl = (input, init) => fetchImpl.call(globalThis, input, init);
  }

  async runVerification(request: VerificationRunRequest): Promise<VerificationRun> {
    return this.#post<VerificationRun>("/verification/run", request);
  }

  async replayVerification(
    request: VerificationReplayRequest
  ): Promise<VerificationReplayResponse> {
    return this.#post<VerificationReplayResponse>("/verification/replay", request);
  }

  async extractClaims(messageText: string): Promise<readonly Claim[]> {
    const response = await this.#post<{ readonly claims: readonly Claim[] }>("/claims/extract", {
      message_text: messageText
    });
    return response.claims;
  }

  async retrieveEvidence(
    claims: readonly Claim[],
    documents: readonly DocumentInput[],
    options: Omit<EvidenceRetrievalRequest, "claims" | "documents"> = {}
  ): Promise<EvidenceRetrievalResponse> {
    return this.#post<EvidenceRetrievalResponse>("/evidence/retrieve", {
      claims,
      documents,
      ...options
    });
  }

  async ingestDocuments(request: DocumentIngestionRequest): Promise<DocumentIngestionResponse> {
    return this.#post<DocumentIngestionResponse>("/documents/ingest", request);
  }

  async getDocumentIngestionStatus(
    request: DocumentIngestionStatusRequest
  ): Promise<DocumentIngestionStatusResponse> {
    return this.#post<DocumentIngestionStatusResponse>("/documents/ingest/status", request);
  }

  async upsertCorpusGrant(request: CorpusGrantUpsertRequest): Promise<CorpusGrantResponse> {
    return this.#post<CorpusGrantResponse>("/rag/corpus-grants/upsert", request);
  }

  async disableCorpusGrant(request: CorpusGrantDisableRequest): Promise<CorpusGrantResponse> {
    return this.#post<CorpusGrantResponse>("/rag/corpus-grants/disable", request);
  }

  async listCorpusGrants(
    request: CorpusGrantListRequest = {}
  ): Promise<CorpusGrantListResponse> {
    return this.#post<CorpusGrantListResponse>("/rag/corpus-grants/list", request);
  }

  async corpusGrantHistory(
    request: CorpusGrantHistoryRequest = {}
  ): Promise<CorpusGrantHistoryResponse> {
    return this.#post<CorpusGrantHistoryResponse>("/rag/corpus-grants/history", request);
  }

  async corpusGrantHistoryDiff(
    request: CorpusGrantHistoryDiffRequest = {}
  ): Promise<CorpusGrantHistoryDiffResponse> {
    return this.#post<CorpusGrantHistoryDiffResponse>(
      "/rag/corpus-grants/history/diff",
      request
    );
  }

  async verifyClaims(
    claims: readonly Claim[],
    evidence: readonly Evidence[]
  ): Promise<readonly ClaimVerdict[]> {
    const response = await this.#post<{ readonly verdicts: readonly ClaimVerdict[] }>(
      "/claims/verify",
      { claims, evidence }
    );
    return response.verdicts;
  }

  async validateToolInput(envelope: ToolCallEnvelope): Promise<ToolValidationResponse> {
    return this.#post<ToolValidationResponse>("/tools/validate-input", envelope);
  }

  async validateToolOutput(envelope: ToolCallEnvelope): Promise<ToolValidationResponse> {
    return this.#post<ToolValidationResponse>("/tools/validate-output", envelope);
  }

  async repairResponse(request: ResponseRepairRequest): Promise<ResponseRepairResponse> {
    return this.#post<ResponseRepairResponse>("/response/repair", request);
  }

  async exportAudit(request: AuditExportRequest = {}): Promise<AuditExportResponse> {
    return this.#post<AuditExportResponse>("/audit/export", request);
  }

  async publishEvalReport(
    request: EvalReportPublishRequest
  ): Promise<EvalReportPublishResponse> {
    return this.#post<EvalReportPublishResponse>("/evals/reports/publish", request);
  }

  async listEvalReports(
    request: EvalReportListRequest = {}
  ): Promise<EvalReportListResponse> {
    return this.#post<EvalReportListResponse>("/evals/reports/list", request);
  }

  async evaluatePolicy(request: PolicyEvaluationRequest): Promise<PolicyEvaluationResponse> {
    return this.#post<PolicyEvaluationResponse>("/policy/evaluate", request);
  }

  async runRepoChecks(request: RepoChecksRunRequest): Promise<SandboxRun> {
    return this.#post<SandboxRun>("/repo/checks/run", request);
  }

  async listApprovals(request: ApprovalListRequest = {}): Promise<ApprovalListResponse> {
    return this.#post<ApprovalListResponse>("/approvals/list", request);
  }

  async decideApproval(request: ApprovalDecisionRequest): Promise<ApprovalDecisionResponse> {
    return this.#post<ApprovalDecisionResponse>("/approvals/decide", request);
  }

  async #post<TResponse>(endpoint: string, body: unknown): Promise<TResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetchImpl(`${this.#baseUrl}${endpoint}`, {
        method: "POST",
        headers: this.#headers(),
        body: JSON.stringify(body),
        signal: controller.signal
      });

      if (!response.ok) {
        const message = await safeErrorMessage(response);
        throw new HalluDefenseError(response.status, endpoint, message);
      }

      return (await response.json()) as TResponse;
    } catch (error) {
      if (error instanceof HalluDefenseError) {
        throw error;
      }
      if (error instanceof Error && error.name === "AbortError") {
        throw new HalluDefenseError(408, endpoint, "Request timed out");
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  #headers(): HeadersInit {
    const headers: Record<string, string> = {
      "content-type": "application/json"
    };
    if (this.#tenantId !== undefined) {
      headers["x-tenant-id"] = this.#tenantId;
    }
    if (this.#traceId !== undefined) {
      headers["x-trace-id"] = this.#traceId;
    }
    if (this.#subjectId !== undefined) {
      headers["x-subject-id"] = this.#subjectId;
    }
    if (this.#roles !== undefined && this.#roles.length > 0) {
      headers["x-roles"] = this.#roles.join(",");
    }
    if (this.#token !== undefined) {
      headers.authorization = `Bearer ${this.#token}`;
    }
    return headers;
  }
}

async function safeErrorMessage(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as {
      readonly detail?: unknown;
      readonly message?: unknown;
    };
    if (typeof payload.message === "string") {
      return payload.message;
    }
    if (typeof payload.detail === "string") {
      return payload.detail;
    }
    return `API request failed with status ${response.status}`;
  } catch {
    return `API request failed with status ${response.status}`;
  }
}
