import type { VerificationRun } from "@hallu-defense/contracts";

export const demoRun: VerificationRun = {
  trace_id: "tr_demo",
  tenant_id: "local-dev",
  input: {
    message_text: "Los empleados part-time reciben 15 dias de vacaciones pagadas al ano.",
    task_type: "document_qa",
    document_count: 1,
    tool_output_count: 0
  },
  claims: [
    {
      claim_id: "clm_0001",
      text: "Los empleados part-time reciben 15 dias de vacaciones pagadas al ano",
      canonical_form: "los empleados part-time reciben 15 dias de vacaciones pagadas al ano",
      type: "doc_grounded",
      risk_level: "medium",
      requires_evidence: true,
      source_span: { message_id: "draft", start_char: 0, end_char: 68 },
      metadata: {}
    }
  ],
  evidence: [
    {
      evidence_id: "ev_001_001",
      kind: "document_chunk",
      source_ref: "hr-manual-v7",
      content: "Part-time employees accrue PTO pro rata based on scheduled hours.",
      structured_content: { metadata: {} },
      authority: "internal",
      freshness: {
        retrieved_at: "2026-07-07T00:00:00Z",
        published_at: null,
        staleness_class: "acceptable"
      }
    }
  ],
  verdicts: [
    {
      claim_id: "clm_0001",
      status: "CONTRADICTED",
      confidence: 0.82,
      evidence_ids: ["ev_001_001"],
      action: "rewrite",
      reason: "Numeric values in claim do not match the strongest evidence.",
      validator_trace: { claim_numbers: ["15"] }
    }
  ],
  final_decision: "repaired",
  final_text:
    "No encontre evidencia suficiente para afirmar 15 dias fijos. La evidencia indica acumulacion proporcional segun horas programadas.",
  policy_version: "2026-07-07",
  created_at: "2026-07-07T00:00:00Z"
};

