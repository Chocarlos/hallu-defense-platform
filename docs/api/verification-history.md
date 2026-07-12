# Verification Completion And History

The verification APIs persist a final run only after orchestration and response
construction succeed:

- `POST /verification/run`
- `POST /v2/verification/run`
- `POST /verification/replay`

Each successful v1/v2 call commits one redacted `VerificationRun` and one
`verification_completed` event through the audit-ledger transaction. Replay commits
those two records plus its `verification_replay` provenance event in the same
transaction. The identity is
`tenant_id + trace_id + path`: a retry of the same identity is idempotent when the
stored minimized run matches, while a conflicting persisted projection fails
closed. Reusing a trace across different verification paths remains compatible and
creates one unit per path. Replay source lookup filters every non-null `replay_of`
marker and reads at most two exact candidates before applying any public export
cap. Zero candidates preserves the tenant-safe `404`, one replays, and duplicates
return a stable `409` before any orchestrator/provider call; even
`audit_export_max_records=1` cannot hide or silently select an original. The
orchestrator does not persist, so there is no second run write hidden below the API
boundary.

If any PostgreSQL insert fails, no row in the unit commits and the endpoint returns `503`
with `Verification persistence is unavailable.` It never returns an unpersisted
successful run. Production and staging require the PostgreSQL audit backend; memory
and JSONL are local/test compatibility backends.

The persisted snapshot passes through Front A's typed pre-storage run/event
redaction seams independently from the public response. A successful response
retains its original fields and adopts only the first committed `created_at` on an
idempotent retry. Full bounded PII and signed-URL coverage across every persisted
field remains a mandatory root-integration dependency on Front B's central
redactor; this branch deliberately does not copy that implementation. The boundary
also rejects an orchestrator result whose tenant or trace differs from the
authenticated request before any write.

Memory and JSONL take deep ownership at every boundary: caller-owned nested model
fields and metadata are cloned before storage, and append/retry/export/snapshot/
pagination/replay-source results are independent clones. Mutating an earlier
return cannot change a later snapshot or a reopened JSONL ledger.

Because current retry comparison uses the minimized persisted projection, two
different sensitive originals that collapse to the same redacted value are not yet
distinguishable. Root integration with Front B must provide a keyed, non-exported
pre-redaction request commitment if that distinction is required; storing an
unkeyed digest of raw PII/secrets is not an acceptable workaround.

`POST /audit/export` reads runs and optional events as one coherent bounded
snapshot. PostgreSQL uses one `REPEATABLE READ, READ ONLY` transaction for both
queries; memory/JSONL copy both collections under one lock. A completion committed
between the two PostgreSQL queries therefore appears in neither half of the
in-flight response. Visible completion/replay units are also cross-checked for
path, final-decision, and provenance parity. A bounded `cap + 1` lookahead detects
real truncation: exact path/triple key sets are required when the collections are
complete, while truly truncated responses validate matching visible units without
guessing about older omitted counterparts.

Any snapshot storage or integrity failure aborts `/audit/export` and returns a
documented generic `503` (`Audit history is unavailable.`); backend exception text
is never included in the response.

## List request

`POST /verification/runs/list` accepts:

```json
{
  "trace_id": "optional-run-trace",
  "limit": 20,
  "cursor": null
}
```

The authenticated principal supplies the tenant; clients cannot select another
tenant in the body. `limit` is between 1 and 100. Results are newest first and the
opaque cursor continues from the last event using `(created_at, event_id)` keyset
ordering. A trace filter is applied in PostgreSQL before the limit.

The response contains safe summaries only:

```json
{
  "trace_id": "request-trace",
  "runs": [
    {
      "trace_id": "run-trace",
      "final_decision": "allow",
      "created_at": "2026-07-11T12:00:00Z"
    }
  ],
  "next_cursor": null
}
```

Before a summary is returned, storage and service layers independently validate the
requested tenant/trace, relational-to-JSON envelope, event type, method, path,
status, outcome, timestamp, event ID, and final decision. A malformed cursor returns
`400`. Any persisted integrity mismatch, cross-tenant row, ordering violation, or
storage failure returns a generic `503` and no partial page.
