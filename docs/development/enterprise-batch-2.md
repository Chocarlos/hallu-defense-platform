# Enterprise Batch 2 Backlog

Status: delegation plan for milestone M6 `Enterprise Runtime Reality` as of
2026-07-09.

Milestone M6 promotes the enterprise capabilities from static-config and
local-JSONL evidence to real distributed runtime. The work is split into 7
delegable vertical batches (B1..B7). Each batch is a bounded assignment that
follows full-slice discipline: implementation, focused tests with injected
fakes, docs, `TRACEABILITY_MATRIX.md` rows, a `WORKLOG.md` entry, and validation
evidence. No item passes beyond `tested` in this milestone. The lead inspects
each diff, revalidates from `master`, and only then integrates.

## Global design decisions

1. Shared pool: new `apps/api/src/hallu_defense/services/postgres.py` with a
   `SqlConnectionProvider` protocol (`execute`, `fetch_all`,
   `execute_returning`) plus `PooledPostgresProvider` over
   `psycopg-pool>=3.2,<4` (new runtime dep). Singleton in
   `api/dependencies.py`; corpus grants adapts to the pool without changing
   `PostgresCorpusGrantStorage`. `execute_returning` gives single-statement
   atomic semantics (decide-once / consume-once / claim-once).
2. Ingestion worker = PostgreSQL outbox (not Redis): fail-closed durability, no
   dual-write, reuses migrations / gates / backup-policy; `FOR UPDATE SKIP
   LOCKED` testable with fakes. Redis documented as not-wired. MinIO wired in
   Batch 7 as encrypted-backup target.
3. Keycloak via committed realm-export (`start-dev --import-realm`), no
   admin-REST bootstrap: realm `hallu-defense`, confidential client
   `hallu-defense-api` with service account (`client_credentials`), realm roles
   (`verifier`, `auditor`, `approval_reviewer`, `rag_writer`, `metrics_reader`,
   `eval_publisher`), `tenant_id` + audience mappers. Client secret = an
   obviously-local literal (OpenSearch convention).
4. Single sandbox image `infra/docker/sandbox.Dockerfile` (`python:3.12-slim` +
   pinned Node LTS + pytest, UID 10001 non-root). Run flags PINNED by gate:
   `--rm --network=none --read-only --tmpfs /tmp --cap-drop ALL --security-opt
   no-new-privileges --pids-limit --memory --cpus --user 10001`; single rw bind
   of workdir at `/workspace`. Preflight regex stays as layer 1; git / AST
   inspection stays host-side read-only.
5. Eval ingestion persists in Postgres via publish API; runners stay
   offline / file-based (CI unchanged); publish sets Prometheus `hallu_eval_*`
   gauges; console stays file-mode (API-mode is follow-up).
6. OIDC in prod without weakening https: `HALLU_DEFENSE_OIDC_JWKS_PATH` (exported
   Keycloak file); `_validate_oidc_url` requires https only on remote URLs, not
   the issuer string.
7. `/metrics` scrape auth: dedicated static bearer token via `SecretManager`
   (`HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME`), accepted ONLY at
   `/metrics` as an alternative to the `metrics_reader` role (constant-time
   compare); mandatory in prod-like with auth. Prod Prometheus uses
   `authorization.credentials_file`. Additive: role routes intact.
8. Migrations stay in `infra/rag/pgvector/` numbered 003+ (renumbering breaks 3
   pinned gates mid-roadmap). New idempotent
   `scripts/dev/apply_postgres_migrations.py` + `schema_migrations` table
   (initdb only runs on empty volumes).
9. Production profile = overlay `docker-compose.prod.yml` (`-f base -f prod`),
   not `profiles:` — clean, standalone-lintable divergence.
10. Live CI = new `.github/workflows/live.yml` with `docker compose up` per job.
    Triggers: `workflow_dispatch` + push to master + weekly cron; teardown
    `docker compose down -v`. `ci.yml` and `security.yml` stay fast / static.

## Batch 1 — PostgreSQL core

**Objective**

Move audit and approvals to a production-grade PostgreSQL backend behind a
shared connection pool, with DB-level concurrency guarantees and repeatable
migrations.

**Slices**

1. `services/postgres.py` (provider + `RecordingSqlProvider` fake) + settings
   `HALLU_DEFENSE_POSTGRES_POOL_{MIN_SIZE,MAX_SIZE,TIMEOUT_SECONDS}` +
   `.env.example` + singleton in `dependencies` + corpus grants over the pool.
2. Migrations `infra/rag/pgvector/000_schema_migrations.sql`,
   `003_audit_ledger.sql` (`audit_runs` / `audit_events`, payload JSONB, indexes
   `(tenant_id, created_at)` and `(tenant_id, trace_id)`),
   `004_approval_queue.sql` (`approval_records` + `approval_execution_grants`,
   `token_hash` PK, `expires_at`, `consumed_at`) + idempotent applier.
3. `PostgresAuditLedgerStorage` in `services/audit.py` (indexed `SELECT WHERE`
   with `ORDER BY` + `LIMIT`, `HALLU_DEFENSE_AUDIT_EXPORT_MAX_RECORDS` default
   1000, behavior change documented across all backends, never replay-all,
   pre-persist redaction intact) + `check_audit_ledger_config.py` + docs.
4. `PostgresApprovalQueueStorage` in `services/approvals.py` (decide-once:
   `UPDATE ... WHERE status='pending' RETURNING` -> 0 rows = 409; consume-once:
   `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() RETURNING` -> 0
   rows = 403; same hashes / fingerprint / redaction as JSONL) +
   `check_approval_queue_config.py` + docs.
5. `scripts/dev/live_postgres_persistence_smoke.py` (applies migrations,
   multi-tenant audit, grant-consume race from 2 threads with exactly 1 success,
   self-cleanup) + targets `postgres-persistence-live-smoke` and
   `postgres-migrations-apply`.

**Evidence**

Unit tests of exact conditional SQL shape, JSONL/PG parity, fail-closed
factories, gate negatives, live smoke with race assertion.

**Matrix**

- New: PY-018 (pool), PY-019 (audit PG), PY-020 (approvals PG).
- Updated: PY-011, PY-013, SEC-004, CTR-010, CTR-023, CTR-025, CI-013, CI-014.

**Risks**

Export `LIMIT` is a visible change (document it; a `limit` field is a
follow-up); `psycopg-pool` on Windows (the smoke proves it); migrations over a
non-empty volume (applier + `IF NOT EXISTS`).

**Dependencies**

None.

## Batch 2 — Live CI lane + Keycloak

**Objective**

Opt-in CI lane with real services and a reproducible local OIDC provider that
exercises the full `oidc_jwt` path.

**Slices**

1. `.github/workflows/live.yml` (dispatch + push master + weekly cron;
   `postgres-live` job running the B1 smoke; extensible structure).
2. `keycloak` service in Compose (`quay.io/keycloak/keycloak:26.3` pinned,
   `start-dev --import-realm`, `8081:8080`, mount
   `./infra/security/keycloak:/opt/keycloak/data/import:ro`) + realm-export
   `infra/security/keycloak/realm-hallu-defense.json` + local-runtime gate to 10
   services + tests + `.env.example`.
3. `scripts/dev/live_oidc_keycloak_smoke.py` (`client_credentials` token via
   stdlib `urllib`; discovery -> JWKS -> verify -> subject / tenant / role; local
   env with `HALLU_DEFENSE_ENV=local`) + target `oidc-keycloak-live-smoke`.
4. `--api` mode (uvicorn with `AUTH_REQUIRED=true` + `AUTH_CLAIMS_MODE=oidc_jwt`
   + discovery to Keycloak; asserts: JWT reaches `/approvals/list` by role,
   tenant claim propagates to audit export, wrong audience 401/403, expired
   token rejected).
5. `keycloak-live` job in `live.yml`.

**Evidence**

Local-runtime gate to 10 + tests, `secret_scan` over the local secret, smokes
executed / skipped.

**Matrix**

- New: SEC-014, CI-022.
- Updated: SEC-001, CI-015, FND-008, FND-010.

**Risks**

Keycloak start-up latency (poll with a deadline), local secret vs `secret_scan`
(local-only convention + test), realm-export drift across versions (exact tag),
port 8081 already taken (override).

**Dependencies**

B1.

## Batch 3 — Sandbox Docker isolation

**Objective**

Real OS isolation behind a backend abstraction; preflight regex = layer 1;
fail-closed in prod.

**Slices**

1. `services/sandbox_exec.py` (protocol `SandboxExecutionBackend` with
   `execute(argv, cwd, env, timeout, output_caps) -> ExecutionResult`;
   `HostSubprocessBackend` = pure extraction of the current `subprocess.run`, the
   sandbox suite passes unchanged; settings `HALLU_DEFENSE_SANDBOX_BACKEND`
   `host|docker` default `host`; production / staging reject `host`).
2. `infra/docker/sandbox.Dockerfile` + Makefile target `sandbox-image` + Trivy in
   `security.yml` + `check_container_scan_config.py` + container-scanning docs.
3. `DockerContainerBackend` (argv-list never shell, minimal env, `docker kill`
   with grace, output caps, injectable docker runner, settings
   `HALLU_DEFENSE_SANDBOX_DOCKER_*`
   `IMAGE`/`PATH`/`MEMORY_MB=512`/`CPUS=1.0`/`PIDS_LIMIT=256`/`TIMEOUT_GRACE_SECONDS`).
4. `check_sandbox_isolation_config.py` (pins the exact flag set, settings,
   fail-closed prod, non-root Dockerfile, wiring) + amend
   `docs/adr/0005-sandbox-model.md` + `test_sandbox_docker_backend.py` (if
   `--network=none` is missing from the recorded argv, it FAILS).
5. `scripts/dev/live_docker_sandbox_smoke.py` (outbound network fails, write
   outside `/workspace` fails, artifact inside captured, timeout kill, limits via
   `docker inspect`) + `sandbox-live` job.

**Evidence**

Unit tests of recorded argv, fail-closed prod, live smoke.

**Matrix**

- New: SBOX-016, SBOX-017, CI-023.
- Updated: SBOX-001/002/003/006, SEC-009, PY-012, API-009.

**Risks**

Windows bind mounts with spaces (argv-list + smoke over a real path), API in
Compose cannot reach the host Docker (resolved in B7 with a documented socket
mount), docker `run` cold-start vs `max_command_seconds` (grace setting).

**Dependencies**

B2 (live job).

## Batch 4 — Live observability + scrape auth

**Objective**

Prove spans leave the API with safe content, Prometheus / Grafana with real
traffic, and close scrape auth in prod.

**Slices**

1. `infra/otel/otel-collector-config.yaml` file exporter `/otel-output/spans.jsonl`
   with rotation (alongside debug) + Compose mounts `./var/otel:/otel-output` +
   local-runtime gate + tests.
2. `scripts/dev/live_otel_export_check.py` (traffic to `/verification/run`,
   `/policy/evaluate`, `/repo/checks/run`; poll `var/otel/spans.jsonl`; asserts
   HTTP `*` / `verification.*` / `policy.evaluate` / `sandbox.run` names and the
   ABSENCE of sensitive attributes).
3. `scripts/dev/live_observability_smoke.py` (Prometheus `/api/v1/targets` up,
   query `hallu_http_requests_total` and `hallu_verification_*`, Grafana
   `/api/health` + datasource).
4. Scrape auth (settings + constant-time check at `/metrics` + fail-closed prod +
   `infra/prometheus/prometheus.prod.yml` with `credentials_file`; tests: no
   token 401/403, valid token 200, role path intact) + `check_auth_config.py` +
   `docs/security/auth-rbac.md`.
5. `check_observability_config.py` + `observability-live` job.

**Evidence**

`/metrics` auth tests + regression that nothing was weakened.

**Matrix**

- New: OBS-004, OBS-005, OBS-006, CI-024.
- Updated: OBS-001/002/003, PY-014, CI-021.

**Risks**

Flakiness from the batch processor flush (poll with a deadline), span-file growth
(rotation + gitignored dir), the metrics token being demonstrably additive.

**Dependencies**

B2.

## Batch 5 — Evals runtime

**Objective**

Externalize and ENFORCE thresholds as a CI gate, produce a reproducible
calibration artifact, and add the runtime persistence + metrics path.

**Slices**

1. Versioned `evals/config/thresholds.json` (per suite: metric -> {op, value})
   covering the hardcoded and the un-gated values + refactor of
   `evals/runners/{smoke,scenarios}.py` + `check_eval_thresholds_config.py` with
   an anti-weakening rule (embedded floor) + wiring in `ci.yml` + `evals.yml`.
2. `scripts/dev/generate_verifier_calibration.py` (deterministic verifier over
   golden sets, buckets confidences 0.25-0.98 vs correctness, writes
   `evals/reports/verifier-calibration.json` with fixed-precision floats) +
   `check_verifier_calibration.py` drift gate (regenerate + diff).
3. Migration `005_eval_reports.sql` + `services/eval_reports.py` (factory
   memory / jsonl / postgres fail-closed prod) + settings
   `HALLU_DEFENSE_EVAL_REPORTS_{BACKEND,PATH}` + endpoints
   `POST /evals/reports/publish` (role `eval_publisher`) and
   `POST /evals/reports/list` (`auditor` or `verifier`) + audit event
   `eval_report_published` + Pydantic / TS / JSON Schema / examples contracts +
   SDK + OpenAPI + role matrix.
4. Gauges
   `hallu_eval_pass_rate{suite}` / `p95_latency_ms{suite}` /
   `scenario_count{suite}` / `groundedness` / `faithfulness` + Grafana panel +
   dashboard lint.
5. `scripts/dev/publish_eval_reports.py` env-gated + `eval-publish-live` job +
   `check_eval_ingestion_config.py`.

**Evidence**

Thresholds enforced in the runner, anti-weakening floor gate, schema sync,
ruff / mypy / pytest + npm.

**Matrix**

- New: EVAL-003, EVAL-004, EVAL-005, API-022, API-023, CTR-026, CI-025, CI-026.
- Updated: EVAL-001/002, PY-015, TS-009, OBS-002, FND-011.

**Risks**

Thresholds as a weakening vector (mandatory floor), non-deterministic floats
(fixed rounding), contract sync in a single slice.

**Dependencies**

B1 (storage / migrations), B2 (lane), B4 (dashboard lint order).

## Batch 6 — Durable ingestion worker

**Objective**

Durable, resumable, tenant-safe async ingestion; idempotent backfill / reindex;
default sync = zero change.

**Slices**

1. Migration `006_ingestion_outbox.sql` (`rag_ingestion_jobs`: `tenant_id`,
   `corpus_id`, `trace_id`, `job_type` `ingest|reindex_corpus`, payload JSONB,
   `status` `queued|running|succeeded|failed|dead`, `attempts`, `available_at`,
   `locked_by`/`at`; index `(status, available_at)`) + `services/ingestion_jobs.py`
   (enqueue, atomic claim `FOR UPDATE SKIP LOCKED`, complete / fail-with-backoff /
   dead-letter; SQL-shape tests).
2. `HALLU_DEFENSE_INGESTION_MODE` `sync|async` (default sync; async requires
   postgres fail-closed; grants / ABAC / writer-role checks AT ENQUEUE;
   `DocumentIngestionResponse` gains `job_id` / `job_status`; `POST
   /documents/ingest/status` tenant-scoped; contracts / SDK / MCP / OpenAPI
   additive).
3. `apps/api/src/hallu_defense/worker.py` (`python -m hallu_defense.worker`:
   poll -> claim batch -> `DocumentIngestionService` -> exponential retry ->
   dead-letter; events `ingestion_job_*`; metrics
   `hallu_ingestion_jobs_total{status}` and `hallu_ingestion_job_latency_ms`;
   Compose service `ingestion-worker` -> local-runtime gate to 11; settings
   `HALLU_DEFENSE_INGESTION_WORKER_*`).
4. Idempotent backfill / reindex (`job_type` `reindex_corpus`; paginates chunks
   by tenant / corpus; recomputes embeddings; upsert by natural key
   `(tenant, evidence_id)`; count parity; `scripts/dev/run_rag_backfill.py`;
   `docs/rag/backfill.md`; deterministic `dim16` embedder stays default, real ML
   embedder out of scope).
5. `scripts/dev/live_ingestion_worker_smoke.py` (enqueue N docs, inline worker,
   kill mid-run, restart, all terminal, docs recoverable tenant-scoped, no
   duplicates) + `check_ingestion_pipeline_config.py` + `ingestion-live` job.

**Evidence**

Unit SQL-shape tests + upsert idempotency + default sync unchanged.

**Matrix**

- New: RAG-008, RAG-009, API-024, CTR-027, CI-027.
- Updated: RAG-001, RAG-004, API-016, CTR-024, MCP-006.

**Risks**

At-least-once requires idempotent upserts, crash-resume flakiness (deterministic
kill points via env hook), local worker footprint.

**Dependencies**

B1, B2 (independent of B5).

## Batch 7 — Production profile + backup + K8s

**Objective**

Fail-closed end-to-end production profile over Compose, real
backup / restore / retention / tenant-deletion, and a Helm chart validated on
kind.

**Slices**

1. Local Vault (`hashicorp/vault:1.17` pinned dev 8200) +
   `scripts/dev/bootstrap_local_vault.py` (seed KV v2: scrape token, gateway
   signing key, backup encryption key) + `scripts/dev/live_vault_secrets_smoke.py`
   + local-runtime gate to 12 + `check_secrets_config.py` + SEC-010.
2. Overlay `docker-compose.prod.yml` (API + worker `ENV=production`,
   `AUTH_REQUIRED=true`, `AUTH_CLAIMS_MODE=oidc_jwt` issuer Keycloak,
   `OIDC_JWKS_PATH=/run/oidc/jwks.json` via
   `scripts/dev/export_keycloak_jwks.py`, backends
   audit / approvals / grants / evals = postgres, `SECRETS_BACKEND=vault`,
   `SANDBOX_BACKEND=docker` with `/var/run/docker.sock` mounted in the API
   (root-equivalent tradeoff documented in ADR), `INGESTION_MODE=async`, OTLP,
   CORS https-only placeholder, Prometheus prod `credentials_file`) +
   `check_prod_profile_config.py` (no memory, no unsigned headers, no host
   sandbox, no default credentials; `docker compose -f base -f prod config
   --quiet`).
3. `scripts/dev/live_prod_profile_e2e.py` (boot overlay -> Keycloak token -> no
   auth 401/403 -> verification run -> high-risk tool -> approval -> decide ->
   grant consume, second consume 403 -> `/repo/checks/run` with containerized
   sandbox and real network-deny -> corpus grant upsert / list -> eval
   publish / list -> audit export -> authenticated `/metrics` -> teardown `-v`) +
   `prod-profile-e2e` job.
4. `services/data_lifecycle.py` (retention driven by
   `infra/security/backup-retention-policy.json`, never deletes before
   `minimum_days`, event `retention_execution`; `delete_tenant_data(tenant_id)`
   across all postgres tables with event `tenant_data_deletion`) +
   `scripts/dev/backup_restore_drill.py` (`pg_dump` via `compose exec -T
   postgres` -> Fernet encryption with dev `cryptography`, key from Vault ->
   upload via bounded in-process SigV4 -> restore into scratch DB -> row / checksum parity ->
   report `var/backup-drills/<ts>.json`) + `scripts/dev/run_retention_execution.py`
   + `check_backup_retention_config.py` requiring the scripts + `backup-drill`
   job + MinIO wired.
5. `infra/k8s/helm/hallu-defense/` (Deployments api / console / ingestion-worker
   non-root with limits / probes / secret templates / scrape annotations;
   StatefulSet pgvector single-replica + OpenSearch for kind; swap points in
   values; migrations Job with the applier) + `check_helm_chart.py`
   (`helm template` + asserts non-root / limits / no plaintext secrets / env
   fail-closed) + `scripts/dev/live_kind_helm_smoke.py` + `kind-helm-live` job +
   new ADR or amend `docs/adr/0002`.

**Evidence**

Static prod-profile gate, unit tests of lifecycle, e2e / drill / kind live.

**Matrix**

- New: FND-013, FND-014, SEC-015, SEC-016, CI-028, CI-029.
- Updated: SEC-010, SEC-012, CI-011, FND-008, CTR-010.

**Risks**

Vault dev-mode is non-productive (documented limitation), `pg_dump` / restore
pinning (same pgvector image via `compose exec`), CI cost of kind + helm (weekly
cron + dispatch), chart scope-creep.

**Dependencies**

ALL previous batches.

## Sequence and dependencies

Recommended order: B1 -> B2 -> B3 -> B4 -> B5 -> B6 -> B7. Each batch is
delegable and independently validable on Windows + Docker Desktop; the `live`
jobs run on ubuntu. B1 has no dependency; B2 depends on B1; B3 on B2 (live job);
B4 on B2; B5 on B1, B2, and B4 (dashboard lint order); B6 on B1 and B2
(independent of B5); B7 depends on all previous batches.

## Integration criterion

Contributor output is not authoritative until the lead:

1. Inspects the actual diff line by line.
2. Rejects blocked or no-diff summaries.
3. Revalidates from `master` with the focused gates and tests.
4. Confirms `TRACEABILITY_MATRIX.md` rows and the `WORKLOG.md` entry.
5. Commits and fast-forwards only after the diff is verified.

Nothing passes beyond `tested` in this milestone.
