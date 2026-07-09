ifeq ($(OS),Windows_NT)
VENV_PY := .venv/Scripts/python
else
VENV_PY := .venv/bin/python
endif

PY := $(if $(wildcard $(VENV_PY)),$(VENV_PY),python)

.PHONY: lint typecheck test build contracts openapi openapi-check foundation-docs-check foundation-infra-check traceability-check worklog-check policy-test sandbox-test sandbox-image sandbox-isolation-config sandbox-live-smoke evals-smoke evals-scenarios eval-thresholds-config dashboard-lint local-runtime-config encryption-config auth-config oidc-provider-smoke oidc-keycloak-live-smoke secrets-config vault-bootstrap vault-live-smoke audit-ledger-config approval-queue-config corpus-grants-config backup-retention-config rag-persistence-config rag-opensearch-template-dry-run rag-opensearch-live-smoke rag-pgvector-live-smoke postgres-migrations-apply postgres-persistence-live-smoke ingestion-pipeline-config python-audit container-scan-config observability-config otel-export-live-smoke observability-live-smoke security-check

lint:
	$(PY) -m ruff check apps/api/src apps/api/tests scripts evals

typecheck:
	$(PY) -m mypy apps/api/src
	npm run typecheck

test:
	$(PY) -m pytest apps/api/tests
	npm run test

build:
	npm run build

contracts:
	$(PY) scripts/ci/check_json_schemas.py
	$(PY) -m pytest apps/api/tests/test_contracts.py
	npm run typecheck --workspaces --if-present

openapi:
	$(PY) scripts/ci/export_openapi.py

openapi-check:
	$(PY) scripts/ci/check_openapi.py

foundation-docs-check:
	$(PY) scripts/ci/check_foundation_docs.py

foundation-infra-check:
	$(PY) scripts/ci/check_foundation_infra.py

traceability-check:
	$(PY) scripts/ci/check_traceability_matrix.py

worklog-check:
	$(PY) scripts/ci/check_worklog.py

policy-test:
	$(PY) scripts/ci/run_policy_tests.py

sandbox-test:
	$(PY) -m pytest apps/api/tests -k sandbox

sandbox-image:
	docker build -f infra/docker/sandbox.Dockerfile -t hallu-defense-sandbox:ci .

sandbox-isolation-config:
	$(PY) scripts/ci/check_sandbox_isolation_config.py

sandbox-live-smoke:
	$(PY) scripts/dev/live_docker_sandbox_smoke.py

evals-smoke:
	$(PY) evals/runners/smoke.py

evals-scenarios:
	$(PY) evals/runners/scenarios.py

eval-thresholds-config:
	$(PY) scripts/ci/check_eval_thresholds_config.py

dashboard-lint:
	$(PY) scripts/ci/check_grafana_dashboards.py

local-runtime-config:
	$(PY) scripts/ci/check_local_runtime_config.py

encryption-config:
	$(PY) scripts/ci/check_encryption_config.py

auth-config:
	$(PY) scripts/ci/check_auth_config.py

oidc-provider-smoke:
	$(PY) scripts/ci/oidc_provider_smoke.py

oidc-keycloak-live-smoke:
	$(PY) scripts/dev/live_keycloak_oidc_smoke.py

secrets-config:
	$(PY) scripts/ci/check_secrets_config.py

vault-bootstrap:
	$(PY) scripts/dev/bootstrap_local_vault.py

vault-live-smoke:
	$(PY) scripts/dev/live_vault_secrets_smoke.py

audit-ledger-config:
	$(PY) scripts/ci/check_audit_ledger_config.py

approval-queue-config:
	$(PY) scripts/ci/check_approval_queue_config.py

corpus-grants-config:
	$(PY) scripts/ci/check_corpus_grants_config.py

backup-retention-config:
	$(PY) scripts/ci/check_backup_retention_config.py

rag-persistence-config:
	$(PY) scripts/ci/check_rag_persistence_config.py
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run

rag-opensearch-template-dry-run:
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run

rag-opensearch-live-smoke:
	$(PY) scripts/dev/live_opensearch_rag_smoke.py

rag-pgvector-live-smoke:
	$(PY) scripts/dev/live_pgvector_rag_smoke.py

postgres-migrations-apply:
	$(PY) scripts/dev/apply_postgres_migrations.py

postgres-persistence-live-smoke:
	$(PY) scripts/dev/live_postgres_persistence_smoke.py

ingestion-pipeline-config:
	$(PY) scripts/ci/check_ingestion_pipeline_config.py

python-audit:
	$(PY) scripts/ci/python_dependency_audit.py

container-scan-config:
	$(PY) scripts/ci/check_container_scan_config.py

observability-config:
	$(PY) scripts/ci/check_observability_config.py

otel-export-live-smoke:
	$(PY) scripts/dev/live_otel_export_check.py

observability-live-smoke:
	$(PY) scripts/dev/live_observability_smoke.py

security-check:
	$(PY) scripts/ci/secret_scan.py
	$(PY) scripts/ci/check_encryption_config.py
	$(PY) scripts/ci/check_auth_config.py
	$(PY) scripts/ci/oidc_provider_smoke.py
	$(PY) scripts/ci/check_secrets_config.py
	$(PY) scripts/ci/check_audit_ledger_config.py
	$(PY) scripts/ci/check_approval_queue_config.py
	$(PY) scripts/ci/check_corpus_grants_config.py
	$(PY) scripts/ci/check_backup_retention_config.py
	$(PY) scripts/ci/check_rag_persistence_config.py
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run
	$(PY) scripts/ci/check_ingestion_pipeline_config.py
	$(PY) scripts/ci/python_dependency_audit.py
	$(PY) scripts/ci/check_sandbox_isolation_config.py
	$(PY) scripts/ci/check_container_scan_config.py
	$(PY) scripts/ci/check_observability_config.py
	npm audit --omit dev
