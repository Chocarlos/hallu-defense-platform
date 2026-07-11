ifeq ($(OS),Windows_NT)
VENV_PY := .venv/Scripts/python
else
VENV_PY := .venv/bin/python
endif

PY := $(if $(wildcard $(VENV_PY)),$(VENV_PY),python)

.PHONY: lint typecheck test build contracts contract-versions-check openapi openapi-check foundation-docs-check foundation-infra-check traceability-check worklog-check policy-test sandbox-test sandbox-image pgvector-image keycloak-image sandbox-isolation-config sandbox-live-smoke evals-smoke evals-scenarios eval-thresholds-config eval-ingestion-config eval-report-publish-smoke verifier-calibration-generate verifier-calibration-check dashboard-lint local-runtime-config encryption-config auth-config oidc-provider-smoke oidc-keycloak-live-smoke secrets-config vault-bootstrap vault-live-smoke provider-vault-live-smoke audit-ledger-config approval-queue-config corpus-grants-config backup-retention-config retention-execution backup-restore-drill minio-backup-drill-config minio-backup-restore-drill prod-secret-files-preflight prod-profile-config prod-profile-up prod-profile-rotate-secrets prod-profile-e2e keycloak-jwks-export helm-chart-check kind-helm-live-smoke rag-persistence-config rag-opensearch-template-dry-run rag-opensearch-live-smoke rag-pgvector-live-smoke rag-hybrid-live-smoke postgres-migrations-check postgres-migrations-apply postgres-persistence-live-smoke ingestion-pipeline-config ingestion-worker-live-smoke python-lock-check python-repro-check python-wheel-repro python-audit gitleaks-config gitleaks-scan container-scan-config metrics-token-materializer-config observability-config otel-export-live-smoke observability-live-smoke security-check

lint:
	$(PY) -m ruff check apps/api/src apps/api/tests scripts evals
	npm run lint

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
	$(PY) scripts/ci/check_contract_versions.py
	$(PY) -m pytest apps/api/tests/test_contracts.py apps/api/tests/test_contract_v2.py apps/api/tests/test_contract_versions_config.py
	npm run typecheck --workspaces --if-present

contract-versions-check:
	$(PY) scripts/ci/check_contract_versions.py

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

pgvector-image:
	docker build -f infra/docker/pgvector.Dockerfile -t hallu-defense-pgvector:ci .

keycloak-image:
	docker build -f infra/docker/keycloak.Dockerfile -t hallu-defense-keycloak:ci .

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

eval-ingestion-config:
	$(PY) scripts/ci/check_eval_ingestion_config.py

eval-report-publish-smoke:
	$(PY) scripts/dev/publish_eval_reports.py --live-smoke

verifier-calibration-generate:
	$(PY) scripts/dev/generate_verifier_calibration.py

verifier-calibration-check:
	$(PY) scripts/ci/check_verifier_calibration.py

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

provider-vault-live-smoke:
	$(PY) scripts/dev/live_provider_vault_smoke.py

audit-ledger-config:
	$(PY) scripts/ci/check_audit_ledger_config.py

approval-queue-config:
	$(PY) scripts/ci/check_approval_queue_config.py

corpus-grants-config:
	$(PY) scripts/ci/check_corpus_grants_config.py

backup-retention-config:
	$(PY) scripts/ci/check_backup_retention_config.py

retention-execution:
	$(PY) scripts/dev/run_retention_execution.py

backup-restore-drill:
	$(PY) scripts/dev/backup_restore_drill.py

minio-backup-drill-config:
	$(PY) scripts/ci/check_minio_backup_drill.py

minio-backup-restore-drill:
	$(PY) scripts/dev/minio_backup_restore_drill.py

prod-secret-files-preflight:
	$(PY) scripts/dev/preflight_runtime_secret_files.py

prod-profile-config:
	$(PY) scripts/ci/check_prod_profile_config.py

prod-profile-up: prod-secret-files-preflight prod-profile-config
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-profile-rotate-secrets: prod-secret-files-preflight prod-profile-config
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate

prod-profile-e2e:
	$(PY) scripts/dev/live_prod_profile_e2e.py

keycloak-jwks-export:
	$(PY) scripts/dev/export_keycloak_jwks.py

helm-chart-check:
	$(PY) scripts/ci/check_helm_chart.py

kind-helm-live-smoke:
	$(PY) scripts/dev/live_kind_helm_smoke.py

rag-persistence-config:
	$(PY) scripts/ci/check_rag_persistence_config.py
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run

rag-opensearch-template-dry-run:
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run

rag-opensearch-live-smoke:
	$(PY) scripts/dev/live_opensearch_rag_smoke.py

rag-pgvector-live-smoke:
	$(PY) scripts/dev/live_pgvector_rag_smoke.py

rag-hybrid-live-smoke:
	$(PY) scripts/dev/live_hybrid_rag_smoke.py

postgres-migrations-check:
	$(PY) scripts/ci/check_postgres_migrations.py

postgres-migrations-apply:
	$(PY) scripts/dev/apply_postgres_migrations.py

postgres-persistence-live-smoke:
	$(PY) scripts/dev/live_postgres_persistence_smoke.py

ingestion-pipeline-config:
	$(PY) scripts/ci/check_ingestion_pipeline_config.py

ingestion-worker-live-smoke:
	$(PY) scripts/dev/live_ingestion_worker_smoke.py

python-lock-check:
	$(PY) scripts/ci/compile_python_locks.py --check

python-repro-check:
	$(PY) scripts/ci/check_python_reproducibility.py

python-wheel-repro:
	$(PY) scripts/ci/build_reproducible_wheel.py

python-audit:
	$(PY) scripts/ci/python_dependency_audit.py

gitleaks-config:
	$(PY) scripts/ci/check_gitleaks_config.py

gitleaks-scan: gitleaks-config
	$(PY) scripts/ci/run_gitleaks.py

container-scan-config:
	$(PY) scripts/ci/check_container_scan_config.py

metrics-token-materializer-config:
	$(PY) scripts/ci/check_metrics_token_materializer.py

observability-config:
	$(PY) scripts/ci/check_observability_config.py

otel-export-live-smoke:
	$(PY) scripts/dev/live_otel_export_check.py

observability-live-smoke:
	$(PY) scripts/dev/live_observability_smoke.py

security-check:
	$(PY) scripts/ci/check_python_reproducibility.py
	$(PY) scripts/ci/check_gitleaks_config.py
	$(PY) scripts/ci/run_gitleaks.py
	$(PY) scripts/ci/secret_scan.py
	$(PY) scripts/ci/check_encryption_config.py
	$(PY) scripts/ci/check_auth_config.py
	$(PY) scripts/ci/oidc_provider_smoke.py
	$(PY) scripts/ci/check_secrets_config.py
	$(PY) scripts/ci/check_audit_ledger_config.py
	$(PY) scripts/ci/check_approval_queue_config.py
	$(PY) scripts/ci/check_corpus_grants_config.py
	$(PY) scripts/ci/check_backup_retention_config.py
	$(PY) scripts/ci/check_minio_backup_drill.py
	$(PY) scripts/ci/check_prod_profile_config.py
	$(PY) scripts/ci/check_helm_chart.py
	$(PY) scripts/ci/check_rag_persistence_config.py
	$(PY) scripts/ci/check_postgres_migrations.py
	$(PY) scripts/dev/bootstrap_opensearch_template.py --dry-run
	$(PY) scripts/ci/check_eval_ingestion_config.py
	$(PY) scripts/ci/check_verifier_calibration.py
	$(PY) scripts/ci/check_ingestion_pipeline_config.py
	$(PY) scripts/ci/python_dependency_audit.py
	$(PY) scripts/ci/check_sandbox_isolation_config.py
	$(PY) scripts/ci/check_container_scan_config.py
	$(PY) scripts/ci/check_metrics_token_materializer.py
	$(PY) scripts/ci/check_observability_config.py
	npm audit --audit-level=high
	npm audit --omit=dev --audit-level=high
