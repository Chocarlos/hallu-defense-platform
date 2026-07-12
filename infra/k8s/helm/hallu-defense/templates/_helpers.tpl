{{- define "hallu-defense.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hallu-defense.fullname" -}}
{{- $fullname := "" -}}
{{- if .Values.fullnameOverride -}}
{{- $fullname = .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "hallu-defense.name" . -}}
{{- if contains $name .Release.Name -}}
{{- $fullname = .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $fullname = printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- if gt (len $fullname) 38 -}}
{{- fail "release-derived fullname must be at most 38 characters so every namespaced resource remains collision-free and within Kubernetes name limits" -}}
{{- end -}}
{{- $fullname -}}
{{- end -}}

{{- define "hallu-defense.labels" -}}
app.kubernetes.io/name: {{ include "hallu-defense.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "hallu-defense.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "hallu-defense.containerSecurityContext" -}}
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end -}}

{{- define "hallu-defense.validatedWorkloadImage" -}}
{{- $message := printf "%s.image.reference is required" .name -}}
{{- $reference := required $message .reference -}}
{{- if not (regexMatch "^[A-Za-z0-9._/@:+-]+$" $reference) -}}
{{- fail (printf "%s.image.reference contains invalid characters" .name) -}}
{{- end -}}
{{- if .root.Values.kindDependencies.enabled -}}
{{- $repository := printf "hallu-defense-%s" .name -}}
{{- if or (eq .name "worker") (eq .name "migrations") -}}
{{- $repository = "hallu-defense-api" -}}
{{- end -}}
{{- if not (regexMatch (printf "^%s:(ci|kind-[a-z0-9][a-z0-9-]{0,31})$" $repository) $reference) -}}
{{- fail (printf "%s.image.reference must use the exact local kind repository with :ci or a :kind-<run-id> scratch tag" .name) -}}
{{- end -}}
{{- end -}}
{{- if and (not .root.Values.kindDependencies.enabled) (not (regexMatch "^[^[:space:]@]+@sha256:[a-f0-9]{64}$" $reference)) -}}
{{- fail (printf "%s.image.reference must use repository@sha256:<64 lowercase hex> outside kind" .name) -}}
{{- end -}}
{{- $reference -}}
{{- end -}}

{{- define "hallu-defense.apiImage" -}}
{{- include "hallu-defense.validatedWorkloadImage" (dict "root" . "name" "api" "reference" .Values.api.image.reference) -}}
{{- end -}}

{{- define "hallu-defense.consoleImage" -}}
{{- include "hallu-defense.validatedWorkloadImage" (dict "root" . "name" "console" "reference" .Values.console.image.reference) -}}
{{- end -}}

{{- define "hallu-defense.workerImage" -}}
{{- include "hallu-defense.validatedWorkloadImage" (dict "root" . "name" "worker" "reference" .Values.worker.image.reference) -}}
{{- end -}}

{{- define "hallu-defense.migrationsImage" -}}
{{- include "hallu-defense.validatedWorkloadImage" (dict "root" . "name" "migrations" "reference" .Values.migrations.image.reference) -}}
{{- end -}}

{{- define "hallu-defense.apiServiceAccountName" -}}
{{- printf "%s-api" (include "hallu-defense.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hallu-defense.runtimeSecretName" -}}
{{- required "secrets.runtime.name is required; precreate the runtime Secret" .Values.secrets.runtime.name -}}
{{- end -}}

{{- define "hallu-defense.migrationsSecretName" -}}
{{- required "secrets.migrations.name is required; precreate the migration Secret" .Values.secrets.migrations.name -}}
{{- end -}}

{{- define "hallu-defense.bootstrapSecretName" -}}
{{- required "secrets.bootstrap.name is required; precreate the bootstrap Secret" .Values.secrets.bootstrap.name -}}
{{- end -}}

{{- define "hallu-defense.sandboxNetworkPolicyName" -}}
{{- printf "%s-sandbox-deny-egress" (include "hallu-defense.fullname" .) | trunc 253 | trimSuffix "-" -}}
{{- end -}}

{{- define "hallu-defense.sandboxNamespace" -}}
{{- $namespace := required "sandbox.namespace is required and must be precreated" .Values.sandbox.namespace | trim -}}
{{- if or (gt (len $namespace) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $namespace)) -}}
{{- fail "sandbox.namespace must be a valid Kubernetes DNS label" -}}
{{- end -}}
{{- if eq $namespace .Release.Namespace -}}
{{- fail "sandbox.namespace must differ from the Helm release namespace" -}}
{{- end -}}
{{- $namespace -}}
{{- end -}}

{{- define "hallu-defense.sandboxAdmissionPolicyName" -}}
{{- $prefix := include "hallu-defense.fullname" . | trunc 40 | trimSuffix "-" -}}
{{- $namespaceHash := sha256sum (printf "%s/%s" .Release.Namespace (include "hallu-defense.sandboxNamespace" .)) | trunc 8 -}}
{{- printf "%s-sandbox-jobs-%s" $prefix $namespaceHash | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hallu-defense.redisCaSecretName" -}}
{{- if and .Values.kindDependencies.enabled .Values.kindDependencies.redis.enabled -}}
{{- required "secrets.kindRedisTls.name is required for the kind Redis fixture" .Values.secrets.kindRedisTls.name -}}
{{- else -}}
{{- required "rateLimit.redis.caSecretName is required for managed production Redis" .Values.rateLimit.redis.caSecretName -}}
{{- end -}}
{{- end -}}

{{- define "hallu-defense.vaultCaSecretName" -}}
{{- if and .Values.kindDependencies.enabled .Values.kindDependencies.vault.enabled -}}
{{- required "secrets.kindVault.name is required for the kind Vault fixture" .Values.secrets.kindVault.name -}}
{{- else -}}
{{- required "vault.caSecretName is required for enterprise Vault TLS" .Values.vault.caSecretName -}}
{{- end -}}
{{- end -}}

{{- define "hallu-defense.postgresCaSecretName" -}}
{{- required "postgres.caSecretName is required for managed production PostgreSQL" .Values.postgres.caSecretName -}}
{{- end -}}

{{- define "hallu-defense.sandboxWorkspaceClaimName" -}}
{{- if .Values.sandbox.workspace.existingClaim -}}
{{- .Values.sandbox.workspace.existingClaim -}}
{{- else if .Values.sandbox.workspace.createClaim -}}
{{- if not .Values.kindDependencies.enabled -}}
{{- fail "sandbox.workspace.createClaim=true is allowed only when kindDependencies.enabled=true; production requires an existing RWX claim" -}}
{{- end -}}
{{- printf "%s-sandbox-workspace" (include "hallu-defense.fullname" .) | trunc 253 | trimSuffix "-" -}}
{{- else -}}
{{- required "sandbox.workspace.existingClaim is required unless sandbox.workspace.createClaim=true (kind only)" .Values.sandbox.workspace.existingClaim -}}
{{- end -}}
{{- end -}}

{{- define "hallu-defense.sandboxApiWorkspaceClaimName" -}}
{{- if .Values.sandbox.workspace.apiExistingClaim -}}
{{- .Values.sandbox.workspace.apiExistingClaim -}}
{{- else if .Values.sandbox.workspace.createClaim -}}
{{- if not .Values.kindDependencies.enabled -}}
{{- fail "sandbox.workspace.createClaim=true is allowed only when kindDependencies.enabled=true; production requires existing namespaced RWX claims" -}}
{{- end -}}
{{- printf "%s-sandbox-workspace-reader" (include "hallu-defense.fullname" .) | trunc 253 | trimSuffix "-" -}}
{{- else -}}
{{- required "sandbox.workspace.apiExistingClaim is required unless sandbox.workspace.createClaim=true (kind only)" .Values.sandbox.workspace.apiExistingClaim -}}
{{- end -}}
{{- end -}}

{{- define "hallu-defense.sandboxImage" -}}
{{- $reference := required "sandbox.image.reference is required" .Values.sandbox.image.reference -}}
{{- if not (regexMatch "^[A-Za-z0-9._/@:+-]+$" $reference) -}}
{{- fail "sandbox.image.reference contains invalid characters" -}}
{{- end -}}
{{- if and .Values.kindDependencies.enabled (not (regexMatch "^hallu-defense-sandbox:(ci|kind-[a-z0-9][a-z0-9-]{0,31})$" $reference)) -}}
{{- fail "sandbox.image.reference must use hallu-defense-sandbox:ci or a :kind-<run-id> scratch tag in kind" -}}
{{- end -}}
{{- if and (not .Values.kindDependencies.enabled) (not (regexMatch "^[^[:space:]@]+@sha256:[a-f0-9]{64}$" $reference)) -}}
{{- fail "sandbox.image.reference must use repository@sha256:<64 lowercase hex> outside kind" -}}
{{- end -}}
{{- $reference -}}
{{- end -}}

{{- define "hallu-defense.kindDependencyImage" -}}
{{- $reference := required (printf "kindDependencies.%s.image is required" .name) .reference -}}
{{- $repository := printf "hallu-defense-%s" .name -}}
{{- if not (regexMatch (printf "^%s:(ci|kind-[a-z0-9][a-z0-9-]{0,31})$" $repository) $reference) -}}
{{- fail (printf "kindDependencies.%s.image must use the exact local repository with :ci or a :kind-<run-id> scratch tag" .name) -}}
{{- end -}}
{{- $reference -}}
{{- end -}}

{{- define "hallu-defense.postgresWaitInitContainer" -}}
- name: wait-for-postgres
  image: {{ include "hallu-defense.migrationsImage" . | quote }}
  imagePullPolicy: {{ .Values.global.imagePullPolicy }}
  securityContext:
    {{- include "hallu-defense.containerSecurityContext" . | nindent 4 }}
  env:
    - name: HALLU_DEFENSE_POSTGRES_DSN_FILE
      value: /run/secrets/hallu_defense_postgres_dsn
    {{- if .Values.kindDependencies.enabled }}
    - name: HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED
      value: "true"
    {{- else }}
    - name: HALLU_DEFENSE_POSTGRES_CA_CERT_PATH
      value: {{ .Values.postgres.caPath | quote }}
    {{- end }}
  command:
    - python
    - -c
    - |
      import os
      import time
      from pathlib import Path

      import psycopg

      from hallu_defense.postgres_tls import validate_postgres_tls
      from hallu_defense.runtime_secrets import read_runtime_secret_file

      dsn = read_runtime_secret_file(
          "/run/secrets/hallu_defense_postgres_dsn",
          variable_name="HALLU_DEFENSE_POSTGRES_DSN_FILE",
      )
      postgres_ca = os.getenv("HALLU_DEFENSE_POSTGRES_CA_CERT_PATH")
      validate_postgres_tls(
          dsn,
          environment="production",
          ca_cert_path=Path(postgres_ca) if postgres_ca else None,
          kind_insecure_tls_enabled=(
              os.getenv("HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED") == "true"
          ),
      )

      deadline = time.monotonic() + {{ .Values.migrations.waitTimeoutSeconds }}
      while True:
          try:
              with psycopg.connect(dsn, connect_timeout=3) as connection:
                  connection.execute("SELECT 1")
              break
          except psycopg.Error:
              if time.monotonic() >= deadline:
                  raise SystemExit("PostgreSQL did not become ready before the deadline")
              time.sleep(2)
  volumeMounts:
    - name: migration-secrets
      mountPath: /run/secrets
      readOnly: true
    {{- if not .Values.kindDependencies.enabled }}
    - name: postgres-ca
      mountPath: {{ .Values.postgres.caPath | quote }}
      subPath: {{ .Values.postgres.caSecretKey | quote }}
      readOnly: true
    {{- end }}
  resources:
    requests:
      cpu: 25m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
{{- end -}}

{{- define "hallu-defense.migrationWaitInitContainer" -}}
- name: wait-for-migrations
  image: {{ include "hallu-defense.migrationsImage" . | quote }}
  imagePullPolicy: {{ .Values.global.imagePullPolicy }}
  securityContext:
    {{- include "hallu-defense.containerSecurityContext" . | nindent 4 }}
  env:
    - name: HALLU_DEFENSE_POSTGRES_DSN_FILE
      value: /run/secrets/hallu_defense_postgres_dsn
    {{- if .Values.kindDependencies.enabled }}
    - name: HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED
      value: "true"
    {{- else }}
    - name: HALLU_DEFENSE_POSTGRES_CA_CERT_PATH
      value: {{ .Values.postgres.caPath | quote }}
    {{- end }}
  command:
    - python
    - -c
    - |
      import os
      import time
      from pathlib import Path

      from hallu_defense.postgres_tls import validate_postgres_tls
      from hallu_defense.runtime_secrets import read_runtime_secret_file

      from hallu_defense.services.readiness import (
          PostgresMigrationsReadinessCheck,
          PsycopgMigrationLedgerReader,
          ReadinessCheckError,
          discover_expected_migrations,
      )

      dsn = read_runtime_secret_file(
          "/run/secrets/hallu_defense_postgres_dsn",
          variable_name="HALLU_DEFENSE_POSTGRES_DSN_FILE",
      )
      postgres_ca = os.getenv("HALLU_DEFENSE_POSTGRES_CA_CERT_PATH")
      validate_postgres_tls(
          dsn,
          environment="production",
          ca_cert_path=Path(postgres_ca) if postgres_ca else None,
          kind_insecure_tls_enabled=(
              os.getenv("HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED") == "true"
          ),
      )
      expected_migrations = discover_expected_migrations(
          Path("/app/infra/rag/pgvector")
      )
      migration_check = PostgresMigrationsReadinessCheck(
          PsycopgMigrationLedgerReader(
              dsn=dsn,
              timeout_seconds=3,
          ),
          expected_migrations=expected_migrations,
      )
      deadline = time.monotonic() + {{ .Values.migrations.waitTimeoutSeconds }}
      while True:
          try:
              migration_check.run()
              break
          except ReadinessCheckError:
              pass
          if time.monotonic() >= deadline:
              raise SystemExit("PostgreSQL migrations did not complete before the deadline")
          time.sleep(2)
  volumeMounts:
    - name: runtime-postgres-secret
      mountPath: /run/secrets
      readOnly: true
    {{- if not .Values.kindDependencies.enabled }}
    - name: postgres-ca
      mountPath: {{ .Values.postgres.caPath | quote }}
      subPath: {{ .Values.postgres.caSecretKey | quote }}
      readOnly: true
    {{- end }}
  resources:
    requests:
      cpu: 25m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
{{- end -}}

{{- define "hallu-defense.apiEnv" -}}
- name: HALLU_DEFENSE_ENV
  value: production
- name: HALLU_DEFENSE_RUNTIME_ROLE
  value: api
- name: HALLU_DEFENSE_AUTH_REQUIRED
  value: "true"
- name: HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS
  value: "15"
- name: HALLU_DEFENSE_AUTH_CLAIMS_MODE
  value: oidc_jwt
- name: HALLU_DEFENSE_OIDC_ISSUER
  value: {{ required "oidc.issuer is required" .Values.oidc.issuer | quote }}
- name: HALLU_DEFENSE_OIDC_AUDIENCE
  value: {{ required "oidc.audience is required" .Values.oidc.audience | quote }}
- name: HALLU_DEFENSE_OIDC_JWKS_PATH
  value: {{ .Values.oidc.jwksPath | quote }}
- name: HALLU_DEFENSE_CORS_ALLOW_ORIGINS
  value: {{ join "," (required "cors.allowOrigins is required" .Values.cors.allowOrigins) | quote }}
- name: HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS
  value: {{ join "," (required "outboundHttps.allowedOrigins is required" .Values.outboundHttps.allowedOrigins) | quote }}
- name: HALLU_DEFENSE_SECRETS_BACKEND
  value: vault
- name: HALLU_DEFENSE_VAULT_ADDR
  value: {{ required "vault.address is required" .Values.vault.address | quote }}
- name: HALLU_DEFENSE_VAULT_MOUNT
  value: {{ .Values.vault.mount | quote }}
- name: HALLU_DEFENSE_VAULT_TOKEN_FILE
  value: /run/secrets/hallu_defense_vault_token
- name: HALLU_DEFENSE_VAULT_CA_CERT_PATH
  value: {{ .Values.vault.caPath | quote }}
- name: HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME
  value: observability/metrics-scrape-token
- name: HALLU_DEFENSE_POSTGRES_DSN_FILE
  value: /run/secrets/hallu_defense_postgres_dsn
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED
  value: "true"
{{- else }}
- name: HALLU_DEFENSE_POSTGRES_CA_CERT_PATH
  value: {{ .Values.postgres.caPath | quote }}
{{- end }}
- name: HALLU_DEFENSE_AUDIT_LEDGER_BACKEND
  value: postgres
- name: HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME
  value: audit/request-commitment-key
- name: HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND
  value: postgres
- name: HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME
  value: {{ required "approvalCommitment.activeSecretName is required" .Values.approvalCommitment.activeSecretName | quote }}
- name: HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_KEY_ID
  value: {{ required "approvalCommitment.activeKeyId is required" .Values.approvalCommitment.activeKeyId | quote }}
{{- $previousApprovalSecret := .Values.approvalCommitment.previousSecretName }}
{{- $previousApprovalKeyId := .Values.approvalCommitment.previousKeyId }}
{{- $previousApprovalValidUntil := .Values.approvalCommitment.previousValidUntil }}
{{- if or $previousApprovalSecret $previousApprovalKeyId $previousApprovalValidUntil }}
{{- if not (and $previousApprovalSecret $previousApprovalKeyId $previousApprovalValidUntil) }}
{{- fail "approvalCommitment previousSecretName, previousKeyId, and previousValidUntil must be configured together" }}
{{- end }}
- name: HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_SECRET_NAME
  value: {{ $previousApprovalSecret | quote }}
- name: HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_KEY_ID
  value: {{ $previousApprovalKeyId | quote }}
- name: HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_VALID_UNTIL
  value: {{ $previousApprovalValidUntil | quote }}
{{- end }}
- name: HALLU_DEFENSE_CORPUS_GRANTS_BACKEND
  value: postgres
- name: HALLU_DEFENSE_EVAL_REPORTS_BACKEND
  value: postgres
- name: HALLU_DEFENSE_PROVIDER_BACKEND
  value: {{ required "provider.backend is required" .Values.provider.backend | quote }}
- name: HALLU_DEFENSE_PROVIDER_MODEL
  value: {{ required "provider.model is required" .Values.provider.model | quote }}
- name: HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL
  value: {{ required "provider.openaiCompatibleBaseUrl is required" .Values.provider.openaiCompatibleBaseUrl | quote }}
- name: HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME
  value: {{ required "provider.apiKeySecretName is required" .Values.provider.apiKeySecretName | quote }}
- name: HALLU_DEFENSE_RAG_INDEX_BACKEND
  value: {{ required "ragIndex.backend is required" .Values.ragIndex.backend | quote }}
- name: HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS
  value: {{ .Values.ragIndex.timeoutSeconds | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_ENDPOINT
  value: {{ required "opensearch.endpoint is required" .Values.opensearch.endpoint | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_INDEX_NAME
  value: {{ required "opensearch.indexName is required" .Values.opensearch.indexName | quote }}
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED
  value: "true"
{{- else }}
- name: HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME
  value: {{ required "opensearch.authorizationSecretName is required outside kind" .Values.opensearch.authorizationSecretName | quote }}
{{- if .Values.opensearch.caSecretName }}
- name: HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH
  value: {{ .Values.opensearch.caPath | quote }}
{{- end }}
{{- end }}
- name: HALLU_DEFENSE_INGESTION_MODE
  value: async
- name: HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND
  value: {{ .Values.rateLimit.backend | quote }}
- name: HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME
  value: {{ .Values.rateLimit.redis.urlSecretName | quote }}
- name: HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS
  value: {{ .Values.rateLimit.redis.timeoutSeconds | quote }}
- name: HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH
  value: {{ .Values.rateLimit.redis.caPath | quote }}
- name: HALLU_DEFENSE_OPA_ENABLED
  value: "true"
- name: HALLU_DEFENSE_OPA_PATH
  value: /usr/local/bin/opa
- name: HALLU_DEFENSE_OPA_POLICY_DIR
  value: /app/infra/opa/policies
- name: HALLU_DEFENSE_OTEL_ENABLED
  value: {{ .Values.otel.enabled | quote }}
{{- if .Values.otel.enabled }}
- name: HALLU_DEFENSE_OTEL_EXPORTER
  value: {{ .Values.otel.exporter | quote }}
- name: HALLU_DEFENSE_OTEL_ENDPOINT
  value: {{ required "otel.endpoint is required when otel.enabled=true" .Values.otel.endpoint | quote }}
{{- end }}
- name: HALLU_DEFENSE_SANDBOX_BACKEND
  value: {{ required "sandbox.backend is required" .Values.sandbox.backend | quote }}
- name: HALLU_DEFENSE_ALLOWED_WORKSPACE
  value: {{ .Values.sandbox.workspace.mountPath | quote }}
- name: HALLU_DEFENSE_MAX_COMMAND_SECONDS
  value: {{ .Values.sandbox.commandTimeoutSeconds | quote }}
- name: HALLU_DEFENSE_SANDBOX_DOCKER_CPUS
  value: {{ .Values.sandbox.resources.cpu | quote }}
- name: HALLU_DEFENSE_SANDBOX_DOCKER_MEMORY_MB
  value: {{ .Values.sandbox.resources.memoryMb | quote }}
- name: HALLU_DEFENSE_SANDBOX_DOCKER_PIDS_LIMIT
  value: {{ .Values.sandbox.resources.pidsLimit | quote }}
{{- if eq .Values.sandbox.backend "kubernetes" }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE
  value: {{ include "hallu-defense.sandboxImage" . | quote }}
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE
  value: "true"
{{- end }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE
  value: {{ include "hallu-defense.sandboxNamespace" . | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME
  value: {{ include "hallu-defense.sandboxWorkspaceClaimName" . | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH
  value: {{ .Values.sandbox.workspace.mountPath | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME
  value: {{ include "hallu-defense.sandboxNetworkPolicyName" . | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID
  value: {{ required "sandbox.tenantId is required for one-tenant-per-workspace isolation" .Values.sandbox.tenantId | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_POLL_INTERVAL_SECONDS
  value: {{ .Values.sandbox.pollIntervalSeconds | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_JOB_TTL_SECONDS
  value: {{ .Values.sandbox.jobTtlSeconds | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_API_REQUEST_TIMEOUT_SECONDS
  value: {{ .Values.sandbox.apiRequestTimeoutSeconds | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS
  value: {{ .Values.sandbox.cleanupGraceSeconds | quote }}
- name: HALLU_DEFENSE_SANDBOX_KUBERNETES_SETUP_GRACE_SECONDS
  value: {{ .Values.sandbox.setupGraceSeconds | quote }}
{{- end }}
{{- end -}}

{{- define "hallu-defense.workerEnv" -}}
- name: HALLU_DEFENSE_ENV
  value: production
- name: HALLU_DEFENSE_RUNTIME_ROLE
  value: worker
- name: HALLU_DEFENSE_SECRETS_BACKEND
  value: vault
- name: HALLU_DEFENSE_VAULT_ADDR
  value: {{ required "vault.address is required" .Values.vault.address | quote }}
- name: HALLU_DEFENSE_VAULT_MOUNT
  value: {{ .Values.vault.mount | quote }}
- name: HALLU_DEFENSE_VAULT_TOKEN_FILE
  value: /run/secrets/hallu_defense_vault_token
- name: HALLU_DEFENSE_VAULT_CA_CERT_PATH
  value: {{ .Values.vault.caPath | quote }}
- name: HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME
  value: observability/metrics-scrape-token
- name: HALLU_DEFENSE_POSTGRES_DSN_FILE
  value: /run/secrets/hallu_defense_postgres_dsn
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED
  value: "true"
{{- else }}
- name: HALLU_DEFENSE_POSTGRES_CA_CERT_PATH
  value: {{ .Values.postgres.caPath | quote }}
{{- end }}
- name: HALLU_DEFENSE_AUDIT_LEDGER_BACKEND
  value: postgres
- name: HALLU_DEFENSE_AUDIT_REQUEST_COMMITMENT_SECRET_NAME
  value: audit/request-commitment-key
- name: HALLU_DEFENSE_CORPUS_GRANTS_BACKEND
  value: postgres
- name: HALLU_DEFENSE_RAG_INDEX_BACKEND
  value: {{ required "ragIndex.backend is required" .Values.ragIndex.backend | quote }}
- name: HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS
  value: {{ .Values.ragIndex.timeoutSeconds | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_ENDPOINT
  value: {{ required "opensearch.endpoint is required" .Values.opensearch.endpoint | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_INDEX_NAME
  value: {{ required "opensearch.indexName is required" .Values.opensearch.indexName | quote }}
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED
  value: "true"
{{- else }}
- name: HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME
  value: {{ required "opensearch.authorizationSecretName is required outside kind" .Values.opensearch.authorizationSecretName | quote }}
{{- if .Values.opensearch.caSecretName }}
- name: HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH
  value: {{ .Values.opensearch.caPath | quote }}
{{- end }}
{{- end }}
- name: HALLU_DEFENSE_INGESTION_MODE
  value: async
- name: HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS
  value: {{ join "," (required "outboundHttps.allowedOrigins is required" .Values.outboundHttps.allowedOrigins) | quote }}
- name: HALLU_DEFENSE_INGESTION_WORKER_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.uid
{{- end -}}

{{- define "hallu-defense.opensearchBootstrapEnv" -}}
- name: HALLU_DEFENSE_ENV
  value: production
- name: HALLU_DEFENSE_RUNTIME_ROLE
  value: opensearch-bootstrap
- name: HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS
  value: {{ join "," (required "outboundHttps.allowedOrigins is required" .Values.outboundHttps.allowedOrigins) | quote }}
- name: HALLU_DEFENSE_SECRETS_BACKEND
  value: vault
- name: HALLU_DEFENSE_VAULT_ADDR
  value: {{ required "vault.address is required" .Values.vault.address | quote }}
- name: HALLU_DEFENSE_VAULT_MOUNT
  value: {{ .Values.vault.mount | quote }}
- name: HALLU_DEFENSE_VAULT_TOKEN_FILE
  value: /run/secrets/hallu_defense_vault_token
- name: HALLU_DEFENSE_VAULT_CA_CERT_PATH
  value: {{ .Values.vault.caPath | quote }}
- name: HALLU_DEFENSE_RAG_INDEX_BACKEND
  value: opensearch
- name: HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS
  value: {{ .Values.ragIndex.timeoutSeconds | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_ENDPOINT
  value: {{ required "opensearch.endpoint is required" .Values.opensearch.endpoint | quote }}
- name: HALLU_DEFENSE_OPENSEARCH_INDEX_NAME
  value: {{ required "opensearch.indexName is required" .Values.opensearch.indexName | quote }}
{{- if .Values.kindDependencies.enabled }}
- name: HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED
  value: "true"
{{- else }}
- name: HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME
  value: {{ required "opensearch.authorizationSecretName is required outside kind" .Values.opensearch.authorizationSecretName | quote }}
{{- if .Values.opensearch.caSecretName }}
- name: HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH
  value: {{ .Values.opensearch.caPath | quote }}
{{- end }}
{{- end }}
{{- end -}}
