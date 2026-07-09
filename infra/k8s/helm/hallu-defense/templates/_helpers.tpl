{{- define "hallu-defense.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hallu-defense.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "hallu-defense.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
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

{{- define "hallu-defense.apiEnv" -}}
- name: HALLU_DEFENSE_ENV
  value: production
- name: HALLU_DEFENSE_AUTH_REQUIRED
  value: "true"
- name: HALLU_DEFENSE_AUTH_CLAIMS_MODE
  value: oidc_jwt
- name: HALLU_DEFENSE_OIDC_ISSUER
  value: {{ .Values.oidc.issuer | quote }}
- name: HALLU_DEFENSE_OIDC_AUDIENCE
  value: {{ .Values.oidc.audience | quote }}
- name: HALLU_DEFENSE_OIDC_JWKS_PATH
  value: {{ .Values.oidc.jwksPath | quote }}
- name: HALLU_DEFENSE_CORS_ALLOW_ORIGINS
  value: {{ join "," .Values.cors.allowOrigins | quote }}
- name: HALLU_DEFENSE_SECRETS_BACKEND
  value: vault
- name: HALLU_DEFENSE_VAULT_ADDR
  value: {{ .Values.vault.address | quote }}
- name: HALLU_DEFENSE_VAULT_MOUNT
  value: {{ .Values.vault.mount | quote }}
- name: HALLU_DEFENSE_VAULT_TOKEN_ENV
  value: {{ .Values.vault.tokenEnv | quote }}
- name: HALLU_DEFENSE_RUNTIME_VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "hallu-defense.fullname" . }}-runtime
      key: vault-token
- name: HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME
  value: observability/metrics-scrape-token
- name: HALLU_DEFENSE_POSTGRES_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "hallu-defense.fullname" . }}-runtime
      key: postgres-dsn
- name: HALLU_DEFENSE_AUDIT_LEDGER_BACKEND
  value: postgres
- name: HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND
  value: postgres
- name: HALLU_DEFENSE_CORPUS_GRANTS_BACKEND
  value: postgres
- name: HALLU_DEFENSE_RAG_INDEX_BACKEND
  value: pgvector
- name: HALLU_DEFENSE_INGESTION_MODE
  value: async
- name: HALLU_DEFENSE_OTEL_ENABLED
  value: "true"
- name: HALLU_DEFENSE_OTEL_EXPORTER
  value: otlp
- name: HALLU_DEFENSE_OTEL_ENDPOINT
  value: http://otel-collector:4318/v1/traces
- name: HALLU_DEFENSE_SANDBOX_BACKEND
  value: docker
- name: HALLU_DEFENSE_SANDBOX_DOCKER_IMAGE
  value: hallu-defense-sandbox:ci
- name: HALLU_DEFENSE_SANDBOX_DOCKER_PATH
  value: docker
{{- end -}}
