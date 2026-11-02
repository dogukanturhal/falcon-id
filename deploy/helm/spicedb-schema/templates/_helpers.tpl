{{/* templates/_helpers.tpl */}}

{{- define "spicedb-schema.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "spicedb-schema.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "spicedb-schema.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "spicedb-schema.labels" -}}
helm.sh/chart: {{ include "spicedb-schema.chart" . }}
{{ include "spicedb-schema.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hexxlock-platform
{{- end -}}

{{- define "spicedb-schema.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spicedb-schema.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
  No spicedb-schema.serviceAccountName helper — deliberately. See
  templates/schema-write-job.yaml's header comment (t-582 hook-ordering
  incident, 2026-09-08/09): a dedicated ServiceAccount as a plain
  (non-hook) resource cannot exist in time for a PreSync-hook Job in the
  same Application to reference it, and making the ServiceAccount itself
  a hook reintroduces the same race (or a same-sync one, if its
  hook-delete-policy includes HookSucceeded). The write Job needs zero
  Kubernetes API access — it only speaks HTTP to SpiceDB's gateway using
  a preshared key — so it runs as the namespace's automatically-created
  `default` ServiceAccount (exists before ArgoCD ever touches this
  Application; no ordering dependency possible) with
  automountServiceAccountToken set at the POD level to preserve the
  original no-token intent without depending on any SA object's own
  settings.
*/}}
