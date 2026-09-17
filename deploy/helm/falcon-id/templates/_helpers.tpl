{{/* templates/_helpers.tpl */}}

{{- define "falcon-id.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "falcon-id.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "falcon-id.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "falcon-id.labels" -}}
helm.sh/chart: {{ include "falcon-id.chart" . }}
{{ include "falcon-id.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hexxlock-platform
app.kubernetes.io/component: identity-plane
hexxlock.com/environment: {{ .Values.global.environment }}
hexxlock.com/region: {{ .Values.global.region }}
{{- end -}}

{{- define "falcon-id.selectorLabels" -}}
app.kubernetes.io/name: {{ include "falcon-id.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "falcon-id.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "falcon-id.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
falcon-id.podTemplate emits the `template:` block used by both the
Deployment (templates/deployment.yaml) and the Argo Rollouts Rollout
(templates/rollout.yaml) so the two delivery shapes share a single
source of truth for the pod spec.

Caller embeds it under `spec:` like:

    spec:
      ...
      {{- include "falcon-id.podTemplate" . | nindent 2 }}

The template emits flush-left (no leading indentation); the caller's
`nindent 2` lifts it to the appropriate column. `nindent 2` because
both Deployment and Rollout have `template:` at .spec.template (one
level under spec).

History: extracted on 2026-05-01 after MR !99 introduced rollout.yaml
as a duplicate of deployment.yaml's pod spec — the duplication was
flagged for refactor in the same MR's commit message. This define
block is the follow-up. Future edits to env / probes / volumes /
ports happen here once and apply to both delivery modes.
*/}}
{{- define "falcon-id.podTemplate" -}}
template:
  metadata:
    {{- with .Values.podAnnotations }}
    annotations:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    labels:
      {{- include "falcon-id.selectorLabels" . | nindent 6 }}
      app.kubernetes.io/name: falcon-id  # NetworkPolicy selector in apisix-redis + spicedb
  spec:
    serviceAccountName: {{ include "falcon-id.serviceAccountName" . }}
    # Token mounted because the realm DB provisioner calls the Keystone
    # SDK (pkg/sdk/keystone.EnrollSchema) at runtime, which requires
    # in-cluster k8s API access via rest.InClusterConfig().
    # RBAC: the falcon-id ServiceAccount binds to ClusterRole
    # `keystone-tenant-enroller` (LogicalDatabase + DatabaseSchema only)
    # via the namespace-scoped RoleBinding shipped in the GitOps repository
    # platform/keystone/resources/falcon-id/rolebinding-tenant-enroller.yaml.
    # Phase-2b MR4 (2026-05-04) flipped this from false to true.
    automountServiceAccountToken: true
    imagePullSecrets:
      - name: {{ .Values.global.imagePullSecret }}
    securityContext:
      {{- toYaml .Values.podSecurityContext | nindent 6 }}
    containers:
      - name: falcon-id
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        securityContext:
          {{- toYaml .Values.containerSecurityContext | nindent 10 }}
        ports:
          - name: http
            containerPort: {{ .Values.service.containerPort }}
            protocol: TCP
          {{- if .Values.pprof.enabled }}
          - name: pprof
            containerPort: {{ .Values.pprof.containerPort }}
            protocol: TCP
          {{- end }}
        env:
          {{- if .Values.pprof.enabled }}
          - name: FALCON_PPROF_ENABLED
            value: "true"
          - name: FALCON_PPROF_ADDR
            value: ":{{ .Values.pprof.containerPort }}"
          {{- end }}
          {{- range $k, $v := .Values.env }}
          - name: {{ $k }}
            value: {{ $v | quote }}
          {{- end }}
          {{- if .Values.internalTlsTrust.enabled }}
          - name: SSL_CERT_FILE
            value: {{ printf "%s/%s" .Values.internalTlsTrust.mountPath .Values.internalTlsTrust.sslCertFileKey | quote }}
          {{- end }}
        envFrom:
          - secretRef:
              name: {{ include "falcon-id.fullname" . }}-vault
              optional: false
          {{- range .Values.extraEnvFrom }}
          - secretRef:
              name: {{ .secretRef.name }}
              optional: {{ .secretRef.optional | default false }}
          {{- end }}
        livenessProbe:
          {{- toYaml .Values.livenessProbe | nindent 10 }}
        readinessProbe:
          {{- toYaml .Values.readinessProbe | nindent 10 }}
        resources:
          {{- toYaml .Values.resources | nindent 10 }}
        volumeMounts:
          - name: tmp
            mountPath: /tmp
          {{- if .Values.internalTlsTrust.enabled }}
          - name: internal-tls-trust
            mountPath: {{ .Values.internalTlsTrust.mountPath }}
            readOnly: true
          {{- end }}
    volumes:
      - name: tmp
        emptyDir: {}
      {{- if .Values.internalTlsTrust.enabled }}
      - name: internal-tls-trust
        configMap:
          name: {{ .Values.internalTlsTrust.configMapName }}
          optional: false
      {{- end }}
    {{- with .Values.topologySpreadConstraints }}
    topologySpreadConstraints:
      {{- toYaml . | nindent 6 }}
    {{- end }}
{{- end -}}
