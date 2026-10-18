{{- define "chariot-mongodb.fullname" -}}
{{- printf "%s-mongodb" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "chariot-mongodb.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: mongodb
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
app.kubernetes.io/part-of: epic-ai-chariot
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "chariot-mongodb.selectorLabels" -}}
app.kubernetes.io/name: mongodb
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Name of the Secret holding mongodb-root-password (existing or generated). */}}
{{- define "chariot-mongodb.secretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "chariot-mongodb.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Resolved image reference (CH-26/CH-29). Reuses the umbrella imageRef helper. */}}
{{- define "chariot-mongodb.image" -}}
{{- if and (not .Values.image.digest) (or (not .Values.image.tag) (eq (.Values.image.tag | toString) "latest")) -}}
{{- fail "CH-26 violation: mongodb.image must set an immutable tag or digest; \"latest\" is forbidden." -}}
{{- end -}}
{{- include "chariot.imageRef" (dict "registry" (include "chariot.resolveRegistry" (dict "imageRegistry" .Values.image.registry "global" .Values.global)) "repository" .Values.image.repository "tag" .Values.image.tag "digest" .Values.image.digest) -}}
{{- end -}}
