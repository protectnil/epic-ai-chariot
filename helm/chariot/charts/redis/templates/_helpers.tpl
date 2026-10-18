{{- define "chariot-redis.fullname" -}}
{{- printf "%s-redis" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "chariot-redis.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: redis
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: cache
app.kubernetes.io/part-of: epic-ai-chariot
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "chariot-redis.selectorLabels" -}}
app.kubernetes.io/name: redis
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "chariot-redis.secretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "chariot-redis.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "chariot-redis.image" -}}
{{- if and (not .Values.image.digest) (or (not .Values.image.tag) (eq (.Values.image.tag | toString) "latest")) -}}
{{- fail "CH-26 violation: redis.image must set an immutable tag or digest; \"latest\" is forbidden." -}}
{{- end -}}
{{- include "chariot.imageRef" (dict "registry" (include "chariot.resolveRegistry" (dict "imageRegistry" .Values.image.registry "global" .Values.global)) "repository" .Values.image.repository "tag" .Values.image.tag "digest" .Values.image.digest) -}}
{{- end -}}
