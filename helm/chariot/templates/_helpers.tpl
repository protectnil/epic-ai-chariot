{{/*
Epic AI® Chariot — chart helpers.
*/}}

{{- define "chariot.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "chariot.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "chariot.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "chariot.labels" -}}
helm.sh/chart: {{ include "chariot.chart" . }}
{{ include "chariot.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: epic-ai-chariot
{{- end -}}

{{- define "chariot.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chariot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "chariot.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "chariot.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
chariot.resolveRegistry — resolve the registry host for one image.

AWS Marketplace requires the registry to be breakable out into a field on the
SAME LEVEL as `repository` so its regionalization step can rewrite it per
region ("Helm chart structure requirements", container-product-policies).
Resolution order, most specific first:
  1. the image's own `registry` field  (what AWS rewrites)
  2. `global.imageRegistry`            (CH-29 single-knob air-gap override)
  3. none — the render ABORTS (CHARIOT-SPEC §23.2 / CH-29). A bare repository
     would be resolved by the container runtime's default registry, which is
     Docker Hub; §23.2 requires every image to come from the AWS-managed
     Marketplace ECR "(no Docker Hub / Quay / ECR Public)".
Order 2 is retained so an existing air-gap install that only sets
`global.imageRegistry` keeps working unchanged.
Usage: include "chariot.resolveRegistry" (dict "imageRegistry" $img.registry "global" .Values.global)
*/}}
{{- define "chariot.resolveRegistry" -}}
{{- $perImage := .imageRegistry | default "" | toString | trim -}}
{{- $resolved := $perImage -}}
{{- if and (not $resolved) .global -}}
{{- $resolved = .global.imageRegistry | default "" | toString | trim -}}
{{- end -}}
{{- if not $resolved -}}
{{- fail "CH-29 fail-closed: no image registry resolved (the image's own `registry` and `global.imageRegistry` are both empty), so the image would pull from Docker Hub. Set global.imageRegistry (see values-airgap.yaml) or each image's `registry` to your Marketplace ECR host, e.g. <acct>.dkr.ecr.<region>.amazonaws.com. The chart never defaults to Docker Hub." -}}
{{- end -}}
{{- $resolved -}}
{{- end -}}

{{/*
chariot.imageRef — assemble a fully-qualified image reference (CH-26/CH-29).
All image refs are built from values only. Digest wins over tag when set.
Usage: include "chariot.imageRef" (dict "registry" $reg "repository" $repo "tag" $tag "digest" $digest)
*/}}
{{- define "chariot.imageRef" -}}
{{- $repo := .repository -}}
{{- if .registry -}}
{{- $repo = printf "%s/%s" .registry .repository -}}
{{- end -}}
{{- if .digest -}}
{{- printf "%s@%s" $repo .digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (.tag | toString) -}}
{{- end -}}
{{- end -}}

{{/*
chariot.imageRepository — return the fully qualified repository path without
tag or digest. Used by signature policy patterns and ECS lifecycle hooks.
*/}}
{{- define "chariot.imageRepository" -}}
{{- $repo := .repository -}}
{{- if .registry -}}
{{- printf "%s/%s" .registry .repository -}}
{{- else -}}
{{- $repo -}}
{{- end -}}
{{- end -}}

{{/*
chariot.gatewayImage — the gateway image, enforcing CH-26 (no "latest", tag
required when no digest).
*/}}
{{- define "chariot.gatewayImage" -}}
{{- $img := .Values.gateway.image -}}
{{- if and (not $img.digest) (or (not $img.tag) (eq ($img.tag | toString) "latest")) -}}
{{- fail "CH-26 violation: gateway.image must set an immutable tag (chariot-vX.Y.Z) or a digest; \"latest\" is forbidden." -}}
{{- end -}}
{{- include "chariot.imageRef" (dict "registry" (include "chariot.resolveRegistry" (dict "imageRegistry" $img.registry "global" .Values.global)) "repository" $img.repository "tag" $img.tag "digest" $img.digest) -}}
{{- end -}}

{{/*
chariot.gatewayImageRepository — the gateway repository string without tag or
digest. Used for signature policy image references.
*/}}
{{- define "chariot.gatewayImageRepository" -}}
{{- $img := .Values.gateway.image -}}
{{- include "chariot.imageRepository" (dict "registry" (include "chariot.resolveRegistry" (dict "imageRegistry" $img.registry "global" .Values.global)) "repository" $img.repository) -}}
{{- end -}}

{{/*
chariot.assertStrongSecret — CH-28 fail-closed credential gate. Aborts the
render when an inline password is blank or a known insecure default. Mirrors
src/iam/bootstrap.ts requireEnv + WEAK_SECRETS.
Usage: include "chariot.assertStrongSecret" (dict "value" $pw "field" "mongodb.auth.rootPassword")
*/}}
{{- define "chariot.assertStrongSecret" -}}
{{- $val := .value | default "" | trim -}}
{{- $field := .field -}}
{{- if eq $val "" -}}
{{- fail (printf "CH-28 fail-closed: %s is empty/blank. Supply operator credentials via an existing K8s Secret (auth.existingSecret) or a strong value; the chart never defaults a password." $field) -}}
{{- end -}}
{{- $weak := list "change-me" "changeme" "changeit" "change_me" "change" "secret" "mysecret" "topsecret" "supersecret" "password" "passwd" "pwd" "p@ssword" "p@ssw0rd" "admin" "administrator" "root" "user" "test" "demo" "example" "default" "defaultpassword" "defaultsecret" "your-secret-here" "your_secret_here" "your-secret" "your_secret" "replace-me" "replace_me" "replaceme" "todo" "fixme" "tbd" "placeholder" "12345" "123456" "12345678" "123456789" "1234567890" "qwerty" "abc123" "password1" "password123" "sample" "dev" "devsecret" "dev-secret" "localhost" "local" -}}
{{- if has (lower $val) $weak -}}
{{- fail (printf "CH-28 fail-closed: %s is set to an insecure default (%q). Set a real high-entropy value." $field $val) -}}
{{- end -}}
{{- end -}}

{{/*
chariot.podSecurityContext — renders .Values.podSecurityContext, swapping in
the hardened Localhost seccomp profile (GAP #10) when
seccomp.customProfile.enabled is true. RuntimeDefault (the values.yaml
default) is left completely untouched when the flag is false — no
regression on existing installs.
*/}}
{{- define "chariot.podSecurityContext" -}}
{{- if .Values.seccomp.customProfile.enabled -}}
{{- if not .Values.seccomp.customProfile.localhostProfile -}}
{{- fail "GAP-10 fail-closed: seccomp.customProfile.enabled=true but seccomp.customProfile.localhostProfile is empty. Set it to the profile's path relative to <kubelet-root-dir>/seccomp/." -}}
{{- end -}}
{{- $ctx := omit .Values.podSecurityContext "seccompProfile" -}}
{{- $seccomp := dict "type" "Localhost" "localhostProfile" .Values.seccomp.customProfile.localhostProfile -}}
{{- toYaml (merge $ctx (dict "seccompProfile" $seccomp)) -}}
{{- else -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}
{{- end -}}

{{/*
chariot.imageVerificationEngine — resolve imageVerification.engine, defaulting
to "kyverno" so charts rendered before this field existed (or that never set
it) keep their EKS-era behavior unchanged.
*/}}
{{- define "chariot.imageVerificationEngine" -}}
{{- .Values.imageVerification.engine | default "kyverno" -}}
{{- end -}}

{{/*
chariot.assertImageVerifyFailClosed — CH-54 fail-closed admission gate. Called
UNCONDITIONALLY from every template that would otherwise skip rendering the
verifier resource (image-verify-policy.yaml, rhacs-signature-integration-note.yaml)
so it cannot be bypassed by the very setting it is meant to guard — see the
first block below, which fires whenever imageVerification.enabled=false or
engine="none", cases where NO verifier resource renders at all and a
`{{- if .Values.imageVerification.enabled -}}`-gated assert would never run.
Aborts the render unless the operator sets the explicit break-glass flag
imageVerification.allowInsecureAdmissionMode=true. Mirrors the CH-28 precedent.
*/}}
{{- define "chariot.assertImageVerifyFailClosed" -}}
{{- $iv := .Values.imageVerification -}}
{{- $engine := include "chariot.imageVerificationEngine" . -}}
{{- $insecure := $iv.allowInsecureAdmissionMode -}}
{{- $noVerifier := or (not $iv.enabled) (eq $engine "none") -}}
{{- if and $noVerifier (not $insecure) -}}
{{- fail (printf "CH-54 fail-closed: no deploy-time image-signature verifier will run (imageVerification.enabled=%v, imageVerification.engine=%q). Set imageVerification.enabled=true with engine \"kyverno\" or \"rhacs\", or set imageVerification.allowInsecureAdmissionMode=true to deliberately install without one." $iv.enabled $engine) -}}
{{- end -}}
{{- if and $iv.enabled (eq $engine "kyverno") (not $insecure) -}}
{{- $vfa := $iv.kyverno.validationFailureAction -}}
{{- $fp := $iv.kyverno.failurePolicy -}}
{{- if ne $vfa "Enforce" -}}
{{- fail (printf "CH-54 fail-closed: imageVerification.kyverno.validationFailureAction must be \"Enforce\" (got %q); \"Audit\" silently admits unsigned images. Set imageVerification.allowInsecureAdmissionMode=true to override deliberately." $vfa) -}}
{{- end -}}
{{- if ne $fp "Fail" -}}
{{- fail (printf "CH-54 fail-closed: imageVerification.kyverno.failurePolicy must be \"Fail\" (got %q); \"Ignore\" admits images when the admission webhook is unavailable. Set imageVerification.allowInsecureAdmissionMode=true to override deliberately." $fp) -}}
{{- end -}}
{{- end -}}
{{- if and $iv.enabled (eq $engine "rhacs") (not $insecure) (not $iv.rhacs.signatureIntegrationName) -}}
{{- fail "CH-54 fail-closed: imageVerification.engine=\"rhacs\" requires imageVerification.rhacs.signatureIntegrationName. This chart cannot verify RHACS itself enforces the policy (RHACS is Central-managed, not Helm-managed — see templates/rhacs-signature-integration-note.yaml); an empty name means the ConfigMap this chart ships has no name to render, i.e. nothing for the operator to act on. Set imageVerification.allowInsecureAdmissionMode=true to override deliberately." -}}
{{- end -}}
{{- end -}}
