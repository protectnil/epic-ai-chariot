# syntax=docker/dockerfile:1.7
#
# Epic AI® Chariot — `chariot-gateway` container image (CHARIOT-SPEC §23.2, CH-24…CH-30).
#
# Single image, single process: the gateway plus its embedded vector runtime.
# Because Qdrant Edge is linked **into** `chariot-native.node` (§2.2/CH-27), this
# image carries no separate vector pod/service — the deployment is gateway +
# MongoDB + Redis only (the three-image set; Mongo/Redis are vendored, see helm/).
#
# Build contract — this Dockerfile ASSEMBLES already-built artifacts; it does not
# compile TypeScript or the Rust addon. The release pipeline stages the following
# into the build context before `docker build`; paths are overridable via ARG so
# Phase 3 (native + EdgeShard) and Phase 5 (signed/sealed bundle) wire in at
# integration without editing this file:
#   - dist/                          compiled TS (Phase: existing `npm run build`)
#   - native/chariot-native.node     napi addon, embedded Qdrant Edge + fastembed-rs (P3)
#   - native/integrity.json          Ed25519-signed per-platform hash manifest
#   - chariot-adapter-*.json(.sig)   signed catalog + registry artifacts (P5)
#   - ${EDGESHARD_SNAPSHOT}          sealed (AES-256-GCM) + signed EdgeShard snapshot (P5)
#   - ${SPLADE_DIR}                  SPLADE query-encoder model + tokenizer (P5)
#   - ${BIEN_DIR}                    BIEN dense document-encoder model + tokenizer (P5, BIEN::§9::10)
#   - ${ONNXRUNTIME_DIR}             ONNX runtime shared libs, when not statically linked
#
# NOTE (CH-25): every COPY below is an explicit allow-list. There is deliberately
# no `COPY . .`, so source `.env`, `.git`, keys, or AWS credentials can never enter
# the image even if present in the build context.
#
# Build MUST target a single architecture (CH-30) — the napi target is
# `x86_64-unknown-linux-gnu`, so build with: `docker build --platform=linux/amd64 …`.

# glibc base — Red Hat Universal Base Image 9, Node.js 22 minimal (OpenShift /
# IBM Marketplace container certification: "Container images must use a
# Universal Base Image (UBI) provided by Red Hat", docs.redhat.com container
# policy guide). NOT Alpine: the napi addon is built for
# `x86_64-unknown-linux-gnu` (glibc), and musl would fail to load it (§23.2).
# UBI9 is glibc-based RHEL userspace, so the addon loads unchanged.
#
# Pinned by immutable Red Hat catalog tag (`<rhel-minor>-<build-epoch>`, NOT
# the floating `9.8`/`latest` tags, which are periodically repointed at a
# newer rebuild) plus the matching manifest digest, verified live against the
# Red Hat Ecosystem Catalog API on 2026-09-03:
#   registry.access.redhat.com/ubi9/nodejs-22-minimal:9.8-1788225630
#   @sha256:afb61551cc2872c2c6ad54b610a3cf05372404c0ac8e2c9d1ab9627242b1d15d
# `registry.access.redhat.com` is Red Hat's unauthenticated public mirror of
# the UBI images (no `docker login` needed), matching CH-29 zero-egress-secret
# builds; `registry.redhat.io` (auth-gated) is an equally valid alternative.
#
# A non-UBI build (local dev, or any channel outside the IBM/OpenShift
# Marketplace listing) stays possible via `--build-arg
# BASE_IMAGE=node:${NODE_VERSION}-bookworm-slim` — the package-manager RUN
# below detects and supports both bases.
ARG NODE_VERSION=22.13.0
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/nodejs-22-minimal:9.8-1788225630@sha256:afb61551cc2872c2c6ad54b610a3cf05372404c0ac8e2c9d1ab9627242b1d15d

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 — production dependencies only
# ──────────────────────────────────────────────────────────────────────────────
# DL3006 ignored: BASE_IMAGE's ARG default is version-pinned (registry.access.redhat.com UBI9 image@digest, or node:<ver>-bookworm-slim under override).
# hadolint ignore=DL3006
FROM ${BASE_IMAGE} AS deps

# The UBI9 nodejs-22-minimal image's OWN final layer already declares
# `USER 1001` (non-root, per Red Hat's sclorg s2i-nodejs-container build,
# verified live 2026-09-03: `USER 1001` in 22-minimal/Dockerfile.rhel9, no
# named "node" user — numeric UID only). WORKDIR below would otherwise try to
# `mkdir /app` as that unprivileged, non-root-owned UID and fail closed with
# permission denied; `npm ci` needs root to write /app regardless. Reclaim
# root for this build-only stage — its layers are discarded by the multi-stage
# COPY --from in Stage 2, so this never ships root into the final image. A
# no-op under the Debian override, whose default user is already root here.
USER 0

WORKDIR /app

# Lockfile-pinned, reproducible install. `--ignore-scripts` blocks any package
# lifecycle script from running during image build (supply-chain hardening).
# `--omit=optional` skips the per-platform `@epicai/chariot-bin-*` packages: the
# native addon is delivered by COPY in the runtime stage and resolved via
# `../../native/chariot-native.node`, so the optional platform packages are not
# needed and only bloat the image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional --ignore-scripts \
 && npm cache clean --force

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime image
# ──────────────────────────────────────────────────────────────────────────────
# DL3006 ignored: BASE_IMAGE's ARG default is version-pinned (registry.access.redhat.com UBI9 image@digest, or node:<ver>-bookworm-slim under override).
# hadolint ignore=DL3006
FROM ${BASE_IMAGE} AS runtime

# Reclaim root for this stage's own setup (package install, COPY, chown) — see
# the Stage 1 comment above for why the UBI9 base leaves us at non-root
# `USER 1001` by default. This stage's *final* USER (below, after the chown
# block) is what actually ships in the image; this early USER 0 does not.
USER 0

# Image version is the package version; the release tag is `chariot-v${version}`
# (CH-26, emitted by `scripts/release.mjs --emit-image-tag`).
ARG CHARIOT_VERSION=0.0.0-dev
# Red Hat container-certification "release" label: increments on a rebuild of
# the SAME CHARIOT_VERSION (e.g. a base-image CVE respin) — distinct from the
# semantic version, which only moves on an actual product release. Defaults to
# 1 for a version's first build; the release pipeline overrides it on a
# same-version respin.
ARG CHARIOT_RELEASE=1

# LABEL block carries both label vocabularies over the same values, no
# aliasing: the `org.opencontainers.image.*` keys are the existing OCI
# annotations (unchanged); the unprefixed keys below are what Red Hat's
# container-certification policy guide requires verbatim: "Container images
# must include the following labels: name, maintainer, vendor, version,
# release, summary, description." `name`/`maintainer`/`vendor` are ours
# (protectNIL / Epic AI®), not a Red Hat trademark, satisfying the adjacent
# "must not begin with a Red Hat trademark" clause.
LABEL org.opencontainers.image.title="epic-ai-chariot-gateway" \
      org.opencontainers.image.description="Epic AI® Chariot IVA MCP Gateway — embedded hybrid retrieval (Qdrant Edge), enterprise IAM/RBAC/vault." \
      org.opencontainers.image.vendor="protectNIL Inc." \
      org.opencontainers.image.licenses="SEE LICENSE IN LICENSE-ELASTIC" \
      org.opencontainers.image.source="https://github.com/protectnil/epic-ai-chariot" \
      org.opencontainers.image.version="${CHARIOT_VERSION}" \
      name="epic-ai-chariot-gateway" \
      maintainer="protectNIL Inc. <support@protectnil.com>" \
      vendor="protectNIL Inc." \
      version="${CHARIOT_VERSION}" \
      release="${CHARIOT_RELEASE}" \
      summary="Epic AI® Chariot IVA MCP Gateway" \
      description="Epic AI® Chariot IVA MCP Gateway — embedded hybrid retrieval (Qdrant Edge), enterprise IAM/RBAC/vault."

# Runtime libraries the ONNX runtime / fastembed-rs path depends on (libgomp =
# OpenMP; package is `libgomp1` on Debian, `libgomp` on RHEL/UBI9 — same
# shared object). `ca-certificates` is included for TLS to in-cluster
# MongoDB/Redis; it pulls nothing at runtime (air-gap-safe — §2.3/CH-29).
# Detects the base image's own package manager so the Debian override (see
# the BASE_IMAGE ARG comment above) keeps working unchanged: `microdnf` on the
# UBI9 default, `apt-get` under `--build-arg BASE_IMAGE=node:...-bookworm-slim`.
# Recommends/docs are disabled and package caches are removed to keep the
# layer minimal on either path.
# hadolint ignore=DL3008
RUN set -eu; \
    if command -v microdnf >/dev/null 2>&1; then \
      microdnf install -y --nodocs --setopt=install_weak_deps=0 libgomp ca-certificates \
      && microdnf clean all; \
    elif command -v apt-get >/dev/null 2>&1; then \
      apt-get update \
      && apt-get install -y --no-install-recommends libgomp1 ca-certificates \
      && rm -rf /var/lib/apt/lists/*; \
    else \
      echo "no supported package manager (microdnf/apt-get) found in BASE_IMAGE" >&2; exit 1; \
    fi

ENV NODE_ENV=production \
    # All runtime writers (license cache, recovery store, Edge shard, health
    # file) target this directory (CH-30). It is a mounted writable volume in
    # k8s/ECS so the root filesystem can stay read-only.
    EPIC_AI_DIR_OVERRIDE=/var/lib/chariot \
    # Gateway listens on the §-default port (DEFAULT_GATEWAY_CONFIG.port = 8000).
    PORT=8000 \
    # `ort`'s `load-dynamic` feature dlopens the BARE name
    # `libonnxruntime.so`, which the linker resolves only from
    # LD_LIBRARY_PATH, the fixed /lib + /usr/lib set, or a directory
    # registered via /etc/ld.so.conf.d. This image ships the runtime to
    # /app/artifacts/onnxruntime (the COPY below), which is NONE of those, and
    # set no ORT_DYLIB_PATH — so the encoder's pre-flight guard correctly
    # refused to load and the SPLADE/dense legs could not start in the
    # container even though the library was present in the image. Naming the
    # file explicitly is the resolution `ort` checks FIRST
    # (native/src/ort_dylib.rs), so it needs no ldconfig run at build time and
    # no writable /etc at runtime (the root FS is read-only, CH-30).
    ORT_DYLIB_PATH=/app/artifacts/onnxruntime/libonnxruntime.so \
    # The SPLADE query encoder is COPYed into this image (below) but nothing
    # named its location, and ChariotState's `loadSparseEncoder()` reads
    # CHARIOT_SPLADE_MODEL_DIR — unset — so it returned null and the sparse leg
    # was off in every shipped deployment. Same defect shape as the ONNX dylib
    # above: the asset ships, no variable points at it. The path mirrors the
    # `COPY ${SPLADE_DIR}/ ./artifacts/models/splade/` destination below; an
    # operator overriding SPLADE_DIR at build time must override this too.
    CHARIOT_SPLADE_MODEL_DIR=/app/artifacts/models/splade \
    # Taken from the pinned model's OWN config.json
    # (`max_position_embeddings: 512`), never guessed —
    # `loadSparseEncoder()` refuses to run at a width it cannot justify, and a
    # width that disagrees with the export silently changes embeddings.
    CHARIOT_SPLADE_MAX_LENGTH=512 \
    # BIEN::§9::10 — the document-side BIEN dense encoder is COPYed into this
    # image at ${BIEN_DIR} (below) but nothing named its location without
    # this, and ChariotState's `loadDenseEncoder()` reads
    # CHARIOT_DENSE_MODEL_DIR — unset — so the dense leg (and the on-device
    # overlay doc-embedding path this node requires) could not start even
    # though the artifact ships. Same defect shape CHARIOT_SPLADE_MODEL_DIR
    # closes above. The path mirrors the `COPY ${BIEN_DIR}/
    # ./artifacts/models/bien/` destination below; an operator overriding
    # BIEN_DIR at build time must override this too.
    #
    # CHARIOT_DENSE_MAX_LENGTH is taken from the pinned model's OWN export
    # config, the same way SPLADE's 512 is above — read directly from the
    # bien-m8-export artifact's tokenizer_config.json
    # (`max_length`/`model_max_length`: 2048) and config.json
    # (`max_position_embeddings`: 2048); both agree. rulings item 94
    # (BIEN-U1) corrects the prior "no verified pin exists yet" note: the
    # doc-side freeze-pipeline codebase already exists and
    # landed 2026-07-30 — the BIEN §9 "presently UNBUILT" language
    # predates it and is stale for the SPLADE doc-side leg it describes
    # (see the BIEN SPEC.md:75 spec-edit proposal, rulings item 94
    # report). The dense leg's OWN export (`bien-m8-export`, hash-pinned
    # `export_metadata.json`) independently already exists and matches
    # this image's compiled contract (`VectorIndexVerifier.ts`
    # `DEFAULT_RETRIEVAL_CONTRACT`) by model id, version, and dims.
    CHARIOT_DENSE_MAX_LENGTH=2048 \
    # CHARIOT_DENSE_POOLING=mean, pinned per rulings item 108
    # (verification round 2, 2026-09-04 17:05 — src/engine/retrieval/
    # denseEncoder.pooling-mode.test.ts run against the canonical
    # bien-m8-export artifact): BOTH 'mean' and 'cls' produced a unit-norm
    # 768-d vector for the same fixed input
    # ({"mean":{"passed":true,"dims":768},"cls":{"passed":true,"dims":768}}),
    # because the BIEN export step (`export_to_onnx`) already bakes
    # mean-pooling + L2-normalization into the ONNX graph itself — the
    # graph output IS the final embedding, so fastembed-rs's OWN pooling
    # mode has nothing left to pool over and is INERT on this export, not
    # a live double-pool hazard. 'mean' is pinned (not an arbitrary choice
    # between two equally-inert options) because it also matches the
    # export's actual baked-in algorithm. The regression test now asserts
    # BOTH modes stay unit-norm AND numerically IDENTICAL (max abs diff
    # <= 1e-6) — a future non-pre-pooled export would make the two modes
    # DIVERGE while both still individually pass the unit-norm check,
    # which `validate_dense_vector` alone cannot detect; that divergence,
    # not a thrown error, is what would re-open this as a live hazard.
    CHARIOT_DENSE_POOLING=mean \
    CHARIOT_DENSE_MODEL_DIR=/app/artifacts/models/bien \
    # CHARIOT_RERANKER_DIR mirrors CHARIOT_SPLADE_MODEL_DIR /
    # CHARIOT_DENSE_MODEL_DIR above: the Tier-1 reranker artifact is
    # COPYed into this image at ${RERANKER_DIR} (below) but nothing named
    # its location before this, so ChariotState.ts's loadRerankScorer()
    # (which already reads CHARIOT_RERANKER_DIR, fail-closed) could never
    # find it even though the artifact ships once RERANKER_DIR is staged.
    # CHARIOT-SPEC.md §23.2's runtime-load acceptance test (a)-(d)
    # requires this directory to resolve; it cannot without this
    # variable. rulings item 94 (BIEN-U2).
    CHARIOT_RERANKER_DIR=/app/artifacts/models/reranker \
    # CHARIOT-SPEC.md §23.2 "Reranker delivery contract": the image "SHALL
    # set CHARIOT_RERANKER_MAX_LENGTH to the maximum sequence length of the
    # exported reranker", "sourced from the artifact's own configuration,
    # never assumed". ChariotState.ts loadRerankScorer() reads it through
    # requiredPositiveIntEnv() and DISABLES the rerank stage when it is
    # unset, so without this line the reranker COPYed below ships inert.
    # 512 is read from the pinned cross-encoder/ms-marco-MiniLM-L6-v2 export
    # itself: tokenizer_config.json `model_max_length: 512` and config.json
    # `max_position_embeddings: 512` (both files agree). The native
    # CrossEncoderScorer::load uses it as the tokenizer truncation length
    # and requires it to match the export (native/src/reranker.rs).
    CHARIOT_RERANKER_MAX_LENGTH=512 \
    # CHARIOT::§5.7 sealed path switch. ChariotState.ts selects the sealed
    # unseal -> unpack -> load path ONLY when
    # CHARIOT_EDGE_SEALED_SHARD_DESCRIPTOR_PATH (sealedShardConfig.ts
    # SEALED_SHARD_DESCRIPTOR_ENV) is set; when unset it falls back to the
    # plaintext dev-dir branch and the sealed descriptor COPYed to
    # ./artifacts/edgeshard/catalog.edgeshard.sealed (below) is never read.
    # Same defect shape as the model-dir variables above: the asset ships,
    # no variable points at it. The path mirrors the `COPY
    # ${EDGESHARD_SNAPSHOT} ./artifacts/edgeshard/catalog.edgeshard.sealed`
    # destination below; an operator overriding EDGESHARD_SNAPSHOT at build
    # time does not change the in-image destination, so this value stays
    # valid. Setting it makes the deployment DECLARE a sealed install, so a
    # missing/invalid descriptor fails closed (no plaintext fallback).
    CHARIOT_EDGE_SEALED_SHARD_DESCRIPTOR_PATH=/app/artifacts/edgeshard/catalog.edgeshard.sealed

WORKDIR /app

# Production node_modules from the deps stage.
COPY --from=deps /app/node_modules ./node_modules

# Compiled application + package manifest. `package.json` is required at runtime
# for native-binary integrity version checks (src/license/binding.ts).
COPY dist/ ./dist/
COPY package.json ./package.json

# Native addon (embedded Qdrant Edge + fastembed-rs, P3) and its signed integrity
# manifest, placed where the loader resolves them: `../../native/...` from
# `dist/license/binding.js` (src/license/binding.ts:149,300).
#
# BIEN::§9::11 — this COPY is what ships the document-side hashed
# `serialize_tool` serializer: it is compiled into this same addon
# (native/src/bien_serializer.rs `napi_serialize_tool`, `mod bien_serializer`
# in native/src/lib.rs), not a separate on-disk artifact, so shipping
# chariot-native.node here satisfies the node without an extra COPY.
ARG NATIVE_DIR=native
COPY ${NATIVE_DIR}/chariot-native.node ./native/chariot-native.node
COPY ${NATIVE_DIR}/integrity.json ./native/integrity.json

# Signed catalog + registry artifacts (P5). Listed in package.json#files and
# resolved at gateway boot by src/catalog/artifacts.ts.
COPY chariot-adapter-bundle.json chariot-adapter-bundle.json.sig ./
COPY chariot-adapter-catalog.json chariot-adapter-catalog.json.sig ./
COPY chariot-current.json ./

# Sealed/signed EdgeShard snapshot + SPLADE query/document-encoder + BIEN
# dense document-encoder + ONNX runtime (P3/P5). Parameterized so the
# integration build points them at real outputs. They are bundled INTO the
# image so install/runtime needs zero external egress (CH-29).
#
# BIEN_DIR ships the document-side BIEN dense encoder (BIEN::§9::10) so the
# runtime can embed newly customer-verified tools on-device into the
# per-tenant overlay EdgeShard (BIEN §9 "Progressive-auth overlay"; AS §1.2a /
# CHARIOT §8.6a). It ships ALONGSIDE SPLADE_DIR (BIEN::§9::12) — neither
# replaces the other.
# RERANKER_DIR ships the Tier-1 cross-encoder reranker (CHARIOT-SPEC.md
# §23.2 "Reranker delivery contract", AMENDED 2026-08-09, MASTER chat
# authorization) — model.onnx, tokenizer.json, config.json,
# special_tokens_map.json, tokenizer_config.json under one directory,
# identity-locked to cross-encoder/ms-marco-MiniLM-L6-v2
# (ChariotState.ts SHIPPED_RERANKER_MODEL / assertShippedRerankerModel,
# which aborts startup on any other value rather than degrading
# quietly). This COPY line and the ENV above (rulings item 94, BIEN-U2)
# close the exact gap release-plan item 3.2 named: the runtime loader
# already existed and was already fail-closed; only the build-context
# staging was missing.
ARG EDGESHARD_SNAPSHOT=artifacts/edgeshard/catalog.edgeshard.sealed
# CHARIOT §5.7 envelope fields (AMENDED 2026-10-14): the descriptor names its
# ciphertext as a file reference ({ "file": "<basename>", "sha256": … })
# resolved in the descriptor's own directory, so the ciphertext file is
# copied beside it under the fixed in-image name the producer writes
# (`<descriptor basename>.ciphertext`). A real shard exceeds V8's maximum
# string length and cannot ride inline in the descriptor.
ARG EDGESHARD_SNAPSHOT_CIPHERTEXT=${EDGESHARD_SNAPSHOT}.ciphertext
ARG SPLADE_DIR=artifacts/models/splade
ARG BIEN_DIR=artifacts/models/bien
ARG ONNXRUNTIME_DIR=artifacts/onnxruntime
ARG RERANKER_DIR=artifacts/models/reranker
COPY ${EDGESHARD_SNAPSHOT} ./artifacts/edgeshard/catalog.edgeshard.sealed
COPY ${EDGESHARD_SNAPSHOT_CIPHERTEXT} ./artifacts/edgeshard/catalog.edgeshard.sealed.ciphertext
COPY ${SPLADE_DIR}/ ./artifacts/models/splade/
COPY ${BIEN_DIR}/ ./artifacts/models/bien/
COPY ${ONNXRUNTIME_DIR}/ ./artifacts/onnxruntime/
COPY ${RERANKER_DIR}/ ./artifacts/models/reranker/

# Red Hat / OpenShift container-certification requirement: a certified image
# must carry a /licenses directory at its root containing the licence terms
# that govern the image (this project's own terms plus its third-party
# dependency notices). THIRD-PARTY-NOTICES.md is generated by
# scripts/generate-third-party-notices.mjs and its freshness is enforced by
# the release pipeline before this Dockerfile is ever built (release.yml).
COPY LICENSE-ELASTIC THIRD-PARTY-NOTICES.md /licenses/

# Create the writable runtime dir and hand /app + /licenses + the volume to
# the unprivileged uid/gid 1000. Chowned NUMERICALLY, not by the name `node`:
# the official Debian node image defines a `node` user at uid/gid 1000, but
# the UBI9 nodejs-22-minimal base (verified live 2026-09-03, sclorg
# 22-minimal/Dockerfile.rhel9) defines NO named user at all — only a numeric
# `USER 1001` — so `chown node:node` would fail closed on that base with
# "invalid user". The numeric form works identically on both bases and is not
# tied to either image's own default UID (1000 here is our OWN choice, kept
# stable across the base-image swap so nothing downstream — the podSpec
# comments, the OpenShift SCC notes below — has to change).
# At runtime the root FS is mounted read-only (CH-30); only
# ${EPIC_AI_DIR_OVERRIDE} is writable.
#
# ARBITRARY-UID COMPATIBILITY (OpenShift restricted-v2). OpenShift's default SCC
# uses the MustRunAsRange strategy: it injects a per-namespace UID from the
# project's openshift.io/sa.scc.uid-range annotation (ranges look like
# 1000680000-1000689999), overriding this USER. It does NOT change the group --
# the process always gets supplemental GID 0. So `chown 1000:1000` alone leaves
# an injected UID unable to write /app or the runtime dir, and the gateway
# fails on a read-only root FS with nowhere to write.
#
# Group-0 ownership plus group-write is the standard remedy: any injected UID is
# in group 0 and can therefore write. The setgid bit on directories keeps files
# created at runtime in group 0, so a later restart under a DIFFERENT injected
# UID still has access. This grants no privilege on non-OpenShift runtimes --
# uid 1000 is already the owner there and the group is its own.
RUN mkdir -p "${EPIC_AI_DIR_OVERRIDE}" \
 && chown -R 1000:1000 /app /licenses "${EPIC_AI_DIR_OVERRIDE}" \
 && chgrp -R 0 /app /licenses "${EPIC_AI_DIR_OVERRIDE}" \
 && chmod -R g+rwX /app /licenses "${EPIC_AI_DIR_OVERRIDE}" \
 && find /app /licenses "${EPIC_AI_DIR_OVERRIDE}" -type d -exec chmod g+s {} +

# Drop root (CH-30). Numeric form so k8s `runAsNonRoot` can assert uid != 0.
#
# KEEP this USER even though OpenShift overrides it. Red Hat's guidance is to
# declare a non-root USER in the image and NOT pin runAsUser in the manifest:
# with no USER and runAsNonRoot=true, admission rejects the pod with "container
# has runAsNonRoot and image will run as root". This directive is what satisfies
# runAsNonRoot on vanilla Kubernetes while leaving OpenShift free to inject.
USER 1000:1000

EXPOSE 8000

VOLUME ["/var/lib/chariot"]

# Liveness: the gateway serves GET /health (src/engine/gateway/InferenceGateway.ts:167).
# Uses node's built-in http client so the image needs no curl/wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "require('node:http').get({host:'127.0.0.1',port:process.env.PORT||8000,path:'/health',timeout:4000},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1)).on('timeout',function(){this.destroy();process.exit(1)})"

# package.json#bin: chariot-gateway -> dist/bin/gateway.js
ENTRYPOINT ["node", "dist/bin/gateway.js"]
