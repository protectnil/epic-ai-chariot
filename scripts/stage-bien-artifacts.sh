#!/usr/bin/env bash
# CH-10-unrelated: BIEN/reranker/SPLADE build-context staging (rulings item 94,
# BIEN-U1/U2). This is a CI/operator step, NOT something the Dockerfile or a
# builder invokes automatically — it copies the pinned, hash-verified
# artifacts a freeze pipeline (or an operator's manual export run) produced
# into the paths the Dockerfile's `SPLADE_DIR` / `BIEN_DIR` / `RERANKER_DIR`
# build args expect, immediately before `docker build`.
#
# CHARIOT-SPEC.md §23.2 "Reranker delivery contract" (AMENDED 2026-08-09,
# MASTER chat authorization): "The chariot-gateway image SHALL contain the
# Tier-1 reranker artifact together with its tokenizer and configuration
# files — model.onnx, tokenizer.json, config.json, special_tokens_map.json,
# tokenizer_config.json — under the single directory
# /app/artifacts/models/reranker/." This script is what stages that
# directory's SOURCE side (before the Dockerfile COPY places it under
# /app/...).
#
# Deliberately takes source directories as ARGUMENTS/ENV VARS, never a
# hardcoded path — this repo is the public mirror and must not name internal
# host paths (repo hygiene: no absolute internal host paths in any file).
#
# Usage:
#   BIEN_SOURCE_DIR=<path-to-the-bien-dense-encoder-export> \
#   SPLADE_SOURCE_DIR=<path-to-the-splade-document-encoder> \
#   RERANKER_SOURCE_DIR=<path-to-the-bien-m10-reranker-export> \
#   ./scripts/stage-bien-artifacts.sh [DEST_ROOT]
#
# DEST_ROOT defaults to the repo root's own `artifacts/` — the Dockerfile's
# ARG defaults (SPLADE_DIR=artifacts/models/splade, BIEN_DIR=artifacts/
# models/bien, RERANKER_DIR=artifacts/models/reranker) are relative to the
# docker build context, which IS this repo root when `docker build .` is run
# from here (release.yml / marketplace-ecr.yml's build step).
#
# Fail-closed: refuses to stage a source directory that is missing any of the
# files the corresponding consumer requires, rather than staging a partial
# directory that would only fail much later at runtime-load-acceptance.
set -euo pipefail

DEST_ROOT="${1:-artifacts}"

require_files() {
  local label="$1" dir="$2"
  shift 2
  if [ -z "${dir}" ]; then
    echo "::error::${label}: source directory not set (expected an env var pointing at it) — refusing to stage a partial artifact set" >&2
    return 1
  fi
  if [ ! -d "${dir}" ]; then
    echo "::error::${label}: source directory does not exist: ${dir}" >&2
    return 1
  fi
  local missing=0
  for f in "$@"; do
    if [ ! -e "${dir}/${f}" ]; then
      echo "::error::${label}: required file missing from ${dir}: ${f}" >&2
      missing=1
    fi
  done
  return "${missing}"
}

stage() {
  local label="$1" src="$2" dest="$3"
  echo "staging ${label}: ${src} -> ${dest}"
  mkdir -p "$(dirname "${dest}")"
  rm -rf "${dest}"
  cp -a "${src}" "${dest}"
}

status=0

# BIEN dense encoder (BIEN::§9::10). The pinned export ships model.onnx
# alongside the tokenizer files — this script does NOT resolve which
# per-width subdirectory (e.g. `dim_768/`) holds the .onnx file; the caller
# points BIEN_SOURCE_DIR at a directory that already has `model.onnx` at its
# top level (i.e., the caller has already resolved the canonical export
# variant and width — see rulings item 94's evidence-based canonicalization
# of `bien-m8-export` over its `-mined`/`-mined-v2` siblings, which lack a
# stamped `export_metadata.json` and so cannot be identity-verified here).
if ! require_files "BIEN dense encoder" "${BIEN_SOURCE_DIR:-}" \
  model.onnx tokenizer.json config.json special_tokens_map.json tokenizer_config.json; then
  status=1
else
  stage "BIEN dense encoder" "${BIEN_SOURCE_DIR}" "${DEST_ROOT}/models/bien"
fi

# SPLADE document encoder (BIEN::§9::12 / CHARIOT §8.6a).
if ! require_files "SPLADE document encoder" "${SPLADE_SOURCE_DIR:-}" \
  model.onnx tokenizer.json config.json special_tokens_map.json tokenizer_config.json; then
  status=1
else
  stage "SPLADE document encoder" "${SPLADE_SOURCE_DIR}" "${DEST_ROOT}/models/splade"
fi

# Tier-1 reranker (CHARIOT-SPEC.md §23.2 "Reranker delivery contract").
if ! require_files "Tier-1 reranker" "${RERANKER_SOURCE_DIR:-}" \
  model.onnx tokenizer.json config.json special_tokens_map.json tokenizer_config.json; then
  status=1
else
  stage "Tier-1 reranker" "${RERANKER_SOURCE_DIR}" "${DEST_ROOT}/models/reranker"
fi

if [ "${status}" -ne 0 ]; then
  echo "::error::stage-bien-artifacts.sh: one or more artifact sets failed the required-file check above — refusing to leave a partially-staged build context" >&2
  exit 1
fi

echo "staged: ${DEST_ROOT}/models/{bien,splade,reranker}"
