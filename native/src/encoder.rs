// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// Phase 3.2 (encoder) — in-process fastembed-rs encoder compiled into
// chariot-native.node.
//
// CHARIOT-SPEC §8.6 step 2: the 768-d BIEN dense encoder is loaded via
// fastembed's custom-model path (`TextEmbedding::try_new_from_user_defined`)
// from user-supplied ONNX + tokenizer bytes. Qdrant Edge contains NO embedding
// model — this encoder produces the dense vectors the EdgeShard indexes/queries.
//
// AIR-GAP (CH-29/CH-30): the model is passed in as bytes — never fetched from
// the HuggingFace hub. The crate is built with `default-features = false` so
// the hf-hub download path is not compiled, and ONNX Runtime is provided via
// `ort/load-dynamic` (the container ships libonnxruntime; no build-time binary
// download). Zero external egress.
//
// ── SPLADE (sparse) — implemented in `splade.rs`, NOT here ──
// fastembed 5.17.2's `SparseTextEmbedding` has no `try_new_from_user_defined`
// (verified in crate source: that path exists only for TextEmbedding /
// ImageEmbedding / Bgem3Embedding / TextRerank; `UserDefinedSparseModel` is
// defined but consumed by no method), and its only constructor `try_new`
// downloads from the HF hub — so an air-gapped custom-model SPLADE load is
// impossible *via fastembed*. Option (b) was chosen:
// drive Splade_PP_en_v1 directly through the already-linked `ort` + `tokenizers`
// crates (zero new tree crates), replicating fastembed's `post_process_splade`
// under a strict doc-side/query-side lockstep contract. That lives in
// `splade.rs` (SpladeEncoder + the `splade_post_process` parity primitive). This
// dense module owns only the dense leg.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use fastembed::{
    InitOptionsUserDefined, Pooling, TextEmbedding, TokenizerFiles, UserDefinedEmbeddingModel,
};

/// The four tokenizer files fastembed needs, as raw bytes (from the signed
/// bundle, never the network). Mirrors `fastembed::TokenizerFiles`.
#[napi(object)]
pub struct TokenizerFilesInput {
    pub tokenizer_file: Buffer,
    pub config_file: Buffer,
    pub special_tokens_map_file: Buffer,
    pub tokenizer_config_file: Buffer,
}

impl From<TokenizerFilesInput> for TokenizerFiles {
    fn from(t: TokenizerFilesInput) -> Self {
        TokenizerFiles {
            tokenizer_file: t.tokenizer_file.to_vec(),
            config_file: t.config_file.to_vec(),
            special_tokens_map_file: t.special_tokens_map_file.to_vec(),
            tokenizer_config_file: t.tokenizer_config_file.to_vec(),
        }
    }
}

fn map_err<E: std::fmt::Display>(e: E) -> Error {
    Error::from_reason(e.to_string())
}

/// The shipping dense width. `CHARIOT-SPEC.md:445` pins
/// `| encoder.denseDims | number | 768 | Shipping dense dimension |` as a
/// CONSTANT, not an operator knob, and CH-21 (`CHARIOT-SPEC.md:264`) makes the
/// verifier "fail closed on any mismatch" against the compiled-in contract.
/// It is hardcoded here for the same reason `VectorIndexVerifier.ts:117`
/// hardcodes it: a configurable width could be configured away, which defeats
/// the invariant it exists to hold.
const SHIPPING_DIMENSIONS: usize = 768;

/// L2-norm tolerance. §17 bakes mean-pooling + L2 into the exported ONNX graph,
/// so a conforming graph returns unit vectors; this absorbs f32 rounding only.
const L2_TOLERANCE: f64 = 1e-3;

/// Fail-closed validation of one emitted dense vector.
///
/// CH-21 makes `VectorIndexVerifier` reject a MANIFEST whose `encoder.denseDims`
/// is not 768, and that check already exists (`VectorIndexVerifier.ts:242-245`).
/// This is the other half, which did not: the manifest is a CLAIM about the
/// model, and nothing verified the model honoured it. A bundle stamped
/// `denseDims: 768` shipping a 384-d ONNX graph passed the manifest gate and
/// then silently produced vectors in a different space from the freeze side —
/// no error, just wrong retrieval, exactly the silent-corruption class CH-21
/// exists to prevent. BIEN §15::21 forbids mixing 384-d and 768-d artifacts.
///
/// Ported from `bien_encoder.rs::embed_serialized`, which carries these same
/// three checks but is NOT in the module tree (`lib.rs` declares `encoder`,
/// never `bien_encoder`), so none of it has ever been compiled.
///
/// WHY THIS IS A RUNTIME CHECK AND NOT A LOAD-TIME ONE. `CHARIOT-SPEC.md:316`
/// blocks startup when the "Encoder artifact missing or fails to LOAD
/// (startup)" — a wrong-width ONNX graph LOADS cleanly, so that row does not
/// apply to it. The row that does is `:317`: "Dense or sparse search throws
/// during select() (RUNTIME, on a successfully-loaded bundle) | BM25 results
/// returned alone, capped at maxTools/maxPerServer | WARN per query". Throwing
/// from `embed()` is therefore the SPECIFIED behaviour, and `HybridRetriever`
/// already catches it and degrades the dense leg to BM25. Do not "fix" this by
/// adding a probe inference at load time: that would move the failure into a
/// row the spec assigns different semantics, and cost a forward pass on every
/// startup.
///
/// The norm is accumulated in f32, matching `bien_encoder.rs:118-122` exactly.
/// An earlier draft used f64 for precision; that was reverted under review as a
/// LOCKSTEP HAZARD — if a freeze-side producer accepts on an f32-accumulated
/// norm and this consumer rejects on an f64 one, a vector within the rounding
/// delta of the tolerance is accepted by one side and rejected by the other.
/// The two sides must decide identically, so the algorithm is pinned to the
/// ported one. Changing it requires changing both sides together.
fn validate_dense_vector(vector: Vec<f32>) -> Result<Vec<f64>> {
    if vector.len() != SHIPPING_DIMENSIONS {
        return Err(Error::from_reason(format!(
            "dense model emitted {} dimensions; the shipping contract is \
             {SHIPPING_DIMENSIONS} (CHARIOT-SPEC 5.6 encoder.denseDims / CH-21). \
             A model whose width disagrees with the manifest produces vectors in \
             a different space from the freeze side and MUST NOT be used.",
            vector.len()
        )));
    }
    if let Some(bad) = vector.iter().position(|value| !value.is_finite()) {
        return Err(Error::from_reason(format!(
            "dense model emitted a non-finite value at index {bad}; refusing to \
             index or query on NaN/Inf"
        )));
    }
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if (f64::from(norm) - 1.0).abs() > L2_TOLERANCE {
        return Err(Error::from_reason(format!(
            "dense model output is not L2-normalized: norm={norm}. \
             17 bakes mean-pooling + L2 into the exported graph, so a non-unit \
             norm means the wrong pooling mode or the wrong export — either way \
             the vector space does not match the freeze side."
        )));
    }
    Ok(vector.into_iter().map(f64::from).collect())
}

/// In-process dense text encoder (the fine-tuned BIEN 768-d model).
#[napi]
pub struct DenseEncoder {
    inner: TextEmbedding,
}

#[napi]
impl DenseEncoder {
    /// Load a dense encoder from user-supplied ONNX + tokenizer bytes (the BIEN
    /// model). `mean_pool=true` selects mean pooling; `max_length` is the
    /// tokenizer truncation length. CPU execution providers only (deterministic,
    /// air-gapped). No hub access.
    #[napi(factory)]
    pub fn load(
        onnx_file: Buffer,
        tokenizer_files: TokenizerFilesInput,
        mean_pool: bool,
        max_length: u32,
    ) -> Result<Self> {
        // Fail-fast guard (see native/src/ort_dylib.rs for the strace-proven
        // root cause): fastembed's try_new_from_user_defined below calls
        // into the SAME ort::Session::builder() lazy-dlopen path splade.rs
        // uses, and the bug's own discrimination matrix proved DenseEncoder
        // hangs identically. Refuse to enter that path when the ONNX
        // Runtime dylib isn't resolvable, rather than triggering the hang.
        crate::ort_dylib::ensure_ort_dylib_available().map_err(Error::from_reason)?;
        let pooling = if mean_pool {
            Pooling::Mean
        } else {
            Pooling::Cls
        };
        let model = UserDefinedEmbeddingModel::new(onnx_file.to_vec(), tokenizer_files.into())
            .with_pooling(pooling);
        // Default execution providers = CPU; we do NOT auto-add GPU EPs so the
        // numeric path is stable across hosts (determinism, §8.6 / CH-23).
        //
        // intra_threads=1 is REQUIRED, same rationale as splade.rs: fastembed
        // defaults intra_threads to available_parallelism(), and multi-threaded
        // ORT intra-op reductions partition non-associative f32 accumulations
        // differently across hosts with different core counts / cgroup quotas —
        // bit-different dense vectors flip near-tie RRF ranks, violating the
        // CH-23/§8.6 byte-identical selection contract. Single-threaded →
        // cross-host bit-reproducible. Any doc-side dense publisher MUST pin
        // the same setting (lockstep contract).
        let opts = InitOptionsUserDefined::new()
            .with_max_length(max_length as usize)
            .with_intra_threads(1);
        let inner = TextEmbedding::try_new_from_user_defined(model, opts).map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Embed a batch of texts → one dense `[f64]` per input. The caller
    /// serializes the BIEN `search_document:` / `search_query:` text (via the
    /// native serializer) before passing it here.
    #[napi]
    pub fn embed(&mut self, texts: Vec<String>) -> Result<Vec<Vec<f64>>> {
        // An empty batch is not an error and must not reach the model.
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let out = self.inner.embed(texts, None).map_err(map_err)?;
        // Fail closed on the WHOLE batch if any vector violates the contract:
        // returning the good rows and dropping the bad ones would silently
        // shorten the batch and misalign it with the caller's input order.
        out.into_iter().map(validate_dense_vector).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression coverage for the `ensure_ort_dylib_available()`
    // guard called at the top of `load()` lives in
    // `native/src/ort_dylib.rs::tests` (`rejects_a_nonexistent_explicit_dylib_path`,
    // `accepts_an_existing_explicit_dylib_path`) — NOT here, for the same
    // reason documented in `splade.rs::tests`: constructing a real
    // `Buffer`/`TokenizerFilesInput` and calling this `#[napi(factory)]`
    // `load()` directly pulls N-API runtime glue into the `cargo test --lib`
    // binary that fails to link without a Node.js host process providing
    // those symbols (confirmed by reverting this crate's diff — the
    // unmodified crate's `cargo test --lib` links and passes cleanly).

    /// A unit vector of `n` components, so `sum(c^2) == 1` exactly by
    /// construction for the widths under test.
    fn unit_vector(n: usize) -> Vec<f32> {
        let c = (1.0f64 / (n as f64)).sqrt() as f32;
        vec![c; n]
    }

    #[test]
    fn accepts_a_768d_unit_vector() {
        let v = validate_dense_vector(unit_vector(SHIPPING_DIMENSIONS)).unwrap();
        assert_eq!(v.len(), SHIPPING_DIMENSIONS);
    }

    #[test]
    fn rejects_384_dimensions() {
        // The exact confusion BIEN 15::21 forbids: a 384-d artifact reaching a
        // 768-d shipping path.
        let err = validate_dense_vector(unit_vector(384)).unwrap_err();
        assert!(err.reason.contains("384 dimensions"), "got: {}", err.reason);
        assert!(err.reason.contains("768"), "must name the contract width");
    }

    #[test]
    fn rejects_off_by_one_width() {
        assert!(validate_dense_vector(unit_vector(767)).is_err());
        assert!(validate_dense_vector(unit_vector(769)).is_err());
    }

    #[test]
    fn rejects_an_empty_vector() {
        assert!(validate_dense_vector(Vec::new()).is_err());
    }

    #[test]
    fn rejects_nan_and_infinity() {
        let mut nan = unit_vector(SHIPPING_DIMENSIONS);
        nan[500] = f32::NAN;
        let err = validate_dense_vector(nan).unwrap_err();
        assert!(err.reason.contains("non-finite"), "got: {}", err.reason);
        assert!(err.reason.contains("500"), "must name the offending index");

        let mut inf = unit_vector(SHIPPING_DIMENSIONS);
        inf[0] = f32::INFINITY;
        assert!(validate_dense_vector(inf).is_err());

        let mut neg_inf = unit_vector(SHIPPING_DIMENSIONS);
        neg_inf[767] = f32::NEG_INFINITY;
        assert!(validate_dense_vector(neg_inf).is_err());
    }

    #[test]
    fn rejects_a_non_normalized_vector() {
        // Correct width, finite, but norm == 2 — the signature of a wrong
        // pooling mode or an export without the L2 head.
        let doubled: Vec<f32> = unit_vector(SHIPPING_DIMENSIONS)
            .into_iter()
            .map(|c| c * 2.0)
            .collect();
        let err = validate_dense_vector(doubled).unwrap_err();
        assert!(err.reason.contains("not L2-normalized"), "got: {}", err.reason);
    }

    #[test]
    fn rejects_the_all_zero_vector() {
        // norm == 0: right width, finite, and useless — cosine against it is
        // undefined. Must not slip through as "close enough".
        assert!(validate_dense_vector(vec![0.0f32; SHIPPING_DIMENSIONS]).is_err());
    }

    #[test]
    fn tolerance_boundary_is_enforced_on_both_sides() {
        // Just inside 1e-3 → accepted; clearly outside → rejected. Proves the
        // check is a real bound, not a formality that accepts anything finite.
        let inside: Vec<f32> = unit_vector(SHIPPING_DIMENSIONS)
            .into_iter()
            .map(|c| c * 1.0005)
            .collect();
        assert!(validate_dense_vector(inside).is_ok(), "norm within 1e-3 must pass");

        let outside: Vec<f32> = unit_vector(SHIPPING_DIMENSIONS)
            .into_iter()
            .map(|c| c * 1.01)
            .collect();
        assert!(validate_dense_vector(outside).is_err(), "norm outside 1e-3 must fail");
    }

    #[test]
    fn rejects_an_under_normalized_vector_too() {
        // The tolerance is |norm - 1| > 1e-3, so it must bite BELOW 1.0 as well
        // as above. Testing only the over-normalized side would leave a
        // one-directional guard that passes every shrunken vector — the shape a
        // wrong pooling mode actually tends to produce.
        let under: Vec<f32> = unit_vector(SHIPPING_DIMENSIONS)
            .into_iter()
            .map(|c| c * 0.99)
            .collect();
        let err = validate_dense_vector(under).unwrap_err();
        assert!(err.reason.contains("not L2-normalized"), "got: {}", err.reason);
    }

    #[test]
    fn the_norm_guard_is_independently_proven() {
        // Anti-vacuous companion to the width mutation: a vector of the RIGHT
        // width and entirely finite, failing ONLY on norm. If the norm branch
        // were removed this is the case that would silently pass.
        let right_width_wrong_norm = vec![1.0f32; SHIPPING_DIMENSIONS]; // norm = sqrt(768)
        assert_eq!(right_width_wrong_norm.len(), SHIPPING_DIMENSIONS);
        assert!(right_width_wrong_norm.iter().all(|v| v.is_finite()));
        assert!(validate_dense_vector(right_width_wrong_norm).is_err());
    }

    #[test]
    fn the_finite_guard_is_independently_proven() {
        // Right width, and the NaN is placed so the surviving components would
        // still norm to ~1 if NaN were ignored — so only the explicit
        // non-finite branch can reject this.
        let mut v = unit_vector(SHIPPING_DIMENSIONS);
        v[123] = f32::NAN;
        assert_eq!(v.len(), SHIPPING_DIMENSIONS);
        let err = validate_dense_vector(v).unwrap_err();
        assert!(err.reason.contains("non-finite"), "got: {}", err.reason);
    }
}
