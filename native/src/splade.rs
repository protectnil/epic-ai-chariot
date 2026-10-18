// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// Phase 3.2 (SPLADE) — in-process Splade_PP_en_v1 sparse query encoder compiled
// into chariot-native.node. Option (b) was selected: run
// SPLADE through `ort` directly (fastembed 5.17.2 has no user-defined sparse
// load path — SparseTextEmbedding exposes only the HF-hub `try_new`), reusing
// the ort + tokenizers crates already linked transitively via fastembed (ZERO
// new tree crates). The doc-side sparse producer (the catalog build pipeline) emits the frozen
// doc-side artifact under the SAME contract; native owns the query path.
//
// ── LOCKSTEP CONTRACT (doc-side producer MUST equal query-side native, byte-exact) ─
//  - Model pin    : Qdrant/Splade_PP_en_v1 @ efcd182b, whose immutable bytes
//                   are governed through the shared artifact pin under
//                   CHARIOT §5.6; ONNX bytes are passed in here (air-gapped).
//  - Tokenizer pin: exact tokenizer files + revision pinned both sides; loaded
//                   here exactly as fastembed::common::load_tokenizer does
//                   (from_bytes + BatchLongest padding + max_length truncation +
//                   special-tokens-map) so normalization / casing / pre-tokenization
//                   / special-tokens / truncation / padding are identical.
//  - Inference pin: same ONNX bytes, same ORT version/build (=2.0.0-rc.12), CPU
//                   EP only, GraphOptimizationLevel::Level3, and intra_threads=1
//                   (single-threaded → cross-host bit-reproducible; multi-thread
//                   ORT reductions are NOT bit-stable across hosts). The publisher
//                   MUST also pin intra_threads=1.
//  - Activation   : ReLU(logits) then log1p, i.e. ln(1 + max(0, x)) in f32 —
//                   identical to fastembed::post_process_splade.
//  - Pooling      : max over the sequence axis per vocab term, masked positions
//                   excluded (contribution = relu_log * mask, then max). Max is
//                   order-independent, so the result is reduction-order stable.
//  - IDF          : NONE inside SPLADE. BM25 idf is fused only at rank time.
//  - Serialization: canonical sparse vector ordered by ascending token id, fixed
//                   precision (SPLADE_PRECISION decimal places, round-half-to-even
//                   via Rust float formatting), zero-suppressed (>0 after relu,
//                   plus drop any term that rounds to all-zero at that precision).
//  - Parity gate  : `splade_post_process` + the committed golden fixture
//                   (__test__/splade-parity-golden.json) lock the post-process +
//                   serialization here (Rust unit test + Node smoke). The
//                   end-to-end real-model hash-match between the doc-side producer
//                   output and this query path is the RELEASE gate, run once the
//                   pinned model artifact + publisher exist.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::{Outlet, TensorElementType, Value};
use sha2::{Digest, Sha256};
use tokenizers::{AddedToken, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

use crate::encoder::TokenizerFilesInput;
use crate::ort_dylib::ensure_ort_dylib_available;

/// Decimal places for the canonical sparse serialization. Part of the lockstep
/// contract — the doc-side sparse producer MUST round to the same precision.
const SPLADE_PRECISION: usize = 4;

fn map_err<E: std::fmt::Display>(e: E) -> Error {
    Error::from_reason(e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpladeGraphTensor {
    name: String,
    element_type: Option<TensorElementType>,
    rank: Option<usize>,
}

fn graph_signature(outlets: &[Outlet]) -> Vec<SpladeGraphTensor> {
    outlets
        .iter()
        .map(|outlet| SpladeGraphTensor {
            name: outlet.name().to_string(),
            element_type: outlet.dtype().tensor_type(),
            rank: outlet.dtype().tensor_shape().map(|shape| shape.len()),
        })
        .collect()
}

/// Admit only the byte-pinned Qdrant/Splade_PP_en_v1 graph recorded by
/// CHARIOT §5.6 and the shared `splade/artifact-pin.ts` module. Names are not
/// aliases: accepting another export under the same model identity would put
/// the frozen document vectors and runtime query vectors in different spaces.
fn validate_splade_graph_signature(
    inputs: &[SpladeGraphTensor],
    outputs: &[SpladeGraphTensor],
) -> Result<()> {
    let expected_inputs = [
        SpladeGraphTensor {
            name: "input_ids".into(),
            element_type: Some(TensorElementType::Int64),
            rank: Some(2),
        },
        SpladeGraphTensor {
            name: "attention_mask".into(),
            element_type: Some(TensorElementType::Int64),
            rank: Some(2),
        },
        SpladeGraphTensor {
            name: "token_type_ids".into(),
            element_type: Some(TensorElementType::Int64),
            rank: Some(2),
        },
    ];
    let expected_outputs = [SpladeGraphTensor {
        name: "logits".into(),
        element_type: Some(TensorElementType::Float32),
        rank: Some(3),
    }];

    if inputs != expected_inputs || outputs != expected_outputs {
        return Err(Error::from_reason(format!(
            "SPLADE graph signature mismatch; expected inputs {:?} and outputs {:?}, got inputs {:?} and outputs {:?}; refusing non-pinned export",
            expected_inputs, expected_outputs, inputs, outputs
        )));
    }
    Ok(())
}

/// SHA-256 hex of a string (manual hex; no extra crate).
fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pure SPLADE post-process for ONE sequence row. `logits` is the flat
/// `[seq * vocab]` MLM-head output (row-major), `mask` is `[seq]`. Returns
/// `(indices ascending, values)` for terms with score > 0. Mirrors
/// fastembed::post_process_splade exactly: relu_log = ln(1 + max(0,x)); multiply
/// by the attention mask (masked → 0); max over the sequence axis per vocab
/// term; keep strictly-positive terms.
fn splade_post_process_row(
    logits: &[f32],
    seq: usize,
    vocab: usize,
    mask: &[i64],
) -> (Vec<u32>, Vec<f32>) {
    let mut scores = vec![f32::NEG_INFINITY; vocab];
    for p in 0..seq {
        let m = mask[p] as f32;
        let base = p * vocab;
        let row = &logits[base..base + vocab];
        for v in 0..vocab {
            let relu_log = (1.0f32 + row[v].max(0.0)).ln();
            let contrib = relu_log * m;
            if contrib > scores[v] {
                scores[v] = contrib;
            }
        }
    }
    let mut indices = Vec::new();
    let mut values = Vec::new();
    for (v, score) in scores.iter().enumerate() {
        if *score > 0.0 {
            indices.push(v as u32);
            values.push(*score);
        }
    }
    (indices, values)
}

/// Canonicalize a sparse vector once: sort by token id, then drop any term
/// whose rendered value would round to `0.0000` at SPLADE_PRECISION. This is
/// the single support set used by both the returned sparse vector and the hash.
fn canonicalize_sparse(indices: Vec<u32>, values: Vec<f32>) -> (Vec<u32>, Vec<f32>) {
    let mut pairs: Vec<(u32, f32)> = indices.into_iter().zip(values.into_iter()).collect();
    pairs.sort_by_key(|(i, _)| *i);
    let zero = format!("{:.*}", SPLADE_PRECISION, 0.0f32);
    let mut out_indices = Vec::with_capacity(pairs.len());
    let mut out_values = Vec::with_capacity(pairs.len());
    for (i, v) in pairs {
        if format!("{:.*}", SPLADE_PRECISION, v) != zero {
            out_indices.push(i);
            out_values.push(v);
        }
    }
    (out_indices, out_values)
}

/// Canonical serialization of a sparse vector: ascending token id, fixed
/// precision, comma-joined `idx:value`. Inputs are assumed already canonicalized
/// by `canonicalize_sparse()`.
fn canonical_sparse(indices: &[u32], values: &[f32]) -> String {
    let mut toks: Vec<String> = Vec::with_capacity(indices.len());
    for (i, v) in indices.iter().copied().zip(values.iter().copied()) {
        toks.push(format!("{}:{:.*}", i, SPLADE_PRECISION, v));
    }
    toks.join(",")
}

/// A sparse vector returned to JS: parallel `indices` (token ids) and `values`.
#[napi(object)]
#[derive(Debug)]
pub struct NativeSparseVector {
    pub indices: Vec<u32>,
    pub values: Vec<f64>,
}

/// Result of the SPLADE post-process parity helper: the sparse vector plus its
/// canonical serialization and parity SHA-256 (the cross-side verification key).
#[napi(object)]
#[derive(Debug)]
pub struct SpladeParityResult {
    pub indices: Vec<u32>,
    pub values: Vec<f64>,
    pub canonical: String,
    pub sha256: String,
}

/// Run the SPLADE post-process on raw MLM logits and return the canonical sparse
/// vector + parity SHA-256. Pure, deterministic, model-free — this is the parity
/// primitive: the doc-side sparse producer and this query path must produce the same
/// `sha256` for the same logits. `logits` is flat row-major `[seq * vocab]`.
#[napi]
pub fn splade_post_process(
    logits: Vec<f64>,
    seq: u32,
    vocab: u32,
    attention_mask: Vec<i32>,
) -> Result<SpladeParityResult> {
    let s = seq as usize;
    let v = vocab as usize;
    if logits.len() != s * v {
        return Err(Error::from_reason(format!(
            "logits length {} != seq*vocab {}",
            logits.len(),
            s * v
        )));
    }
    if attention_mask.len() != s {
        return Err(Error::from_reason(format!(
            "attention_mask length {} != seq {}",
            attention_mask.len(),
            s
        )));
    }
    let logits_f32: Vec<f32> = logits.iter().map(|x| *x as f32).collect();
    let mask: Vec<i64> = attention_mask.iter().map(|x| *x as i64).collect();
    let (indices, values) = splade_post_process_row(&logits_f32, s, v, &mask);
    let (indices, values) = canonicalize_sparse(indices, values);
    let canonical = canonical_sparse(&indices, &values);
    let sha256 = sha256_hex(&canonical);
    Ok(SpladeParityResult {
        indices,
        values: values.iter().map(|x| *x as f64).collect(),
        canonical,
        sha256,
    })
}

/// In-process SPLADE (Splade_PP_en_v1) sparse query encoder.
#[napi]
pub struct SpladeEncoder {
    tokenizer: Tokenizer,
    session: Session,
}

/// Build the tokenizer from user-supplied bytes, replicating
/// fastembed::common::load_tokenizer (from_bytes + BatchLongest padding +
/// max_length truncation capped by model_max_length + special-tokens-map) so the
/// query path tokenizes byte-identically to a fastembed-based publisher.
fn build_tokenizer(files: &TokenizerFilesInput, max_length: usize) -> Result<Tokenizer> {
    let config: serde_json::Value = serde_json::from_slice(files.config_file.as_ref())
        .map_err(|_| Error::from_reason("invalid config.json"))?;
    let special_tokens_map: serde_json::Value =
        serde_json::from_slice(files.special_tokens_map_file.as_ref())
            .map_err(|_| Error::from_reason("invalid special_tokens_map.json"))?;
    let tokenizer_config: serde_json::Value =
        serde_json::from_slice(files.tokenizer_config_file.as_ref())
            .map_err(|_| Error::from_reason("invalid tokenizer_config.json"))?;
    let mut tokenizer = Tokenizer::from_bytes(files.tokenizer_file.as_ref())
        .map_err(|_| Error::from_reason("invalid tokenizer.json"))?;

    let model_max_length = tokenizer_config["model_max_length"]
        .as_f64()
        .ok_or_else(|| {
            Error::from_reason("tokenizer_config.json missing numeric model_max_length")
        })? as f32;
    let max_length = max_length.min(model_max_length as usize);
    let pad_id = config["pad_token_id"].as_u64().unwrap_or(0) as u32;
    let pad_token: String = tokenizer_config["pad_token"]
        .as_str()
        .ok_or_else(|| Error::from_reason("tokenizer_config.json missing string pad_token"))?
        .into();

    let mut tokenizer = tokenizer
        .with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::BatchLongest,
            pad_token,
            pad_id,
            ..Default::default()
        }))
        .with_truncation(Some(TruncationParams {
            max_length,
            ..Default::default()
        }))
        .map_err(map_err)?
        .clone();

    if let serde_json::Value::Object(root_object) = special_tokens_map {
        for (_, value) in root_object.iter() {
            if value.is_string() {
                if let Some(content) = value.as_str() {
                    tokenizer.add_special_tokens(&[AddedToken {
                        content: content.into(),
                        special: true,
                        ..Default::default()
                    }]);
                }
            } else if value.is_object() {
                if let (
                    Some(content),
                    Some(single_word),
                    Some(lstrip),
                    Some(rstrip),
                    Some(normalized),
                ) = (
                    value["content"].as_str(),
                    value["single_word"].as_bool(),
                    value["lstrip"].as_bool(),
                    value["rstrip"].as_bool(),
                    value["normalized"].as_bool(),
                ) {
                    tokenizer.add_special_tokens(&[AddedToken {
                        content: content.into(),
                        special: true,
                        single_word,
                        lstrip,
                        rstrip,
                        normalized,
                    }]);
                }
            }
        }
    }
    // `with_padding`/`with_truncation`/`clone` yield a `TokenizerImpl`; `.into()`
    // wraps it back into the public `Tokenizer` (mirrors fastembed::load_tokenizer).
    Ok(tokenizer.into())
}

#[napi]
impl SpladeEncoder {
    /// Load the SPLADE encoder from user-supplied ONNX + tokenizer bytes (the
    /// pinned Splade_PP_en_v1 artifact from the signed bundle). CPU EP only,
    /// single intra-op thread (determinism). No hub access, no network.
    #[napi(factory)]
    pub fn load(
        onnx_file: Buffer,
        tokenizer_files: TokenizerFilesInput,
        max_length: u32,
    ) -> Result<Self> {
        // Fail-fast guard (see native/src/ort_dylib.rs for the strace-proven
        // root cause): if the ONNX Runtime dylib isn't resolvable, refuse to
        // call ort::Session::builder() at all rather than triggering the
        // dlopen-failure deadlock. Must run before build_tokenizer so the
        // guard is exercised independent of tokenizer byte validity.
        ensure_ort_dylib_available().map_err(Error::from_reason)?;
        let tokenizer = build_tokenizer(&tokenizer_files, max_length as usize)?;
        let mut builder = Session::builder()
            .map_err(map_err)?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(map_err)?
            .with_intra_threads(1)
            .map_err(map_err)?;
        let session = builder
            .commit_from_memory(onnx_file.as_ref())
            .map_err(map_err)?;
        validate_splade_graph_signature(
            &graph_signature(session.inputs()),
            &graph_signature(session.outputs()),
        )?;

        Ok(Self { tokenizer, session })
    }

    /// Internal: tokenize → ORT infer → post-process each row.
    fn embed_rows(&mut self, texts: Vec<String>) -> Result<Vec<(Vec<u32>, Vec<f32>)>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let encodings = self
            .tokenizer
            .encode_batch(texts, true)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let batch = encodings.len();
        let seq = encodings.first().map(|e| e.len()).unwrap_or(0);
        if seq == 0 {
            return Ok(vec![(Vec::new(), Vec::new()); batch]);
        }

        let mut ids = Vec::with_capacity(batch * seq);
        let mut mask = Vec::with_capacity(batch * seq);
        let mut type_ids = Vec::with_capacity(batch * seq);
        for enc in &encodings {
            ids.extend(enc.get_ids().iter().map(|x| *x as i64));
            mask.extend(enc.get_attention_mask().iter().map(|x| *x as i64));
            type_ids.extend(enc.get_type_ids().iter().map(|x| *x as i64));
        }

        let inputs = ort::inputs![
            "input_ids" => Value::from_array(([batch, seq], ids.clone())).map_err(map_err)?,
            "attention_mask" => Value::from_array(([batch, seq], mask.clone())).map_err(map_err)?,
            "token_type_ids" => Value::from_array(([batch, seq], type_ids)).map_err(map_err)?,
        ];

        let outputs = self.session.run(inputs).map_err(map_err)?;
        // The exact output name and rank were admitted before this encoder was
        // constructed; there is no fallback to another tensor or export.
        let (shape, data) = outputs["logits"]
            .try_extract_tensor::<f32>()
            .map_err(map_err)?;
        let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
        if dims.len() != 3 {
            return Err(Error::from_reason(format!(
                "expected [batch, seq, vocab] logits, got {:?}",
                dims
            )));
        }
        let (out_batch, out_seq, vocab) = (dims[0], dims[1], dims[2]);
        if out_batch != batch || out_seq != seq {
            return Err(Error::from_reason(format!(
                "model output [{}, {}, _] mismatches input [{}, {}, _]",
                out_batch, out_seq, batch, seq
            )));
        }

        let mut result = Vec::with_capacity(batch);
        for b in 0..batch {
            let row_logits = &data[b * seq * vocab..(b + 1) * seq * vocab];
            let row_mask = &mask[b * seq..(b + 1) * seq];
            let (raw_idx, raw_val) = splade_post_process_row(row_logits, seq, vocab, row_mask);
            // Canonicalize immediately: both `embed()` and `canonical_hash()`
            // derive from this same filtered support set, ensuring byte parity.
            result.push(canonicalize_sparse(raw_idx, raw_val));
        }
        Ok(result)
    }

    /// Embed a batch of texts → one sparse vector per input. The caller passes
    /// the canonical query text (BIEN `search_query:` serialization).
    #[napi]
    pub fn embed(&mut self, texts: Vec<String>) -> Result<Vec<NativeSparseVector>> {
        let rows = self.embed_rows(texts)?;
        Ok(rows
            .into_iter()
            .map(|(indices, values)| NativeSparseVector {
                indices,
                values: values.iter().map(|x| *x as f64).collect(),
            })
            .collect())
    }

    /// Canonical parity SHA-256 for one query — the cross-side verification key
    /// (the doc-side sparse producer must reproduce this for the same input + pinned model).
    #[napi]
    pub fn canonical_hash(&mut self, text: String) -> Result<String> {
        let mut rows = self.embed_rows(vec![text])?;
        let (indices, values) = rows.pop().unwrap_or((Vec::new(), Vec::new()));
        Ok(sha256_hex(&canonical_sparse(&indices, &values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tensor(name: &str, element_type: TensorElementType, rank: usize) -> SpladeGraphTensor {
        SpladeGraphTensor {
            name: name.into(),
            element_type: Some(element_type),
            rank: Some(rank),
        }
    }

    fn pinned_inputs() -> Vec<SpladeGraphTensor> {
        vec![
            tensor("input_ids", TensorElementType::Int64, 2),
            tensor("attention_mask", TensorElementType::Int64, 2),
            tensor("token_type_ids", TensorElementType::Int64, 2),
        ]
    }

    fn pinned_outputs() -> Vec<SpladeGraphTensor> {
        vec![tensor("logits", TensorElementType::Float32, 3)]
    }

    #[test]
    fn governed_splade_graph_signature_is_admitted() {
        validate_splade_graph_signature(&pinned_inputs(), &pinned_outputs()).unwrap();
    }

    #[test]
    fn splade_graph_rejects_the_ungoverned_0934583a_names() {
        let aliases = vec![
            tensor("input_ids", TensorElementType::Int64, 2),
            tensor("input_mask", TensorElementType::Int64, 2),
            tensor("segment_ids", TensorElementType::Int64, 2),
        ];
        assert!(validate_splade_graph_signature(&aliases, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_attention_mask_alias_alone() {
        let mut aliases = pinned_inputs();
        aliases[1].name = "input_mask".into();
        assert!(validate_splade_graph_signature(&aliases, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_missing_input() {
        let mut missing = pinned_inputs();
        missing.pop();
        assert!(validate_splade_graph_signature(&missing, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_extra_input() {
        let mut extra = pinned_inputs();
        extra.push(tensor("unexpected", TensorElementType::Int64, 2));
        assert!(validate_splade_graph_signature(&extra, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_reordered_inputs() {
        let mut reordered = pinned_inputs();
        reordered.swap(0, 1);
        assert!(validate_splade_graph_signature(&reordered, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_duplicate_input() {
        let mut duplicate = pinned_inputs();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_splade_graph_signature(&duplicate, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_empty_inputs() {
        assert!(validate_splade_graph_signature(&[], &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_wrong_input_type() {
        let mut wrong_type = pinned_inputs();
        wrong_type[1].element_type = Some(TensorElementType::Int32);
        assert!(validate_splade_graph_signature(&wrong_type, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_wrong_input_rank() {
        let mut wrong_rank = pinned_inputs();
        wrong_rank[1].rank = Some(3);
        assert!(validate_splade_graph_signature(&wrong_rank, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_non_tensor_input() {
        let mut non_tensor = pinned_inputs();
        non_tensor[1].element_type = None;
        non_tensor[1].rank = None;
        assert!(validate_splade_graph_signature(&non_tensor, &pinned_outputs()).is_err());
    }

    #[test]
    fn splade_graph_rejects_wrong_output_name() {
        let wrong_name = vec![tensor("output", TensorElementType::Float32, 3)];
        assert!(validate_splade_graph_signature(&pinned_inputs(), &wrong_name).is_err());
    }

    #[test]
    fn splade_graph_rejects_extra_output() {
        let mut extra = pinned_outputs();
        extra.push(tensor("extra", TensorElementType::Float32, 3));
        assert!(validate_splade_graph_signature(&pinned_inputs(), &extra).is_err());
    }

    #[test]
    fn splade_graph_rejects_no_outputs() {
        assert!(validate_splade_graph_signature(&pinned_inputs(), &[]).is_err());
    }

    #[test]
    fn splade_graph_rejects_wrong_output_type() {
        let wrong_type = vec![tensor("logits", TensorElementType::Float64, 3)];
        assert!(validate_splade_graph_signature(&pinned_inputs(), &wrong_type).is_err());
    }

    #[test]
    fn splade_graph_rejects_wrong_output_rank() {
        let wrong_rank = vec![tensor("logits", TensorElementType::Float32, 2)];
        assert!(validate_splade_graph_signature(&pinned_inputs(), &wrong_rank).is_err());
    }

    // Regression coverage for the `ensure_ort_dylib_available()`
    // guard called at the top of `load()` lives in
    // `native/src/ort_dylib.rs::tests` (`rejects_a_nonexistent_explicit_dylib_path`,
    // `accepts_an_existing_explicit_dylib_path`) — NOT here. A test that
    // constructs a real `Buffer`/`TokenizerFilesInput` and calls this
    // `#[napi(factory)]` `load()` directly pulls the N-API runtime glue
    // (`Buffer`'s `Drop`, `JsError` conversion) into the `cargo test --lib`
    // binary, which fails to LINK on this host: those symbols
    // (`napi_get_reference_value`, `napi_create_error`, etc.) are provided at
    // runtime by the Node.js host process, not by `cargo test`'s plain
    // executable (confirmed: reverting this crate's diff and running `cargo
    // test --lib` links and passes cleanly — no pre-existing napi-linkage
    // path in this crate's Rust tests touches `Buffer` or a `#[napi]`
    // factory for exactly this reason). The guard's OWN logic is fully
    // exercised, hermetically and deterministically, without that
    // dependency; the one-line call at the top of `load()` wiring it in is
    // reviewed as code, not re-proven by a napi-linked unit test.

    /// Parity gate: the committed golden fixture (synthetic logits) must produce
    /// the exact indices, canonical serialization, and SHA-256 — locking the
    /// activation / pooling / zero-suppression / ordering / rounding contract.
    #[test]
    fn splade_post_process_parity_golden() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../__test__/splade-parity-golden.json"))
                .expect("golden fixture parses");
        let dims: Vec<usize> = fixture["dims"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        let (batch, seq, vocab) = (dims[0], dims[1], dims[2]);
        assert_eq!(batch, 1, "golden fixture is single-row");
        let logits: Vec<f32> = fixture["logits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap() as f32)
            .collect();
        let mask: Vec<i64> = fixture["attention_mask"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();

        let (indices, values) = splade_post_process_row(&logits, seq, vocab, &mask);
        let (indices, values) = canonicalize_sparse(indices, values);
        let exp_idx: Vec<u32> = fixture["expected_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(indices, exp_idx, "SPLADE indices must match golden");

        let canonical = canonical_sparse(&indices, &values);
        assert_eq!(
            canonical,
            fixture["expected_canonical"].as_str().unwrap(),
            "canonical serialization must match golden"
        );
        assert_eq!(
            sha256_hex(&canonical),
            fixture["expected_sha256"].as_str().unwrap(),
            "parity sha256 must match golden"
        );

        // Determinism: recompute is byte-identical.
        let (i2, v2) = splade_post_process_row(&logits, seq, vocab, &mask);
        let (i2, v2) = canonicalize_sparse(i2, v2);
        assert_eq!(canonical_sparse(&i2, &v2), canonical);
    }

    /// Parity invariant: the support set returned by embed() equals the support
    /// set used when computing canonical_hash(). Both derive from canonicalize_sparse
    /// applied once inside embed_rows() and splade_post_process(). This test
    /// exercises the sub-precision edge case: a logit that produces a relu_log
    /// score that is positive but
    /// rounds to 0.0000 at SPLADE_PRECISION must be absent from BOTH the returned
    /// vector AND the canonical serialization (single source of truth).
    #[test]
    fn embed_and_hash_support_sets_are_identical() {
        // seq=1, vocab=3.
        //   term 0: logit = 0.000005  → relu_log ≈ 4.999988e-6  → rounds to "0.0000" → MUST be dropped
        //   term 1: logit = 1.0       → relu_log = ln(2) ≈ 0.6931 → rounds to "0.6931" → kept
        //   term 2: logit = -1.0      → relu_log = 0              → NOT positive → excluded by splade_post_process_row
        let logits = vec![0.000005f32, 1.0f32, -1.0f32];
        let mask = vec![1i64];

        let (raw_idx, raw_val) = splade_post_process_row(&logits, 1, 3, &mask);
        // Raw output includes term 0 (positive, pre-filter) and term 1.
        assert!(raw_idx.contains(&0), "raw includes sub-precision term 0");
        assert!(raw_idx.contains(&1), "raw includes term 1");

        // After canonicalize_sparse, term 0 must be gone.
        let (canon_idx, canon_val) = canonicalize_sparse(raw_idx, raw_val);
        assert_eq!(
            canon_idx,
            vec![1u32],
            "sub-precision term dropped by canonicalize_sparse"
        );

        // The canonical serialization must reference the same support set.
        let canonical = canonical_sparse(&canon_idx, &canon_val);
        let canonical_support: Vec<u32> = canonical
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|tok| tok.split(':').next().unwrap().parse::<u32>().unwrap())
            .collect();
        assert_eq!(
            canon_idx, canonical_support,
            "embed() support set must equal canonical_hash() support set"
        );

        // Sanity: the kept term's value must match ln(2) within f32 precision.
        assert!(
            (canon_val[0] - (2.0f32).ln()).abs() < 1e-6,
            "kept term value must equal ln(2)"
        );
    }

    /// Masked positions are excluded from the max-pool.
    #[test]
    fn masked_positions_excluded() {
        // seq=2, vocab=2. Position 1 has the large logits but is masked out.
        let logits = vec![1.0f32, 0.0, 9.0, 9.0];
        let mask = vec![1i64, 0];
        let (idx, vals) = splade_post_process_row(&logits, 2, 2, &mask);
        assert_eq!(idx, vec![0], "only the unmasked positive term survives");
        assert!((vals[0] - (1.0f32 + 1.0).ln()).abs() < 1e-6);
    }
}
