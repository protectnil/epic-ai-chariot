// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// Phase 3.3 (cross-encoder rerank) — in-process fastembed-rs TextRerank
// compiled into chariot-native.node.
//
// CHARIOT-SPEC §8.6 step 7: "The fused shortlist is reranked by a fine-tuned
// cross-encoder — the LLM-free re-ranking router of BIEN §7 (LOCKED) — to
// produce the final ordering." This module is the NAPI surface that stage runs
// on. Before it existed, `ArtifactSource.loadRerankScorer()` had no scorer it
// could ever return, so `loadRetrieval.ts` never constructed
// `CrossEncoderReranker` and Tier-1 ordering was BM25-only .
//
// AIR-GAP (CH-29/CH-30): the model is passed in as bytes — never fetched from
// the HuggingFace hub. fastembed is built with `default-features = false` so
// the hf-hub path is not compiled; `try_new_from_user_defined` is the only
// constructor reachable here. ONNX Runtime is provided via `ort/load-dynamic`.
//
// ── DETERMINISM (§8.6 / CH-23) ──
// Tier-1 selection must be byte-identical for an identical request, so this
// scorer is pinned on two axes that would otherwise vary per host or per call:
//
//   1. `intra_threads(1)` — identical rationale to `encoder.rs` and
//      `splade.rs`. ORT's multi-threaded intra-op reductions partition
//      non-associative f32 accumulations by available core count / cgroup
//      quota, so a host with a different core count produces bit-different
//      logits. Single-threaded → cross-host bit-reproducible.
//
//   2. `batch_size = 1` — fastembed's `rerank` tokenizes each batch with
//      `encode_batch`, which pads every member to the longest sequence IN THAT
//      BATCH, then runs one `(batch, seq_len)` tensor. A document's padded
//      width therefore depends on which OTHER documents share its batch, and
//      ORT reductions over a different tensor width can accumulate in a
//      different order. With the crate default (`DEFAULT_BATCH_SIZE`) the score
//      of a (query, document) pair would not be a pure function of that pair —
//      it would depend on shortlist composition, which breaks the §8.6
//      byte-identical-selection contract in exactly the way that is hardest to
//      observe. Scoring one pair per forward pass removes the coupling
//      entirely. The rerank stage runs over the bounded post-RRF shortlist
//      (`maxTools`-capped), never the full index, so the cost is bounded by
//      design — §8.6 already specifies "exact (brute-force) cross-encoder
//      rescoring over the fixed shortlist".
//
// ── ORDER CONTRACT ──
// `TextRerank::rerank` returns results SORTED BY SCORE DESCENDING, carrying the
// original position in `RerankResult.index`. The TypeScript `RerankScorer`
// contract (`src/engine/retrieval/types.ts:97`) is the opposite: `score(query,
// docs) -> number[]` must be aligned to INPUT order, one score per input, and
// `CrossEncoderReranker` throws if the lengths differ. This module performs
// that re-mapping and fails closed on any malformed result set (wrong count,
// out-of-range index, duplicate index) rather than emitting a silently
// misaligned score vector — a misaligned vector would attach one document's
// relevance to another document's id, which is a wrong-tool routing defect that
// no downstream check could catch.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use fastembed::{RerankInitOptionsUserDefined, RerankResult, TextRerank, UserDefinedRerankingModel};

use crate::encoder::TokenizerFilesInput;

fn map_err<E: std::fmt::Display>(e: E) -> Error {
    Error::from_reason(e.to_string())
}

/// One (query, document) pair per forward pass. See DETERMINISM note 2 above:
/// any value > 1 makes a pair's score depend on its batch-mates' lengths.
const DETERMINISTIC_BATCH_SIZE: usize = 1;

/// Re-map score-sorted rerank results back to INPUT order (the `RerankScorer`
/// contract). Pure and separately unit-tested: this is the step where a silent
/// error attaches one document's relevance to another document's id, which is a
/// wrong-tool routing defect no downstream check can catch — so it fails closed
/// on a wrong count, an out-of-range index, or a duplicate index.
///
/// Coverage is tracked in a separate `filled` vector rather than by sentinel
/// value: a model that legitimately emits a non-finite logit must stay
/// distinguishable from a position the scorer never covered. Non-finite scores
/// pass through — `CrossEncoderReranker.rerank` already coerces them to
/// NEGATIVE_INFINITY so they rank last deterministically and the CH-49
/// abstention floor reads them as zero evidence. Erroring on them here would
/// escalate one degraded candidate into a failed query.
fn remap_to_input_order(ranked: Vec<RerankResult>, n: usize) -> Result<Vec<f64>> {
    if ranked.len() != n {
        return Err(Error::from_reason(format!(
            "rerank returned {} results for {} documents",
            ranked.len(),
            n
        )));
    }

    let mut scores = vec![0.0_f64; n];
    let mut filled = vec![false; n];
    for r in ranked {
        if r.index >= n {
            return Err(Error::from_reason(format!(
                "rerank result index {} out of range for {} documents",
                r.index, n
            )));
        }
        if filled[r.index] {
            return Err(Error::from_reason(format!(
                "rerank returned duplicate result index {}",
                r.index
            )));
        }
        scores[r.index] = r.score as f64;
        filled[r.index] = true;
    }
    // Unreachable while `ranked.len() == n` and every index is unique and in
    // range (pigeonhole), but asserted explicitly so a future change to either
    // guard above cannot silently emit a misaligned score vector.
    if let Some(pos) = filled.iter().position(|f| !f) {
        return Err(Error::from_reason(format!(
            "rerank produced no score for document index {}",
            pos
        )));
    }

    Ok(scores)
}

/// In-process cross-encoder rerank scorer (the BIEN §7 re-ranking router).
///
/// Satisfies the `RerankScorer` interface consumed by `CrossEncoderReranker`:
/// one relevance score per (query, document) pair, in input order,
/// deterministic for a fixed model.
#[napi]
pub struct CrossEncoderScorer {
    inner: TextRerank,
}

#[napi]
impl CrossEncoderScorer {
    /// Load a cross-encoder from user-supplied ONNX + tokenizer bytes. CPU
    /// execution providers only (deterministic, air-gapped). No hub access.
    ///
    /// `max_length` is the tokenizer truncation length; it MUST match the value
    /// the model was exported with, and is stamped in the bundle manifest
    /// alongside the model identity + immutable revision (§17.6.4).
    #[napi(factory)]
    pub fn load(
        onnx_file: Buffer,
        tokenizer_files: TokenizerFilesInput,
        max_length: u32,
    ) -> Result<Self> {
        let model = UserDefinedRerankingModel::new(onnx_file.to_vec(), tokenizer_files.into());
        let opts = RerankInitOptionsUserDefined::new()
            .with_max_length(max_length as usize)
            .with_intra_threads(1);
        let inner = TextRerank::try_new_from_user_defined(model, opts).map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Score every (query, document) pair. Returns one score per document, in
    /// the SAME order as `documents` — never the crate's score-sorted order.
    ///
    /// An empty document list returns an empty vector without touching the
    /// model (the shortlist-empty case is not an error).
    #[napi]
    pub fn score(&mut self, query: String, documents: Vec<String>) -> Result<Vec<f64>> {
        if documents.is_empty() {
            return Ok(Vec::new());
        }
        let n = documents.len();

        let ranked = self
            .inner
            .rerank(
                query,
                documents,
                /* return_documents */ false,
                Some(DETERMINISTIC_BATCH_SIZE),
            )
            .map_err(map_err)?;

        remap_to_input_order(ranked, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(index: usize, score: f32) -> RerankResult {
        RerankResult {
            document: None,
            score,
            index,
        }
    }

    #[test]
    fn remaps_score_sorted_results_back_to_input_order() {
        // The crate returns DESC by score; input order was [a, b, c] with
        // scores [0.1, 0.9, 0.5], so the sorted set is index 1, 2, 0.
        let ranked = vec![r(1, 0.9), r(2, 0.5), r(0, 0.1)];
        let out = remap_to_input_order(ranked, 3).expect("remap");
        assert_eq!(out.len(), 3);
        assert!((out[0] - 0.1_f32 as f64).abs() < 1e-12);
        assert!((out[1] - 0.9_f32 as f64).abs() < 1e-12);
        assert!((out[2] - 0.5_f32 as f64).abs() < 1e-12);
    }

    #[test]
    fn single_document_round_trips() {
        let out = remap_to_input_order(vec![r(0, -2.5)], 1).expect("remap");
        assert_eq!(out, vec![-2.5_f32 as f64]);
    }

    #[test]
    fn non_finite_score_passes_through_and_is_not_a_coverage_hole() {
        // A NaN logit must NOT be mistaken for "position never scored" — the TS
        // layer sanitizes it to NEGATIVE_INFINITY and ranks it last.
        let out = remap_to_input_order(vec![r(0, f32::NAN), r(1, 0.4)], 2).expect("remap");
        assert!(out[0].is_nan(), "NaN must survive to the TS sanitizer");
        assert!((out[1] - 0.4_f32 as f64).abs() < 1e-12);
    }

    #[test]
    fn rejects_short_result_set() {
        assert!(remap_to_input_order(vec![r(0, 1.0)], 2).is_err());
    }

    #[test]
    fn rejects_long_result_set() {
        assert!(remap_to_input_order(vec![r(0, 1.0), r(1, 2.0)], 1).is_err());
    }

    #[test]
    fn rejects_out_of_range_index() {
        assert!(remap_to_input_order(vec![r(0, 1.0), r(7, 2.0)], 2).is_err());
    }

    #[test]
    fn rejects_duplicate_index() {
        // Count is right but position 1 is never covered — emitting here would
        // give document 1 document 0's relevance score.
        assert!(remap_to_input_order(vec![r(0, 1.0), r(0, 2.0)], 2).is_err());
    }

    #[test]
    fn empty_input_is_not_an_error() {
        assert_eq!(remap_to_input_order(Vec::new(), 0).expect("remap").len(), 0);
    }
}
