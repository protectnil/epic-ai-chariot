// Include ONLY the serializer module's source — NOT the whole `chariot-native`
// rlib. Linking the crate drags in every module's `#[napi]` exports, whose
// `napi_*` runtime symbols are provided by the Node host and are undefined when
// linking a standalone Rust test binary (rust-lld: undefined symbol napi_*).
// Isolating the serializer file is the working approach; its own `#[cfg(test)]`
// unit tests are hermetic (no fs/env), so re-compiling them here is harmless.
#[path = "../src/bien_serializer.rs"]
mod bien_serializer;

use bien_serializer::{serialize_query_json, serialize_tool_json, FROZEN_SERIALIZER_HASH};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn corpus_rows() -> impl Iterator<Item = Value> {
    include_str!("conformance/expected.jsonl")
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(serde_json::from_str::<Value>(trimmed).expect("parse corpus row"))
            }
        })
}

#[test]
fn conformance_corpus_byte_equal() {
    let mut saw_meta = false;
    let mut meta_case_count: Option<usize> = None;
    let mut checked = 0usize;

    for row in corpus_rows() {
        let kind = row["kind"].as_str().expect("row kind");

        if kind == "meta" {
            saw_meta = true;
            let serializer_hash = row["serializer_hash"]
                .as_str()
                .expect("meta serializer_hash");
            assert_eq!(
                serializer_hash, FROZEN_SERIALIZER_HASH,
                "serializer_hash drift: corpus meta != compiled-in FROZEN_SERIALIZER_HASH"
            );
            meta_case_count = row
                .get("case_count")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize);
            continue;
        }

        let input = &row["input"];
        let expected = row["serialized"].as_str().expect("expected serialized");
        let expected_sha256 = row["sha256"].as_str().expect("expected sha256");
        let id = row["id"].as_str().unwrap_or("<no id>");
        // Per-row base, NEVER a default: the corpus deliberately carries
        // non-nomic cases (e5, minilm) to pin the per-base prefix asymmetry.
        // Hardcoding DEFAULT_BASE here serialized the e5/minilm fixtures with
        // the nomic prefix and could only stay green while those cases were
        // absent — the exact blind spot the widened corpus exists to close.
        // A row without a base is a corpus defect: fail, don't guess.
        let base = row["base"]
            .as_str()
            .unwrap_or_else(|| panic!("fixture {id} has no \"base\" field — every non-meta corpus row pins its base"));

        let got = match kind {
            "tool" => serialize_tool_json(base, input).expect("serialize tool"),
            "query" => serialize_query_json(base, input).expect("serialize query"),
            other => panic!("unknown corpus kind {other:?}"),
        };

        assert_eq!(got, expected, "byte mismatch on fixture {id}");
        assert_eq!(
            sha256_hex(&got),
            expected_sha256,
            "sha256 mismatch on fixture {id}"
        );
        checked += 1;
    }

    assert!(saw_meta, "corpus had no meta line (serializer_hash gate)");
    // A truncated vendored copy must FAIL here, not shrink the gate silently.
    // The expected count comes from the corpus META line, which the upstream
    // generator writes only after every fixture row exists — NOT from a
    // literal in this file. A hardcoded number freezes the gate at whatever
    // the corpus held the day it was written: 8-of-31 sat green for weeks that
    // way, and 31-of-33 repeated it after the capability-residual fixtures
    // landed upstream. Deriving the number from this same file instead would
    // be circular (a short file yields a short count and passes), so the
    // expectation must arrive as DATA from the side that owns the fixtures.
    //
    // Absent/!u64 `case_count` is a hard failure, never a skip: an old corpus
    // that predates the field is exactly the under-vendored state this gate
    // exists to catch. The upstream CI half additionally asserts this file is
    // byte-identical to the source of truth, so meta and rows cannot drift
    // apart without one side going red.
    let expected_cases = meta_case_count.expect(
        "fail-closed: corpus meta line carries no `case_count` — re-vendor from the \
         upstream source of truth (its generator emits the field)",
    );
    assert_eq!(
        checked, expected_cases,
        "fail-closed: corpus declares {expected_cases} non-meta fixtures but {checked} were \
         checked (corpus under/over-vendored vs upstream)"
    );
}
