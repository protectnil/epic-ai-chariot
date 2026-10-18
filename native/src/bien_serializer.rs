// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// CH-23 — BIEN canonical serializer, Rust port.
//
// The BIEN Python serializer (`canonical.py` + `fields.py`) is the
// authoritative contract. This module is a hand-port that MUST reproduce the
// BIEN conformance corpus (`expected.jsonl`) byte-for-byte. Both repos' CI
// assert byte-equality against that corpus (dual-repo gate, BIEN SPEC
// §16.4 / CHARIOT CH-23).
//
// This port does NOT recompute `serializer_hash` from source. Per
// `PORTING.md`, the Rust side carries the manifest's hash value as an OPAQUE
// version token (`FROZEN_SERIALIZER_HASH`) and the fail-closed loader rejects
// any bundle whose `serializer_hash` ≠ this compiled-in constant. Behavior is
// proven by the corpus, not by re-hashing source.
//
// ── Invariants the port matches byte-for-byte (PORTING.md §1–8) ──────────
//  1. Per-value op order: NFC-normalize → strip → (lists: filter-empty →
//     dedup → sort) → join ", " → truncate to `max_chars` *codepoints*
//     (semantic value, pre-escape) → escape.
//  2. NFC normalization. The Python contract froze UCD 15.0.0
//     (`unicodedata.unidata_version == 15.0.0`); this build uses
//     `unicode-normalization` 0.1.25 (pinned EXACTLY in Cargo.toml), whose
//     tables are UCD **17.0.0** — charabia (via qdrant-edge) forbids a
//     UCD-15.0 build of the crate. ACCEPTED POLICY: single-codepoint NFC is
//     version-stable, so all corpus fixtures byte-match; the residual
//     divergence surface is sequences containing combining marks ASSIGNED
//     AFTER UCD 15.0 (e.g. U+0897, U+1ACF..U+1ADB, U+1AE0..U+1AE4), which
//     canonical-reorder here but are inert (ccc=0/unassigned) in Python
//     15.0. Enforced fail-closed by (a) the vendored-corpus byte-equality
//     gate, (b) a UNICODE_VERSION pin test, and (c) a reordering sentinel
//     test documenting the known delta — all three break the build if the
//     tables ever drift again.
//  3. String-only inputs (and lists of strings); no non-string coercion.
//  4. Sort is Unicode-codepoint order. Rust byte-wise sort of UTF-8 equals
//     codepoint order, so `sort()` on `&str` is correct.
//  5. Escape table is order-sensitive, backslash FIRST: `\`→`\\`, `\n`→`\n`
//     (literal), `«`(U+00AB)→`«`, `»`(U+00BB)→`»`. Single LTR pass.
//  6. Tag wrap `«TAG»value`; lines joined by `\n`; per-base prefix prepended
//     once (`search_document: ` / `search_query: ` for the locked Nomic base).
//  7. Null-omission: absent / empty-after-strip fields emit no line.
//  8. Param fields (`required_params`, `optional_params`, `enum_values`,
//     `examples`) are enabled and emitted when present (best-effort).

use unicode_normalization::UnicodeNormalization;

/// Frozen serializer hash from BIEN M1 (`fields.SERIALIZER_VERSION` +
/// SHA-256 of the serializer module source). Carried as an opaque version
/// token — the loader fails closed when a bundle manifest disagrees.
/// Source of truth: the BIEN conformance corpus's `expected.jsonl`
/// meta line. Frozen 2026-05-30.
pub const FROZEN_SERIALIZER_HASH: &str =
    "8bed00ff2afed5367ac607b388be2f2c76d797108dbde9d08e31d74e109de43f";

/// One field of the canonical text spine.
struct FieldSpec {
    /// Key in the input record.
    key: &'static str,
    /// `«TAG»` label.
    tag: &'static str,
    /// Per-field truncation in Unicode scalar values (codepoints), not bytes.
    max_chars: usize,
    /// List-valued field (filter-empty → dedup → sort → join ", ").
    is_list: bool,
}

/// Fixed field order — mirrors `fields.TOOL_FIELDS` exactly. Param-signature
/// fields (REQ/OPT/ENUM/EX) are enabled per §17.6.3 (MASTER 2026-05-30).
const TOOL_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        key: "name",
        tag: "NAME",
        max_chars: 128,
        is_list: false,
    },
    FieldSpec {
        key: "connector_family",
        tag: "FAMILY",
        max_chars: 64,
        is_list: false,
    },
    FieldSpec {
        key: "category",
        tag: "CATEGORY",
        max_chars: 64,
        is_list: false,
    },
    FieldSpec {
        key: "description",
        tag: "DESC",
        max_chars: 1024,
        is_list: false,
    },
    FieldSpec {
        key: "keywords",
        tag: "KW",
        max_chars: 512,
        is_list: true,
    },
    FieldSpec {
        key: "departments",
        tag: "DEPT",
        max_chars: 256,
        is_list: true,
    },
    FieldSpec {
        key: "industries",
        tag: "IND",
        max_chars: 256,
        is_list: true,
    },
    FieldSpec {
        key: "auth_model",
        tag: "AUTH",
        max_chars: 64,
        is_list: false,
    },
    FieldSpec {
        key: "operation",
        tag: "OP",
        max_chars: 32,
        is_list: false,
    },
    FieldSpec {
        key: "output_type",
        tag: "OUT",
        max_chars: 64,
        is_list: false,
    },
    FieldSpec {
        key: "side_effects",
        tag: "SIDE",
        max_chars: 256,
        is_list: true,
    },
    FieldSpec {
        key: "risk_flags",
        tag: "RISK",
        max_chars: 128,
        is_list: true,
    },
    FieldSpec {
        key: "required_params",
        tag: "REQ",
        max_chars: 512,
        is_list: true,
    },
    FieldSpec {
        key: "optional_params",
        tag: "OPT",
        max_chars: 512,
        is_list: true,
    },
    FieldSpec {
        key: "enum_values",
        tag: "ENUM",
        max_chars: 512,
        is_list: true,
    },
    FieldSpec {
        key: "examples",
        tag: "EX",
        max_chars: 512,
        is_list: true,
    },
];

/// Mirrors `fields.QUERY_FIELDS`.
const QUERY_FIELDS: &[FieldSpec] = &[FieldSpec {
    key: "text",
    tag: "Q",
    max_chars: 512,
    is_list: false,
}];

/// Per-base asymmetric prefixes (`fields.BASE_PREFIXES`). The base is locked to
/// Nomic for 4.0.0; the table is kept whole so an unknown base is a controlled
/// error, matching the Python `_prefix` total-over-base behavior.
fn base_prefix(base: &str, kind: Kind) -> Result<&'static str, String> {
    let (document, query) = match base {
        "nomic" => ("search_document: ", "search_query: "),
        "e5" => ("passage: ", "query: "),
        "minilm" => ("", ""),
        other => {
            return Err(format!(
                "unknown base {other:?}; valid bases: [\"e5\", \"minilm\", \"nomic\"]"
            ))
        }
    };
    Ok(match kind {
        Kind::Document => document,
        Kind::Query => query,
    })
}

/// Default base (`fields.DEFAULT_BASE`).
pub const DEFAULT_BASE: &str = "nomic";

#[derive(Clone, Copy)]
enum Kind {
    Document,
    Query,
}

/// NFC-normalize. `unicode-normalization` is pinned to =0.1.25 (UCD 17.0.0
/// tables — a UCD-15.0 build is impossible in this tree, see the module
/// header invariant 2 for the accepted-divergence policy and the sentinel
/// tests that fail closed on any further table drift).
fn norm(s: &str) -> String {
    s.nfc().collect::<String>()
}

/// Order-sensitive escape, single left-to-right pass, backslash FIRST
/// (PORTING.md §5 / `fields.ESCAPE`). A single `chars()` pass with explicit
/// per-character mapping is equivalent to the Python sequential `replace`
/// chain *because* backslash is handled first: once we emit `\\` for a source
/// backslash in the same pass, we never re-scan it, so the later rules cannot
/// touch the backslashes we introduced. The remaining source characters
/// (`\n`, `«`, `»`) are disjoint from `\`, so order among them is immaterial.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\u{00ab}' => out.push_str("\\u00ab"),
            '\u{00bb}' => out.push_str("\\u00bb"),
            _ => out.push(ch),
        }
    }
    out
}

/// Truncate to `max_chars` Unicode scalar values (codepoints), counting the
/// *semantic* (pre-escape) value (PORTING.md §1).
fn truncate_codepoints(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// A field value supplied by the caller: scalar string or list of strings.
/// Strings only — the contract embeds strings (PORTING.md §3).
pub enum FieldValue<'a> {
    Scalar(&'a str),
    List(Vec<&'a str>),
    /// Explicitly absent — emits no line (null-omission).
    Null,
}

/// Render one field value to its rendered string, or `None` to omit
/// (null-omission). Mirrors `canonical._render_value`.
fn render_value(spec: &FieldSpec, value: &FieldValue) -> Option<String> {
    let rendered = match value {
        FieldValue::Null => return None,
        FieldValue::List(items) => {
            if !spec.is_list {
                // Mirrors Python: a non-list spec receives a scalar. A list
                // arriving for a scalar spec is a caller contract violation;
                // we treat it as absent rather than guessing a coercion.
                return None;
            }
            let mut cleaned: Vec<String> = items
                .iter()
                .filter(|v| !v.trim().is_empty())
                .map(|v| norm(v).trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            if cleaned.is_empty() {
                return None;
            }
            cleaned.sort(); // codepoint order (UTF-8 byte order == codepoint order)
            cleaned.dedup();
            cleaned.join(", ")
        }
        FieldValue::Scalar(v) => {
            if spec.is_list {
                return None;
            }
            let r = norm(v).trim().to_string();
            if r.is_empty() {
                return None;
            }
            r
        }
    };
    // Truncate on the semantic value (pre-escape), then escape.
    let truncated = truncate_codepoints(&rendered, spec.max_chars);
    Some(escape(&truncated))
}

/// Core serialize over a field table. `lookup` returns the caller's value for a
/// given key. Mirrors `canonical._serialize`.
fn serialize_with<'a, F>(specs: &[FieldSpec], prefix: &str, mut lookup: F) -> String
where
    F: FnMut(&str) -> FieldValue<'a>,
{
    let mut lines: Vec<String> = Vec::with_capacity(specs.len());
    for spec in specs {
        let value = lookup(spec.key);
        if let Some(rendered) = render_value(spec, &value) {
            let mut line = String::with_capacity(spec.tag.len() + rendered.len() + 2);
            line.push('\u{00ab}');
            line.push_str(spec.tag);
            line.push('\u{00bb}');
            line.push_str(&rendered);
            lines.push(line);
        }
    }
    let mut out = String::from(prefix);
    out.push_str(&lines.join("\n"));
    out
}

/// Serialize a tool record (`canonical.serialize_tool`). `lookup` supplies each
/// field by key; absent fields return `FieldValue::Null`.
pub fn serialize_tool_with<'a, F>(base: &str, lookup: F) -> Result<String, String>
where
    F: FnMut(&str) -> FieldValue<'a>,
{
    let prefix = base_prefix(base, Kind::Document)?;
    Ok(serialize_with(TOOL_FIELDS, prefix, lookup))
}

/// Serialize a query record (`canonical.serialize_query`).
pub fn serialize_query_with<'a, F>(base: &str, lookup: F) -> Result<String, String>
where
    F: FnMut(&str) -> FieldValue<'a>,
{
    let prefix = base_prefix(base, Kind::Query)?;
    Ok(serialize_with(QUERY_FIELDS, prefix, lookup))
}

// ── serde_json convenience adapters ─────────────────────────────────────
// The freeze/load paths carry records as JSON. These adapters map a
// `serde_json::Value` object to the string/list-of-string contract, treating
// any non-string / non-array-of-strings as absent (null-omission) — never
// coercing, per PORTING.md §3.

use serde_json::Value;

fn json_field<'a>(obj: &'a Value, key: &str) -> FieldValue<'a> {
    match obj.get(key) {
        None | Some(Value::Null) => FieldValue::Null,
        Some(Value::String(s)) => FieldValue::Scalar(s.as_str()),
        Some(Value::Array(items)) => {
            // Keep only string items; preserve order (cleaning happens in
            // render_value). Non-string items are dropped (no coercion).
            let strs: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
            FieldValue::List(strs)
        }
        // Numbers/bools/objects are not part of the string contract → absent.
        Some(_) => FieldValue::Null,
    }
}

/// Serialize a tool record given as a JSON object.
pub fn serialize_tool_json(base: &str, rec: &Value) -> Result<String, String> {
    serialize_tool_with(base, |k| json_field(rec, k))
}

/// Serialize a query record given as a JSON object.
pub fn serialize_query_json(base: &str, q: &Value) -> Result<String, String> {
    serialize_query_with(base, |k| json_field(q, k))
}

// ── NAPI surface ─────────────────────────────────────────────────────────
// Exposes the serializer to the TypeScript layer so query-side serialization
// is byte-identical to the doc/freeze side (the SAME compiled code — CH-23
// lockstep). `rec_json` is a JSON object string of the tool/query record.
//
// The integration test includes this source file directly and compiles it in a
// `cfg(test)` context, so the Node-API shims must be excluded there. That lets
// the test exercise only the pure serializer code while the production addon
// keeps the full NAPI surface.

#[cfg(not(test))]
/// NAPI: serialize a tool record. `base` is the encoder base ("nomic").
#[napi_derive::napi(js_name = "serializeTool")]
pub fn napi_serialize_tool(base: String, rec_json: String) -> napi::Result<String> {
    let rec: Value = serde_json::from_str(&rec_json)
        .map_err(|e| napi::Error::from_reason(format!("invalid record JSON: {e}")))?;
    serialize_tool_json(&base, &rec).map_err(napi::Error::from_reason)
}

#[cfg(not(test))]
/// NAPI: serialize a query record. `base` is the encoder base ("nomic").
#[napi_derive::napi(js_name = "serializeQuery")]
pub fn napi_serialize_query(base: String, rec_json: String) -> napi::Result<String> {
    let rec: Value = serde_json::from_str(&rec_json)
        .map_err(|e| napi::Error::from_reason(format!("invalid record JSON: {e}")))?;
    serialize_query_json(&base, &rec).map_err(napi::Error::from_reason)
}

#[cfg(not(test))]
/// NAPI: the compiled-in frozen serializer hash (CH-23 opaque version token).
/// The loader compares a bundle manifest's `serializer_hash` to this and fails
/// closed on divergence.
#[napi_derive::napi(js_name = "frozenSerializerHash")]
pub fn napi_frozen_serializer_hash() -> String {
    FROZEN_SERIALIZER_HASH.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The corpus byte-equality gate lives in the self-contained integration
    // test `native/tests/serializer_conformance.rs` (vendored corpus via
    // include_str!, no filesystem/env dependency). The prior filesystem-based
    // unit test here read BIEN_CONFORMANCE_CORPUS and panicked on CI runners
    // where that path is absent — removed to keep this gate hermetic + fail-closed.

    #[test]
    fn unknown_base_is_controlled_error() {
        let rec = serde_json::json!({ "name": "x" });
        let err = serialize_tool_json("does-not-exist", &rec).unwrap_err();
        assert!(err.contains("unknown base"), "got: {err}");
    }

    #[test]
    fn escape_backslash_first_single_pass() {
        // A literal backslash followed by 'n' must NOT become a newline escape:
        // source `\` → `\\`, source `n` stays `n` ⇒ `\\n` (three chars: \ \ n).
        assert_eq!(escape("\\n"), "\\\\n");
        // A real newline becomes the two-char escape `\n`.
        assert_eq!(escape("\n"), "\\n");
        assert_eq!(escape("«»"), "\\u00ab\\u00bb");
    }

    #[test]
    fn truncate_counts_codepoints_not_bytes() {
        // 'é' is 2 UTF-8 bytes but 1 codepoint; max_chars=1 keeps exactly "é".
        assert_eq!(truncate_codepoints("éx", 1), "é");
    }

    /// DRIFT SENTINEL (module header invariant 2): the compiled normalization
    /// tables must be exactly the reviewed UCD version. `unicode-normalization`
    /// is pinned `=0.1.25` in Cargo.toml; if a future dependency bump swaps the
    /// tables, this fails the build so the cross-repo divergence surface is
    /// re-reviewed (and the corpus re-synced) instead of drifting silently.
    #[test]
    fn unicode_tables_pinned_to_reviewed_version() {
        assert_eq!(
            unicode_normalization::UNICODE_VERSION,
            (17, 0, 0),
            "unicode-normalization tables changed — re-review the BIEN §16.4/CH-23 \
             divergence surface vs the Python UCD 15.0.0 contract and update the \
             module header + Cargo.toml pin deliberately"
        );
    }

    /// DRIFT SENTINEL: the known, accepted UCD 15.0→17.0 divergence class.
    /// U+0897 (ARABIC PEPET, assigned after UCD 15.0, ccc=230) followed by
    /// U+0316 (ccc=220) canonical-reorders under these tables; Python 15.0
    /// leaves the sequence untouched (U+0897 unassigned → ccc=0). Pinning the
    /// CURRENT behavior means any table change that alters this class breaks
    /// the build and forces the cross-repo contract review.
    #[test]
    fn known_post_ucd15_reordering_delta_is_stable() {
        let input = "a\u{0897}\u{0316}";
        let normalized = norm(input);
        assert_eq!(
            normalized, "a\u{0316}\u{0897}",
            "UCD-17 canonical reordering of post-15.0 combining marks changed — \
             the accepted divergence surface vs Python UCD 15.0 no longer holds"
        );
    }
}
