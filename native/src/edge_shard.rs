// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// Phase 3 — NAPI bindings for the in-process Qdrant Edge vector runtime.
//
// CHARIOT-SPEC §2.2 / §4.3 / §8.6: Chariot 4.0.0 runs vector search IN-PROCESS
// via `qdrant-edge` (an `EdgeShard`) — no server, no port, no network. This
// module exposes a small, JSON-driven NAPI surface over `EdgeShard` so the
// TypeScript retrieval layer (P4) can create/load a shard, upsert tool
// vectors, run the hybrid dense+sparse+RRF query, snapshot, and unpack.
//
// Design: qdrant-edge's update/config types are serde-`Deserialize`, so those
// paths take JSON directly. The query path's internal `ShardQueryRequest` is
// `Serialize`-only (its rest/grpc deserialize conversions are behind the crate
// `api` feature, which is OFF here), so we construct `ShardQueryRequest`
// programmatically from a purpose-built request struct that models exactly the
// hybrid shape the spec requires: per-leg `Nearest` prefetches (dense + sparse,
// MaxSim-capable) fused with `Fusion::Rrf`. This keeps the binding type-safe
// and the determinism contract (§8.6/CH-23) explicit on our side.
//
// SEAL/VERIFY guardrail (§8.6): snapshot sealing (AES-256-GCM) and signature
// verification (Ed25519) are CHARIOT-side, NOT Edge. This module only does
// plaintext Edge I/O (`unpack_snapshot`, `load`). The unseal+verify wrapper
// lives in `edge_snapshot.rs` and runs BEFORE these functions touch a shard.
// ENFORCED, not convention: `edge_unpack_snapshot` requires the process-local
// receipt returned by `unseal_and_verify_snapshot` for the exact archive
// bytes, and `EdgeShardHandle::load` requires (and re-verifies) the HMAC'd
// per-file digest manifest that unpack emits. The receipt/manifest key is
// random per process, so plaintext cached from a previous process never
// verifies — every restart must re-run unseal+verify. A load/unpack that
// skips verification fails closed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

// All qdrant-edge types are reached via the crate-root re-exports: `qdrant-edge`
// exposes only `pub use edge::*` at the root, and `edge/mod.rs` does
// `pub use reexports::*` + `pub use config::shard::EdgeConfig` + `pub use
// info::ShardInfo`. The `shard`/`segment` modules are private, so we must NOT
// import their internal paths directly — only the curated re-exports below.
use qdrant_edge::external::ordered_float::OrderedFloat;
use qdrant_edge::{
    EdgeConfig, EdgeShard, Filter, Fusion, NamedQuery, PointInsertOperations, PointOperations,
    PointId, PointStructPersisted, Prefetch, QueryEnum, QueryRequest as ShardQueryRequest, ScoringQuery,
    SearchParams, SparseVector, TypedMultiDenseVector, UpdateOperation, VectorInternal,
};

/// Opaque, thread-safe handle to a loaded edge shard. `EdgeShard` is `Send +
/// Sync`; we wrap it in `Arc` so the JS side can hold one handle and call from
/// the libuv thread pool. The shard flushes on drop (qdrant-edge `Drop`); that
/// drop-flush can PANIC on I/O failure (qdrant-edge surfaces flush errors via
/// `expect`), so GC finalization goes through a guarded `ObjectFinalize` that
/// converts the panic into a JS error instead of letting it unwind through the
/// NAPI `extern "C"` finalizer and abort the Node.js process. TS SHOULD still
/// call `flush()` explicitly before releasing the last handle so the Drop
/// flush is a no-op backup.
#[napi(custom_finalize)]
pub struct EdgeShardHandle {
    /// `None` only after the finalizer has taken the shard for its guarded
    /// drop-flush; every live handle holds `Some`.
    inner: Option<Arc<EdgeShard>>,
    /// Binding-side serialization between mutating ops (upsert) and flush.
    /// qdrant-edge's `EdgeShard::flush` uses `try_lock().expect("WAL lock
    /// acquired")` internally, so a flush racing an in-flight update PANICS
    /// on transient contention instead of blocking. Serializing both paths
    /// through this gate means the shard's internal `try_lock` never observes
    /// contention from this handle.
    flush_gate: Mutex<()>,
}

impl ObjectFinalize for EdgeShardHandle {
    /// Guarded GC finalizer: dropping the last `Arc<EdgeShard>` runs
    /// qdrant-edge's `Drop`, which flushes via `expect()` and panics on I/O
    /// failure (disk-full, EROFS). An unwind out of napi's `extern "C"`
    /// finalizer aborts the whole Node process; catching here converts the
    /// failure into a JS exception instead (fail-closed, not fail-fatal).
    fn finalize(mut self, _env: Env) -> Result<()> {
        let Some(arc) = self.inner.take() else {
            return Ok(());
        };
        let _gate = self.flush_gate.lock().unwrap_or_else(|p| p.into_inner());
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(arc))).map_err(|e| {
            Error::from_reason(format!("EdgeShard drop-flush failed: {}", panic_msg(&e)))
        })
    }
}

impl EdgeShardHandle {
    fn from_shard(shard: EdgeShard) -> Self {
        Self {
            inner: Some(Arc::new(shard)),
            flush_gate: Mutex::new(()),
        }
    }

    /// The live shard. Errs (rather than panics) in the window where the
    /// finalizer has already taken it.
    fn shard(&self) -> Result<&Arc<EdgeShard>> {
        self.inner
            .as_ref()
            .ok_or_else(|| Error::from_reason("EdgeShard handle already finalized"))
    }

    /// Acquire the binding-side flush gate. Panics inside gated sections are
    /// caught by `catch_unwind` before they can cross the guard, so poisoning
    /// should be impossible — recover defensively regardless.
    fn gate(&self) -> std::sync::MutexGuard<'_, ()> {
        self.flush_gate.lock().unwrap_or_else(|p| p.into_inner())
    }
}

// ── helpers ─────────────────────────────────────────────────────────────

fn map_op_err<E: std::fmt::Display>(e: E) -> Error {
    Error::from_reason(e.to_string())
}

/// Extract a printable message from a caught panic payload.
fn panic_msg(e: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn parse_config(config_json: Option<String>) -> Result<Option<EdgeConfig>> {
    match config_json {
        None => Ok(None),
        Some(s) => {
            let cfg: EdgeConfig = serde_json::from_str(&s)
                .map_err(|e| Error::from_reason(format!("invalid EdgeConfig JSON: {e}")))?;
            Ok(Some(cfg))
        }
    }
}

// ── query request model (constructed → ShardQueryRequest) ───────────────
//
// Mirrors the qdrant-edge Python `QueryRequest`/`Prefetch`/`Fusion.Rrf`
// surface, narrowed to the legs Chariot uses. JSON in from TS; never trusts a
// raw internal type.

/// One vector leg: a `Nearest` search against a named vector. `vector` is a
/// dense `[f32]`, OR a sparse `{indices,values}`, OR a multivector
/// `[[f32]]` (MaxSim) — exactly one must be set.
#[napi(object)]
#[derive(Debug, Clone, Deserialize)]
pub struct NativeVectorQuery {
    /// Named vector to search (e.g. "dense", "splade"). Empty → default vector.
    pub using: String,
    /// Dense query vector.
    pub dense: Option<Vec<f64>>,
    /// Sparse query vector indices (paired with `sparse_values`).
    pub sparse_indices: Option<Vec<u32>>,
    /// Sparse query vector values (paired with `sparse_indices`).
    pub sparse_values: Option<Vec<f64>>,
    /// Multivector (late-interaction / MaxSim) query: list of dense rows.
    pub multi: Option<Vec<Vec<f64>>>,
}

/// A prefetch leg: a vector query with its own candidate `limit`.
#[napi(object)]
#[derive(Debug, Clone, Deserialize)]
pub struct NativePrefetch {
    pub query: NativeVectorQuery,
    pub limit: u32,
}

/// The hybrid query request. If `prefetches` is non-empty, the root fuses them
/// with RRF (`rrf_k`, optional `rrf_weights`). If empty, `query` is a single
/// vector search. Exactly one of {non-empty prefetches, query} is meaningful.
#[napi(object)]
#[derive(Debug, Clone, Deserialize)]
pub struct NativeQueryRequest {
    /// Prefetch legs to fuse (dense + sparse + multivector). Empty → single leg.
    pub prefetches: Vec<NativePrefetch>,
    /// Single-leg query (used only when `prefetches` is empty).
    pub query: Option<NativeVectorQuery>,
    /// Final result limit.
    pub limit: u32,
    /// RRF k (typical 60). Required when `prefetches` is non-empty.
    pub rrf_k: Option<u32>,
    /// Optional per-prefetch RRF weights (len must equal prefetches len).
    pub rrf_weights: Option<Vec<f64>>,
    /// Include payload in results (default true).
    pub with_payload: Option<bool>,
    /// Optional JSON `Filter` (qdrant-edge schema), applied at the root.
    pub filter_json: Option<String>,
    /// Exact (full-scan / brute-force) search on every leg. REQUIRED for the
    /// CH-23 / §8.6 deterministic selection path (approximate HNSW is not
    /// byte-identical across replicas). Default false (ANN).
    pub exact: Option<bool>,
}

/// Build a `VectorInternal` from a single `NativeVectorQuery`, enforcing
/// exactly-one-of {dense, sparse, multi}.
fn to_vector_internal(q: &NativeVectorQuery) -> Result<VectorInternal> {
    let set = [
        q.dense.is_some(),
        q.sparse_indices.is_some() || q.sparse_values.is_some(),
        q.multi.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if set != 1 {
        return Err(Error::from_reason(
            "NativeVectorQuery must set exactly one of {dense, sparse_indices+sparse_values, multi}",
        ));
    }

    if let Some(dense) = &q.dense {
        let v: Vec<f32> = dense.iter().map(|x| *x as f32).collect();
        return Ok(VectorInternal::Dense(v));
    }
    if let Some(multi) = &q.multi {
        let dim = multi.first().map(|r| r.len()).unwrap_or(0);
        if dim == 0 || multi.iter().any(|r| r.len() != dim) {
            return Err(Error::from_reason(
                "multivector rows must be non-empty and equal length",
            ));
        }
        let flat: Vec<f32> = multi.iter().flatten().map(|x| *x as f32).collect();
        // MultiDenseVectorInternal = TypedMultiDenseVector<f32>; built from the
        // flattened row-major buffer + row dimension (MaxSim late-interaction).
        let mv = TypedMultiDenseVector::new(flat, dim);
        return Ok(VectorInternal::MultiDense(mv));
    }
    // sparse
    let indices = q
        .sparse_indices
        .clone()
        .ok_or_else(|| Error::from_reason("sparse_indices required for sparse query"))?;
    let values_f64 = q
        .sparse_values
        .clone()
        .ok_or_else(|| Error::from_reason("sparse_values required for sparse query"))?;
    if indices.len() != values_f64.len() {
        return Err(Error::from_reason(
            "sparse_indices and sparse_values must have equal length",
        ));
    }
    let values: Vec<f32> = values_f64.iter().map(|x| *x as f32).collect();
    let sv = SparseVector::new(indices, values).map_err(map_op_err)?;
    Ok(VectorInternal::Sparse(sv))
}

/// Build a `ScoringQuery::Vector(Nearest)` for a leg.
fn to_nearest(q: &NativeVectorQuery) -> Result<ScoringQuery> {
    let vector = to_vector_internal(q)?;
    let using = if q.using.is_empty() {
        None
    } else {
        Some(q.using.clone().into())
    };
    Ok(ScoringQuery::Vector(QueryEnum::Nearest(NamedQuery {
        query: vector,
        using,
    })))
}

fn parse_filter(filter_json: &Option<String>) -> Result<Option<Filter>> {
    match filter_json {
        None => Ok(None),
        Some(s) => {
            let f: Filter = serde_json::from_str(s)
                .map_err(|e| Error::from_reason(format!("invalid Filter JSON: {e}")))?;
            Ok(Some(f))
        }
    }
}

/// `SearchParams { exact: true }` when the request asks for the deterministic
/// full-scan path (CH-23), else `None` (ANN defaults). `SearchParams::default()`
/// has `exact=false`; we only attach params when exact is requested.
fn exact_params(req: &NativeQueryRequest) -> Option<SearchParams> {
    if req.exact.unwrap_or(false) {
        Some(SearchParams {
            exact: true,
            ..Default::default()
        })
    } else {
        None
    }
}

/// Collect an iterator of fallible scored-point mappings, propagating any
/// serialization error fail-closed. Extracted from `EdgeShardHandle::query()`
/// so the error-propagation contract can be tested by passing a failing
/// iterator to this real production function — without re-implementing the
/// collect pattern in the test.
pub(crate) fn collect_scored_points(
    iter: impl Iterator<Item = Result<NativeScoredPoint>>,
) -> Result<Vec<NativeScoredPoint>> {
    iter.collect()
}

/// Translate the NAPI request into a qdrant-edge `ShardQueryRequest`.
fn build_shard_query(req: &NativeQueryRequest) -> Result<ShardQueryRequest> {
    // Reject degenerate parameters before they reach the vector runtime.
    // limit=0 returns no results (caller almost certainly has a bug).
    // rrf_k=0 is only consulted when prefetches are non-empty (the fusion
    // path); reject it there because it changes RRF scoring from the
    // documented 1/(60+rank) baseline to 1/(0+rank), producing a different
    // rank distribution and violating the deterministic selection contract
    // (CH-23/§8.6).
    if req.limit == 0 {
        return Err(Error::from_reason("limit must be > 0"));
    }
    if !req.prefetches.is_empty() {
        if let Some(k) = req.rrf_k {
            if k == 0 {
                return Err(Error::from_reason(
                    "rrf_k must be > 0 (typical value: 60); 0 alters RRF scoring",
                ));
            }
        }
    }

    let with_payload = req.with_payload.unwrap_or(true).into();
    let root_filter = parse_filter(&req.filter_json)?;
    let params = exact_params(req);

    if req.prefetches.is_empty() {
        // Single-leg vector search.
        let q = req
            .query
            .as_ref()
            .ok_or_else(|| Error::from_reason("query required when prefetches is empty"))?;
        return Ok(ShardQueryRequest {
            prefetches: Vec::new(),
            query: Some(to_nearest(q)?),
            filter: root_filter,
            score_threshold: None,
            limit: req.limit as usize,
            offset: 0,
            params,
            with_vector: false.into(),
            with_payload,
        });
    }

    // Multi-leg hybrid → RRF fusion at the root.
    let k = req
        .rrf_k
        .ok_or_else(|| Error::from_reason("rrf_k required when prefetches is non-empty"))?;
    let weights = match &req.rrf_weights {
        None => None,
        Some(w) => {
            if w.len() != req.prefetches.len() {
                return Err(Error::from_reason(
                    "rrf_weights length must equal prefetches length",
                ));
            }
            Some(w.iter().map(|x| OrderedFloat(*x as f32)).collect())
        }
    };

    let mut prefetches = Vec::with_capacity(req.prefetches.len());
    for pf in &req.prefetches {
        prefetches.push(Prefetch {
            prefetches: Vec::new(),
            query: Some(to_nearest(&pf.query)?),
            limit: pf.limit as usize,
            params: params.clone(),
            filter: None,
            score_threshold: None,
        });
    }

    Ok(ShardQueryRequest {
        prefetches,
        query: Some(ScoringQuery::Fusion(Fusion::Rrf {
            k: k as usize,
            weights,
        })),
        filter: root_filter,
        score_threshold: None,
        limit: req.limit as usize,
        offset: 0,
        params: None,
        with_vector: false.into(),
        with_payload,
    })
}

/// One scored result returned to JS. `id` is stringified (point ids are
/// int/uuid/str); `payload` is the raw JSON payload (if requested).
#[napi(object)]
#[derive(Debug, Serialize)]
pub struct NativeScoredPoint {
    pub id: String,
    pub score: f64,
    pub version: i64,
    /// Payload as a JSON string (null if not requested / absent).
    pub payload_json: Option<String>,
}

#[napi]
impl EdgeShardHandle {
    /// Create a new edge shard at `path` with `config_json` (a serialized
    /// `EdgeConfig`). Fails if the path already contains segment data.
    #[napi(factory)]
    pub fn create(path: String, config_json: String) -> Result<Self> {
        let cfg: EdgeConfig = serde_json::from_str(&config_json)
            .map_err(|e| Error::from_reason(format!("invalid EdgeConfig JSON: {e}")))?;
        let shard = EdgeShard::new(&PathBuf::from(path), cfg).map_err(map_op_err)?;
        Ok(Self::from_shard(shard))
    }

    /// Load an existing edge shard from `path`. VERIFY-BEFORE-LOAD (§8.6) is
    /// ENFORCED here: the shard directory must contain the HMAC'd per-file
    /// digest manifest emitted by `edge_unpack_snapshot` in THIS process, and
    /// every file digest must still match. A directory that was not produced
    /// by a receipt-checked unpack (e.g. plaintext cached from a previous
    /// process, or files tampered at rest after unpack) fails closed — re-run
    /// `unseal_and_verify_snapshot` + `edge_unpack_snapshot` first.
    #[napi(factory)]
    pub fn load(path: String, config_json: Option<String>) -> Result<Self> {
        let cfg = parse_config(config_json)?;
        let dir = PathBuf::from(&path);
        verify_shard_manifest(&dir)?;
        let shard = EdgeShard::load(&dir, cfg).map_err(map_op_err)?;
        Ok(Self::from_shard(shard))
    }

    /// Upsert points. `points_json` is a JSON array of point objects
    /// `{id, vector, payload?}` in qdrant-edge `PointStructPersisted` shape
    /// (`vector` may be a dense array, a `{indices,values}` sparse object,
    /// `[[...]]` multivector, or a named map). Insert-or-update semantics.
    #[napi]
    pub fn upsert(&self, points_json: String) -> Result<()> {
        let points: Vec<PointStructPersisted> = serde_json::from_str(&points_json)
            .map_err(|e| Error::from_reason(format!("invalid points JSON: {e}")))?;
        let op = UpdateOperation::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperations::PointsList(points),
        ));
        // Gate against flush(): EdgeShard::update holds the WAL lock for the
        // whole upsert, and EdgeShard::flush try_lock().expect()s it — see
        // `flush_gate` docs.
        let _gate = self.gate();
        self.shard()?.update(op).map_err(map_op_err)
    }

    /// Delete points by their canonical ids. This is the mutation primitive
    /// used by the atomic adapter-delta publisher: unchanged points remain in
    /// the loaded shard; only the changed adapter's ids are removed/upserted.
    #[napi]
    pub fn delete_points(&self, ids_json: String) -> Result<()> {
        let ids: Vec<PointId> = serde_json::from_str(&ids_json)
            .map_err(|e| Error::from_reason(format!("invalid point-id JSON: {e}")))?;
        let op = UpdateOperation::PointOperation(PointOperations::DeletePoints { ids });
        let _gate = self.gate();
        self.shard()?.update(op).map_err(map_op_err)
    }

    /// Run a hybrid query. Returns scored points (highest score first, as
    /// produced by Edge). See `NativeQueryRequest`.
    #[napi]
    pub fn query(&self, request: NativeQueryRequest) -> Result<Vec<NativeScoredPoint>> {
        let shard_req = build_shard_query(&request)?;
        let scored = self.shard()?.query(shard_req).map_err(map_op_err)?;
        // Delegate the fallible collect to `collect_scored_points` so the
        // error-propagation contract (fail-closed, never "" fail-open) is tested
        // against the real production function.
        collect_scored_points(scored.into_iter().map(|p| -> Result<NativeScoredPoint> {
            let payload_json = p
                .payload
                .as_ref()
                .map(|pl| {
                    serde_json::to_string(pl).map_err(|e| {
                        Error::from_reason(format!("payload serialization failed: {e}"))
                    })
                })
                .transpose()?;
            Ok(NativeScoredPoint {
                id: p.id.to_string(),
                score: p.score as f64,
                version: p.version as i64,
                payload_json,
            })
        }))
    }

    /// Flush WAL + segments to disk. Returns an error if the flush panics
    /// internally (qdrant-edge surfaces I/O errors via `expect`/panic rather
    /// than `Result`; we catch those at the NAPI boundary so a flush failure
    /// does not crash the Node.js process). Transient lock contention with an
    /// in-flight update is surfaced as a distinct retryable "EdgeShard busy"
    /// error, never misreported as an I/O flush failure.
    #[napi]
    pub fn flush(&self) -> Result<()> {
        // Gate against upsert(): serializing here means EdgeShard::flush's
        // internal try_lock never observes contention from this handle.
        let _gate = self.gate();
        let inner = Arc::clone(self.shard()?);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || inner.flush())).map_err(|e| {
            let msg = panic_msg(&e);
            // qdrant-edge flush() panics with these exact expect() messages
            // on try_lock contention — a transient scheduling condition,
            // NOT an I/O failure. Classify as retryable busy.
            if msg.contains("WAL lock acquired") || msg.contains("segment holder lock acquired") {
                Error::from_reason(format!(
                    "EdgeShard busy: flush contended with an in-flight operation, retry ({msg})"
                ))
            } else {
                Error::from_reason(format!("EdgeShard flush failed: {msg}"))
            }
        })
    }

    /// Number of points in the shard (from shard info).
    #[napi]
    pub fn points_count(&self) -> Result<i64> {
        let info = self.shard()?.info();
        Ok(info.points_count as i64)
    }

    /// Release a producer's private shard before deleting its staging tree.
    /// GC otherwise performs a drop-flush after the files have disappeared.
    #[napi]
    pub fn close(&mut self) -> Result<()> {
        let _gate = self.flush_gate.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(inner) = self.inner.take() {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(inner)))
                .map_err(|e| Error::from_reason(format!("EdgeShard close failed: {}", panic_msg(&e))))?;
        }
        Ok(())
    }

    /// Return the snapshot manifest as a JSON string (for co-version /
    /// integrity checks at freeze time).
    #[napi]
    pub fn snapshot_manifest_json(&self) -> Result<String> {
        let manifest = self.shard()?.snapshot_manifest().map_err(map_op_err)?;
        serde_json::to_string(&manifest)
            .map_err(|e| Error::from_reason(format!("failed to serialize manifest: {e}")))
    }
}

// ── §8.6 verify-before-load enforcement (receipt + digest manifest) ──────

/// Name of the HMAC'd per-file digest manifest `edge_unpack_snapshot` writes
/// into the unpacked shard directory and `EdgeShardHandle::load` requires.
const VERIFY_MANIFEST_FILE: &str = ".chariot-verify-manifest.json";

/// SHA-256 (hex) of every regular file under `root`, keyed by root-relative
/// path (the verify manifest itself is excluded). BTreeMap → deterministic
/// serialization for the HMAC.
fn collect_file_digests(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::from_reason(format!("cannot walk shard directory: {e}")))?
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| Error::from_reason(format!("path outside shard root: {e}")))?
            .to_string_lossy()
            .to_string();
        if rel == VERIFY_MANIFEST_FILE {
            continue;
        }
        let bytes = std::fs::read(entry.path())
            .map_err(|e| Error::from_reason(format!("cannot read shard file {rel}: {e}")))?;
        map.insert(
            rel,
            crate::edge_snapshot::hex_encode(&Sha256::digest(&bytes)),
        );
    }
    Ok(map)
}

/// Write the HMAC'd digest manifest for a freshly unpacked shard directory.
fn write_shard_manifest(root: &Path) -> Result<()> {
    let files = collect_file_digests(root)?;
    let files_json = serde_json::to_string(&files)
        .map_err(|e| Error::from_reason(format!("manifest serialization failed: {e}")))?;
    let manifest = serde_json::json!({
        "files": files,
        "hmac": crate::edge_snapshot::process_hmac_hex(files_json.as_bytes()),
    });
    std::fs::write(
        root.join(VERIFY_MANIFEST_FILE),
        serde_json::to_vec(&manifest)
            .map_err(|e| Error::from_reason(format!("manifest serialization failed: {e}")))?,
    )
    .map_err(|e| Error::from_reason(format!("cannot write verify manifest: {e}")))
}

/// Fail-closed §8.6 gate for `EdgeShardHandle::load`: require the manifest,
/// require its HMAC (process-local key — a manifest from another process
/// never verifies, forcing re-unseal on restart), and require every file
/// digest to still match (tamper-at-rest detection).
fn verify_shard_manifest(root: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(root.join(VERIFY_MANIFEST_FILE)).map_err(|e| {
        Error::from_reason(format!(
            "verify-before-load (§8.6): missing or unreadable {VERIFY_MANIFEST_FILE} in shard \
             directory — this shard was not produced by a receipt-checked edge_unpack_snapshot \
             in this process; re-run unseal_and_verify_snapshot + edge_unpack_snapshot: {e}"
        ))
    })?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| Error::from_reason(format!("verify manifest is corrupt: {e}")))?;
    let files: BTreeMap<String, String> =
        serde_json::from_value(v.get("files").cloned().unwrap_or(serde_json::Value::Null))
            .map_err(|e| Error::from_reason(format!("verify manifest is corrupt: {e}")))?;
    let hmac = v.get("hmac").and_then(|h| h.as_str()).unwrap_or("");
    let files_json = serde_json::to_string(&files)
        .map_err(|e| Error::from_reason(format!("manifest serialization failed: {e}")))?;
    if !crate::edge_snapshot::constant_time_eq_str(
        &crate::edge_snapshot::process_hmac_hex(files_json.as_bytes()),
        hmac,
    ) {
        return Err(Error::from_reason(
            "verify-before-load (§8.6): shard verify manifest HMAC mismatch — the manifest was \
             not produced by this process (stale plaintext from a previous run, or tampered); \
             re-run unseal_and_verify_snapshot + edge_unpack_snapshot",
        ));
    }
    let actual = collect_file_digests(root)?;
    if actual != files {
        return Err(Error::from_reason(
            "verify-before-load (§8.6): shard files do not match the verified digest manifest \
             (added/removed/modified since unpack) — refusing to load; re-run \
             unseal_and_verify_snapshot + edge_unpack_snapshot",
        ));
    }
    Ok(())
}

/// Unpack a plaintext Edge snapshot archive at `snapshot_path` into
/// `target_path`. STATIC because it operates on files, not a live shard.
///
/// §8.6 verify-before-load, ENFORCED: `receipt` must be the value returned by
/// `unseal_and_verify_snapshot` / `unseal_and_verify_snapshot_to_file` for
/// these exact archive bytes. The receipt is recomputed over the file at
/// `snapshot_path` BEFORE anything is unpacked; an archive that did not pass
/// unseal+verify in this process fails closed. After unpacking, an HMAC'd
/// per-file digest manifest is written into `target_path`, which
/// `EdgeShardHandle::load` requires and re-verifies.
#[napi]
pub fn edge_unpack_snapshot(
    snapshot_path: String,
    target_path: String,
    receipt: String,
) -> Result<()> {
    let snap = PathBuf::from(&snapshot_path);
    let bytes = std::fs::read(&snap)
        .map_err(|e| Error::from_reason(format!("cannot read snapshot archive: {e}")))?;
    if !crate::edge_snapshot::verify_unseal_receipt(&bytes, &receipt) {
        return Err(Error::from_reason(
            "verify-before-load (§8.6): snapshot receipt verification failed — the archive at \
             snapshot_path is not the exact bytes produced by unseal_and_verify_snapshot in \
             this process; refusing to unpack",
        ));
    }
    let target = PathBuf::from(&target_path);
    EdgeShard::unpack_snapshot(&snap, &target).map_err(map_op_err)?;
    write_shard_manifest(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_request(limit: u32) -> NativeQueryRequest {
        NativeQueryRequest {
            prefetches: vec![],
            query: Some(NativeVectorQuery {
                using: "dense".to_string(),
                dense: Some(vec![0.1, 0.2, 0.3]),
                sparse_indices: None,
                sparse_values: None,
                multi: None,
            }),
            limit,
            rrf_k: None,
            rrf_weights: None,
            with_payload: None,
            filter_json: None,
            exact: None,
        }
    }

    /// limit=0 must be rejected before the query reaches qdrant-edge.
    #[test]
    fn limit_zero_rejected() {
        let req = minimal_request(0);
        let r = build_shard_query(&req);
        assert!(r.is_err(), "limit=0 must be rejected");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("limit"),
            "error must mention 'limit', got: {msg}"
        );
    }

    /// rrf_k=0 must be rejected when prefetches are present.
    #[test]
    fn rrf_k_zero_rejected() {
        let leg = NativePrefetch {
            query: NativeVectorQuery {
                using: "dense".to_string(),
                dense: Some(vec![0.1, 0.2, 0.3]),
                sparse_indices: None,
                sparse_values: None,
                multi: None,
            },
            limit: 10,
        };
        let req = NativeQueryRequest {
            prefetches: vec![leg],
            query: None,
            limit: 5,
            rrf_k: Some(0), // invalid
            rrf_weights: None,
            with_payload: None,
            filter_json: None,
            exact: None,
        };
        let r = build_shard_query(&req);
        assert!(r.is_err(), "rrf_k=0 must be rejected");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("rrf_k"),
            "error must mention 'rrf_k', got: {msg}"
        );
    }

    /// rrf_k=0 when no prefetches are present (not consulted) must pass
    /// limit validation and fail only on missing query, not on rrf_k.
    #[test]
    fn rrf_k_zero_ignored_without_prefetches() {
        let mut req = minimal_request(5);
        req.rrf_k = Some(0); // set but irrelevant — no prefetches
                             // Should not be rejected on rrf_k; the query is present so it would
                             // reach the single-leg path. Just check it does not error on rrf_k.
                             // (It may still succeed or error on EdgeShard; we only care that the
                             // rrf_k=0 guard is NOT triggered when prefetches is empty.)
        let r = build_shard_query(&req);
        // Error, if any, must NOT mention rrf_k (it may mention other things).
        if let Err(ref e) = r {
            let msg = e.to_string();
            assert!(
                !msg.contains("rrf_k"),
                "rrf_k guard must not fire without prefetches; got: {msg}"
            );
        }
    }

    /// Drive `collect_scored_points` — the real production function called by
    /// `EdgeShardHandle::query()` — with an injected failing row and assert the
    /// error propagates fail-closed. The pre-fix `unwrap_or_default()` would have
    /// returned Ok(vec![..., ""]) for the failing slot; the fixed
    /// `collect_scored_points` must return Err.
    #[test]
    fn serialization_error_propagates_not_silenced() {
        // Build a realistic sequence: two valid points bookending one failure —
        // exactly the shape the map() in query() produces when serde_json::to_string
        // fails on a payload value (e.g. a float NaN in a custom qdrant Value).
        let rows: Vec<Result<NativeScoredPoint>> = vec![
            Ok(NativeScoredPoint {
                id: "1".to_string(),
                score: 0.95_f64,
                version: 1,
                payload_json: Some(r#"{"tool":"alpha"}"#.to_string()),
            }),
            // Injected serialization failure — the unwrap_or_default() path would
            // have silently replaced this with payload_json: Some("".to_string()).
            Err(Error::from_reason(
                "payload serialization failed: value not JSON-encodable",
            )),
            Ok(NativeScoredPoint {
                id: "3".to_string(),
                score: 0.70_f64,
                version: 1,
                payload_json: None,
            }),
        ];
        // Call the REAL production function — not a re-implemented collect.
        let result = collect_scored_points(rows.into_iter());
        assert!(
            result.is_err(),
            "collect_scored_points must propagate a serialization failure, never fail-open"
        );
        let msg = result.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("payload serialization failed"),
            "propagated error must preserve the original message; got: {msg}"
        );
    }

    /// Real EdgeShard end-to-end: create a 4-d dense shard, upsert points with
    /// payload, query exact nearest, verify the collect::<Result<Vec<_>>>() path
    /// works on real qdrant-edge scored points, and confirm that flush succeeds
    /// then returns Err when the shard directory is made read-only (I/O failure
    /// is surfaced as napi::Error, not a process crash).
    ///
    /// Cleanup ordering is explicit: restore permissions → drop the handle inside
    /// catch_unwind (EdgeShard::Drop calls flush; the directory must be writable
    /// and present) → remove the directory.
    #[test]
    fn real_shard_roundtrip_and_flush_io_error() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let base = format!(
            "/tmp/chariot-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let shard_path = format!("{}/shard", base);
        fs::create_dir_all(&shard_path).expect("create shard dir");

        // Config mirrors the smoke test (4-d dense cosine, in-memory payload).
        let config_json =
            r#"{"vectors":{"dense":{"size":4,"distance":"Cosine"}},"on_disk_payload":false}"#;
        let handle = EdgeShardHandle::create(shard_path.clone(), config_json.to_string())
            .expect("EdgeShardHandle::create must succeed");

        // Upsert three points with payload — exercises the upsert → serde path.
        let points_json = r#"[
            {"id":1,"vector":{"dense":[1.0,0.0,0.0,0.0]},"payload":{"tool":"alpha","rank":1}},
            {"id":2,"vector":{"dense":[0.0,1.0,0.0,0.0]},"payload":{"tool":"beta","rank":2}},
            {"id":3,"vector":{"dense":[0.9,0.1,0.0,0.0]},"payload":{"tool":"gamma","rank":3}}
        ]"#;
        handle
            .upsert(points_json.to_string())
            .expect("upsert must succeed");
        assert_eq!(
            handle.points_count().expect("points_count"),
            3,
            "3 points must be stored"
        );

        // Exact single-leg query: nearest to [1,0,0,0] must be point 1.
        let req = NativeQueryRequest {
            prefetches: vec![],
            query: Some(NativeVectorQuery {
                using: "dense".to_string(),
                dense: Some(vec![1.0, 0.0, 0.0, 0.0]),
                sparse_indices: None,
                sparse_values: None,
                multi: None,
            }),
            limit: 3,
            rrf_k: None,
            rrf_weights: None,
            with_payload: Some(true),
            filter_json: None,
            exact: Some(true),
        };
        let results = handle.query(req).expect("query must succeed");
        assert_eq!(results.len(), 3, "exact query must return all 3 points");
        assert_eq!(results[0].id, "1", "nearest to [1,0,0,0] must be point 1");

        // Payload must survive the collect::<Result<Vec<_>>>() round-trip.
        let top_payload = results[0]
            .payload_json
            .as_deref()
            .expect("payload must be present for the top hit");
        let parsed: serde_json::Value =
            serde_json::from_str(top_payload).expect("payload_json must be valid JSON");
        assert_eq!(
            parsed["tool"].as_str(),
            Some("alpha"),
            "payload field 'tool' must survive the serde round-trip; got: {top_payload}"
        );

        // Initial flush in normal conditions must succeed (writes WAL data to
        // segment files under shard/segments/<uuid>/).
        handle.flush().expect("initial flush must succeed");

        // Lock the segment UUID directories so flush cannot create atomic temp
        // files. qdrant-edge writes segment data by creating a temp file inside
        // each segment UUID dir (observed: ".../segments/<uuid>/.atomicwriteXXX"),
        // then renaming it atomically. chmod 555 on those subdirs causes mkstemp
        // to fail with EACCES; qdrant-edge's expect() panics; catch_unwind in
        // EdgeShardHandle::flush() catches the panic and returns napi::Error.
        //
        // We lock the UUID dirs specifically (not the top-level shard/ dir) so the
        // WAL directory remains writable and upsert can produce dirty data.
        let segments_dir = format!("{}/segments", shard_path);
        let locked_uuid_dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&segments_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| {
                fs::set_permissions(e.path(), fs::Permissions::from_mode(0o555))
                    .ok()
                    .map(|_| e.path())
            })
            .collect();

        let io_flush_result: Option<Result<()>> = if !locked_uuid_dirs.is_empty() {
            // Upsert a new point so WAL has unflushed data the next flush must
            // migrate to the (now-locked) segment dirs.
            handle
                .upsert(
                    r#"[{"id":4,"vector":{"dense":[0.0,0.0,1.0,0.0]},"payload":{"tool":"delta"}}]"#
                        .to_string(),
                )
                .expect("upsert must succeed — WAL dir is still writable");
            Some(handle.flush())
        } else {
            None
        };

        // Restore segment UUID dir permissions before the handle drops, so that
        // EdgeShard::Drop's internal flush can succeed.
        for dir in &locked_uuid_dirs {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
        }

        // Explicitly drop the handle inside catch_unwind — guards against any
        // residual panic from partial flush state.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(handle)));

        // Directory is now safe to remove (handle fully dropped, all fds closed).
        let _ = fs::remove_dir_all(&base);

        // qdrant-edge panics when mkstemp fails inside a locked segment UUID dir.
        // EdgeShardHandle::flush()'s catch_unwind must surface that panic as
        // napi::Error — never unwind through the NAPI frame and crash Node.js.
        let flush_err = io_flush_result
            .expect("segment UUID dirs were locked so flush was attempted")
            .err()
            .expect(
                "flush with locked segment dirs must return Err — \
                 catch_unwind must convert the qdrant-edge panic to napi::Error",
            );
        let msg = flush_err.to_string();
        assert!(
            msg.contains("EdgeShard flush failed"),
            "napi::Error must identify the flush context; got: {msg}"
        );
    }

    /// Build a small real shard on disk and return its path (handle dropped,
    /// files flushed).
    fn build_shard_dir(tag: &str) -> String {
        use std::fs;
        let base = format!(
            "/tmp/chariot-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let shard_path = format!("{}/shard", base);
        fs::create_dir_all(&shard_path).expect("create shard dir");
        let config_json =
            r#"{"vectors":{"dense":{"size":4,"distance":"Cosine"}},"on_disk_payload":false}"#;
        let handle = EdgeShardHandle::create(shard_path.clone(), config_json.to_string())
            .expect("create shard");
        handle
            .upsert(
                r#"[{"id":1,"vector":{"dense":[1.0,0.0,0.0,0.0]},"payload":{"tool":"alpha"}}]"#
                    .to_string(),
            )
            .expect("upsert");
        handle.flush().expect("flush");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(handle)));
        shard_path
    }

    /// §8.6 verify-before-load is ENFORCED: loading a shard directory that
    /// was not produced by a receipt-checked unpack (no verify manifest)
    /// must fail closed — even though the shard files themselves are valid.
    #[test]
    fn load_without_verify_manifest_fails_closed() {
        let shard_path = build_shard_dir("vbl");
        let r = EdgeShardHandle::load(shard_path.clone(), None);
        assert!(r.is_err(), "load without verify manifest must fail closed");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("verify-before-load"),
            "error must identify the §8.6 gate; got: {msg}"
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(&shard_path).parent().unwrap());
    }

    /// A shard directory blessed by `write_shard_manifest` loads; tampering
    /// any file after blessing fails closed at the digest check.
    #[test]
    fn manifest_roundtrip_then_tamper_fails_closed() {
        use std::io::Write;
        let shard_path = build_shard_dir("mrt");
        let root = std::path::PathBuf::from(&shard_path);

        write_shard_manifest(&root).expect("bless shard dir");
        {
            let loaded = EdgeShardHandle::load(shard_path.clone(), None)
                .expect("manifest-blessed shard must load");
            assert_eq!(loaded.points_count().expect("points"), 1);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(loaded)));
        }

        // Tamper one manifest-covered file (append a byte) → load must fail
        // closed BEFORE qdrant-edge opens anything.
        let digests = collect_file_digests(&root).expect("collect");
        let victim = digests.keys().next().expect("shard has files").clone();
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(root.join(&victim))
                .expect("open victim file");
            f.write_all(b"x").expect("tamper");
        }
        let r = EdgeShardHandle::load(shard_path.clone(), None);
        assert!(r.is_err(), "tampered shard must fail closed");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("do not match the verified digest manifest"),
            "error must identify the digest mismatch; got: {msg}"
        );
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    /// edge_unpack_snapshot must refuse an archive whose bytes do not carry a
    /// valid process-local unseal receipt — BEFORE touching the target.
    #[test]
    fn unpack_rejects_missing_or_forged_receipt() {
        let base = format!(
            "/tmp/chariot-rcpt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        std::fs::create_dir_all(&base).expect("mkdir");
        let snap = format!("{}/snap.archive", base);
        std::fs::write(&snap, b"not-a-verified-archive").expect("write");

        let r = edge_unpack_snapshot(
            snap.clone(),
            format!("{}/target", base),
            "deadbeef".to_string(),
        );
        assert!(r.is_err(), "forged receipt must be rejected");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("receipt verification failed"),
            "error must identify the receipt gate; got: {msg}"
        );
        assert!(
            !std::path::Path::new(&format!("{}/target", base)).exists()
                || std::fs::read_dir(format!("{}/target", base))
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(true),
            "nothing may be unpacked on receipt failure"
        );

        // A correct receipt over the same bytes passes the gate (it then
        // fails later inside qdrant-edge because the bytes are not a real
        // archive — but the failure must NOT be the receipt gate).
        // catch_unwind because qdrant-edge may surface archive-parse
        // failures as panics rather than Err.
        let receipt = crate::edge_snapshot::compute_unseal_receipt(b"not-a-verified-archive");
        let target2 = format!("{}/target2", base);
        let r2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            edge_unpack_snapshot(snap.clone(), target2.clone(), receipt.clone())
        }));
        if let Ok(Err(e)) = r2 {
            let msg2 = e.to_string();
            assert!(
                !msg2.contains("receipt verification failed"),
                "valid receipt must pass the gate; got: {msg2}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
