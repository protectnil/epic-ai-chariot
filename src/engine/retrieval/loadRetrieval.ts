/**
 * @epicai/chariot — Retrieval load path (§4.3 / §4.4 / §8.6 / 4.6)
 *
 * Decides, at startup, whether Tier-1 runs the 4.0.0 HYBRID stack (BM25 + dense
 * + SPLADE over the in-process EdgeShard, RRF + cross-encoder rerank) or the
 * BM25-only steady state, and fails closed when a hybrid bundle is present but
 * does not satisfy the compiled-in contract.
 *
 * The decision (per §4.4 failure-mode table):
 *   - No `manifest` in the bundle envelope → BM25-only (a legacy/3.1.x bundle
 *     carries no retrieval contract; the lexical path is the correct behavior).
 *   - Manifest present → VectorIndexVerifier.admit() runs FIRST. A manifest
 *     mismatch / serializer divergence / failed signature / replay / downgrade /
 *     CH-35 gate failure is FAIL-CLOSED: no routing begins (ERROR at startup).
 *     There is never a silent fallback to a different model.
 *   - Manifest ADMITTED but the native Edge module / dense encoder artifact is
 *     missing or fails to load → FAIL-CLOSED at startup, ERROR logged, no
 *     routing begins (§4.4 row 2 / §4.1, AMENDED 2026-07-16b: there is NO BM25
 *     fallback for a bundle whose encoder artifact cannot load at startup).
 *     The BM25-only degradation applies only to a RUNTIME select() throw on an
 *     already-loaded bundle (§4.4 row 3, handled by `HybridRetriever`'s
 *     try/catch), never to a startup load failure.
 *   - Manifest admitted AND encoders load → HYBRID; the accepted
 *     `{epoch, catalogVersion}` is persisted atomically (§5.6) BEFORE the
 *     retriever is advertised.
 *
 * The shard unseal/verify (AES-256-GCM + Ed25519, Chariot-side wrapper, §8.6)
 * and the dense-model bytes are provided by the injected `ArtifactSource`, so
 * the decision logic is unit-tested with fakes; the disk-backed source and the
 * real sealed bundle + BIEN ONNX + SPLADE land in P5/P8.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { HybridRetriever, type HybridRetrieverConfig, type RetrieverLogger } from './HybridRetriever.js';
import { CompositeEdgeShard } from './overlay/CompositeEdgeShard.js';
import {
  VectorIndexVerifier,
  type BundleEnvelope,
  type AdmissionCode,
} from './VectorIndexVerifier.js';
import type {
  NativeEdgeBinding,
  NativeEdgeShard,
  NativeDenseEncoder,
} from './nativeEdge.js';
import type { QuerySerializer, SparseQueryEncoder } from './types.js';
import { CrossEncoderReranker } from './CrossEncoderReranker.js';
import type { RerankScorer } from './types.js';
import type { CatalogEpochState } from '../federation/AdapterCatalog.js';

/**
 * Supplies the loaded, verified retrieval artifacts, never a partial/unsafe
 * object. `loadShard`/`loadDenseEncoder` returning null is a STARTUP
 * fail-closed load error (§4.4 row 2 / §4.1, amended 2026-07-16b — NO BM25
 * fallback); `loadSparseEncoder`/`loadRerankScorer` returning null are
 * optional legs that stay inside the hybrid path (sparse/rerank absence
 * degrades gracefully, it does not block startup). The shard accessor is
 * responsible for the Chariot-side unseal+verify (native
 * `unsealAndVerifySnapshot`) + unpack + `EdgeShardHandle.load` before
 * returning a live shard (§8.6 guardrail).
 */
export interface ArtifactSource {
  /** Unseal+verify+unpack+load the sealed EdgeShard snapshot, or null. */
  loadShard(): NativeEdgeShard | null;
  /** Load the in-process BIEN dense encoder from bundle bytes, or null. */
  loadDenseEncoder(): NativeDenseEncoder | null;
  /** SPLADE query encoder, or null until the native sparse path lands. */
  loadSparseEncoder(): SparseQueryEncoder | null;
  /** Cross-encoder rerank scorer (BIEN M10), or null until it lands. */
  loadRerankScorer(): RerankScorer | null;
  /** Lockstep query serializer (native `serializeQuery`). */
  querySerializer(): QuerySerializer;
  /**
   * §8.6a on-device overlay shard resolver (BIEN::§9::14), PER REQUESTING
   * TENANT (gate finding D1 — a static list/array is wrong here: it would
   * either never populate, since overlay shards open lazily on first embed
   * long after this one-time startup wiring runs, or expose every tenant's
   * overlay to every query). Returns the SPECIFIC tenant's overlay shard,
   * or `null` when that tenant has none (never creates one on a query — see
   * `OverlayEmbedder.ts::NativeOverlayEmbedder.getOverlayShard`, the
   * intended implementation of this accessor). OPTIONAL and additive: a
   * source that does not implement it leaves retrieval byte-identical to
   * the pre-overlay single-shard path — `wireHybridRetrieval` below wraps
   * `shard` in a `CompositeEdgeShard` only when this accessor exists at
   * all (the composite itself falls back to sealed-only per-query when a
   * given tenant, or no tenant, has an overlay).
   */
  overlayShardFor?(tenantId: string): NativeEdgeShard | null;
  /**
   * Gate-round-3 finding E1(b) — "the overlay is never CORRECTED, only
   * grown": the native shard has no delete, so a stale tool a re-embed
   * dropped stays physically retrievable from `overlayShardFor`'s own
   * shard. This accessor supplies `CompositeEdgeShard`'s per-tenant
   * stale-point filter — see `OverlayEmbedder.ts::
   * NativeOverlayEmbedder.liveOverlayToolIds`, the intended
   * implementation. OPTIONAL, but always paired with `overlayShardFor` in
   * practice (both come from the same wired `NativeOverlayEmbedder`) —
   * when `overlayShardFor` is set and this is not, `wireHybridRetrieval`
   * supplies a fail-closed default that treats every overlay point as
   * stale (drops everything) rather than surface unverified freshness.
   */
  overlayLiveToolIds?(tenantId: string): ReadonlySet<string> | null;
  /**
   * §8.6a determinism extension (CHARIOT-SPEC.md:763/:767) — surfaces the
   * wired overlay embedder's PER-TENANT `overlayStateHash` accessor
   * (gate finding D2) onto `RetrievalOutcome.overlayStateHash` for the
   * REQUESTING tenant only. Returns `undefined` when that tenant has no
   * overlay.
   */
  overlayStateHash?(tenantId: string): string | undefined;
}

export interface WireRetrievalOptions {
  envelope: BundleEnvelope;
  /** Result of the Ed25519 envelope-signature check at the file boundary. */
  signatureVerified: boolean;
  /**
   * SHA-256 (hex) of the exact signature-verified envelope bytes. Identity-
   * binds the §5.6 anti-rollback mark so re-admitting the IDENTICAL bundle
   * across a restart is an idempotent no-op instead of a permanent
   * epoch_replay_rejected boot brick, while any other bundle at <= the
   * persisted epoch stays rejected. Compute it from the same bytes that
   * passed the signature check (verifiedReadFailClosed).
   */
  bundleSha256?: string;
  persisted: CatalogEpochState | null;
  persist: (state: CatalogEpochState) => void;
  native: NativeEdgeBinding | null;
  artifacts: ArtifactSource | null;
  verifier?: VectorIndexVerifier;
  config?: HybridRetrieverConfig;
  logger?: RetrieverLogger;
}

export type WireResult =
  | { mode: 'hybrid'; retriever: HybridRetriever }
  | { mode: 'bm25-only'; reason: string }
  | { mode: 'fail-closed'; reason: string; code: AdmissionCode };

/** True when the envelope carries a retrieval manifest (a 4.0.0 hybrid bundle). */
function hasManifest(envelope: BundleEnvelope): boolean {
  return !!envelope && typeof envelope === 'object' && envelope.manifest != null && typeof envelope.manifest === 'object';
}

/**
 * Decide the Tier-1 retrieval mode for a loaded bundle. Pure except for the
 * `persist` side effect on admit (atomic §5.6 write performed by the caller's
 * injected function). The caller attaches the retriever on `hybrid`, logs and
 * continues on `bm25-only`, and aborts startup on `fail-closed`.
 */
export function wireHybridRetrieval(opts: WireRetrievalOptions): WireResult {
  const { envelope, logger } = opts;

  // Legacy / 3.1.x bundle with no retrieval contract → BM25-only.
  if (!hasManifest(envelope)) {
    return { mode: 'bm25-only', reason: 'bundle carries no retrieval manifest (BM25-only)' };
  }

  const verifier = opts.verifier ?? new VectorIndexVerifier();
  const nativeSerializerHash = opts.native?.frozenSerializerHash();
  const admission = verifier.admit(envelope, {
    persisted: opts.persisted,
    signatureVerified: opts.signatureVerified,
    ...(nativeSerializerHash !== undefined ? { nativeSerializerHash } : {}),
    ...(opts.bundleSha256 !== undefined ? { bundleSha256: opts.bundleSha256 } : {}),
    ...(logger ? { logger } : {}),
  });

  // Fail-closed on ANY contract/anti-rollback/agent-field failure (§4.4 ERROR).
  if (!admission.admitted) {
    // §5.6: a replay/downgrade rejection (epoch <= persisted_epoch without
    // proven identity) MUST additionally log the exact spec-named event
    // `catalog.epoch_replay_rejected` carrying `{bundleEpoch, persistedEpoch,
    // reason}` — the generic `retrieval.bundle_rejected {code, reason}` log
    // below does not name the epoch values and is not a substitute.
    if (admission.code === 'epoch_replay_rejected') {
      logger?.warn('catalog.epoch_replay_rejected', {
        bundleEpoch: (envelope as { epoch?: number }).epoch,
        persistedEpoch: opts.persisted?.epoch,
        reason: admission.reason,
      });
    }
    logger?.warn('retrieval.bundle_rejected', { code: admission.code, reason: admission.reason });
    return { mode: 'fail-closed', reason: admission.reason, code: admission.code };
  }

  // §4.4 row 2 / §4.1 (AMENDED 2026-07-16b): encoder/native artifact missing or
  // failing to LOAD AFTER manifest admission is a STARTUP fail-closed load
  // error — "there is NO BM25 fallback for a bundle whose encoder artifact
  // cannot load" — NOT a degradation. This is distinct from §4.4 row 3, the
  // RUNTIME select()-throws-on-an-already-loaded-bundle case handled by
  // HybridRetriever's try/catch, which DOES degrade to BM25. Startup must
  // block here with an ERROR log, never a WARN-and-continue.
  if (!opts.native || !opts.artifacts) {
    logger?.error('retrieval.encoder_unavailable', {
      reason: 'manifest verified but native module / artifacts unavailable; fail-closed (§4.4 row 2, no BM25 fallback)',
    });
    return {
      mode: 'fail-closed',
      reason: 'manifest verified; native module/artifacts unavailable at startup (§4.4 row 2 — fail-closed, no BM25 fallback)',
      code: 'encoder_load_failed',
    };
  }

  const shard = opts.artifacts.loadShard();
  const denseEncoder = opts.artifacts.loadDenseEncoder();
  if (!shard || !denseEncoder) {
    logger?.error('retrieval.encoder_unavailable', {
      reason: 'shard or dense encoder failed to load; fail-closed (§4.4 row 2, no BM25 fallback)',
    });
    return {
      mode: 'fail-closed',
      reason: 'shard/dense encoder failed to load at startup (§4.4 row 2 — fail-closed, no BM25 fallback)',
      code: 'encoder_load_failed',
    };
  }

  const sparseEncoder: SparseQueryEncoder | null = opts.artifacts.loadSparseEncoder();
  const rerankScorer = opts.artifacts.loadRerankScorer();
  const reranker = rerankScorer ? new CrossEncoderReranker(rerankScorer) : null;

  // §8.6a / BIEN::§9::14 (gate finding D1) — fan EVERY query out, PER
  // REQUESTING TENANT, to that tenant's overlay shard alongside the sealed
  // catalog shard ("queryable together without a separate index or
  // re-embedding step"). Wrapping is unconditional whenever the source
  // implements `overlayShardFor` at all — resolution happens per-query
  // inside `CompositeEdgeShard`, not here, so an ArtifactSource with no
  // `overlayShardFor` leaves `queryShard` byte-identical to the pre-overlay
  // `shard`, and one that DOES implement it but has no overlay for a given
  // tenant (or a query with no tenant at all) falls back to sealed-only
  // per that same per-query resolution — never a static, once-computed list.
  const queryShard = opts.artifacts.overlayShardFor
    ? new CompositeEdgeShard(
        shard,
        opts.artifacts.overlayShardFor.bind(opts.artifacts),
        // E1(b) fail-closed default: an ArtifactSource that wires
        // `overlayShardFor` without `overlayLiveToolIds` gets "no liveness
        // answer for anyone" — CompositeEdgeShard's own contract for that
        // is to drop every checkable overlay point, never to trust
        // unverified freshness.
        opts.artifacts.overlayLiveToolIds
          ? opts.artifacts.overlayLiveToolIds.bind(opts.artifacts)
          : () => null,
      )
    : shard;

  const retriever = new HybridRetriever(
    {
      shard: queryShard,
      serializeQuery: opts.artifacts.querySerializer(),
      denseEncoder,
      sparseEncoder,
      reranker,
      ...(logger ? { logger } : {}),
      ...(opts.artifacts.overlayStateHash ? { overlayStateHash: opts.artifacts.overlayStateHash.bind(opts.artifacts) } : {}),
    },
    opts.config ?? {},
  );

  // Persist the accepted epoch high-water mark only on the FULL-admission path
  // (native present, encoders loaded, retriever being advertised). Persisting
  // earlier (on admit alone) advances the epoch before the hybrid stack is
  // live.
  //
  // `nextEpochState` is present ONLY on an advance: the verifier omits it on a
  // re-admission because a re-admission is not a publication and the mark
  // SHALL NOT be rewritten (CHARIOT-SPEC.md:431, :457). There is deliberately
  // no equality test here any more — the previous one also silently upgraded a
  // legacy hash-less record by writing an unproven bundle's hash onto it, which
  // CHARIOT-SPEC.md:434 forbids.
  if (admission.nextEpochState) {
    opts.persist(admission.nextEpochState);
  }

  return { mode: 'hybrid', retriever };
}
