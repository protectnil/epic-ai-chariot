/**
 * @epicai/chariot — Native Edge binding (typed loader)
 *
 * Typed accessor for the embedded-vector NAPI surface compiled into
 * `chariot-native.node` by Phase 3 (`native/src/edge_shard.rs`,
 * `encoder.rs`, `edge_snapshot.rs`, `bien_serializer.rs`): the in-process
 * Qdrant Edge `EdgeShard`, the fastembed-rs `DenseEncoder`, the Chariot-side
 * snapshot unseal/verify wrapper, and the lockstep serializer.
 *
 * This module declares the surface as TypeScript interfaces and resolves the
 * SAME `chariot-native.node` the license binding loads (`src/license/binding.ts`
 * owns license/RBAC/vault/discovery; this owns the retrieval surface — separate
 * accessors over one binary). It returns `null` when the binary is absent (the
 * binary ships only the license surface on platforms without the 4.0.0 native
 * retrieval build, or in dev/test where it is not built). All consumers
 * (`HybridRetriever`, the load path) take these as INJECTED dependencies so the
 * unit suite exercises the orchestration with deterministic fakes — the real
 * sealed bundle + BIEN ONNX land in P5/P8.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { loadVerifiedNativeModule } from '../../license/binding.js';

// ── EdgeShard query model (mirrors NativeQueryRequest in edge_shard.rs) ──────
//
// napi-rs camelCases `#[napi(object)]` fields and snake_case method names, so
// the Rust `rrf_k` / `sparse_indices` / `points_count` become `rrfK` /
// `sparseIndices` / `pointsCount` here.

/** One vector leg: exactly one of {dense, sparse, multi} is set. */
export interface NativeVectorQuery {
  /** Named vector to search ("dense" | "splade"). Empty → default vector. */
  using: string;
  dense?: number[];
  sparseIndices?: number[];
  sparseValues?: number[];
  multi?: number[][];
}

export interface NativePrefetch {
  query: NativeVectorQuery;
  limit: number;
}

export interface NativeQueryRequest {
  /** Prefetch legs to fuse (RRF at the root). Empty → single-leg `query`. */
  prefetches: NativePrefetch[];
  query?: NativeVectorQuery;
  limit: number;
  /** RRF k (required when prefetches is non-empty). */
  rrfK?: number;
  rrfWeights?: number[];
  withPayload?: boolean;
  filterJson?: string;
  /**
   * Exact (full-scan / brute-force) search on every leg. REQUIRED for the
   * deterministic selection path (§8.6 / CH-23) — approximate HNSW is not
   * byte-identical across replicas. Default false (ANN).
   */
  exact?: boolean;
}

export interface NativeScoredPoint {
  id: string;
  score: number;
  version: number;
  /** Payload as a JSON string (null/undefined if not requested / absent). */
  payloadJson?: string;
}

/** Loaded edge shard handle. */
export interface NativeEdgeShard {
  /** Explicit release for offline producers before staging-tree removal. */
  close?(): void;
  upsert(pointsJson: string): void;
  /** Delete canonical point ids. Used by adapter-scoped atomic deltas. */
  deletePoints?(idsJson: string): void;
  /**
   * `tenantId` is an OPTIONAL TS-side-only parameter (§8.6a /
   * `overlay/CompositeEdgeShard.ts`) — the compiled native
   * `EdgeShardHandle.query` (`native/src/edge_shard.rs`) takes exactly one
   * argument and never reads a second one; passing it to the REAL native
   * binding is harmless (napi-rs's generated call site only inspects the
   * arguments it declares) and it is never serialized into
   * `NativeQueryRequest` itself, so the native struct/function contract is
   * completely unchanged. Only `CompositeEdgeShard`'s own TS implementation
   * actually reads this second argument, to resolve the requesting
   * tenant's overlay shard.
   */
  query(request: NativeQueryRequest, tenantId?: string): NativeScoredPoint[];
  flush(): void;
  pointsCount(): number;
  snapshotManifestJson(): string;
}

/** In-process dense encoder (BIEN 768-d). */
export interface NativeDenseEncoder {
  embed(texts: string[]): number[][];
}

/** The four tokenizer files fastembed needs, as raw bytes. */
export interface NativeTokenizerFiles {
  tokenizerFile: Buffer;
  configFile: Buffer;
  specialTokensMapFile: Buffer;
  tokenizerConfigFile: Buffer;
}

/** One SPLADE sparse vector as the native encoder returns it (§8.6 step 3). */
export interface NativeSparseVector {
  indices: number[];
  values: number[];
}

/**
 * In-process SPLADE sparse encoder (`Splade_PP_en_v1`). NOTE the method name is
 * `embed`, not the `embedSparse` of the `SparseQueryEncoder` interface the
 * retrieval stack consumes — the call site adapts between the two rather than
 * either side guessing at the other's shape.
 */
export interface NativeSpladeEncoder {
  embed(texts: string[]): NativeSparseVector[];
}

/**
 * In-process cross-encoder rerank scorer (§8.6 step 7 / BIEN §7). Structurally
 * identical to the `RerankScorer` interface in `types.ts` — one score per
 * (query, document) pair, in INPUT order — so the native object satisfies the
 * rerank stage's contract directly, with no adapter shim to drift out of sync.
 */
export interface NativeCrossEncoderScorer {
  score(query: string, documents: string[]): number[];
}

export interface NativeUnsealedSnapshot {
  plaintextB64: string;
  /**
   * §8.6 verify-before-load receipt: HMAC-SHA256 over SHA-256(plaintext) under
   * a process-local key. `edgeUnpackSnapshot` REFUSES any archive whose bytes
   * do not match it, so this is not an optional diagnostic — it is the chain of
   * custody between unseal and load. Omitting it from this type made the
   * guarantee unrepresentable in TypeScript.
   */
  receipt: string;
}

/**
 * The `sealedShard` descriptor `seal_edge_snapshot` (native/src/edge_snapshot.rs
 * `struct SealedShard`) returns — CHARIOT::§5.7::1-7. Field names/order MUST
 * match the Rust struct exactly (evals/napi-seam-conformance.mjs asserts this).
 */
export interface NativeSealedShard {
  ciphertextB64: string;
  ivB64: string;
  signatureB64: string;
  salt: string;
  aad: string;
}

/**
 * The file-form result `seal_edge_snapshot_file` (native/src/edge_snapshot.rs
 * `struct SealedShardFile`) returns — CHARIOT §5.7 envelope fields, AMENDED
 * 2026-10-14 (`ciphertext` "as a file reference or base64 string"). The
 * ciphertext itself is written to the caller's `ciphertextPath` and never
 * crosses the JS boundary; `ciphertextSha256Hex` is the lowercase hex SHA-256
 * of exactly those bytes. Field names/order MUST match the Rust struct
 * exactly (evals/napi-seam-conformance.mjs asserts this).
 */
export interface NativeSealedShardFile {
  ivB64: string;
  signatureB64: string;
  salt: string;
  aad: string;
  ciphertextSha256Hex: string;
}

/**
 * Receipt-only result of `unseal_and_verify_snapshot_to_file`
 * (native/src/edge_snapshot.rs `struct UnsealReceipt`): the plaintext is on
 * disk at the caller's `outPath`; `receipt` is the same §8.6
 * verify-before-load receipt `edgeUnpackSnapshot` requires.
 */
export interface NativeUnsealReceipt {
  receipt: string;
}

/** The retrieval-facing surface of `chariot-native.node`. */
export interface NativeEdgeBinding {
  EdgeShardHandle: {
    create(path: string, configJson: string): NativeEdgeShard;
    load(path: string, configJson?: string): NativeEdgeShard;
  };
  DenseEncoder: {
    load(
      onnxFile: Buffer,
      tokenizerFiles: NativeTokenizerFiles,
      meanPool: boolean,
      maxLength: number,
    ): NativeDenseEncoder;
  };
  /**
   * SPLADE sparse encoder factory (§8.6 step 3). OPTIONAL for the same reason
   * as `CrossEncoderScorer` below: `hasEdgeSurface` does not require it, so a
   * build without it still serves dense + BM25 rather than being demoted.
   * Probe at runtime before use.
   */
  SpladeEncoder?: {
    load(
      onnxFile: Buffer,
      tokenizerFiles: NativeTokenizerFiles,
      maxLength: number,
    ): NativeSpladeEncoder;
  };
  /**
   * Cross-encoder rerank scorer factory (§8.6 step 7). OPTIONAL on the type
   * because `hasEdgeSurface` deliberately does not require it: a binary built
   * before the rerank module landed still carries a complete, usable
   * dense+sparse retrieval surface, and demanding this symbol would demote
   * those builds to BM25-only — a regression, not a safety gain. Every call
   * site MUST therefore probe it at runtime (`typeof … .load === 'function'`)
   * before use; absence means the rerank stage does not run, which the load
   * path already models as `rerankScorer === null`.
   */
  CrossEncoderScorer?: {
    load(
      onnxFile: Buffer,
      tokenizerFiles: NativeTokenizerFiles,
      maxLength: number,
    ): NativeCrossEncoderScorer;
  };
  /**
   * Unpack a VERIFIED plaintext snapshot. `receipt` is mandatory — the native
   * side (`edge_shard.rs:634`) refuses any archive whose bytes do not match the
   * receipt issued by `unsealAndVerifySnapshot` in THIS process. The prior
   * 2-parameter declaration made the verify-before-load gate impossible to
   * satisfy from TypeScript.
   */
  edgeUnpackSnapshot(snapshotPath: string, targetPath: string, receipt: string): void;
  /** Ed25519 verify of a detached signature; throws on any failure (fail-closed). */
  verifySnapshotSignature(messageB64: string, signatureB64: string, publicKeyPem: string): void;
  /**
   * Unseal + verify a sealed Edge snapshot; throws on any failure (fail-closed).
   *
   * CHARIOT::§5.7::31/32/33 (CH-56) — the anti-rollback floor is NOT
   * a bare scalar parameter. A prior `minEpoch: number` declaration made the
   * floor defeatable by any caller (careless or compromised) passing zero;
   * that parameter is REMOVED. The native entry point now takes the REAL
   * customer license artifact itself (`licenseJwt`), verifies its Ed25519
   * signature against the compiled-in accepted key set IN-PROCESS (mirroring
   * `src/license/loader.ts::verifyAndDecode`), and reads
   * `min_security_epoch` from the VERIFIED payload — a TypeScript caller can
   * no longer supply an unverified floor at all.
   *
   * `licenseJwt` is the compact JWT from the envelope at
   * `~/.epic-ai/chariot.license` (`{ "jwt": "<compact JWT>", "renewal_secret":
   * … }`, `src/license/loader.ts`) — the SAME artifact the license loader
   * verifies for licensing/entitlement, NOT a separate detached-signature
   * format. `sealedShardConfig.ts` resolves it via `loader.ts`'s own
   * `readLicenseEnvelope()` / `licenseFilePath()` rather than a bespoke path.
   *
   * CHARIOT::§5.7::34-36 — `watermarkDir` names the directory a persisted,
   * monotonically non-decreasing epoch watermark is read from and written
   * to. Pass the same shard/data directory this snapshot targets. A snapshot
   * OR a license-derived floor below the persisted watermark is rejected,
   * closing the "downgrade the license, replay the matching old snapshot"
   * rollback path a bundle-scoped floor alone cannot close.
   *
   * `aad` MUST be structured `<context>|epoch=N` with EXACTLY ONE `epoch=`
   * segment (CHARIOT::§5.7::27); `salt` MUST be non-empty and MUST equal the
   * aad `<context>` segment (§5.7::17), which itself MUST equal the context
   * the verified license authorizes (§5.7::37/38 — `tenant_id` when present,
   * else `sub`/company id; NEEDS-MASTER-RULING on §5.7::16's "catalog version
   * identifier" wording — see `native/src/edge_snapshot.rs::seal_edge_snapshot`
   * doc and `seal-edge-snapshot.ts`'s `--salt` note for the R1 interim);
   * `secretRootB64` MUST decode to >= 32 bytes of SECRET material — the
   * per-license secret key or ENTERPRISE_MASTER_KEY, never the public signed
   * license blob.
   */
  // master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)
  unsealAndVerifySnapshot(
    ciphertextB64: string,
    ivB64: string,
    signatureB64: string,
    publicKeyPem: string,
    secretRootB64: string,
    salt: string,
    aad: string,
    licenseJwt: string,
    watermarkDir: string,
  ): NativeUnsealedSnapshot;
  /**
   * File-to-file variant of `unsealAndVerifySnapshot` (CHARIOT §5.7
   * file-reference form, AMENDED 2026-10-14): identical fail-closed pipeline
   * (pinned key, license-derived floor + context, persisted watermark,
   * Ed25519-then-AEAD), but the ciphertext is read from `sealedPath` (a
   * regular file, opened O_NOFOLLOW — a symlink is refused) and the plaintext
   * is written to `outPath`, which MUST NOT exist (O_CREAT|O_EXCL|O_NOFOLLOW,
   * mode 0600, fsync). No base64 string crosses the JS boundary, so a shard
   * larger than V8's maximum string length can be loaded. Returns the receipt
   * to pass to `edgeUnpackSnapshot(outPath, target, receipt)`. OPTIONAL: a
   * binary signed before the file-form consumer shipped may lack it; probe
   * at the call site.
   */
  // master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)
  unsealAndVerifySnapshotToFile?(
    sealedPath: string,
    outPath: string,
    ivB64: string,
    signatureB64: string,
    publicKeyPem: string,
    secretRootB64: string,
    salt: string,
    aad: string,
    licenseJwt: string,
    watermarkDir: string,
  ): NativeUnsealReceipt;
  /**
   * CHARIOT::§5.7 producer — encrypt-then-sign seal a plaintext Edge snapshot
   * archive into a `sealedShard` descriptor. Operator/tooling path (a
   * `chariot` CLI seam calls this — see `src/engine/bin/seal-edge-snapshot.ts`),
   * NOT part of the retrieval consumer surface `hasEdgeSurface` requires, so
   * it is declared OPTIONAL here the same way `SpladeEncoder` /
   * `CrossEncoderScorer` are: probe at the call site before use.
   *
   * `signingKeySeedB64` is the base64 32-byte raw Ed25519 signing-key seed
   * (operator private key material) — NOT a PEM/PKCS8 file. The
   * corresponding public key MUST be one of the compiled-in accepted keys
   * (`native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM`) for any consumer to
   * later unseal the result.
   */
  sealEdgeSnapshot?(
    plaintextB64: string,
    secretRootB64: string,
    salt: string,
    context: string,
    epoch: number,
    signingKeySeedB64: string,
  ): NativeSealedShard;
  /**
   * File-to-file variant of `sealEdgeSnapshot` (CHARIOT §5.7 file-reference
   * form, AMENDED 2026-10-14): identical guards and encrypt-then-sign, but the
   * plaintext archive is read from `plaintextPath` (a regular file, opened
   * O_NOFOLLOW) and the ciphertext is written to `ciphertextPath`, which MUST
   * NOT exist (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, fsync). Returns every
   * descriptor field except the ciphertext, plus the lowercase hex SHA-256 of
   * the written ciphertext bytes. OPTIONAL for the same reason as
   * `sealEdgeSnapshot`: a producer/tooling seam, probed at the call site.
   */
  sealEdgeSnapshotFile?(
    plaintextPath: string,
    ciphertextPath: string,
    secretRootB64: string,
    salt: string,
    context: string,
    epoch: number,
    signingKeySeedB64: string,
  ): NativeSealedShardFile;
  /**
   * CHARIOT::§5.7 gate round 4 finding F2 (2026-09-04) — descriptor-based,
   * TOCTOU-safe removal of one §5.7 sealed-shard stale-backup directory
   * (`native/src/edge_cleanup.rs::remove_stale_dir_validated`). OPTIONAL:
   * the runtime binary stays whatever was last signed until an operator
   * re-signs it after this export ships, so `ChariotState.ts` MUST probe
   * for this at runtime and never fall back to a path-based `rmSync` when
   * it is absent — the entry simply stays registered and is retried on the
   * next successful load.
   *
   * Returns `true` if `parent/name` was validated and fully removed,
   * `false` only when `parent/name` does not exist (a benign, already-gone
   * state — NOT an error). Throws on any validation failure (not a
   * directory, a symlink, wrong owner, `expectedUid === 0`) with a message
   * prefixed `REMOVE_VALIDATION_FAILED:`, or on a failure during removal
   * itself (after validation passed) with a message prefixed
   * `REMOVE_IO_FAILED:` — the two prefixes let the caller distinguish "drop
   * this registry entry, it was never really ours" from "keep it, retry
   * next time."
   */
  removeStaleDirValidated?(parent: string, name: string, expectedUid: number): boolean;
  /** Lockstep query serializer (§8.6 step 1, byte-identical to freeze side). */
  serializeQuery(base: string, recJson: string): string;
  /** Lockstep document serializer (CH-23). */
  serializeTool(base: string, recJson: string): string;
  /** Compiled-in frozen serializer hash (CH-23 lockstep gate). */
  frozenSerializerHash(): string;
}

let _binding: NativeEdgeBinding | null = null;
let _loadAttempted = false;
let _loadError: string | null = null;

/**
 * Structural check that the loaded binary actually carries the retrieval
 * surface (the license-only binary on a non-4.0.0 build will not). Used to fail
 * closed to the BM25-only path rather than throwing at query time.
 */
function hasEdgeSurface(b: unknown): b is NativeEdgeBinding {
  if (!b || typeof b !== 'object') return false;
  const obj = b as Record<string, unknown>;
  const EdgeShardHandle = obj.EdgeShardHandle as { create?: unknown; load?: unknown } | undefined;
  const DenseEncoder = obj.DenseEncoder as { load?: unknown } | undefined;
  return (
    !!EdgeShardHandle &&
    typeof EdgeShardHandle.load === 'function' &&
    typeof EdgeShardHandle.create === 'function' &&
    !!DenseEncoder &&
    typeof DenseEncoder.load === 'function' &&
    typeof obj.unsealAndVerifySnapshot === 'function' &&
    typeof obj.serializeQuery === 'function' &&
    typeof obj.frozenSerializerHash === 'function'
  );
}

/**
 * Load the retrieval surface of the native binary, or null when it is absent or
 * does not carry the 4.0.0 Edge surface. Idempotent (cached after first call).
 */
export function loadNativeEdge(): NativeEdgeBinding | null {
  if (_loadAttempted) return _binding;
  _loadAttempted = true;
  try {
    // The addon is loaded only through the shared loader in
    // src/license/binding.ts, which verifies the signed integrity manifest
    // BEFORE the file is required (CHARIOT §3.5::10, §12.6::2/3). Node caches
    // the module, so this is the same verified instance the license loader
    // uses.
    const verified = loadVerifiedNativeModule();
    if (!verified.ok) {
      _loadError = verified.kind === 'integrity'
        ? `${verified.message} Retrieval falls back to BM25-only.`
        : `Native Edge binding not loaded (${verified.message}); retrieval falls back to BM25-only.`;
      return null;
    }
    const candidate = verified.module;
    if (!hasEdgeSurface(candidate)) {
      _loadError =
        'Native binary loaded but does not carry the 4.0.0 Edge retrieval surface; ' +
        'retrieval falls back to BM25-only.';
      return null;
    }
    _binding = candidate;
    return _binding;
  } catch (err) {
    _loadError = `Native Edge binding not loaded (${err instanceof Error ? err.message : String(err)}).`;
    return null;
  }
}

/** Last load error, for startup/health diagnostics. */
export function getNativeEdgeLoadError(): string | null {
  return _loadError;
}

/** Test-only: reset the cached binding so a fake can be re-resolved. */
export function __resetNativeEdgeCacheForTests(): void {
  _binding = null;
  _loadAttempted = false;
  _loadError = null;
}
