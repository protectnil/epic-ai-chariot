/**
 * @epicai/chariot — §8.6a on-device overlay embedder (BIEN::§9::10/13/14)
 *
 * CHARIOT-SPEC.md:767 (§8.6a), verbatim (the clause this module implements
 * the embed/upsert half of — the transport-specific customer-credential
 * connect + `tools/list` half is a separate, disjoint module owned by a
 * different builder in this same row): "The runtime then serializes each
 * returned tool via the byte-identical `serialize_tool` (BIEN §16.4
 * lockstep), embeds it ON-DEVICE with the BIEN **document** encoder + the
 * SPLADE **document** encoder + Edge-native BM25, and upserts the vectors
 * (`EdgeShard.load → update(upsert_points) → flush`, verified against
 * qdrant.tech Edge docs) into a **per-tenant writable overlay `EdgeShard`**
 * ... The sealed catalog shard is NEVER mutated (immutable, §5 / BIEN §3
 * constraint 6). The customer credential, tools, and vectors NEVER leave the
 * host ... Query-time `HybridRetriever` fuses catalog-shard + overlay-shard
 * results under RRF; the overlay contributes to the `overlayStateHash` that
 * scopes §8.6 determinism."
 *
 * BIEN SPEC.md:51 (§3 constraint 4), quoted with one word redacted for this
 * PUBLIC repo's leak-denylist (the freeze-pipeline operator's internal name;
 * see the leak-scan note at the end of this file for the exact byte
 * changed): "the BIEN model used to embed documents (freeze pipeline) MUST
 * be byte-identical to the model used to
 * embed queries (Chariot runtime) AND to the model used for **on-device
 * document embedding of customer-verified tools into the per-tenant
 * overlay** ... same weights, same ONNX, same input-construction/prompt-
 * prefix across all three sites."
 *
 * ── §9::13 byte-identical check: HOW it is actually provable at runtime ──
 * There is no native introspection API that reports a *loaded*
 * `DenseEncoder`'s model id/version back to TypeScript (`encoder.rs`'s
 * `DenseEncoder` is an opaque handle: `load()` → `embed()`, nothing else —
 * confirmed by reading the full `#[napi] impl DenseEncoder` block). The only
 * facts checkable at runtime are therefore: (a) the compiled-in serializer
 * hash (`native.frozenSerializerHash()`, `bien_serializer.rs`'s
 * `napi_frozen_serializer_hash`) against the manifest's `serializer_hash`
 * (exactly what `VectorIndexVerifier.ts:107/412` already does for the
 * sealed-catalog load), and (b) the shipping dense width
 * (`manifestEncoder.denseDims === 768`, the SAME constant
 * `VectorIndexVerifier.ts:74`/`encoder.rs::SHIPPING_DIMENSIONS` pin, and
 * `encoder.rs::validate_dense_vector` — compiled, wired — independently
 * re-asserts this on the OUTPUT of every single `embed()` call, rejecting a
 * wrong-width vector before it ever reaches this class). The genuinely
 * strong guarantee this class adds on top of both of those is STRUCTURAL,
 * not a value comparison: it accepts the dense/sparse encoder objects as
 * CONSTRUCTOR-INJECTED dependencies and never loads a second, independent
 * encoder instance of its own — the caller (`ChariotState.ts` /
 * `loadRetrieval.ts` wiring) MUST pass the exact same `NativeDenseEncoder` /
 * `NativeSpladeEncoder` object `HybridRetriever` already uses for the query
 * side, which by construction already passed `VectorIndexVerifier.admit()`
 * before it was ever loaded (`loadRetrieval.ts`'s admitted-then-load
 * ordering). One shared encoder object, one shared serializer function
 * (`native.serializeTool`, the SAME compiled `bien_serializer.rs` the
 * query-side `native.serializeQuery` binds) — literally the "one shared
 * encoder definition" BIEN §3 constraint 4 requires, not two definitions
 * that happen to agree. `assertEncoderIdentity` below still performs the
 * value-level checks (a)/(b) as an explicit, fail-closed, non-silent gate at
 * construction time, so a caller that DOES wire a stale/mismatched manifest
 * block is refused immediately rather than embedding first and finding out
 * never.
 *
 * ── Tenant isolation (gate-round-2 finding D1, 2026-09-05) ──
 * §8.6a's overlay is PER-TENANT customer data ("the customer credential,
 * tools, and vectors NEVER leave the host"). Every disk path this class
 * touches is rooted at `<overlayRootDir>/<tenantId>/`, so `tenantId` is a
 * path segment and MUST be confined: `assertValidTenantId` rejects anything
 * outside `[A-Za-z0-9._-]{1,128}` (rejects empty, oversized, `/`, and any
 * `..`-traversal attempt) BEFORE it is ever joined into a path, in every
 * method that takes one. There is deliberately no "sanitize and continue"
 * path — an invalid tenantId is refused (thrown), never coerced.
 *
 * ── Persistence across restarts (gate-round-2 finding D3, 2026-09-05) ──
 * `overlayStateHash` MUST be a function of the ON-DISK overlay state, not of
 * this-process-lifetime bookkeeping — CHARIOT-SPEC.md:763's "byte-identical
 * for an identical request against an identical `(sealed-bundle version,
 * overlay-state snapshot)`" is a claim about the SNAPSHOT, and a snapshot
 * that survives process restart (the shard itself is a persisted qdrant-edge
 * segment) is not "identical" to itself if the hash is computed from a
 * memory structure that resets on restart. Each tenant directory therefore
 * carries a `overlay-manifest.json` — `{ [toolId]: {adapterId, toolName,
 * contentHash} }`, `contentHash` = sha256 of the exact serialized document
 * text that drove the embedding (the input, not the output vector, so the
 * hash is meaningful even against a fixture encoder whose output is not
 * bit-reproducible) — written atomically (write-temp + fdatasync + rename,
 * mirroring `src/engine/audit/verifyKeyStore.ts::atomicWriteStore`'s
 * replace-in-place pattern) immediately after the corresponding
 * `shard.upsert()+flush()` succeeds, and loaded back whenever a tenant's
 * shard is opened (by `embedCustomerVerifiedTools` OR by `getOverlayShard`)
 * and not already resident in memory. `overlayStateHash` reads ONLY this
 * loaded-from-disk map, never a write-time-only cache, so a brand-new
 * `NativeOverlayEmbedder` instance constructed over the same
 * `overlayRootDir` after a process restart reproduces the identical hash
 * for identical on-disk content.
 *
 * ── Persistence (§9::14 / §8.6a) ──
 * BIEN SPEC.md:166 pins the on-disk destination for the mechanically
 * different (host-TOFU-signed) `discovered-adapters` overlay at
 * `~/.epic-ai/discovered-adapters/` — that mechanism is unrelated to this
 * one (see `src/discovery/envelope.ts`'s own header: a per-host Ed25519
 * signing envelope for catalog-publication-lag adapters, with no encoder,
 * no embed step, and no relation to `requiresCustomerAuth`). This
 * class's overlay `EdgeShard` is per-tenant AND per-adapter-embedding
 * state (raw qdrant-edge segment files, not JSON envelopes), so it is
 * rooted at a DISTINCT path, `~/.epic-ai/overlay-shards/<tenantId>/`, never
 * inside `discovered-adapters/` — colocating two unrelated on-disk formats
 * under one directory would make a future reader of either mechanism
 * misattribute the other's files.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fdatasyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';

import { COMPILED_SERIALIZER_HASH } from '../VectorIndexVerifier.js';
import type {
  NativeDenseEncoder,
  NativeEdgeBinding,
  NativeEdgeShard,
  NativeSpladeEncoder,
} from '../nativeEdge.js';

/** One tool the runtime obtained from a `requiresCustomerAuth` adapter's
 * customer-credentialed `tools/list` (CHARIOT-SPEC.md:767). Supplied by the
 * (separate) transport-connect module — this class never talks to a
 * network/spawned-process itself. */
export interface CustomerVerifiedTool {
  name: string;
  description: string;
  inputSchema: unknown;
}

export interface OverlayEmbedResult {
  tenantId: string;
  adapterId: string;
  embedded: number;
  overlayStateHash: string;
}

export interface OverlayEmbedder {
  embedCustomerVerifiedTools(
    tenantId: string,
    adapterId: string,
    tools: ReadonlyArray<CustomerVerifiedTool>,
  ): Promise<OverlayEmbedResult>;
  overlayStateHash(tenantId: string): string;
}

/** The subset of a `RetrievalManifest.encoder` block (`VectorIndexVerifier.ts`)
 * this class needs to prove the on-device embed uses the byte-identical
 * model + serializer as the freeze side (BIEN §3 constraint 4 / §9::13).
 * `sparseModelId` is optional because the SPLADE leg itself is optional
 * (mirrors `ChariotState.ts::loadSparseEncoder` returning `null` when the
 * SPLADE artifact directory is not staged — §4.4's existing "optional leg"
 * precedent, not a new exception invented here). */
export interface OverlayEncoderIdentity {
  denseModelId: string;
  denseModelVersion: string;
  denseDims: number;
  sparseModelId?: string;
  serializerHash: string;
}

const SHIPPING_DIMENSIONS = 768;

/** Path-segment confinement for `tenantId` (D1 gate finding): no `/`, no
 * `..`, no empty string, bounded length. Anything else is a directory a
 * hostile tenantId could escape `overlayRootDir` with. */
const TENANT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/** Thrown by every method taking a `tenantId` when it is not a confined path
 * segment. FAIL-CLOSED: never sanitized-and-continued. */
export class InvalidTenantIdError extends Error {
  constructor(public readonly tenantId: string) {
    super(`invalid tenantId ${JSON.stringify(tenantId)}: must match ${TENANT_ID_PATTERN}`);
    this.name = 'InvalidTenantIdError';
  }
}

function assertValidTenantId(tenantId: string): void {
  if (typeof tenantId !== 'string' || !TENANT_ID_PATTERN.test(tenantId)) {
    throw new InvalidTenantIdError(tenantId);
  }
  // Belt-and-suspenders: the pattern above already excludes '/' and '.'
  // sequences long enough to traverse, but '..' alone (two dots, no
  // separator) DOES match `[A-Za-z0-9._-]{1,128}` — explicitly reject it
  // and any segment that is exactly '.' or '..' after the fact.
  if (tenantId === '.' || tenantId === '..' || tenantId.includes('..')) {
    throw new InvalidTenantIdError(tenantId);
  }
}

/**
 * Thrown by the constructor when the injected encoder identity does not
 * match the compiled-in / sealed-manifest contract. FAIL-CLOSED: the caller
 * MUST NOT catch this and silently fall back to embedding anyway — it is
 * the same failure class as `loadRetrieval.ts`'s `encoder_load_failed`
 * (§4.4 row 2, no BM25-style degradation for a startup/identity failure).
 */
export class OverlayEncoderIdentityMismatchError extends Error {
  constructor(public readonly mismatches: readonly string[]) {
    super(`overlay embed refused: encoder identity mismatch: ${mismatches.join(', ')}`);
    this.name = 'OverlayEncoderIdentityMismatchError';
  }
}

/** Deterministic 128-bit id from a seed string, formatted as a valid v5-style
 * UUID string. qdrant-edge's point id (`ExtendedPointId`, vendored
 * `qdrant-edge-0.7.2/src/segment/types.rs:169`) is `NumId(u64) | Uuid(Uuid)`
 * ONLY — an arbitrary string (e.g. `overlay:<tenant>:<adapter>:<tool>`) is
 * NOT a valid point id and would fail native deserialization at `upsert()`.
 * The LOGICAL identity that must be collision-safe across shards
 * (`overlay:<tenantId>:<adapterId>:<toolName>`) is carried in the point's
 * PAYLOAD `toolId` field instead (see `CompositeEdgeShard.ts`'s doc comment
 * for why that, not the raw point id, is what `HybridRetriever`'s fusion
 * actually keys on) — this function only needs to produce a
 * deterministic, syntactically valid, practically-collision-free raw
 * storage key so re-embedding the identical tool twice (idempotent
 * customer-verified reconnect) upserts the SAME point rather than
 * accumulating duplicates.
 */
function deterministicPointId(seed: string): string {
  const digest = createHash('sha256').update(seed, 'utf8').digest();
  const hex = digest.subarray(0, 16).toString('hex');
  // RFC 4122 layout with version/variant nibbles forced valid so every
  // qdrant-edge/uuid-crate parse succeeds regardless of the hash bytes.
  const bytes = hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-'
    + '5' + hex.slice(13, 16) + '-'
    + '8' + hex.slice(17, 20) + '-'
    + hex.slice(20, 32);
  return bytes;
}

/** The reserved `toolId` namespace for every overlay-embedded point — see
 * `CompositeEdgeShard.ts`'s header for why this prefix is the actual
 * collision-safety property (a sealed catalog `toolId` is always
 * `server:name` and can never start with `overlay:`). */
export function overlayToolId(tenantId: string, adapterId: string, toolName: string): string {
  return `overlay:${tenantId}:${adapterId}:${toolName}`;
}

/** JSON-Schema → BIEN `required_params`/`optional_params` best-effort
 * extraction (BIEN SPEC.md §15.2: "when the source stage exposes it ...
 * when it is absent, treat it as optional enrichment"). `inputSchema` here
 * is a bare `unknown` per the `CustomerVerifiedTool` contract (the
 * transport-connect module hands back whatever the MCP server's
 * `tools/list` returned), so every access is defensively typed — a
 * malformed schema degrades to "no param signature", never a thrown error
 * that would abort the whole batch. */
function paramSignature(inputSchema: unknown): { required: string[]; optional: string[] } {
  if (!inputSchema || typeof inputSchema !== 'object') return { required: [], optional: [] };
  const schema = inputSchema as { properties?: unknown; required?: unknown };
  const properties = schema.properties && typeof schema.properties === 'object'
    ? Object.keys(schema.properties as Record<string, unknown>)
    : [];
  const required = Array.isArray(schema.required)
    ? schema.required.filter((r): r is string => typeof r === 'string')
    : [];
  const requiredSet = new Set(required);
  const optional = properties.filter((p) => !requiredSet.has(p));
  return { required, optional };
}

function assertEncoderIdentity(identity: OverlayEncoderIdentity | null | undefined, nativeFrozenHash: string | undefined): void {
  const mismatches: string[] = [];
  if (!identity) {
    mismatches.push('manifestEncoder is absent — refusing to embed against an unverified encoder identity');
  } else {
    if (identity.denseDims !== SHIPPING_DIMENSIONS) {
      mismatches.push(`encoder.denseDims ${JSON.stringify(identity.denseDims)} != ${SHIPPING_DIMENSIONS}`);
    }
    if (identity.serializerHash !== COMPILED_SERIALIZER_HASH) {
      mismatches.push(`serializer_hash ${JSON.stringify(identity.serializerHash)} != compiled-in ${COMPILED_SERIALIZER_HASH}`);
    }
  }
  if (nativeFrozenHash !== undefined && nativeFrozenHash !== COMPILED_SERIALIZER_HASH) {
    mismatches.push(`native frozenSerializerHash ${nativeFrozenHash} != compiled-in ${COMPILED_SERIALIZER_HASH}`);
  }
  if (mismatches.length > 0) {
    throw new OverlayEncoderIdentityMismatchError(mismatches);
  }
}

export interface NativeOverlayEmbedderOptions {
  native: NativeEdgeBinding;
  /** MUST be the exact same instance `HybridRetriever`/query-side wiring
   * uses (see the class-level doc comment on why identity, not value
   * comparison, is the strong half of the §9::13 guarantee). */
  denseEncoder: NativeDenseEncoder;
  /** Optional — mirrors `loadSparseEncoder()`'s own optional-leg contract. */
  sparseEncoder?: NativeSpladeEncoder | null;
  /** The admitted bundle's `manifest.encoder` block + `serializer_hash`,
   * i.e. exactly what already passed `VectorIndexVerifier.admit()` for the
   * sealed catalog this process is running. */
  manifestEncoder: OverlayEncoderIdentity;
  /** Root directory for per-tenant overlay shards. Defaults to
   * `~/.epic-ai/overlay-shards` (distinct from the unrelated
   * `discovered-adapters/` TOFU mechanism — see class header). */
  overlayRootDir?: string;
  /** BIEN encoder base name (`bien_serializer.rs`'s `base_prefix`). Matches
   * the query-side default (`ChariotState.ts:2438` uses `'nomic'`). */
  serializerBase?: string;
}

const DEFAULT_OVERLAY_ROOT = () => join(
  process.env.HOME ?? process.env.USERPROFILE ?? '.',
  '.epic-ai',
  'overlay-shards',
);

const MANIFEST_FILENAME = 'overlay-manifest.json';

/** One tool's persisted content record (D3 gate finding). */
interface ManifestEntry {
  adapterId: string;
  toolName: string;
  contentHash: string;
}

/**
 * Thrown by `readManifest` (and therefore by every accessor that loads a
 * tenant's manifest: `overlayStateHash`, `listTools`, `getOverlayShard`,
 * `liveOverlayToolIds`, `openShardForWrite`/`embedCustomerVerifiedTools`)
 * when the on-disk manifest file EXISTS but fails to parse as JSON or does
 * not validate against the persisted shape (gate-round-3 finding E2).
 *
 * A MISSING file is legitimate "no prior state" (a tenant/adapter that has
 * never embedded) and does NOT throw this — only an EXISTING, DAMAGED file
 * does. Silently treating a damaged file as empty (the prior behavior) is
 * exactly the silent-failure class CHARIOT-SPEC.md:763's determinism
 * contract forbids: `overlayStateHash`/`listTools` would quietly report
 * "no overlay tools" for a tenant whose overlay is actually intact but
 * unreadable, which is indistinguishable from a legitimate empty state and
 * would silently demote every customer-verified tool back to
 * non-dispatchable. `TenantOverlayToolRegistry` (federation-side) already
 * throws its own typed `TenantOverlayRegistryCorruptError` for the exact
 * same reason on its own manifest file — this mirrors that precedent on
 * the retrieval side rather than inventing a different failure mode for
 * the same class of damage.
 */
export class OverlayManifestCorruptError extends Error {
  constructor(
    public readonly tenantId: string,
    public readonly filePath: string,
    reason: string,
  ) {
    super(`overlay manifest is corrupt for tenant "${tenantId}" (${filePath}): ${reason}`);
    this.name = 'OverlayManifestCorruptError';
  }
}

/**
 * Dense-vector-only overlay config (the shard's OWN persisted `EdgeConfig`
 * once created — `EdgeShardHandle.load`'s `config_json` is optional and
 * reads the persisted file thereafter, `edge_shard.rs:429-439`).
 * `size: 768` mirrors the compiled-in shipping contract
 * (`VectorIndexVerifier.ts:74`/`encoder.rs::SHIPPING_DIMENSIONS`); `Cosine`
 * is the only distance value this codebase's own fixtures ever construct
 * (`native/src/edge_shard.rs:812,950` — no sealed-catalog config is visible
 * from this consumer repo, since the sealed shard's `EdgeConfig` is written
 * by the freeze-side producer, not read from here). Because
 * `encoder.rs::validate_dense_vector` requires every dense vector to be
 * L2-unit-normalized before it is ever returned to TypeScript, Cosine and
 * (normalized) Dot-product distance rank identically — so this choice
 * cannot diverge from the sealed shard's ranking behavior on THIS encoder's
 * output regardless of which of the two the freeze-side producer used.
 * `splade: {}` carries no `modifier` — `splade.rs`'s own module header
 * states "IDF: NONE inside SPLADE. BM25 idf is fused only at rank time",
 * so no on-shard IDF modifier belongs on the sparse vector config either.
 */
function overlayShardConfigJson(): string {
  return JSON.stringify({
    vectors: { dense: { size: SHIPPING_DIMENSIONS, distance: 'Cosine' } },
    sparse_vectors: { splade: {} },
    on_disk_payload: false,
  });
}

/**
 * Crash-safe write-or-replace of the tenant's manifest JSON. Mirrors
 * `src/engine/audit/verifyKeyStore.ts::atomicWriteStore`'s pattern
 * (write-temp with a random suffix, fdatasync, rename over the target) —
 * unlike `auditFs.ts::atomicWriteNew` this REPLACES an existing file (the
 * manifest is a single mutable per-tenant document, not an append-only
 * log), so it must not throw EEXIST.
 */
function atomicWriteManifest(dir: string, entries: Record<string, ManifestEntry>): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const finalPath = join(dir, MANIFEST_FILENAME);
  const tmpPath = `${finalPath}.tmp-${randomBytes(6).toString('hex')}`;
  const data = Buffer.from(JSON.stringify(entries, null, 2) + '\n', 'utf-8');
  const fd = openSync(tmpPath, 'wx', 0o600);
  try {
    writeSync(fd, data);
    fdatasyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmpPath, finalPath);
}

/**
 * Read a tenant's persisted manifest: an empty map when the file does not
 * exist yet (legitimate "no prior state" — this tenant/adapter has never
 * embedded), or the parsed+validated contents. Gate-round-3 finding E2: a
 * file that DOES exist but fails to parse or validate throws
 * `OverlayManifestCorruptError` — it is NOT swallowed into an empty map.
 * The prior behavior ("corrupted manifest degrades to re-embedding, losing
 * only hash continuity") silently made `overlayStateHash`/`listTools`
 * report "no overlay tools" for a tenant whose overlay is actually intact
 * but unreadable — exactly the silent-failure class the determinism
 * contract forbids, and inconsistent with `TenantOverlayToolRegistry`'s
 * own typed `TenantOverlayRegistryCorruptError` for the identical failure
 * class on its sibling manifest file.
 */
function readManifest(dir: string, tenantId: string): Map<string, ManifestEntry> {
  const path = join(dir, MANIFEST_FILENAME);
  if (!existsSync(path)) return new Map();
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'));
  } catch (err) {
    throw new OverlayManifestCorruptError(tenantId, path, `JSON parse failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new OverlayManifestCorruptError(tenantId, path, 'top-level JSON value is not an object');
  }
  const out = new Map<string, ManifestEntry>();
  for (const [toolId, value] of Object.entries(raw as Record<string, unknown>)) {
    if (
      value && typeof value === 'object'
      && typeof (value as ManifestEntry).adapterId === 'string'
      && typeof (value as ManifestEntry).toolName === 'string'
      && typeof (value as ManifestEntry).contentHash === 'string'
    ) {
      out.set(toolId, value as ManifestEntry);
    } else {
      throw new OverlayManifestCorruptError(tenantId, path, `entry "${toolId}" does not match {adapterId, toolName, contentHash}`);
    }
  }
  return out;
}

/**
 * Reference implementation of `OverlayEmbedder`. One instance per process;
 * holds one open `EdgeShardHandle` per tenant it has embedded for or
 * queried (opened lazily, kept for the process lifetime — mirrors the
 * sealed shard's own single-open-handle lifecycle).
 *
 * CORRECTION, NOT ONLY GROWTH (gate-round-3 finding E1). The native shard
 * exposes `upsert`/`query`/`flush` only — no delete — so a tool a re-embed
 * no longer reports stays physically present in the shard's segment files
 * until a native delete operation exists. `embedCustomerVerifiedTools`'s
 * own doc comment below details the fix: EVERY observable surface this
 * class and `CompositeEdgeShard` expose (the manifest — hence
 * `listTools`/`overlayStateHash` — and `liveOverlayToolIds`, which
 * `CompositeEdgeShard` filters every overlay query result against BEFORE
 * merge/sort/slice) already excludes a stale tool, so the physical
 * leftover vector is inert: unreachable, uncounted, and never surfaced.
 */
export class NativeOverlayEmbedder implements OverlayEmbedder {
  private readonly native: NativeEdgeBinding;
  private readonly denseEncoder: NativeDenseEncoder;
  private readonly sparseEncoder: NativeSpladeEncoder | null;
  private readonly overlayRootDir: string;
  private readonly serializerBase: string;
  private readonly shardsByTenant = new Map<string, NativeEdgeShard>();
  /** Per-tenant content manifest, mirrored from (and the source of truth
   * for) `<tenantDir>/overlay-manifest.json` — see the class-level "D3"
   * doc comment. Loaded from disk the first time a tenant is touched in
   * this process; never the ONLY copy of the truth. */
  private readonly contentByTenant = new Map<string, Map<string, ManifestEntry>>();

  constructor(options: NativeOverlayEmbedderOptions) {
    assertEncoderIdentity(options.manifestEncoder, options.native.frozenSerializerHash?.());
    this.native = options.native;
    this.denseEncoder = options.denseEncoder;
    this.sparseEncoder = options.sparseEncoder ?? null;
    this.overlayRootDir = options.overlayRootDir ?? DEFAULT_OVERLAY_ROOT();
    this.serializerBase = options.serializerBase ?? 'nomic';
  }

  private tenantShardDir(tenantId: string): string {
    assertValidTenantId(tenantId);
    return join(this.overlayRootDir, tenantId);
  }

  /** Load the tenant's persisted manifest into memory if not already
   * resident. Idempotent; safe to call on every shard touch. */
  private ensureManifestLoaded(tenantId: string, dir: string): void {
    if (this.contentByTenant.has(tenantId)) return;
    this.contentByTenant.set(tenantId, readManifest(dir, tenantId));
  }

  /** Open (creating if absent) the tenant's overlay shard for a WRITE
   * (embed). Unlike `getOverlayShard`, this creates the directory/shard
   * when it does not exist yet — an embed is the only operation allowed to
   * bring a tenant's overlay into existence. */
  private openShardForWrite(tenantId: string): NativeEdgeShard {
    const existing = this.shardsByTenant.get(tenantId);
    if (existing) return existing;
    const dir = this.tenantShardDir(tenantId);
    let shard: NativeEdgeShard;
    if (existsSync(dir)) {
      shard = this.native.EdgeShardHandle.load(dir, overlayShardConfigJson());
    } else {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      shard = this.native.EdgeShardHandle.create(dir, overlayShardConfigJson());
    }
    this.ensureManifestLoaded(tenantId, dir);
    this.shardsByTenant.set(tenantId, shard);
    return shard;
  }

  /**
   * Resolve the tenant's overlay shard for a READ (query), per gate finding
   * D1: this is the exact `(tenantId: string) => NativeEdgeShard | null`
   * provider shape `CompositeEdgeShard` takes. NEVER creates a shard — a
   * tenant with no prior `embedCustomerVerifiedTools` call (in this process
   * OR ever, on disk) has no overlay to query, and must return `null` so
   * `CompositeEdgeShard` falls back to sealed-only results, not an empty
   * freshly-created shard (which would still be "successfully queried",
   * masking the truth that this tenant has never verified anything).
   * Lazily loads from disk (`EdgeShardHandle.load`) the first time a
   * tenant's ALREADY-PERSISTED shard is queried in THIS process (e.g. after
   * a restart, or a process that only serves queries and never itself ran
   * an embed).
   */
  getOverlayShard(tenantId: string): NativeEdgeShard | null {
    const existing = this.shardsByTenant.get(tenantId);
    if (existing) return existing;
    const dir = this.tenantShardDir(tenantId);
    if (!existsSync(dir)) return null;
    const shard = this.native.EdgeShardHandle.load(dir, overlayShardConfigJson());
    this.ensureManifestLoaded(tenantId, dir);
    this.shardsByTenant.set(tenantId, shard);
    return shard;
  }

  /**
   * The tools embedded for a tenant, from the PERSISTED manifest (survives
   * restart) — build-133b's tool-registry consumer. Returns an empty array
   * for an unknown tenant (never throws for "no overlay yet"; DOES throw
   * `InvalidTenantIdError` for a malformed tenantId, same as every other
   * method here).
   */
  listTools(tenantId: string): ReadonlyArray<{ adapterId: string; toolName: string; toolId: string }> {
    const dir = this.tenantShardDir(tenantId);
    this.ensureManifestLoaded(tenantId, dir);
    const entries = this.contentByTenant.get(tenantId) ?? new Map<string, ManifestEntry>();
    return [...entries.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([toolId, entry]) => ({ adapterId: entry.adapterId, toolName: entry.toolName, toolId }));
  }

  /**
   * Gate-round-3 finding E1(b) — the exact `(tenantId) => ReadonlySet<
   * string> | null` provider shape `CompositeEdgeShard`'s stale-point
   * filter takes (its second constructor argument). Derived from the SAME
   * persisted manifest `listTools`/`overlayStateHash` read, so a tool this
   * method excludes is, by construction, ALSO excluded from those two —
   * one source of truth for "is this tool currently live," not three that
   * could drift apart.
   *
   * Returns `null` — meaning "no liveness answer at all" — ONLY when this
   * tenant has never had an overlay (no on-disk directory AND nothing
   * recorded in this process): `CompositeEdgeShard` treats `null` as
   * "cannot verify freshness, drop every overlay point" (fail-closed), so
   * this must be reserved for genuine absence, never returned for a
   * tenant that legitimately has zero live tools right now (a full
   * revoke) — that case returns an EMPTY (but non-null) `Set`, which
   * correctly filters out everything without masking the distinction
   * between "no overlay" and "overlay with nothing live."
   */
  liveOverlayToolIds(tenantId: string): ReadonlySet<string> | null {
    const dir = this.tenantShardDir(tenantId);
    // Ground truth is disk existence, NOT `contentByTenant.has(tenantId)`:
    // `overlayStateHash`/`listTools` eagerly populate `contentByTenant`
    // with an EMPTY map even for a tenant that has never had an overlay
    // (so a repeat call is O(1) instead of re-checking the filesystem) —
    // relying on that populated-ness here would make "never had an
    // overlay" vs. "has one with zero live tools" depend on which OTHER
    // accessor happened to run first for this tenant, which is exactly
    // the ambiguity this method exists to resolve reliably. Mirrors
    // `getOverlayShard`'s own `!existsSync(dir)` null-check for the same
    // reason.
    if (!existsSync(dir)) return null;
    this.ensureManifestLoaded(tenantId, dir);
    return new Set(this.contentByTenant.get(tenantId)!.keys());
  }

  /**
   * §9::14 / AS §3.2 G10 "runtime mismatch corrects the overlay"
   * (gate-round-3 finding E1). The native shard has no delete
   * (`edge_shard.rs` exposes `upsert`/`query`/`flush` only, and a native
   * change is not available before this cut), so a tool the live
   * `tools/list` for `(tenantId, adapterId)` no longer reports CANNOT be
   * physically removed from the shard's vector storage here. What this
   * method DOES guarantee — on every embed call, whether `tools` is
   * empty or not — is that every OBSERVABLE surface treats the stale tool
   * as gone:
   *   (a) the persisted manifest DROPS every prior entry for this
   *       `adapterId` that is not in the new `tools` list, BEFORE the new
   *       entries are added and the manifest is written — so `listTools`
   *       and `overlayStateHash` (both manifest-derived) never count it
   *       again, matching a fresh embed of the corrected set exactly;
   *   (b) `liveOverlayToolIds` (manifest-derived, same source) no longer
   *       contains it, and `CompositeEdgeShard` (query/overlay/
   *       CompositeEdgeShard.ts) filters every overlay point against that
   *       live set BEFORE merge/sort/slice — a stale point can score
   *       arbitrarily high in the shard's own dense/sparse ranking and
   *       will still never reach the top-k, because it is dropped before
   *       the merge ever runs, not after;
   *   (c) `TenantOverlayToolRegistry.resolveForTenant` (federation-side,
   *       a SEPARATE persisted registry `CustomerAuthOverlayConnector`
   *       writes in the same connect, per that module's own header) is
   *       replaced wholesale per adapter by `recordTools`, so dispatch
   *       validation and `chariot_query` listing already exclude it too.
   * The physical stale vector remains in the shard's segment files until
   * a native delete operation exists — that is a disk-space/on-disk-state
   * fact, not an observable-behavior one, and every consumer this class
   * exposes has been checked above to already exclude it.
   */
  async embedCustomerVerifiedTools(
    tenantId: string,
    adapterId: string,
    tools: ReadonlyArray<CustomerVerifiedTool>,
  ): Promise<OverlayEmbedResult> {
    assertValidTenantId(tenantId);
    const dir = this.tenantShardDir(tenantId);
    // Loaded (and validated — may throw OverlayManifestCorruptError, E2)
    // up front, unconditionally: the correction step below needs to see
    // whatever this adapter previously recorded even when the NEW list is
    // empty (a full revoke), so it cannot be skipped by the empty-tools
    // early return the way shard creation still is.
    this.ensureManifestLoaded(tenantId, dir);
    const tenantContent = this.contentByTenant.get(tenantId) ?? new Map<string, ManifestEntry>();

    const toolIds = tools.map((tool) => overlayToolId(tenantId, adapterId, tool.name));
    const newToolIdSet = new Set(toolIds);

    // E1(a) — correction: remove every prior entry for THIS adapter that
    // is not in the new live list. Scoped to `adapterId` so a re-embed for
    // one adapter never touches another adapter's entries for the same
    // tenant (each adapter's live list is independent).
    let manifestChanged = false;
    for (const [existingToolId, entry] of [...tenantContent.entries()]) {
      if (entry.adapterId === adapterId && !newToolIdSet.has(existingToolId)) {
        tenantContent.delete(existingToolId);
        manifestChanged = true;
      }
    }

    if (tools.length === 0) {
      // Empty tool list embeds no vectors and never creates a shard
      // directory for a tenant with nothing to embed — but if this
      // adapter previously had live entries (a full revoke), the
      // correction above already dropped them and that correction MUST
      // still be persisted, or a restart would resurrect the stale
      // entries from the still-unmodified on-disk manifest.
      if (manifestChanged) {
        this.contentByTenant.set(tenantId, tenantContent);
        atomicWriteManifest(dir, Object.fromEntries(tenantContent));
      }
      return { tenantId, adapterId, embedded: 0, overlayStateHash: this.overlayStateHash(tenantId) };
    }

    const serializedDocs: string[] = [];
    for (const tool of tools) {
      const { required, optional } = paramSignature(tool.inputSchema);
      const record: Record<string, unknown> = {
        name: tool.name,
        description: tool.description,
      };
      if (required.length > 0) record.required_params = required;
      if (optional.length > 0) record.optional_params = optional;
      const doc = this.native.serializeTool(this.serializerBase, JSON.stringify(record));
      serializedDocs.push(doc);
    }

    // §9::10/13: the BIEN document encoder, batch call, same instance the
    // query side uses (identity asserted at construction).
    const denseVectors = this.denseEncoder.embed(serializedDocs);
    // §9::10: SPLADE document encoder — optional leg (see class header),
    // fed the SAME serialized document text as the dense leg (one
    // canonical serializer, both legs — no separate re-serialization).
    const sparseVectors = this.sparseEncoder ? this.sparseEncoder.embed(serializedDocs) : null;

    const points = tools.map((tool, i) => {
      const vector: Record<string, unknown> = { dense: denseVectors[i] };
      if (sparseVectors) {
        vector.splade = { indices: sparseVectors[i].indices, values: sparseVectors[i].values };
      }
      return {
        id: deterministicPointId(toolIds[i]),
        vector,
        payload: { toolId: toolIds[i], tenantId, adapterId, name: tool.name, description: tool.description },
      };
    });

    const shard = this.openShardForWrite(tenantId);
    shard.upsert(JSON.stringify(points));
    shard.flush();

    // D3: update the in-memory mirror AND persist it atomically — the
    // upsert+flush above is the source of truth for the VECTORS; this
    // manifest is the source of truth for `overlayStateHash`, and both must
    // reach durable storage together (in that order: vectors first, so a
    // crash between the two leaves, at worst, a vector with no manifest
    // entry — re-embedding is idempotent and repairs it — never a manifest
    // entry claiming a vector that was never durably written).
    tools.forEach((tool, i) => {
      tenantContent.set(toolIds[i], {
        adapterId,
        toolName: tool.name,
        contentHash: createHash('sha256').update(serializedDocs[i], 'utf8').digest('hex'),
      });
    });
    this.contentByTenant.set(tenantId, tenantContent);
    atomicWriteManifest(dir, Object.fromEntries(tenantContent));

    return {
      tenantId,
      adapterId,
      embedded: tools.length,
      overlayStateHash: this.overlayStateHash(tenantId),
    };
  }

  /**
   * §4.5/§8.6 determinism contract extension (CHARIOT-SPEC.md:767: "the
   * overlay contributes to the `overlayStateHash` that scopes §8.6
   * determinism" — read together with §8.6's own top-of-file statement,
   * `CHARIOT-SPEC.md:763`: "Tier-1 selection is byte-identical for an
   * identical request against an identical `(sealed-bundle version,
   * overlay-state snapshot)`"). Identical overlay content (same set of
   * `{toolId, serialized-document-text}` pairs for a tenant, regardless of
   * embedding order, which adapter connected first, or WHICH PROCESS —
   * see the class-level "D3" comment on why this reads the persisted
   * manifest, not a this-process-only cache) MUST hash identically — this
   * is the exact content-addressed hash of what was actually fed to the
   * encoder, sorted by `toolId` so insertion order never leaks into the
   * hash. Distinct from — and MUST NOT be confused with — `ChariotState.ts`'s
   * unrelated `discovered-adapters` overlay bookkeeping (a different,
   * TOFU-signature mechanism with no encoder/embed step; see this module's
   * header). An unknown/never-embedded-for tenant returns a stable constant
   * (`sha256("")`), matching the "empty tool list → no-op with stable hash"
   * contract even for a tenant this instance has never seen.
   */
  overlayStateHash(tenantId: string): string {
    assertValidTenantId(tenantId);
    const dir = this.tenantShardDir(tenantId);
    this.ensureManifestLoaded(tenantId, dir);
    const tenantContent = this.contentByTenant.get(tenantId);
    if (!tenantContent || tenantContent.size === 0) {
      return createHash('sha256').update('').digest('hex');
    }
    const canonical = [...tenantContent.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([toolId, entry]) => `${toolId}=${entry.contentHash}`)
      .join('\n');
    return createHash('sha256').update(canonical, 'utf8').digest('hex');
  }
}

// Leak-denylist note (this is a PUBLIC repo, `.leak-denylist/patterns.txt`
// forbids the freeze-pipeline operator's internal name): the BIEN SPEC.md:51
// quote near the top of this file reads "freeze pipeline" where the on-disk
// spec's own bytes name the internal operator; every other citation in this
// file already used the public-safe "freeze side"/"freeze-side" terms this
// codebase's own `HybridRetriever.ts`/`nativeEdge.ts`/`VectorIndexVerifier.ts`
// use throughout, so only that one quoted word was substituted — the
// normative content (byte-identical model+serializer across doc-freeze,
// query, and on-device overlay embedding) is unchanged.
