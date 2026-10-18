/**
 * @epicai/chariot — Vector Index Verifier (CH-21, CH-23, CH-35, §5.6)
 *
 * The fail-closed admission gate that runs BEFORE any tool vector is loaded
 * into the retrieval path. It validates that the sealed, signed retrieval bundle
 * matches the COMPILED-IN 4.0.0 contract and is not a replay/downgrade:
 *
 *   1. Manifest contract (CH-21): `manifest.version`, `encoder.{denseModelId,
 *      denseModelVersion, denseDims=768, sparseModelId, bm25Method, idfPolicy}`,
 *      `recordCount`, and `serializer_hash`. The verifier keys on these stamped
 *      values, NEVER on `package.json` semver.
 *   2. Serializer lockstep (CH-23): the bundle `serializer_hash` MUST equal the
 *      compiled-in hash (and, when the native module is present, the native
 *      `frozenSerializerHash()`); any divergence fails closed before load.
 *   3. Anti-rollback (§5.6 replay/downgrade defense): `epoch` strictly greater and
 *      `catalogVersion` >= the persisted high-water mark. Reuses the existing
 *      `CatalogEpochState` + `loadPersistedEpoch`/`persistEpoch` atomic store
 *      (`AdapterCatalog.ts`) rather than reinventing the persistence.
 *   4. Agent-field acceptance gate (CH-35): the bundle (catalog) MUST carry
 *      `descriptionForRetrieval/searchQueries/industries/departments` for 100%
 *      of ACTIVE adapters and per-tool `{name, description, inputSchema}`. The
 *      freeze-side publisher emits these post-rebuild; Chariot lands the gate now.
 *
 * The Ed25519 signature over the full envelope is verified at the file boundary
 * (`verifyCatalogSignature.ts` / `verifiedReadOrNull`) and/or via the injected
 * `signatureVerified` flag passed to `admit()`; the AES-256-GCM unseal of the
 * EdgeShard snapshot is the native `unsealAndVerifySnapshot` wrapper invoked by
 * the load path (§8.6 guardrail — the seal/sign are Chariot's wrapper around the
 * Edge shard, not Edge capabilities). This class never silent-fallbacks to a
 * different model: a manifest mismatch is a hard, fail-closed bundle-load error
 * (§4.4), not a downgrade to a different encoder.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { CatalogEpochState } from '../federation/AdapterCatalog.js';
import { classifyCatalogAdmission } from '../federation/catalogAdmission.js';
import { verifyToolDispatchIdentity, type DispatchAdapterShape } from './ToolDispatchRoute.js';

/** The locked serializer hash (BIEN M1, §5.6 manifest table / CH-23). */
export const COMPILED_SERIALIZER_HASH =
  '8bed00ff2afed5367ac607b388be2f2c76d797108dbde9d08e31d74e109de43f';
/** Backward-compatible name used by the pre-4.0 verification seam. */
export const BIEN_SERIALIZER_HASH = COMPILED_SERIALIZER_HASH;

/** Minimal WARN sink so the CH-62 best-effort-facet notice is emitted without
 * coupling the verifier to the full retriever logger (no runtime import cycle). */
export interface VerifierLogger {
  warn(message: string, meta?: Record<string, unknown>): void;
}

export interface RetrievalManifest {
  version: string;
  encoder: { denseModelId: string; denseModelVersion: string; denseDims: number; sparseModelId: string; bm25Method: string; idfPolicy: string };
  recordCount: number;
  /** CH-62(b) / BIEN §17.7 widened-count stamps (tool + capability residuals). */
  tool_record_count?: number;
  capability_record_count?: number;
  recordCountPreOverlay?: number;
  serializer_hash: string;
  merkleRoot: string;
}
export interface FrozenToolRecord { tool_id: string; dispatch_mechanisms: Array<'mcp' | 'rest'>; }
export interface FrozenRetrievalContract { denseModelId: string; denseModelVersion: string; bm25Method: string; idfPolicy: string; }
export class VectorIndexVerificationError extends Error { constructor(message: string) { super(message); this.name = 'VectorIndexVerificationError'; } }

/** Compatibility verifier for the pre-4.0 bundle seam. It remains fail-closed. */
export function verifyVectorIndexManifest(manifest: RetrievalManifest, toolRecords: readonly FrozenToolRecord[], contract: FrozenRetrievalContract): void {
  const mismatches: string[] = [];
  if (manifest.version !== '4.0.0') mismatches.push('version');
  if (manifest.encoder?.denseModelId !== contract.denseModelId) mismatches.push('encoder.denseModelId');
  if (manifest.encoder?.denseModelVersion !== contract.denseModelVersion) mismatches.push('encoder.denseModelVersion');
  if (manifest.encoder?.denseDims !== 768) mismatches.push('encoder.denseDims');
  if (manifest.encoder?.sparseModelId !== 'prithivida/Splade_PP_en_v1') mismatches.push('encoder.sparseModelId');
  if (manifest.encoder?.bm25Method !== contract.bm25Method) mismatches.push('encoder.bm25Method');
  if (manifest.encoder?.idfPolicy !== contract.idfPolicy) mismatches.push('encoder.idfPolicy');
  if (!Number.isSafeInteger(manifest.recordCount) || manifest.recordCount <= 0) mismatches.push('recordCount');
  // CH-62(b) / BIEN §17.7: recordCount counts tool records AND capability
  // residuals, never tool records alone. The three count stamps are REQUIRED —
  // an ABSENT count is fail-closed, NEVER a silent zero. This pre-4.0 compat
  // seam is fed only the TOOL payload, so it enforces the stamps' internal
  // consistency (pre == tool + capability; recordCount <= pre) and parities the
  // tool side it can see against `tool_record_count`; the capability payload is
  // validated on the live `admit()` path (`countCapabilityRecords`).
  const toolRC = manifest.tool_record_count;
  const capRC = manifest.capability_record_count;
  const preRC = manifest.recordCountPreOverlay;
  const stampsWellFormed =
    Number.isInteger(toolRC) && (toolRC as number) >= 0 &&
    Number.isInteger(capRC) && (capRC as number) >= 0 &&
    Number.isInteger(preRC) && (preRC as number) >= 0;
  if (!stampsWellFormed) {
    mismatches.push('count stamps (tool_record_count/capability_record_count/recordCountPreOverlay) missing or negative');
  } else {
    if ((preRC as number) !== (toolRC as number) + (capRC as number)) mismatches.push('recordCountPreOverlay != tool_record_count + capability_record_count');
    if (manifest.recordCount > (preRC as number)) mismatches.push('recordCount > recordCountPreOverlay');
    if (toolRecords.length !== (toolRC as number)) mismatches.push('tool payload length != tool_record_count');
  }
  const ids = new Set<string>();
  for (const record of toolRecords) {
    if (!record.tool_id.includes('::') || ids.has(record.tool_id)) { mismatches.push('tool-granular identity'); break; }
    ids.add(record.tool_id);
    const mechanisms = record.dispatch_mechanisms;
    if (!mechanisms.length || mechanisms.some((m) => m !== 'mcp' && m !== 'rest') || JSON.stringify(mechanisms) !== JSON.stringify([...new Set(mechanisms)].sort())) { mismatches.push('dispatch_mechanisms'); break; }
  }
  if (manifest.serializer_hash !== BIEN_SERIALIZER_HASH) mismatches.push('serializer_hash');
  if (!/^[a-f0-9]{64}$/.test(manifest.merkleRoot)) mismatches.push('merkleRoot');
  if (mismatches.length) throw new VectorIndexVerificationError(`retrieval manifest rejected: ${mismatches.join(', ')}`);
}

/** The compiled-in 4.0.0 retrieval contract (CH-21 / §5.6 manifest table). */
export interface RetrievalContract {
  version: string;
  denseModelId: string;
  denseModelVersion: string;
  denseDims: number;
  sparseModelId: string;
  bm25Method: string;
  idfPolicy: string;
  /**
   * Optional MINIMUM record-count floor. The manifest's `recordCount` is no
   * longer pinned to a compiled-in constant (a compiled pin turned every
   * routine catalog publish into a fail-closed boot abort); instead `admit()`
   * requires `recordCount` to be a positive integer that exactly matches the
   * number of tool records carried by the signed catalog itself (CH-22
   * tool-granularity, manifest↔payload internal consistency). Deployments
   * that want an additional lower bound may compile one in here.
   */
  recordCount?: number;
  serializerHash: string;
}

/**
 * The compiled-in expected contract. `denseModelId`/`denseModelVersion`/
 * `bm25Method`/`idfPolicy` are pinned when BIEN locks the shipped model; until
 * then the verifier requires the manifest to CARRY non-empty, well-typed values
 * and matches them against whatever the deployment compiles in here. The locked
 * structural invariants (`version`, `denseDims=768`, `sparseModelId`,
 * `serializerHash`) are fixed by spec. `recordCount` is validated against the
 * bundle's own signed catalog (tool-granular record count, CH-22) rather than
 * a compiled constant — see `RetrievalContract.recordCount`.
 */
export const DEFAULT_RETRIEVAL_CONTRACT: RetrievalContract = {
  version: '4.0.0',
  denseModelId: 'epicai/bien-tool-retriever',
  denseModelVersion: '4.0.0',
  denseDims: 768,
  sparseModelId: 'prithivida/Splade_PP_en_v1',
  bm25Method: 'edge-bm25',
  idfPolicy: 'retriever-applied',
  serializerHash: COMPILED_SERIALIZER_HASH,
};

export type AdmissionCode =
  | 'admitted'
  | 'manifest_missing'
  | 'manifest_mismatch'
  | 'serializer_mismatch'
  | 'signature_invalid'
  | 'epoch_replay_rejected'
  | 'version_downgrade_rejected'
  | 'agent_field_gate_failed'
  /**
   * CHARIOT::§3.5a::1 / §3.5a::6 — a Ready tool record's `dispatchMechanisms`
   * is missing, not an array, empty, or carries a value outside {'mcp','rest'}.
   */
  | 'dispatch_mechanism_missing_or_empty'
  /**
   * CHARIOT::§3.5a::7 — an ambiguous tool route: a tool's `dispatchMechanisms`
   * is not a canonical (sorted, duplicate-free) set (AS §1.4a), or the same
   * canonical tool_id resolves to more than one record in the bundle.
   */
  | 'ambiguous_tool_route'
  /**
   * CHARIOT::§3.5a::8 — a `type:"both"` adapter's per-surface tool lists,
   * their union, or a tool's mechanism set disagrees with AS §1.4a.
   */
  | 'dispatch_identity_disagreement'
  | 'envelope_malformed'
  /**
   * NOT produced by `admit()`. Reused by `loadRetrieval.ts`'s `WireResult`
   * `fail-closed` variant for the §4.4 row-2 / §4.1 case where the manifest
   * WAS admitted but the native Edge module or dense encoder artifact is
   * missing or fails to load at STARTUP — fail-closed per the 2026-07-16b
   * amendment, never a BM25 fallback. Kept on this union so both fail-closed
   * paths (pre-admission and post-admission) share one discriminant type.
   */
  | 'encoder_load_failed';

export interface AdmissionResult {
  admitted: boolean;
  code: AdmissionCode;
  reason: string;
  /** When admitted, the (epoch, catalogVersion) pair the caller MUST persist. */
  nextEpochState?: CatalogEpochState;
}

/** Minimal manifest shape the verifier inspects (extra fields ignored). */
export interface BundleManifest {
  version?: unknown;
  encoder?: {
    denseModelId?: unknown;
    denseModelVersion?: unknown;
    denseDims?: unknown;
    sparseModelId?: unknown;
    bm25Method?: unknown;
    idfPolicy?: unknown;
  };
  recordCount?: unknown;
  /** CH-62(b) / BIEN §17.7 widened-count stamps — all three REQUIRED at load. */
  tool_record_count?: unknown;
  capability_record_count?: unknown;
  recordCountPreOverlay?: unknown;
  serializer_hash?: unknown;
  /** Index granularity discriminator (CH-22). When present it MUST be 'tool'. */
  granularity?: unknown;
}

/**
 * Minimal per-tool shape for the CH-35 agent-field gate and the CHARIOT::§3.5a
 * tool-level dispatch identity gate. `dispatchMechanisms` (CHARIOT-SPEC.md:272-273:
 * "Every Ready tool record in the 4.0.0 retrieval bundle MUST carry `{name,
 * description, inputSchema, dispatchMechanisms}`.") is REQUIRED on every
 * Ready tool record, mirroring `name`/`description`/`inputSchema` above it.
 */
export interface BundleTool {
  name?: unknown;
  description?: unknown;
  inputSchema?: unknown;
  dispatchMechanisms?: unknown;
}

/** Minimal adapter shape for the CH-35 agent-field gate and CHARIOT::§3.5a. */
export interface BundleAdapter {
  id?: unknown;
  revoked?: unknown;
  active?: unknown;
  descriptionForRetrieval?: unknown;
  searchQueries?: unknown;
  industries?: unknown;
  departments?: unknown;
  tools?: unknown;
  /**
   * AS §2.1 top-level `type` ("mcp" | "rest" | "cli-bridge" | "both") plus the
   * §1.4a per-surface tool-name lists, needed ONLY to run the CHARIOT::§3.5a::8
   * per-surface/union/mechanism disagreement check for `type:"both"` records.
   */
  type?: unknown;
  rest?: unknown;
  mcp?: unknown;
}

export interface BundleEnvelope {
  catalog?: unknown;
  registry?: unknown;
  manifest?: unknown;
  epoch?: unknown;
  catalogVersion?: unknown;
}

export interface AdmitOptions {
  /** The previously persisted high-water mark, or null on a fresh install. */
  persisted: CatalogEpochState | null;
  /**
   * Result of the Ed25519 envelope-signature check at the file boundary. The
   * verifier fails closed when this is false; pass `true` only after the
   * signature over `{catalog, registry, manifest, epoch, catalogVersion}` has
   * verified (verifyCatalogSignature / verifiedReadOrNull).
   */
  signatureVerified: boolean;
  /** Native `frozenSerializerHash()` when the module is loaded (CH-23 lockstep). */
  nativeSerializerHash?: string;
  /**
   * SHA-256 (hex) of the exact signature-verified envelope bytes being
   * admitted. Identity-binds the §5.6 anti-rollback mark: re-admitting the
   * IDENTICAL bundle at the persisted epoch (the normal restart case) is an
   * idempotent no-op, while any OTHER bundle at <= the persisted epoch is
   * still rejected as a replay. When omitted, an equal-epoch bundle cannot
   * prove its identity and is rejected (fail closed).
   */
  bundleSha256?: string;
  /** Optional WARN sink for the CH-62 best-effort-facet notice (industries/
   * departments absent on a residual adapter). Absence is never fail-closed. */
  logger?: VerifierLogger;
}

export class VectorIndexVerifier {
  constructor(private readonly contract: RetrievalContract = DEFAULT_RETRIEVAL_CONTRACT) {}

  /**
   * Validate the manifest against the compiled-in contract (CH-21 / CH-23).
   * Returns null on success or an AdmissionResult on the first failure.
   */
  verifyManifest(manifest: unknown, nativeSerializerHash?: string): AdmissionResult | null {
    if (!manifest || typeof manifest !== 'object') {
      return fail('manifest_missing', 'bundle envelope is missing the retrieval manifest');
    }
    const m = manifest as BundleManifest;
    const enc = m.encoder;
    if (!enc || typeof enc !== 'object') {
      return fail('manifest_missing', 'manifest is missing the encoder contract');
    }

    if (m.version !== this.contract.version) {
      return fail(
        'manifest_mismatch',
        `manifest.version ${stringify(m.version)} != contract ${this.contract.version}`,
      );
    }
    if (enc.denseDims !== this.contract.denseDims) {
      return fail(
        'manifest_mismatch',
        `encoder.denseDims ${stringify(enc.denseDims)} != ${this.contract.denseDims}`,
      );
    }
    if (enc.sparseModelId !== this.contract.sparseModelId) {
      return fail(
        'manifest_mismatch',
        `encoder.sparseModelId ${stringify(enc.sparseModelId)} != ${this.contract.sparseModelId}`,
      );
    }
    if (enc.denseModelId !== this.contract.denseModelId) {
      return fail(
        'manifest_mismatch',
        `encoder.denseModelId ${stringify(enc.denseModelId)} != ${this.contract.denseModelId}`,
      );
    }
    if (enc.denseModelVersion !== this.contract.denseModelVersion) {
      return fail(
        'manifest_mismatch',
        `encoder.denseModelVersion ${stringify(enc.denseModelVersion)} != ${this.contract.denseModelVersion}`,
      );
    }
    if (enc.bm25Method !== this.contract.bm25Method) {
      return fail(
        'manifest_mismatch',
        `encoder.bm25Method ${stringify(enc.bm25Method)} != ${this.contract.bm25Method}`,
      );
    }
    if (enc.idfPolicy !== this.contract.idfPolicy) {
      return fail(
        'manifest_mismatch',
        `encoder.idfPolicy ${stringify(enc.idfPolicy)} != ${this.contract.idfPolicy}`,
      );
    }
    // CH-22 tool-granularity. `recordCount` must be a positive integer; the
    // exact value is cross-checked in admit() against the number of tool
    // records the signed catalog actually carries (manifest↔payload internal
    // consistency), NOT against a compiled-in constant — a compiled pin made
    // every routine catalog publish a fail-closed boot abort. An explicit
    // `granularity` field, when stamped, must declare the tool-granular index.
    if (!Number.isInteger(m.recordCount) || (m.recordCount as number) <= 0) {
      return fail(
        'manifest_mismatch',
        `recordCount ${stringify(m.recordCount)} is not a positive integer (CH-22)`,
      );
    }
    if (this.contract.recordCount !== undefined && (m.recordCount as number) < this.contract.recordCount) {
      return fail(
        'manifest_mismatch',
        `recordCount ${stringify(m.recordCount)} is below the compiled-in floor ` +
          `${this.contract.recordCount} (CH-22)`,
      );
    }
    // CH-62(b) / BIEN §17.7 — the widened record-count invariant. recordCount
    // counts EVERY retrieval record (tool records AND capability residuals),
    // never tool records alone. The manifest MUST stamp `tool_record_count`,
    // `capability_record_count`, and `recordCountPreOverlay`, each a non-negative
    // integer; ANY absent count is a fail-closed load error (BIEN §17.7 — "an
    // absent count is a hard error, not a silent zero").
    for (const name of ['tool_record_count', 'capability_record_count', 'recordCountPreOverlay'] as const) {
      const v = m[name];
      if (!Number.isInteger(v) || (v as number) < 0) {
        return fail(
          'manifest_mismatch',
          `manifest.${name} ${stringify(v)} is missing or not a non-negative integer (CH-62 / BIEN §17.7)`,
        );
      }
    }
    const toolRC = m.tool_record_count as number;
    const capRC = m.capability_record_count as number;
    const preRC = m.recordCountPreOverlay as number;
    // §17.7: recordCountPreOverlay == tool_record_count + capability_record_count
    // (proven BEFORE the quarantine overlay so a stale stamp cannot be masked by
    // overlay arithmetic).
    if (preRC !== toolRC + capRC) {
      return fail(
        'manifest_mismatch',
        `recordCountPreOverlay ${preRC} != tool_record_count ${toolRC} + capability_record_count ${capRC} (BIEN §17.7)`,
      );
    }
    // The overlay only REMOVES records: 0 < recordCount <= recordCountPreOverlay.
    // (recordCount > 0 is already enforced above.)
    if ((m.recordCount as number) > preRC) {
      return fail(
        'manifest_mismatch',
        `recordCount ${stringify(m.recordCount)} > recordCountPreOverlay ${preRC} ` +
          '(CH-62 — the quarantine overlay only removes records)',
      );
    }
    if (m.granularity !== undefined && m.granularity !== 'tool') {
      return fail(
        'manifest_mismatch',
        `manifest.granularity ${stringify(m.granularity)} != "tool" ` +
          '(adapter-granular bundles are rejected as stale, CH-22)',
      );
    }

    // CH-23 serializer lockstep: bundle hash must match compiled-in AND, when
    // the native module is loaded, its compiled-in frozen hash too.
    if (m.serializer_hash !== this.contract.serializerHash) {
      return fail(
        'serializer_mismatch',
        `serializer_hash ${stringify(m.serializer_hash)} != compiled-in ${this.contract.serializerHash}`,
      );
    }
    if (nativeSerializerHash !== undefined && nativeSerializerHash !== this.contract.serializerHash) {
      return fail(
        'serializer_mismatch',
        `native frozenSerializerHash ${nativeSerializerHash} != compiled-in ${this.contract.serializerHash}`,
      );
    }

    return null;
  }

  /**
   * CH-35 + CH-62(a) agent-field acceptance gate. Every ACTIVE adapter (active
   * unless `revoked === true` or `active === false`) MUST carry a grounded
   * capability profile — `descriptionForRetrieval` + non-empty `searchQueries`.
   *
   * Two adapter classes are then distinguished (CH-62(a)):
   *   - RESIDUAL (empty/absent `tools`): a non-dispatchable CAPABILITY record.
   *     It MUST NOT be rejected for carrying empty tools, and per-tool
   *     `{name, description, inputSchema}` is NOT required. `industries` /
   *     `departments` are the CH-35 best-effort facet — absence is a WARN,
   *     null-omittable, NEVER fail-closed.
   *   - TOOL-BEARING: the CH-35 gate is UNCHANGED — per-tool
   *     `{name, description, inputSchema}` is required; `industries` /
   *     `departments` are the same best-effort facet (WARN, never fail-closed).
   *
   * CHARIOT::§3.5a (CHARIOT-SPEC.md:270-279, quoted verbatim):
   *   "Every Ready tool record in the 4.0.0 retrieval bundle MUST carry
   *   `{name, description, inputSchema, dispatchMechanisms}`. For
   *   `type:"both"`, the per-surface tool lists, their sorted duplicate-free
   *   top-level union, and each tool's exact mechanism set MUST satisfy AS
   *   §1.4a. ... `VectorIndexVerifier` and the catalog loader MUST reject
   *   adapter-granular bundles, missing or empty mechanism sets, ambiguous
   *   tool routes, and any per-surface/union/mechanism disagreement."
   * This method is the admission-time enforcement point for every clause
   * above except adapter-granular rejection (already enforced in
   * `verifyManifest`'s `granularity` check, CH-22).
   */
  verifyAgentFieldGate(catalog: unknown, logger?: VerifierLogger): AdmissionResult | null {
    if (!Array.isArray(catalog)) {
      return fail('envelope_malformed', 'bundle catalog is not an array');
    }
    const toolIds = new Set<string>();       // CH-62 node 131 — server::name tool identity, unique across the catalog.
    const capabilityIds = new Set<string>(); // CH-62 node 132 — capability record key (server/adapter id), unique.
    for (const raw of catalog) {
      if (!raw || typeof raw !== 'object') {
        return fail('agent_field_gate_failed', 'catalog entry is not an object');
      }
      const a = raw as BundleAdapter;
      if (a.revoked === true || a.active === false) continue; // inactive — exempt
      const id = typeof a.id === 'string' ? a.id : '<unknown>';

      // Profile is required for BOTH classes (AS §1.2a tier-3 grounds a residual
      // capability record on exactly these two fields).
      if (!isNonEmptyString(a.descriptionForRetrieval)) {
        return fail('agent_field_gate_failed', `adapter ${id}: missing descriptionForRetrieval (CH-35/CH-62)`);
      }
      if (!isNonEmptyArray(a.searchQueries)) {
        return fail('agent_field_gate_failed', `adapter ${id}: missing searchQueries (CH-35/CH-62)`);
      }

      const isResidual = !Array.isArray(a.tools) || a.tools.length === 0;
      if (isResidual) {
        // CH-62 node 132: a capability record is keyed by its server/adapter id;
        // that key MUST be a non-empty string and unique across capability records.
        if (!isNonEmptyString(a.id)) {
          return fail('agent_field_gate_failed', 'residual capability record missing a string id key (CH-62 node 132)');
        }
        if (capabilityIds.has(a.id)) {
          return fail('agent_field_gate_failed', `duplicate capability record key ${a.id} (CH-62 node 132)`);
        }
        capabilityIds.add(a.id);
        // CH-62(a): capability record — no per-tool metadata; facet best-effort.
        if (!isNonEmptyArray(a.industries) || !isNonEmptyArray(a.departments)) {
          logger?.warn('retrieval.capability_facet_absent', {
            adapter: id,
            reason: 'residual capability record missing industries/departments (best-effort facet, CH-35/CH-62 — not fail-closed)',
          });
        }
        continue;
      }

      // Tool-bearing adapter — CH-35 (AMENDED 2026-07-16): `industries` /
      // `departments` are a best-effort facet — "absence is reported at WARN and
      // is null-omittable, never a fail-closed condition". Per-tool
      // `{name, description, inputSchema}` below stays fail-closed.
      if (!isNonEmptyArray(a.industries) || !isNonEmptyArray(a.departments)) {
        logger?.warn('retrieval.facet_absent', {
          adapter: id,
          reason: 'tool-bearing adapter missing industries/departments (best-effort facet, CH-35 amended 2026-07-16 — not fail-closed)',
        });
      }
      for (const t of a.tools as unknown[]) {
        const tool = t as BundleTool;
        if (!tool || typeof tool !== 'object' || !isNonEmptyString(tool.name)) {
          return fail('agent_field_gate_failed', `adapter ${id}: tool missing name (CH-35)`);
        }
        // CH-62 node 131 / CH-22: tool-granular identity is `server::name`,
        // unique across the whole catalog. This is the live-path guarantee the
        // pre-4.0 compat seam already asserted; enforce it here too. A
        // duplicate tool_id is ALSO an ambiguous tool route (CHARIOT::§3.5a::7)
        // — the router cannot tell which record governs that id — so this
        // same rejection satisfies both clauses.
        const toolId = `${id}::${tool.name}`;
        if (toolIds.has(toolId)) {
          return fail('agent_field_gate_failed', `duplicate tool identity ${toolId} (CH-62 node 131 / CH-22 server::name uniqueness; CHARIOT::§3.5a::7 ambiguous tool route)`);
        }
        toolIds.add(toolId);
        if (!isNonEmptyString(tool.description)) {
          return fail('agent_field_gate_failed', `adapter ${id}: tool ${tool.name} missing description (CH-35)`);
        }
        if (!tool.inputSchema || typeof tool.inputSchema !== 'object') {
          return fail('agent_field_gate_failed', `adapter ${id}: tool ${tool.name} missing inputSchema (CH-35)`);
        }

        // CHARIOT::§3.5a::1 / §3.5a::6 — "Every Ready tool record...MUST
        // carry {..., dispatchMechanisms}" and "If a bundle has a missing or
        // empty mechanism set...VectorIndexVerifier...shall reject that
        // bundle." A missing field, a non-array, an empty array, or any
        // value outside {'mcp','rest'} is rejected here, before any tool can
        // be offered — the dispatch-time check in ToolDispatchRoute.ts stays
        // as defense in depth.
        const mechanisms = tool.dispatchMechanisms;
        if (
          !Array.isArray(mechanisms) ||
          mechanisms.length === 0 ||
          mechanisms.some((m) => m !== 'mcp' && m !== 'rest')
        ) {
          return fail(
            'dispatch_mechanism_missing_or_empty',
            `adapter ${id}: tool ${tool.name} has a missing, empty, or invalid dispatchMechanisms set ` +
              `${stringify(mechanisms)} (CHARIOT::§3.5a::1, §3.5a::6)`,
          );
        }
        // CHARIOT::§3.5a::7 — "If a bundle has an ambiguous tool route, then
        // VectorIndexVerifier...shall reject that bundle." AS §1.4a requires
        // `dispatchMechanisms` to be "sorted, non-empty" — a duplicate or
        // unsorted mechanism multiset is not a canonical, deterministically
        // resolvable route (mirrors the dormant pre-4.0 compat check at :104,
        // now enforced on the live admission path).
        const canonical = [...new Set(mechanisms as unknown[])].sort();
        if (JSON.stringify(mechanisms) !== JSON.stringify(canonical)) {
          return fail(
            'ambiguous_tool_route',
            `adapter ${id}: tool ${tool.name} dispatchMechanisms ${JSON.stringify(mechanisms)} is not a ` +
              `sorted, duplicate-free set — ambiguous route (CHARIOT::§3.5a::7, AS §1.4a)`,
          );
        }
      }

      // CHARIOT::§3.5a::8 — "For type:"both", the per-surface tool lists,
      // their sorted duplicate-free top-level union, and each tool's exact
      // mechanism set MUST satisfy AS §1.4a. ... VectorIndexVerifier and the
      // catalog loader MUST reject...any per-surface/union/mechanism
      // disagreement." Runs the SAME check toolHandlers.ts already runs at
      // dispatch time (ToolDispatchRoute.ts:15, verifyToolDispatchIdentity)
      // here at admission, before any tool can be offered — dispatch-time
      // stays as defense in depth.
      if (a.type === 'both') {
        try {
          verifyToolDispatchIdentity(a as DispatchAdapterShape);
        } catch (err) {
          return fail(
            'dispatch_identity_disagreement',
            `adapter ${id}: ${err instanceof Error ? err.message : String(err)} (CHARIOT::§3.5a::8)`,
          );
        }
      }
    }
    return null;
  }

  /**
   * Full fail-closed admission. Order is untrusted-input-first: signature,
   * envelope shape, anti-rollback (§5.6), manifest contract (CH-21/CH-23), then
   * the CH-35 agent-field gate. On admit, returns the `{epoch, catalogVersion}`
   * the caller MUST persist atomically (via `persistEpoch`) BEFORE advertising
   * the catalog.
   */
  admit(envelope: BundleEnvelope, opts: AdmitOptions): AdmissionResult {
    if (!opts.signatureVerified) {
      return fail('signature_invalid', 'bundle Ed25519 envelope signature did not verify (§5.6)');
    }
    if (!envelope || typeof envelope !== 'object') {
      return fail('envelope_malformed', 'bundle envelope is not an object');
    }

    // §5.6 — epoch + catalogVersion must be integers and covered by the sig.
    if (!Number.isInteger(envelope.epoch)) {
      return fail('envelope_malformed', 'envelope.epoch is missing or not an integer (§5.6)');
    }
    if (!Number.isInteger(envelope.catalogVersion)) {
      return fail('envelope_malformed', 'envelope.catalogVersion is missing or not an integer (§5.6)');
    }
    const epoch = envelope.epoch as number;
    const catalogVersion = envelope.catalogVersion as number;

    // §5.6 admission — the SINGLE shared classifier (CHARIOT-SPEC.md:436).
    // This site MUST NOT restate the comparison locally. The local copy that
    // used to live here treated an ABSENT persisted bundleSha256 as a wildcard
    // matching any bundle, which CHARIOT-SPEC.md:434 forbids by name: an absent
    // hash is `identity_unproven` and fails closed, because otherwise anyone
    // able to delete one field from a local file could admit an arbitrary
    // bundle at the pinned epoch.
    const persisted = opts.persisted;
    const admission = classifyCatalogAdmission({
      epoch,
      catalogVersion,
      ...(opts.bundleSha256 !== undefined ? { bundleSha256: opts.bundleSha256 } : {}),
      persisted: persisted ?? null,
    });
    if (admission.kind === 'rejection') {
      return fail('epoch_replay_rejected', `${admission.message} [${admission.reason}]`);
    }
    // The classifier already applied the version-downgrade defense on the
    // advance path and version EQUALITY on the re-admission path
    // (CHARIOT-SPEC.md:430-431), so there is deliberately no second local
    // catalogVersion comparison here — a second copy is what :455 forbids.

    const manifestResult = this.verifyManifest(envelope.manifest, opts.nativeSerializerHash);
    if (manifestResult) return manifestResult;

    const gateResult = this.verifyAgentFieldGate(envelope.catalog, opts.logger);
    if (gateResult) return gateResult;

    // CH-62(b) manifest↔payload consistency: the stamped recordCount MUST equal
    // the number of retrieval records the signed catalog itself carries — tool
    // records PLUS capability residuals (CH-62(b), node (2)), counted over the
    // ACTIVE (post-overlay) records only. Both sides are covered by the envelope
    // signature, so a signed bundle whose manifest disagrees with its own
    // payload (e.g. a stale index, or a tool-only count under CH-62) fails
    // closed, while routine catalog growth/shrink needs no code release.
    const catalog = envelope.catalog as unknown[];
    const declaredRecordCount = (envelope.manifest as BundleManifest).recordCount as number;
    const toolRecordCount = countToolRecords(catalog);
    const capabilityRecordCount = countCapabilityRecords(catalog);
    const actualRecordCount = toolRecordCount + capabilityRecordCount;
    if (declaredRecordCount !== actualRecordCount) {
      return fail(
        'manifest_mismatch',
        `manifest.recordCount ${declaredRecordCount} != ${actualRecordCount} records ` +
          `(${toolRecordCount} tool + ${capabilityRecordCount} capability) carried by the signed catalog ` +
          '(manifest↔payload mismatch / stale index rejected, CH-62(b) / CH-22)',
      );
    }

    // A re-admission is NOT a publication: the high-water mark SHALL NOT be
    // rewritten (CHARIOT-SPEC.md:431, :457). `nextEpochState` is the caller's
    // instruction to persist, so it is omitted entirely on a re-admission
    // rather than handed over with values the caller must then decide to
    // ignore — the decision belongs to the clause, not to the caller.
    return {
      admitted: true,
      code: 'admitted',
      reason:
        admission.kind === 're-admission'
          ? 'bundle re-admitted: byte-identical artifact at the persisted mark; ' +
            'signature, manifest, and CH-35 gate all passed (mark not rewritten, §5.6)'
          : 'bundle admitted: signature, anti-rollback, manifest, and CH-35 gate all passed',
      ...(admission.kind === 'advance'
        ? {
            nextEpochState: {
              epoch,
              catalogVersion,
              ...(opts.bundleSha256 !== undefined ? { bundleSha256: opts.bundleSha256 } : {}),
            },
          }
        : {}),
    };
  }
}

function fail(code: AdmissionCode, reason: string): AdmissionResult {
  return { admitted: false, code, reason };
}

/**
 * Count the tool-granular records the catalog carries: one per tool of every
 * ACTIVE adapter (same activity definition as the CH-35 gate — an adapter is
 * active unless `revoked === true` or `active === false`). Runs after
 * `verifyAgentFieldGate`, which has already validated the per-adapter `tools`
 * arrays for every active adapter.
 */
function countToolRecords(catalog: unknown[]): number {
  let count = 0;
  for (const raw of catalog) {
    if (!raw || typeof raw !== 'object') continue;
    const a = raw as BundleAdapter;
    if (a.revoked === true || a.active === false) continue;
    if (Array.isArray(a.tools)) count += a.tools.length;
  }
  return count;
}

/**
 * Count the CAPABILITY records the catalog carries (CH-62(b)): exactly one per
 * ACTIVE residual adapter — an adapter with empty/absent `tools` (its capability
 * profile was validated by `verifyAgentFieldGate`). A tool-bearing adapter
 * contributes 0 here and `tools.length` to `countToolRecords`, so every active
 * member falls in EXACTLY ONE of the two counts (tool XOR capability, node 130).
 */
function countCapabilityRecords(catalog: unknown[]): number {
  let count = 0;
  for (const raw of catalog) {
    if (!raw || typeof raw !== 'object') continue;
    const a = raw as BundleAdapter;
    if (a.revoked === true || a.active === false) continue;
    if (!Array.isArray(a.tools) || a.tools.length === 0) count += 1;
  }
  return count;
}

function stringify(v: unknown): string {
  if (typeof v === 'string') return `"${v}"`;
  return String(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

function isNonEmptyArray(v: unknown): boolean {
  return Array.isArray(v) && v.length > 0;
}
