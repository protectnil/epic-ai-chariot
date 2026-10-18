#!/usr/bin/env node
/** Signed catalog -> local document encoders -> Edge snapshot -> §5.7 seal.
 * Governing clauses: CHARIOT-SPEC §5.1, §5.7, §8.6, CH-62 (capability
 * residuals; BIEN §16.5 / §17.7); release instructions are in
 * docs/product/EDGESHARD_SNAPSHOTS.md. No secrets belong in argv.
 * Copyright 2026 protectNIL Inc. Elastic-2.0.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { verifyAndReadArtifact } from '../keys/verifyCatalogSignature.js';
import { loadNativeEdge, type NativeDenseEncoder, type NativeEdgeBinding, type NativeEdgeShard, type NativeSpladeEncoder } from '../retrieval/nativeEdge.js';
import { COMPILED_SERIALIZER_HASH, VectorIndexVerifier } from '../retrieval/VectorIndexVerifier.js';
import { isBareCiphertextBasename, SEALED_SHARD_CIPHERTEXT_SUFFIX, SNAPSHOT_VERIFYING_KEY_PEM } from '../retrieval/sealedShardConfig.js';
import { sha256FileHex } from '../retrieval/fileDigest.js';
import { verifyAndDecode } from '../../license/loader.js';

type Row = Record<string, unknown>;
/** BIEN §17.7 retrieval-record kinds: `record_kind: "tool"` or the AS §1.2a
 * tier-3 `adapter_capability` residual (CH-62). */
export type SnapshotRecordKind = 'tool' | 'adapter_capability';
export interface SnapshotRecord { toolId: string; adapterId: string; record: Row; kind: SnapshotRecordKind; }

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
}

/** CH-62 capability residual: the ONE non-dispatchable record of an ACTIVE
 * adapter whose top-level `tools` is absent or empty — the same predicate the
 * admission gate counts (`VectorIndexVerifier.countCapabilityRecords`). Its
 * text is "its own grounded capability profile already on the row" (BIEN
 * `data/expand.py:build_capability_record` over `extract.py:to_adapter_context`):
 * NAME = `displayName` else the adapter id, FAMILY = catalog `type`, CATEGORY,
 * DESC = `descriptionForRetrieval`, KW/DEPT/IND lists, AUTH = `auth.inferredModel`
 * with none/unknown null-omitted; every per-tool field is empty and therefore
 * null-omitted by the serializer. The native serializer reads only its
 * TOOL_FIELDS keys (`search_queries`, `record_kind`, `dispatchable` are never
 * serialized — BIEN conformance corpus case `adapter-capability-residual`).
 * CH-62(a): `descriptionForRetrieval` + non-empty `searchQueries` are required;
 * `industries`/`departments` are best-effort. Nothing is invented. */
export function capabilityRecord(adapter: Row): Row {
  const id = adapter.id as string;
  if (!isNonEmptyString(adapter.descriptionForRetrieval)) throw new Error(`residual adapter ${id}: missing descriptionForRetrieval (CH-62(a))`);
  // CH-62(a) "non-empty `searchQueries`": at least one non-blank STRING must
  // survive `stringList`, so a payload of `[42]` / `['']` can never yield a
  // capability point whose `search_queries` is silently empty.
  if (!stringList(adapter.searchQueries).some(isNonEmptyString)) throw new Error(`residual adapter ${id}: missing searchQueries (CH-62(a))`);
  const auth = adapter.auth as Row | undefined;
  const inferred = typeof auth?.inferredModel === 'string' ? auth.inferredModel.trim() : '';
  return {
    name: isNonEmptyString(adapter.displayName) ? adapter.displayName : id,
    connector_family: typeof adapter.type === 'string' ? adapter.type : '',
    category: typeof adapter.category === 'string' ? adapter.category : '',
    description: adapter.descriptionForRetrieval,
    keywords: stringList(adapter.keywords),
    departments: stringList(adapter.departments),
    industries: stringList(adapter.industries),
    auth_model: inferred.toLowerCase() === 'none' || inferred.toLowerCase() === 'unknown' ? '' : inferred,
    operation: '',
    output_type: '',
    side_effects: [],
    risk_flags: [],
    required_params: [],
    optional_params: [],
    enum_values: [],
    examples: [],
    search_queries: stringList(adapter.searchQueries),
    record_kind: 'adapter_capability',
    dispatchable: false,
  };
}

/** Use the catalog once: registry duplicates the same adapter identities.
 * The population is EXACTLY the one admission counts (CH-62(b) node (2),
 * `VectorIndexVerifier.admit`): every ACTIVE adapter contributes either its
 * top-level `tools` as tool records XOR one capability record when `tools`
 * is absent/empty. `mcp.tools`, `toolNames` and `toolCount` never add a
 * record — admission does not read them, so the producer must not either. */
export function snapshotRecords(bundle: Row): SnapshotRecord[] {
  if (!Array.isArray(bundle.catalog)) throw new Error('bundle.catalog must be an array');
  const records: SnapshotRecord[] = [];
  const seen = new Set<string>();
  for (const raw of bundle.catalog) {
    if (!raw || typeof raw !== 'object') throw new Error('invalid catalog adapter');
    const adapter = raw as Row;
    if (adapter.active === false || adapter.revoked === true) continue;
    // Same predicate admission applies to a capability key (CH-62 node 132:
    // "non-empty string"): whitespace-only ids are not identities.
    if (!isNonEmptyString(adapter.id)) throw new Error('adapter id is missing');
    const tools = adapter.tools;
    if (!Array.isArray(tools) || tools.length === 0) {
      // Capability record, keyed by the bare adapter id (CH-62 "keyed by its
      // server / adapter id"); the runtime recovers the adapter id from the
      // ABSENCE of a colon (OfficialPartition.adapterIdFromRetrievalId), so a
      // colon-bearing key would be misread as `server:name` — fail closed.
      if (adapter.id.includes(':')) throw new Error(`capability record key ${adapter.id} contains ":" and cannot be keyed by adapter id (CH-62)`);
      if (seen.has(adapter.id)) throw new Error('duplicate capability record key');
      seen.add(adapter.id);
      records.push({ toolId: adapter.id, adapterId: adapter.id, record: capabilityRecord(adapter), kind: 'adapter_capability' });
      continue;
    }
    for (const rawTool of tools) {
      if (!rawTool || typeof rawTool !== 'object') throw new Error('invalid tool record');
      const tool = rawTool as Row;
      if (typeof tool.name !== 'string' || !tool.name || typeof tool.description !== 'string') throw new Error('tool name/description missing');
      const toolId = typeof tool.tool_id === 'string' ? tool.tool_id : `${adapter.id}:${tool.name}`;
      if (seen.has(toolId)) throw new Error('duplicate canonical tool identity');
      seen.add(toolId);
      const schema = tool.inputSchema as Row | undefined;
      const required = Array.isArray(schema?.required) ? schema.required.filter((p): p is string => typeof p === 'string') : [];
      const properties = schema?.properties && typeof schema.properties === 'object' ? Object.keys(schema.properties) : [];
      const record = { ...tool, required_params: required, optional_params: properties.filter(p => !required.includes(p)) };
      records.push({ toolId, adapterId: adapter.id, record, kind: 'tool' });
    }
  }
  records.sort((a, b) => a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0);
  if (records.length === 0) throw new Error('bundle has no retrieval records');
  const manifest = bundle.manifest as Row | undefined;
  // CH-62(b) node (2): recordCount == tool records + capability records carried
  // by the signed catalog (post-overlay). `tool_record_count` /
  // `capability_record_count` are PRE-overlay stamps and are not compared here.
  if (!manifest || manifest.recordCount !== records.length || manifest.serializer_hash !== COMPILED_SERIALIZER_HASH) {
    throw new Error('signed retrieval manifest count/serializer does not match snapshot');
  }
  return records;
}

export function validateSealScope(secretRootB64: string, salt: string, aad: string): number {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(secretRootB64) || Buffer.from(secretRootB64, 'base64').toString('base64') !== secretRootB64 || Buffer.from(secretRootB64, 'base64').length < 32) {
    throw new Error('secret root must be canonical base64 encoding of at least 32 bytes');
  }
  if (!salt) throw new Error('salt must not be empty');
  const match = /^([^|]+)\|epoch=(0|[1-9][0-9]*)$/.exec(aad);
  if (!match || match[1] !== salt) throw new Error('salt/aad context mismatch or invalid epoch');
  const epoch = Number(match[2]);
  if (!Number.isInteger(epoch) || epoch > 0xffffffff) throw new Error('security epoch must fit u32');
  return epoch;
}

export function assertPinnedSigningSeed(seedB64: string): void {
  const seed = Buffer.from(seedB64, 'base64');
  if (seed.length !== 32 || seed.toString('base64') !== seedB64) throw new Error('snapshot signing seed must encode exactly 32 bytes');
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(createPublicKey(SNAPSHOT_VERIFYING_KEY_PEM).export({ format: 'der', type: 'spki' }))) {
    throw new Error('snapshot signing key is outside the consumer pinned key set');
  }
}

export function pointId(toolId: string): string {
  const hex = createHash('sha256').update(toolId).digest('hex').slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20)}`;
}

/** Apply an atomic adapter-scoped delta to a previously unpacked shard.
 *
 * The baseline shard is mutated only in a private staging directory by the
 * caller. Every point belonging to a changed adapter is removed first, then
 * only the candidate records for those adapters are embedded and upserted.
 * All other point bytes stay in the loaded shard untouched. Publication must
 * still use the normal staged ciphertext-then-descriptor rename sequence.
 */
export interface AdapterDeltaOptions {
  baselineBundle: Row;
  candidateBundle: Row;
  changedAdapterIds: ReadonlySet<string>;
  shard: NativeEdgeShard;
  native: NativeEdgeBinding;
  dense: NativeDenseEncoder;
  sparse: NativeSpladeEncoder;
  batchSize?: number;
}

export function applyAdapterDelta(options: AdapterDeltaOptions): { recordCount: number; changedToolIds: string[] } {
  const { baselineBundle, candidateBundle, changedAdapterIds, shard, native, dense, sparse } = options;
  if (!changedAdapterIds || changedAdapterIds.size === 0) throw new Error('delta must name at least one changed adapter');
  if (typeof shard.deletePoints !== 'function') throw new Error('native shard lacks deletePoints; rebuild the current native addon');
  const baseline = snapshotRecords(baselineBundle);
  const candidate = snapshotRecords(candidateBundle);
  const isChanged = (id: string) => changedAdapterIds.has(id);
  const presentAdapters = new Set([...baseline, ...candidate].map(r => r.adapterId));
  for (const id of changedAdapterIds) if (!presentAdapters.has(id)) throw new Error(`delta names unknown adapter: ${id}`);
  const baselineChanged = baseline.filter(r => isChanged(r.adapterId));
  const candidateChanged = candidate.filter(r => isChanged(r.adapterId));
  const unchangedBaseline = baseline.filter(r => !isChanged(r.adapterId));
  const unchangedCandidate = candidate.filter(r => !isChanged(r.adapterId));
  const baseIds = new Set(unchangedBaseline.map(r => r.toolId));
  const candIds = new Set(unchangedCandidate.map(r => r.toolId));
  if (baseIds.size !== candIds.size || [...baseIds].some(id => !candIds.has(id))) {
    throw new Error('delta changed-ids is incomplete: an undeclared adapter changed');
  }
  const removeIds = baselineChanged.map(r => pointId(r.toolId));
  if (removeIds.length) shard.deletePoints(JSON.stringify(removeIds));
  const batchSize = options.batchSize ?? 16;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 256) throw new Error('batch size must be between 1 and 256');
  for (let offset = 0; offset < candidateChanged.length; offset += batchSize) {
    const batch = candidateChanged.slice(offset, offset + batchSize);
    const docs = batch.map(r => native.serializeTool('nomic', JSON.stringify(r.record)));
    const denseVectors = dense.embed(docs);
    const sparseVectors = sparse.embed(docs);
    if (denseVectors.length !== batch.length || sparseVectors.length !== batch.length) throw new Error('encoder batch cardinality mismatch');
    const points = batch.map((r, i) => {
      if (denseVectors[i].length !== 768 || !denseVectors[i].every(Number.isFinite)) throw new Error('invalid dense document vector');
      const sp = sparseVectors[i];
      if (sp.indices.length !== sp.values.length || !sp.values.every(Number.isFinite) || !sp.indices.every((n, j) => Number.isInteger(n) && n >= 0 && (j === 0 || n > sp.indices[j - 1]))) throw new Error('invalid sparse document vector');
      return { id: pointId(r.toolId), vector: { dense: denseVectors[i], splade: sp }, payload: { toolId: r.toolId, adapterId: r.adapterId, name: r.record.name, description: r.record.description, ...(r.kind === 'adapter_capability' ? { dispatchable: false } : {}) } };
    });
    shard.upsert(JSON.stringify(points));
  }
  shard.flush();
  if (shard.pointsCount() !== candidate.length) throw new Error(`delta record count mismatch: shard=${shard.pointsCount()} candidate=${candidate.length}`);
  return { recordCount: candidate.length, changedToolIds: [...new Set([...baselineChanged, ...candidateChanged].map(r => r.toolId))].sort() };
}

/** qdrant-edge 0.7.2's streamable snapshot layout. The source is private to
 * this synchronous producer, flushed, and receives no further mutations.
 * Every segment's persisted files become segments/<id>/files; unpack moves
 * them back before EdgeShard.load. No arbitrary archive paths are accepted.
 *
 * Returns the PATH of the packed archive (`<workDir>/catalog.snapshot`), not
 * its bytes: a real catalog archive (~505 MB) exceeds V8's maximum string
 * length once base64-encoded, so the archive is sealed file-to-file
 * (`sealEdgeSnapshotFile`) and never enters the JS heap. The intermediate
 * layout copy is removed once the tar is written. */
export function packFlushedShard(shardDir: string, workDir: string): string {
  const stage = join(workDir, 'archive-layout');
  mkdirSync(join(stage, 'segments'), { recursive: true, mode: 0o700 });
  for (const entry of readdirSync(shardDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw new Error('symlink in producer shard');
    if (entry.name === 'segments') continue;
    cpSync(join(shardDir, entry.name), join(stage, entry.name), { recursive: true });
  }
  for (const segment of readdirSync(join(shardDir, 'segments'), { withFileTypes: true })) {
    if (!segment.isDirectory() || !/^[0-9a-f-]{36}$/.test(segment.name)) throw new Error('unexpected segment entry');
    cpSync(join(shardDir, 'segments', segment.name), join(stage, 'segments', segment.name, 'files'), { recursive: true });
  }
  const archive = join(workDir, 'catalog.snapshot');
  execFileSync('tar', ['--format=ustar', '--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner', '-cf', archive, '-C', stage, '.']);
  rmSync(stage, { recursive: true, force: true });
  return archive;
}

/** The descriptor `buildSnapshot` publishes (CHARIOT §5.7 envelope fields,
 * AMENDED 2026-10-14, file-reference form): `ciphertext` is
 * `{ file, sha256 }` naming `<descriptor basename>.ciphertext` beside the
 * descriptor; `iv`/`signature` are the §5.7 canonical names and
 * `ivB64`/`signatureB64` the consumer aliases (identical bytes). No inline
 * ciphertext. */
export interface FileSealedDescriptor {
  ciphertext: { file: string; sha256: string };
  iv: string;
  signature: string;
  salt: string;
  aad: string;
  ivB64: string;
  signatureB64: string;
}

export interface BuildOptions {
  bundle: Row;
  native: NativeEdgeBinding;
  dense: NativeDenseEncoder;
  sparse: NativeSpladeEncoder;
  secretRootB64: string;
  signingSeedB64: string;
  securityEpoch: number;
  out: string;
  batchSize?: number;
  /** When supplied, read back via the REAL license-verifying native consumer.
   * A license whose context differs from the catalog version fails closed. */
  licenseJwt?: string;
  /** Persistent release watermark; never stored in disposable staging. */
  watermarkDir?: string;
  /** TEST-ONLY seam for the two publication renames (staged ciphertext →
   * `<out>.ciphertext`, then staged descriptor → `<out>`). Defaults to
   * `renameSync`; lets a test observe the publish order and force a failure. */
  publishRename?: (from: string, to: string) => void;
  /** Atomic adapter-delta mode. The directory must be a receipt-verified,
   * unpacked baseline shard; it is copied into private staging before mutate. */
  baselineShardDir?: string;
  baselineBundle?: Row;
  changedAdapterIds?: ReadonlySet<string>;
  baselineCiphertextPath?: string;
  baselineDescriptor?: FileSealedDescriptor;
  baselineLicenseJwt?: string;
}

export interface BuildResult {
  descriptor: FileSealedDescriptor;
  /** Absolute path of the published descriptor. */
  descriptorPath: string;
  /** Absolute path of the published ciphertext file the descriptor names. */
  ciphertextPath: string;
  /** tool + capability records persisted (== manifest.recordCount). */
  recordCount: number;
  toolRecordCount: number;
  capabilityRecordCount: number;
}

/** Edge shard config for the produced snapshot. qdrant-edge 0.7.2's
 * `WalOptions` has no serde defaults, so a `wal_options` object must carry
 * all three fields (`retain_closed` default is 1, wal/mod.rs). */
export const PRODUCER_SHARD_CONFIG_JSON = JSON.stringify({
  vectors: { dense: { size: 768, distance: 'Cosine' } },
  sparse_vectors: { splade: {} },
  wal_options: { segment_capacity: 1048576, segment_queue_len: 0, retain_closed: 1 },
});

export function buildSnapshot(options: BuildOptions): BuildResult {
  const { bundle, native, dense, sparse, secretRootB64, signingSeedB64, securityEpoch, out } = options;
  if (!Number.isSafeInteger(bundle.epoch) || (bundle.epoch as number) < 0 || !Array.isArray(bundle.registry)) throw new Error('signed bundle epoch/registry missing or malformed');
  if (!Number.isSafeInteger(bundle.catalogVersion) || (bundle.catalogVersion as number) < 0) throw new Error('catalogVersion must be a non-negative integer');
  const salt = String(bundle.catalogVersion); // Exact signed catalog version, never tenant metadata.
  const epoch = validateSealScope(secretRootB64, salt, `${salt}|epoch=${securityEpoch}`);
  if (typeof native.sealEdgeSnapshotFile !== 'function') throw new Error('native binary lacks sealEdgeSnapshotFile; build the current native addon');
  if (options.licenseJwt && typeof native.unsealAndVerifySnapshotToFile !== 'function') throw new Error('native binary lacks unsealAndVerifySnapshotToFile; build the current native addon');
  if (native.frozenSerializerHash() !== COMPILED_SERIALIZER_HASH) throw new Error('native serializer hash mismatch');
  if (new VectorIndexVerifier().verifyManifest(bundle.manifest, native.frozenSerializerHash())) throw new Error('signed retrieval manifest missing or contract mismatch');
  const records = snapshotRecords(bundle);
  const batchSize = options.batchSize ?? 16;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 256) throw new Error('batch size must be between 1 and 256');
  // Output naming is checked before any embedding work: the ciphertext is
  // `<descriptor basename>.ciphertext` beside the descriptor, and must be a
  // reference the consumer accepts (a bare basename, CHARIOT §5.7).
  const descriptorPath = resolve(out);
  const outDir = dirname(descriptorPath);
  const ciphertextName = `${basename(descriptorPath)}${SEALED_SHARD_CIPHERTEXT_SUFFIX}`;
  if (!isBareCiphertextBasename(ciphertextName)) throw new Error(`output name ${JSON.stringify(basename(descriptorPath))} cannot carry a bare-basename ciphertext reference`);
  const ciphertextPath = join(outDir, ciphertextName);
  const work = mkdtempSync(join(tmpdir(), 'chariot-snapshot-'));
  // Keep the handle alive until cleanup: its GC finalizer flushes on drop.
  let shard: ReturnType<NativeEdgeBinding['EdgeShardHandle']['create']> | undefined;
  try {
    const shardDir = join(work, 'shard');
    mkdirSync(shardDir, { mode: 0o700 });
    let packedShardDir = shardDir;
    const deltaMode = options.baselineShardDir !== undefined || options.baselineBundle !== undefined || options.changedAdapterIds !== undefined;
    if (deltaMode && (!options.baselineBundle || !options.changedAdapterIds || (!options.baselineShardDir && (!options.baselineCiphertextPath || !options.baselineDescriptor)))) throw new Error('delta mode requires baseline bundle, changed adapter ids, and either a verified shard or sealed baseline descriptor+ciphertext');
    if (deltaMode) {
      let deltaShardDir = shardDir;
      if (options.baselineCiphertextPath) {
        const baselinePlain = join(work, 'baseline.snapshot');
        deltaShardDir = join(work, 'baseline-shard');
        const bd = options.baselineDescriptor!;
        const receipt = native.unsealAndVerifySnapshotToFile!(resolve(options.baselineCiphertextPath), baselinePlain, bd.ivB64, bd.signatureB64, SNAPSHOT_VERIFYING_KEY_PEM, secretRootB64, bd.salt, bd.aad, options.baselineLicenseJwt ?? options.licenseJwt ?? '', join(work, 'baseline-watermark'));
        native.edgeUnpackSnapshot(baselinePlain, deltaShardDir, receipt.receipt);
      } else {
        cpSync(resolve(options.baselineShardDir!), deltaShardDir, { recursive: true });
      }
      packedShardDir = deltaShardDir;
      shard = native.EdgeShardHandle.load(deltaShardDir, PRODUCER_SHARD_CONFIG_JSON);
    } else {
      shard = native.EdgeShardHandle.create(shardDir, PRODUCER_SHARD_CONFIG_JSON);
    }
    if (!shard.close) throw new Error('native addon lacks producer close; rebuild the current addon');
    if (deltaMode) applyAdapterDelta({ baselineBundle: options.baselineBundle!, candidateBundle: bundle, changedAdapterIds: options.changedAdapterIds!, shard, native, dense, sparse, batchSize });
    else for (let offset = 0; offset < records.length; offset += batchSize) {
      const batch = records.slice(offset, offset + batchSize);
      const docs = batch.map(r => native.serializeTool('nomic', JSON.stringify(r.record)));
      const denseVectors = dense.embed(docs);
      const sparseVectors = sparse.embed(docs);
      if (denseVectors.length !== batch.length || sparseVectors.length !== batch.length) throw new Error('encoder batch cardinality mismatch');
      const points = batch.map((r, i) => {
        if (denseVectors[i].length !== 768 || !denseVectors[i].every(Number.isFinite)) throw new Error('invalid dense document vector');
        const sp = sparseVectors[i];
        if (sp.indices.length !== sp.values.length || !sp.values.every(Number.isFinite) || !sp.indices.every((n, j) => Number.isInteger(n) && n >= 0 && (j === 0 || n > sp.indices[j - 1]))) throw new Error('invalid sparse document vector');
        const payload = { toolId: r.toolId, adapterId: r.adapterId, name: r.record.name, description: r.record.description, ...(r.kind === 'adapter_capability' ? { dispatchable: false } : {}) };
        return { id: pointId(r.toolId), vector: { dense: denseVectors[i], splade: sp }, payload };
      });
      shard.upsert(JSON.stringify(points));
    }
    shard.flush();
    if (shard.pointsCount() !== records.length) throw new Error('persisted shard record count mismatch');
    const archivePath = packFlushedShard(packedShardDir, work);
    // CHARIOT §5.7 file-reference form (AMENDED 2026-10-14): seal file→file
    // straight into a private staging directory INSIDE the output directory
    // (same filesystem, so both publication renames below are atomic). The
    // archive and its ciphertext never become a JS string or Buffer.
    mkdirSync(outDir, { recursive: true });
    const temp = mkdtempSync(join(outDir, '.snapshot-output-'));
    try {
      const stagedCiphertext = join(temp, ciphertextName);
      const sealed = native.sealEdgeSnapshotFile!(archivePath, stagedCiphertext, secretRootB64, salt, salt, epoch, signingSeedB64);
      // Verify the artifact, not the report: the staged bytes must hash to
      // the digest the sealer returned before it is written into the descriptor.
      if (sha256FileHex(stagedCiphertext) !== sealed.ciphertextSha256Hex) throw new Error('sealed ciphertext file does not match the sealer-reported SHA-256');
      if (options.licenseJwt) {
        const watermarkDir = resolve(options.watermarkDir ?? join(outDir, '.edgeshard-watermark'));
        const plain = join(work, 'readback.snapshot');
        const { receipt } = native.unsealAndVerifySnapshotToFile!(stagedCiphertext, plain, sealed.ivB64, sealed.signatureB64, SNAPSHOT_VERIFYING_KEY_PEM, secretRootB64, sealed.salt, sealed.aad, options.licenseJwt, watermarkDir);
        const restored = join(work, 'restored');
        native.edgeUnpackSnapshot(plain, restored, receipt);
        const loaded = native.EdgeShardHandle.load(restored);
        try {
          if (loaded.pointsCount() !== records.length) throw new Error('snapshot read-back count mismatch');
        } finally { loaded.close?.(); }
      }
      // §5.7 canonical envelope names plus the consumer's iv/signature
      // aliases (identical bytes). The ciphertext is a file reference only.
      const descriptor: FileSealedDescriptor = {
        ciphertext: { file: ciphertextName, sha256: sealed.ciphertextSha256Hex },
        iv: sealed.ivB64,
        signature: sealed.signatureB64,
        salt: sealed.salt,
        aad: sealed.aad,
        ivB64: sealed.ivB64,
        signatureB64: sealed.signatureB64,
      };
      const stagedDescriptor = join(temp, 'sealed.json');
      writeFileSync(stagedDescriptor, JSON.stringify(descriptor) + '\n', { mode: 0o600, flag: 'wx' });
      // Publish ciphertext FIRST, descriptor LAST: a descriptor is never
      // visible before the file it names. An interruption between the two
      // leaves any previous descriptor naming a ciphertext whose SHA-256 no
      // longer matches, which the consumer refuses (fail closed).
      const publish = options.publishRename ?? renameSync;
      publish(stagedCiphertext, ciphertextPath);
      publish(stagedDescriptor, descriptorPath);
      const capabilityRecordCount = records.filter(r => r.kind === 'adapter_capability').length;
      return { descriptor, descriptorPath, ciphertextPath, recordCount: records.length, toolRecordCount: records.length - capabilityRecordCount, capabilityRecordCount };
    } finally { rmSync(temp, { recursive: true, force: true }); }
  } finally {
    // A binary without close is rejected; keep its files for its finalizer.
    if (!shard || shard.close) {
      shard?.close?.();
      rmSync(work, { recursive: true, force: true });
    }
  }
}

function readModel(modelPath: string, tokenizerDir: string) {
  return { onnx: readFileSync(modelPath), tokenizerFiles: { tokenizerFile: readFileSync(join(tokenizerDir, 'tokenizer.json')), configFile: readFileSync(join(tokenizerDir, 'config.json')), specialTokensMapFile: readFileSync(join(tokenizerDir, 'special_tokens_map.json')), tokenizerConfigFile: readFileSync(join(tokenizerDir, 'tokenizer_config.json')) } };
}

// Fingerprints of the qualified BIEN 768-d export and the governed SPLADE
// artifact, including tokenizer/config bytes. A path or self-reported model
// name cannot substitute a compatible but different encoder.
const MODEL_PINS = {
  dense: {
    // bien-m8-export-mined-v2 (stage-mined): the ONNX every G-A run measured
    // (gates-20260906 and gates-20260907-depth run-meta dense_onnx_sha256).
    onnx: '908f5e95bf84e9878d860e27e2fb108876704e6b860b62e47c788094bcef0717',
    tokenizerFile: 'f26b7f4b5db8ee4a98e65e2ce4e2c85c0b87ccd533d9e4a1b725e206b325f1e1',
    configFile: 'af8863b3d62ad7a28fd9aa6e698be73c1af07353c6d2f318d6ba8952167b2737',
    specialTokensMapFile: '5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a',
    tokenizerConfigFile: '2c1f87cbda90c1cea7f511273e3f1be5adf5b216face23fc837d22624138fc79',
  },
  sparse: {
    // CHARIOT §5.6 names the shared/splade/artifact-pin.ts module as the
    // single byte-level authority. This is Qdrant/Splade_PP_en_v1 at
    // revision efcd182bc7eb351e81a9445752d4388c2bab500b, whose graph is
    // input_ids + attention_mask + token_type_ids -> logits.
    onnx: '65adbad0d7e1bc882c867d534821d52e60d6f666a91662be3f58457d08d25bf3',
    tokenizerFile: '91f1def9b9391fdabe028cd3f3fcc4efd34e5d1f08c3bf2de513ebb5911a1854',
    configFile: '017fde19abff1131c9c747fbd71f8348173409ac6d3d350fd122fd33341ecd85',
    specialTokensMapFile: '5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a',
    tokenizerConfigFile: '55dc51676b13f29b34f3edfb55092a1947dd24ac3ef0200608a0cc66f1da2628',
  },
} as const;

export function assertModelIdentity(model: ReturnType<typeof readModel>, kind: keyof typeof MODEL_PINS): void {
  const bytes = { onnx: model.onnx, ...model.tokenizerFiles };
  for (const name of Object.keys(MODEL_PINS[kind]) as Array<keyof typeof bytes>) {
    if (createHash('sha256').update(bytes[name]).digest('hex') !== MODEL_PINS[kind][name]) throw new Error(`${kind} encoder artifact identity mismatch`);
  }
}

// CHARIOT-SPEC §23.2 (CHARIOT::§23.2::181): the dense max length is the
// export's own max_position_embeddings, never assumed. config.json and
// tokenizer_config.json must agree on a positive integer.
export function denseMaxLengthFromExport(model: ReturnType<typeof readModel>): number {
  const read = (bytes: Buffer, field: string): unknown => (JSON.parse(bytes.toString('utf8')) as Record<string, unknown>)[field];
  const fromConfig = read(model.tokenizerFiles.configFile, 'max_position_embeddings');
  const fromTokenizer = read(model.tokenizerFiles.tokenizerConfigFile, 'model_max_length');
  if (typeof fromConfig !== 'number' || !Number.isSafeInteger(fromConfig) || fromConfig <= 0 || fromConfig !== fromTokenizer) {
    throw new Error('dense export max length is not a single positive integer in config.json and tokenizer_config.json');
  }
  return fromConfig;
}

/** The recipient licence a sealed shard is produced for (CHARIOT §5.7). */
export interface RecipientLicense { jwt: string; catalogVersion: string; sealSecretB64?: string }

export function readRecipientLicense(path: string): RecipientLicense {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as { jwt?: unknown; seal_secret?: unknown };
  if (!isNonEmptyString(envelope.jwt)) throw new Error('license envelope must contain jwt');
  let sealSecretB64: string | undefined;
  if (envelope.seal_secret !== undefined) {
    const raw = typeof envelope.seal_secret === 'string' ? Buffer.from(envelope.seal_secret, 'base64') : Buffer.alloc(0);
    if (raw.length !== 32 || raw.toString('base64') !== envelope.seal_secret) throw new Error('license seal_secret must be standard base64 of exactly 32 bytes');
    sealSecretB64 = envelope.seal_secret as string;
  }
  if (!verifyAndDecode(envelope.jwt)) throw new Error('license JWT does not verify against the accepted licence keys');
  const claims = JSON.parse(Buffer.from(envelope.jwt.split('.')[1], 'base64url').toString('utf8')) as { catalog_version?: unknown };
  if (!isNonEmptyString(claims.catalog_version)) throw new Error('license carries no catalog_version claim; a sealed shard cannot be bound to it');
  return { jwt: envelope.jwt, catalogVersion: claims.catalog_version, sealSecretB64 };
}

export function main(argv = process.argv.slice(2)): void {
  const allowed = new Set(['--bundle', '--dense-model', '--dense-tokenizer-dir', '--splade-dir', '--security-epoch', '--out', '--batch-size', '--license', '--watermark-dir', '--baseline-shard', '--baseline-bundle', '--changed-adapters', '--baseline-ciphertext', '--baseline-descriptor']);
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    if (!allowed.has(argv[i]) || !argv[i + 1] || args.has(argv[i])) throw new Error('invalid or duplicate producer argument');
    args.set(argv[i], argv[i + 1]);
  }
  const get = (flag: string): string => { const value = args.get(flag); if (!value) throw new Error(`required argument: ${flag}`); return value; };
  const securityEpoch = Number(get('--security-epoch'));
  const signingSeedB64 = process.env.CHARIOT_SEAL_SIGNING_SEED_B64 ?? '';
  assertPinnedSigningSeed(signingSeedB64);
  const signed = verifyAndReadArtifact(resolve(args.get('--bundle') ?? 'chariot-adapter-bundle.json'));
  if (!signed.ok) throw new Error(`bundle signature rejected: ${signed.reason}`);
  const bundle = JSON.parse(signed.bytes.toString('utf8')) as Row;
  let baselineBundle: Row | undefined;
  if (args.has('--baseline-bundle')) {
    const prior = verifyAndReadArtifact(resolve(get('--baseline-bundle')));
    if (!prior.ok) throw new Error(`baseline bundle signature rejected: ${prior.reason}`);
    baselineBundle = JSON.parse(prior.bytes.toString('utf8')) as Row;
  }
  let changedAdapterIds: ReadonlySet<string> | undefined;
  if (args.has('--changed-adapters')) {
    const raw = JSON.parse(readFileSync(resolve(get('--changed-adapters')), 'utf8'));
    if (!Array.isArray(raw) || raw.some(v => typeof v !== 'string' || v.length === 0)) throw new Error('--changed-adapters must contain a JSON array of non-empty adapter ids');
    changedAdapterIds = new Set(raw);
  }
  let baselineDescriptor: FileSealedDescriptor | undefined;
  if (args.has('--baseline-descriptor')) baselineDescriptor = JSON.parse(readFileSync(resolve(get('--baseline-descriptor')), 'utf8')) as FileSealedDescriptor;
  // CHARIOT §5.7: the shard is sealed for one recipient licence. Its root is
  // that licence's seal_secret (else ENTERPRISE_MASTER_KEY) and its context is
  // the licence's signed catalog_version, which must be this bundle's version.
  // The read-back unseal below is therefore always run.
  const recipient = readRecipientLicense(get('--license'));
  if (recipient.catalogVersion !== String(bundle.catalogVersion)) {
    throw new Error(`license catalog_version ${JSON.stringify(recipient.catalogVersion)} does not match bundle catalogVersion ${JSON.stringify(String(bundle.catalogVersion))}`);
  }
  const secretRootB64 = recipient.sealSecretB64 ?? process.env.ENTERPRISE_MASTER_KEY ?? '';
  const licenseJwt = recipient.jwt;
  validateSealScope(secretRootB64, String(bundle.catalogVersion), `${bundle.catalogVersion}|epoch=${securityEpoch}`);
  const native = loadNativeEdge();
  if (!native?.SpladeEncoder || !native.sealEdgeSnapshotFile || !native.unsealAndVerifySnapshotToFile) throw new Error('current native retrieval/seal addon (sealEdgeSnapshotFile, unsealAndVerifySnapshotToFile) is required');
  const denseModel = readModel(get('--dense-model'), get('--dense-tokenizer-dir'));
  const spladeDir = get('--splade-dir');
  const sparseModel = readModel(join(spladeDir, 'model.onnx'), spladeDir);
  assertModelIdentity(denseModel, 'dense');
  assertModelIdentity(sparseModel, 'sparse');
  const dense = native.DenseEncoder.load(denseModel.onnx, denseModel.tokenizerFiles, true, denseMaxLengthFromExport(denseModel));
  const sparse = native.SpladeEncoder.load(sparseModel.onnx, sparseModel.tokenizerFiles, 512);
  const result = buildSnapshot({ bundle, native, dense, sparse, secretRootB64, signingSeedB64, securityEpoch, out: args.get('--out') ?? 'artifacts/edgeshard/catalog.edgeshard.sealed', batchSize: Number(args.get('--batch-size') ?? 16), licenseJwt, watermarkDir: args.get('--watermark-dir'), baselineShardDir: args.get('--baseline-shard'), baselineBundle, changedAdapterIds, baselineCiphertextPath: args.get('--baseline-ciphertext'), baselineDescriptor });
  console.log(`sealed EdgeShard written: ${result.descriptorPath} + ${result.ciphertextPath} (${result.recordCount} records: ${result.toolRecordCount} tool + ${result.capabilityRecordCount} capability)`);
}
