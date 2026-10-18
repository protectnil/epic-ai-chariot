import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildSnapshot, capabilityRecord, snapshotRecords } from './build-edgeshard-snapshot.js';
import { COMPILED_SERIALIZER_HASH, DEFAULT_RETRIEVAL_CONTRACT } from '../retrieval/VectorIndexVerifier.js';
import { loadNativeEdge, type NativeEdgeBinding, type NativeEdgeShard, type NativeSealedShardFile } from '../retrieval/nativeEdge.js';

// CH-62(b) node (2): the producer must enumerate EXACTLY the population
// `VectorIndexVerifier.admit` counts — tool records of every ACTIVE adapter's
// top-level `tools` XOR one capability record per ACTIVE adapter whose `tools`
// is absent/empty. Tests below are derived from the failure classes of that
// clause, not from the implementation.

type Row = Record<string, unknown>;

const manifest = (recordCount: number): Row => ({ version: '4.0.0', encoder: DEFAULT_RETRIEVAL_CONTRACT, serializer_hash: COMPILED_SERIALIZER_HASH, recordCount, tool_record_count: 2, capability_record_count: 1, recordCountPreOverlay: 3 });
const toolAdapter: Row = { id: 'fixture', descriptionForRetrieval: 'Fixture tools', searchQueries: ['fixture'], tools: [
  { name: 'alpha', description: 'Find alpha', inputSchema: { properties: { query: {} }, required: ['query'] } },
  { name: 'beta', description: 'Find beta', inputSchema: {} },
] };
const residual: Row = { id: 'resid', type: 'mcp', category: 'misc', keywords: ['k'], descriptionForRetrieval: 'Residual profile', searchQueries: ['residual q'], industries: [], departments: [], toolNames: [], toolCount: 0 };
const bundleOf = (catalog: Row[], recordCount: number): Row => ({ epoch: 123, catalogVersion: 7, manifest: manifest(recordCount), catalog, registry: catalog.map(a => ({ id: a.id })) });

test('classification follows admission: the top-level tools array alone decides, XOR', () => {
  // zero tools + non-empty toolNames (121 such adapters in the Oct-11 bundle) +
  // mcp.tools (4 such adapters): ONE capability record, no invented tool.
  const withNames = { ...residual, toolNames: ['invented_a', 'invented_b'], toolCount: 2, mcp: { tools: [{ name: 'invented_a', description: 'd', inputSchema: {} }] } };
  const records = snapshotRecords(bundleOf([toolAdapter, withNames], 3));
  assert.deepEqual(records.map(r => [r.toolId, r.adapterId, r.kind]), [['fixture:alpha', 'fixture', 'tool'], ['fixture:beta', 'fixture', 'tool'], ['resid', 'resid', 'adapter_capability']]);
  // tool-bearing adapter with a profile: tool rows only, never also a residual.
  assert.equal(snapshotRecords(bundleOf([toolAdapter], 2)).filter(r => r.kind === 'adapter_capability').length, 0);
  // explicit `tools: []` and non-array `tools` are residuals for admission (countCapabilityRecords).
  assert.equal(snapshotRecords(bundleOf([{ ...residual, tools: [] }], 1))[0].kind, 'adapter_capability');
  assert.equal(snapshotRecords(bundleOf([{ ...residual, tools: 'not-an-array' }], 1))[0].kind, 'adapter_capability');
  // inactive / revoked residuals contribute nothing (same activity rule as the CH-35 gate).
  assert.equal(snapshotRecords(bundleOf([toolAdapter, { ...residual, active: false }, { ...residual, id: 'r2', revoked: true }], 2)).length, 2);
});

test('capability text is the row profile assembled as BIEN build_capability_record assembles it', () => {
  const corpus = readFileSync('native/conformance/expected.jsonl', 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l) as Row);
  const expected = corpus.find(c => c.id === 'adapter-capability-residual') as { input: Row; serialized: string; sha256: string };
  assert.ok(expected, 'vendored BIEN corpus must carry the adapter-capability-residual case');
  const inp = expected.input;
  const adapter: Row = { id: '0xhumans-protocol', displayName: inp.name, type: inp.connector_family, category: inp.category, descriptionForRetrieval: inp.description, keywords: inp.keywords, departments: inp.departments, industries: inp.industries, searchQueries: ['q'], toolNames: [], toolCount: 0 };
  const record = capabilityRecord(adapter);
  const serializerView = Object.fromEntries(Object.keys(inp).map(k => [k, record[k]]));
  assert.deepEqual(serializerView, inp); // every serializer field byte-equal to the BIEN row
  assert.equal(record.record_kind, 'adapter_capability');
  assert.equal(record.dispatchable, false);
  assert.deepEqual(record.search_queries, ['q']);
  assert.ok(!('tools' in record) && !('toolNames' in record) && !('tool_names' in record));
  const native = loadNativeEdge();
  if (native && typeof native.serializeTool === 'function' && native.frozenSerializerHash() === COMPILED_SERIALIZER_HASH) {
    const text = native.serializeTool('nomic', JSON.stringify(record));
    assert.equal(text, expected.serialized);
    assert.equal(createHash('sha256').update(text).digest('hex'), expected.sha256);
  } else {
    console.log('native serializer unavailable in this environment; corpus byte-equality not exercised here');
  }
  // displayName absent (the Oct-11 bundle carries none): NAME falls back to the adapter id (BIEN `display_name or adapter_id`).
  assert.equal(capabilityRecord(residual).name, 'resid');
  assert.equal(capabilityRecord({ ...residual, displayName: '   ' }).name, 'resid');
  // auth.inferredModel: none/unknown null-omitted, a real value kept (BIEN _auth_model).
  assert.equal(capabilityRecord({ ...residual, auth: { inferredModel: 'none' } }).auth_model, '');
  assert.equal(capabilityRecord({ ...residual, auth: { inferredModel: 'Unknown' } }).auth_model, '');
  assert.equal(capabilityRecord({ ...residual, auth: { inferredModel: ' api-key ' } }).auth_model, 'api-key');
  // non-string list members are dropped, never coerced (serializer contract §3).
  assert.deepEqual(capabilityRecord({ ...residual, keywords: ['a', 1, null, 'b'] }).keywords, ['a', 'b']);
  // missing facet lists are empty lists (null-omitted), never a failure (CH-62(a) best-effort).
  const bare = capabilityRecord({ id: 'b', descriptionForRetrieval: 'x', searchQueries: ['y'] });
  assert.deepEqual([bare.keywords, bare.departments, bare.industries, bare.connector_family, bare.category], [[], [], [], '', '']);
});

test('fail-closed classes: profile, key shape, duplicates, counts, serializer hash', () => {
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, descriptionForRetrieval: '   ' }], 1)), /descriptionForRetrieval/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, descriptionForRetrieval: undefined }], 1)), /descriptionForRetrieval/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, searchQueries: [] }], 1)), /searchQueries/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, searchQueries: undefined }], 1)), /searchQueries/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, id: 'ns:resid' }], 1)), /contains ":"/);
  assert.throws(() => snapshotRecords(bundleOf([residual, { ...residual }], 2)), /duplicate capability record key/);
  // a capability key equal to a tool id is a collision (shared identity set).
  assert.throws(() => snapshotRecords(bundleOf([{ ...toolAdapter, tools: [{ name: 'x', description: 'd', tool_id: 'resid' }] }, residual], 2)), /duplicate/);
  // tool-only count under a widened population fails closed (CH-62(b)); exact widened count passes.
  assert.throws(() => snapshotRecords(bundleOf([toolAdapter, residual], 2)), /manifest/);
  assert.equal(snapshotRecords(bundleOf([toolAdapter, residual], 3)).length, 3);
  assert.throws(() => snapshotRecords({ ...bundleOf([toolAdapter, residual], 3), manifest: { ...manifest(3), serializer_hash: 'f'.repeat(64) } }), /manifest/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, active: false }], 0)), /no retrieval records/);
});

test('non-ASCII profile text survives verbatim and ordering is deterministic', () => {
  const text = 'Café – naïve ☕ 日本語 «quoted» back\\slash';
  const r = snapshotRecords(bundleOf([{ ...residual, descriptionForRetrieval: text, keywords: ['Ñandú'] }], 1))[0];
  assert.equal(r.record.description, text);
  assert.deepEqual(r.record.keywords, ['Ñandú']);
  const a = snapshotRecords(bundleOf([toolAdapter, residual, { ...residual, id: 'aardvark' }], 4)).map(x => x.toolId);
  const b = snapshotRecords(bundleOf([{ ...residual, id: 'aardvark' }, residual, toolAdapter], 4)).map(x => x.toolId);
  assert.deepEqual(a, b);
  assert.deepEqual(a, [...a].sort());
});

test('buildSnapshot persists tool + capability points; capability payload is keyed by adapter id and dispatchable:false', () => {
  const dir = mkdtempSync(join(tmpdir(), 'snapshot-cap-'));
  const points: Array<{ id: string; payload: Row }> = [];
  const docs: string[] = [];
  const shard: NativeEdgeShard = {
    upsert(json) { points.push(...JSON.parse(json)); }, flush() {}, close() {}, pointsCount: () => points.length,
    query: () => [], snapshotManifestJson: () => '{}',
  };
  const segmentId = '00000000-0000-5000-8000-000000000001';
  const native = {
    EdgeShardHandle: { create(path: string) { mkdirSync(join(path, 'segments', segmentId), { recursive: true }); writeFileSync(join(path, 'segments', segmentId, 'segment.json'), '{}'); return shard; } },
    frozenSerializerHash: () => COMPILED_SERIALIZER_HASH,
    serializeTool: (_base: string, json: string) => { docs.push(json); return json; },
    // File-to-file transport fixture (CHARIOT §5.7 file-reference form), NOT
    // a crypto implementation; the native Rust tests own the real seal.
    sealEdgeSnapshotFile(plaintextPath: string, ciphertextPath: string, _root: string, salt: string, context: string, epoch: number): NativeSealedShardFile {
      const bytes = readFileSync(plaintextPath);
      writeFileSync(ciphertextPath, bytes, { flag: 'wx', mode: 0o600 });
      return { ivB64: Buffer.alloc(12).toString('base64'), signatureB64: Buffer.alloc(64).toString('base64'), salt, aad: `${context}|epoch=${epoch}`, ciphertextSha256Hex: createHash('sha256').update(bytes).digest('hex') };
    },
  } as unknown as NativeEdgeBinding;
  try {
    const bundle = bundleOf([toolAdapter, { ...residual, descriptionForRetrieval: 'Résumé ☕' }], 3);
    const result = buildSnapshot({ bundle, native, dense: { embed: d => d.map(() => Array(768).fill(0.5)) }, sparse: { embed: d => d.map(() => ({ indices: [1], values: [1] })) }, secretRootB64: Buffer.alloc(32, 41).toString('base64'), signingSeedB64: '', securityEpoch: 5, out: join(dir, 'catalog.edgeshard.sealed'), batchSize: 2 });
    assert.deepEqual([result.recordCount, result.toolRecordCount, result.capabilityRecordCount], [3, 2, 1]);
    assert.equal(points.length, 3);
    const cap = points.find(p => p.payload.toolId === 'resid')!;
    assert.deepEqual(cap.payload, { toolId: 'resid', adapterId: 'resid', name: 'resid', description: 'Résumé ☕', dispatchable: false });
    assert.ok(!cap.payload.toolId.toString().includes(':'));
    const tool = points.find(p => p.payload.toolId === 'fixture:alpha')!;
    assert.ok(!('dispatchable' in tool.payload)); // tool payloads unchanged
    assert.notEqual(cap.id, tool.id);
    const capDoc = JSON.parse(docs.find(d => d.includes('"record_kind":"adapter_capability"'))!) as Row;
    assert.equal(capDoc.description, 'Résumé ☕');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('signed Oct-11 bundle: producer population equals manifest.recordCount (tool + capability)', { skip: !existsSync('chariot-adapter-bundle.json') }, () => {
  const bundle = JSON.parse(readFileSync('chariot-adapter-bundle.json', 'utf8')) as Row;
  const catalog = bundle.catalog as Row[];
  const active = catalog.filter(a => a.active !== false && a.revoked !== true);
  const expectedCapability = active.filter(a => !Array.isArray(a.tools) || (a.tools as unknown[]).length === 0).length;
  const expectedTool = active.reduce((n, a) => n + (Array.isArray(a.tools) ? a.tools.length : 0), 0);
  const records = snapshotRecords(bundle);
  const capability = records.filter(r => r.kind === 'adapter_capability');
  assert.equal(records.length, (bundle.manifest as Row).recordCount);
  assert.equal(capability.length, expectedCapability);
  assert.equal(records.length - capability.length, expectedTool);
  assert.ok(capability.every(r => !r.toolId.includes(':') && r.toolId === r.adapterId && r.record.dispatchable === false));
  assert.ok(records.filter(r => r.kind === 'tool').every(r => r.toolId.includes(':')));
  console.log(`bundle population: ${records.length} = ${records.length - capability.length} tool + ${capability.length} capability`);
});

test('CH-62(a): searchQueries must hold at least one non-blank string (a raw non-empty array of non-strings is not a profile)', () => {
  for (const bad of [[42], [''], ['   '], [null, {}], []]) {
    assert.throws(() => capabilityRecord({ ...residual, searchQueries: bad }), /missing searchQueries/);
  }
  // one usable string among junk is enough; junk is dropped from the payload list.
  assert.deepEqual(capabilityRecord({ ...residual, searchQueries: [42, 'real query', ''] }).search_queries, ['real query', '']);
});

test('CH-62 key: a whitespace-only adapter id is not an identity (residual or tool-bearing)', () => {
  assert.throws(() => snapshotRecords(bundleOf([{ ...residual, id: '   ' }], 1)), /adapter id is missing/);
  assert.throws(() => snapshotRecords(bundleOf([{ ...toolAdapter, id: ' ' }], 2)), /adapter id is missing/);
});
