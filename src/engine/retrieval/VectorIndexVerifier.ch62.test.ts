/**
 * CH-62 — capability-record discovery & widened record-count invariant.
 *
 * Governing clause (CHARIOT-SPEC.md §23.2 ledger, CH-62, verbatim in part):
 *   "(a) … the VectorIndexVerifier / load path MUST NOT reject a residual
 *    adapter for carrying empty tools; for a residual adapter it requires
 *    descriptionForRetrieval + a non-empty searchQueries (industries /
 *    departments stay the best-effort facet of CH-35 — WARN, null-omittable,
 *    never fail-closed) and does NOT require per-tool {name, description,
 *    inputSchema}. A tool-bearing adapter's CH-35 gate is unchanged.
 *    (b) manifest.recordCount counts EVERY retrieval record — tool records AND
 *    capability residuals … The manifest MUST stamp tool_record_count,
 *    capability_record_count, and recordCountPreOverlay … ANY absent count is a
 *    fail-closed load error … (1) recordCountPreOverlay == tool_record_count +
 *    capability_record_count; (2) recordCount == countToolRecords(catalog) +
 *    countCapabilityRecords(catalog) …; (3) 0 < recordCount <=
 *    recordCountPreOverlay."
 *
 * These cases are derived from the clause's failure enumeration, not from the
 * implementation's mental model.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  VectorIndexVerifier,
  COMPILED_SERIALIZER_HASH,
  verifyVectorIndexManifest,
  VectorIndexVerificationError,
} from './VectorIndexVerifier.js';

function validManifest(over: Record<string, unknown> = {}) {
  return {
    version: '4.0.0',
    encoder: {
      denseModelId: 'epicai/bien-tool-retriever',
      denseModelVersion: '4.0.0',
      denseDims: 768,
      sparseModelId: 'prithivida/Splade_PP_en_v1',
      bm25Method: 'edge-bm25',
      idfPolicy: 'retriever-applied',
    },
    recordCount: 1,
    tool_record_count: 1,
    capability_record_count: 0,
    recordCountPreOverlay: 1,
    serializer_hash: COMPILED_SERIALIZER_HASH,
    ...over,
  };
}

/** A tool-bearing adapter — one tool record, full CH-35 profile. */
function toolAdapter(id = 'pagerduty', over: Record<string, unknown> = {}) {
  return {
    id,
    descriptionForRetrieval: 'incident management and on-call alerting',
    searchQueries: ['page on-call', 'create incident'],
    industries: ['software'],
    departments: ['sre'],
    tools: [{ name: 'create_incident', description: 'Create a new incident', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] }],
    ...over,
  };
}

/** A residual (capability) adapter — empty tools, grounded capability profile. */
function capabilityAdapter(id = '99pay', over: Record<string, unknown> = {}) {
  return {
    id,
    descriptionForRetrieval: 'digital wallet and checking-account balance retrieval',
    searchQueries: ['checking account balance', 'wallet balance'],
    industries: ['financial-services'],
    departments: ['treasury'],
    tools: [],
    ...over,
  };
}

function envelope(catalog: unknown[], manifest: unknown) {
  return { catalog, registry: [], manifest, epoch: 1, catalogVersion: 1 };
}

function admit(env: unknown, logger?: { warn(m: string, meta?: Record<string, unknown>): void }) {
  return new VectorIndexVerifier().admit(env as never, {
    persisted: null,
    signatureVerified: true,
    bundleSha256: 'a'.repeat(64),
    ...(logger ? { logger } : {}),
  });
}

// ── CH-62(a): residual acceptance gate ───────────────────────────────────────

test('CH-62(a): a residual adapter (empty tools + profile) is ADMITTED, not rejected for empty tools', () => {
  const env = envelope([capabilityAdapter()], validManifest({ tool_record_count: 0, capability_record_count: 1 }));
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
  assert.equal(r.code, 'admitted');
});

test('CH-62(a): a residual adapter missing descriptionForRetrieval is REJECTED', () => {
  const env = envelope(
    [capabilityAdapter('x', { descriptionForRetrieval: '' })],
    validManifest({ tool_record_count: 0, capability_record_count: 1 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-62(a): a residual adapter with empty searchQueries is REJECTED', () => {
  const env = envelope(
    [capabilityAdapter('x', { searchQueries: [] })],
    validManifest({ tool_record_count: 0, capability_record_count: 1 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-62(a): a residual adapter missing industries/departments is ADMITTED with a WARN (best-effort facet)', () => {
  const warnings: string[] = [];
  const logger = { warn: (m: string) => warnings.push(m) };
  const env = envelope(
    [capabilityAdapter('x', { industries: [], departments: [] })],
    validManifest({ tool_record_count: 0, capability_record_count: 1 }),
  );
  const r = admit(env, logger);
  assert.equal(r.admitted, true, r.reason);
  assert.ok(warnings.includes('retrieval.capability_facet_absent'), 'expected a best-effort-facet WARN');
});

test('CH-62(a): a residual adapter does NOT require per-tool {name,description,inputSchema}', () => {
  // No tools at all — must not trip the CH-35 per-tool checks.
  const env = envelope([capabilityAdapter()], validManifest({ tool_record_count: 0, capability_record_count: 1 }));
  assert.equal(admit(env).admitted, true);
});

test('CH-35 (amended 2026-07-16): a tool-bearing adapter missing industries is ADMITTED with a WARN (best-effort facet)', () => {
  const warnings: string[] = [];
  const logger = { warn: (m: string) => warnings.push(m) };
  const r = admit(envelope([toolAdapter('p', { industries: [] })], validManifest()), logger);
  assert.equal(r.admitted, true, r.reason);
  assert.ok(warnings.includes('retrieval.facet_absent'), 'expected a best-effort-facet WARN');
});

test('CH-35 (amended 2026-07-16): a tool-bearing adapter missing departments is ADMITTED with a WARN (best-effort facet)', () => {
  const warnings: string[] = [];
  const logger = { warn: (m: string) => warnings.push(m) };
  const r = admit(envelope([toolAdapter('p', { departments: [] })], validManifest()), logger);
  assert.equal(r.admitted, true, r.reason);
  assert.ok(warnings.includes('retrieval.facet_absent'), 'expected a best-effort-facet WARN');
});

test('CH-35: a tool-bearing adapter missing descriptionForRetrieval is still REJECTED (retrieval-critical)', () => {
  const r = admit(envelope([toolAdapter('p', { descriptionForRetrieval: '' })], validManifest()));
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-35: a tool-bearing adapter missing searchQueries is still REJECTED (retrieval-critical)', () => {
  const r = admit(envelope([toolAdapter('p', { searchQueries: [] })], validManifest()));
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-35: a tool-bearing adapter whose tool lacks a description is still REJECTED', () => {
  const r = admit(
    envelope([toolAdapter('p', { tools: [{ name: 't', inputSchema: {}, dispatchMechanisms: ['mcp'] }] })], validManifest()),
  );
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-62(a): tool-bearing adapter missing per-tool inputSchema still REJECTS (CH-35 unchanged)', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd' }] })],
    validManifest(),
  );
  assert.equal(admit(env).admitted, false);
});

// ── CH-62(b): widened record-count invariant ─────────────────────────────────

test('CH-62(b): recordCount counts tool + capability — a mixed catalog is ADMITTED at the sum', () => {
  const env = envelope(
    [toolAdapter(), capabilityAdapter()],
    validManifest({ recordCount: 2, tool_record_count: 1, capability_record_count: 1, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
});

test('CH-62(b): recordCount == tool_record_count alone (ignoring capability residuals) is REJECTED', () => {
  // The exact defect BIEN §17 calls out: counting tool records only.
  const env = envelope(
    [toolAdapter(), capabilityAdapter()],
    validManifest({ recordCount: 1, tool_record_count: 1, capability_record_count: 1, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'manifest_mismatch');
});

for (const field of ['tool_record_count', 'capability_record_count', 'recordCountPreOverlay'] as const) {
  test(`CH-62(b)/§17.7: an absent ${field} is a fail-closed load error`, () => {
    const m = validManifest({ tool_record_count: 0, capability_record_count: 1 }) as Record<string, unknown>;
    delete m[field];
    const env = envelope([capabilityAdapter()], m);
    const r = admit(env);
    assert.equal(r.admitted, false);
    assert.equal(r.code, 'manifest_mismatch');
  });
}

test('CH-62(b)/§17.7: recordCountPreOverlay != tool_record_count + capability_record_count is REJECTED', () => {
  const env = envelope(
    [capabilityAdapter()],
    validManifest({ recordCount: 1, tool_record_count: 0, capability_record_count: 1, recordCountPreOverlay: 5 }),
  );
  assert.equal(admit(env).admitted, false);
});

test('CH-62(b): recordCount > recordCountPreOverlay is REJECTED (overlay only removes records)', () => {
  const env = envelope(
    [toolAdapter(), capabilityAdapter()],
    validManifest({ recordCount: 3, tool_record_count: 1, capability_record_count: 1, recordCountPreOverlay: 2 }),
  );
  assert.equal(admit(env).admitted, false);
});

test('CH-62(b): recordCount != payload tool + capability count is REJECTED (manifest↔payload)', () => {
  // Manifest internally consistent (pre == tool+cap, 0<rc<=pre) but disagrees
  // with the catalog the signed bundle actually carries.
  const env = envelope(
    [capabilityAdapter()], // payload: 0 tool + 1 capability = 1
    validManifest({ recordCount: 2, tool_record_count: 1, capability_record_count: 1, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'manifest_mismatch');
});

test('CH-62(b): XOR partition — an inactive residual is not counted as a capability record', () => {
  // pagerduty (1 tool) active + an inactive residual → 1 tool + 0 capability.
  const env = envelope(
    [toolAdapter(), capabilityAdapter('dead', { active: false })],
    validManifest({ recordCount: 1, tool_record_count: 1, capability_record_count: 0, recordCountPreOverlay: 1 }),
  );
  assert.equal(admit(env).admitted, true);
});

// ── CH-62 node 131/132: identity + key uniqueness on the live admit() path ────

test('CH-62 node 131: a duplicate server::name tool identity is REJECTED', () => {
  const env = envelope(
    [toolAdapter('srv', { tools: [
      { name: 'x', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] },
      { name: 'x', description: 'd2', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] },
    ] })],
    validManifest({ recordCount: 2, tool_record_count: 2, capability_record_count: 0, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-62 node 132: a duplicate capability record key (adapter id) is REJECTED', () => {
  const env = envelope(
    [capabilityAdapter('same'), capabilityAdapter('same')],
    validManifest({ recordCount: 2, tool_record_count: 0, capability_record_count: 2, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'agent_field_gate_failed');
});

test('CH-62 node 132: a residual record with no string id key is REJECTED', () => {
  const env = envelope(
    [capabilityAdapter('', { id: '' })],
    validManifest({ recordCount: 1, tool_record_count: 0, capability_record_count: 1, recordCountPreOverlay: 1 }),
  );
  assert.equal(admit(env).admitted, false);
});

// ── CH-62(b): the pre-4.0 compat seam (verifyVectorIndexManifest, :68) ─────────

function compatManifest(over: Record<string, unknown> = {}) {
  return {
    version: '4.0.0',
    encoder: {
      denseModelId: 'epicai/bien-tool-retriever',
      denseModelVersion: '4.0.0',
      denseDims: 768,
      sparseModelId: 'prithivida/Splade_PP_en_v1',
      bm25Method: 'edge-bm25',
      idfPolicy: 'retriever-applied',
    },
    recordCount: 1,
    tool_record_count: 1,
    capability_record_count: 0,
    recordCountPreOverlay: 1,
    serializer_hash: COMPILED_SERIALIZER_HASH,
    merkleRoot: 'a'.repeat(64),
    ...over,
  } as never;
}
const compatContract = { denseModelId: 'epicai/bien-tool-retriever', denseModelVersion: '4.0.0', bm25Method: 'edge-bm25', idfPolicy: 'retriever-applied' } as never;
const compatTools = [{ tool_id: 'srv::t1', dispatch_mechanisms: ['mcp'] }] as never;

test('compat seam: a valid manifest with well-formed count stamps passes', () => {
  assert.doesNotThrow(() => verifyVectorIndexManifest(compatManifest(), compatTools, compatContract));
});

test('compat seam: an ABSENT capability_record_count is fail-closed (not a silent zero)', () => {
  const m = compatManifest();
  delete (m as Record<string, unknown>).capability_record_count;
  assert.throws(() => verifyVectorIndexManifest(m, compatTools, compatContract), VectorIndexVerificationError);
});

test('compat seam: recordCountPreOverlay != tool_record_count + capability_record_count is rejected', () => {
  assert.throws(
    () => verifyVectorIndexManifest(compatManifest({ recordCountPreOverlay: 9 }), compatTools, compatContract),
    VectorIndexVerificationError,
  );
});

test('compat seam: tool payload length != tool_record_count is rejected', () => {
  // manifest says 2 tool records but only 1 tool record is supplied.
  assert.throws(
    () => verifyVectorIndexManifest(
      compatManifest({ recordCount: 2, tool_record_count: 2, recordCountPreOverlay: 2 }),
      compatTools,
      compatContract,
    ),
    VectorIndexVerificationError,
  );
});
