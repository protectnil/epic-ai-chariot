/**
 * CHARIOT::§3.5a — Tool-level dispatch identity amendment, admission-time
 * enforcement (CHARIOT-SPEC.md:270-279, quoted verbatim):
 *   "Every Ready tool record in the 4.0.0 retrieval bundle MUST carry
 *   `{name, description, inputSchema, dispatchMechanisms}`. For
 *   `type:"both"`, the per-surface tool lists, their sorted duplicate-free
 *   top-level union, and each tool's exact mechanism set MUST satisfy AS
 *   §1.4a. Tier 2 MUST submit the exact canonical `tool_id` only through a
 *   mechanism declared by that tool and MUST prefer REST only when REST is
 *   declared for that tool. `VectorIndexVerifier` and the catalog loader
 *   MUST reject adapter-granular bundles, missing or empty mechanism sets,
 *   ambiguous tool routes, and any per-surface/union/mechanism
 *   disagreement."
 *
 * AS §1.4a (ADAPTER-STANDARD-MAY-2026.md:362-390, quoted in part):
 *   "tools[].dispatchMechanisms: <("rest" | "mcp")[]>  sorted, non-empty, and
 *   contains exactly the surfaces advertising that tool ... The publisher
 *   and runtime MUST reject a `both` record whose top-level union,
 *   per-surface list, count, or per-tool mechanism map disagrees with its
 *   authoritative sources."
 *
 * Before this patch, none of these four rejection classes ran at bundle
 * ADMISSION: `BundleTool` carried no `dispatchMechanisms` field,
 * `verifyVectorIndexManifest` (the only function that checked
 * `dispatch_mechanisms` non-emptiness) was never called from production, no
 * ambiguous-tool-route check existed anywhere in VectorIndexVerifier.ts or
 * AdapterCatalog.ts, and the per-surface/union/mechanism disagreement check
 * (`verifyToolDispatchIdentity`) ran ONLY at dispatch time in
 * toolHandlers.ts. Cases below are derived from the clause's failure
 * enumeration, not from the implementation's mental model.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VectorIndexVerifier, COMPILED_SERIALIZER_HASH } from './VectorIndexVerifier.js';

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

/** A single-tool, single-surface (mcp) tool-bearing adapter — full CH-35 profile. */
function toolAdapter(id = 'pagerduty', over: Record<string, unknown> = {}) {
  return {
    id,
    descriptionForRetrieval: 'incident management and on-call alerting',
    searchQueries: ['page on-call', 'create incident'],
    industries: ['software'],
    departments: ['sre'],
    tools: [{
      name: 'create_incident',
      description: 'Create a new incident',
      inputSchema: { type: 'object' },
      dispatchMechanisms: ['mcp'],
    }],
    ...over,
  };
}

function envelope(catalog: unknown[], manifest: unknown) {
  return { catalog, registry: [], manifest, epoch: 1, catalogVersion: 1 };
}

function admit(env: unknown) {
  return new VectorIndexVerifier().admit(env as never, {
    persisted: null,
    signatureVerified: true,
    bundleSha256: 'a'.repeat(64),
  });
}

// ── CHARIOT::§3.5a::1 — every Ready tool record MUST carry dispatchMechanisms ──

test('§3.5a::1: a tool record with dispatchMechanisms present is ADMITTED', () => {
  const env = envelope([toolAdapter()], validManifest());
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
});

test('§3.5a::1 / §3.5a::6: a tool record with dispatchMechanisms ABSENT is REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' } }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_mechanism_missing_or_empty');
});

// ── CHARIOT::§3.5a::6 — missing or empty mechanism sets are REJECTED ───────────

test('§3.5a::6: an EMPTY dispatchMechanisms array is REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: [] }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_mechanism_missing_or_empty');
});

test('§3.5a::6: a NON-ARRAY dispatchMechanisms value is REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: 'mcp' }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_mechanism_missing_or_empty');
});

test('§3.5a::6: dispatchMechanisms carrying a value outside {mcp,rest} is REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['http'] }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_mechanism_missing_or_empty');
});

test('§3.5a::6: dispatchMechanisms:["rest"] alone is ADMITTED (single-surface REST-only is a valid, non-empty set)', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['rest'] }] })],
    validManifest(),
  );
  assert.equal(admit(env).admitted, true);
});

// ── CHARIOT::§3.5a::7 — ambiguous tool routes are REJECTED ─────────────────────

test('§3.5a::7: a DUPLICATE entry within dispatchMechanisms (["mcp","mcp"]) is an ambiguous route — REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp', 'mcp'] }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'ambiguous_tool_route');
});

test('§3.5a::7: an UNSORTED dispatchMechanisms (["rest","mcp"]) is an ambiguous route — REJECTED', () => {
  const env = envelope(
    [toolAdapter('p', { tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['rest', 'mcp'] }] })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'ambiguous_tool_route');
});

test('§3.5a::7: sorted, duplicate-free dispatchMechanisms (["mcp","rest"]) is the CANONICAL form — ADMITTED', () => {
  const env = envelope(
    [toolAdapter('p', {
      type: 'both',
      rest: { toolNames: ['t'] },
      mcp: { toolNames: ['t'] },
      tools: [{ name: 't', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp', 'rest'] }],
    })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
});

test('§3.5a::7: a duplicate canonical tool_id (server::name) across two records is an ambiguous route — REJECTED', () => {
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
  assert.match(r.reason, /ambiguous tool route/);
});

// ── CHARIOT::§3.5a::8 — per-surface/union/mechanism disagreement, type:"both" ──

test('§3.5a::8: a type:"both" adapter whose tools union disagrees with rest+mcp toolNames is REJECTED at admission', () => {
  const env = envelope(
    [toolAdapter('p', {
      type: 'both',
      rest: { toolNames: ['a', 'b'] },
      mcp: { toolNames: ['a'] },
      // Union should be ['a','b'] but only 'a' is routed — disagreement.
      tools: [{ name: 'a', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp', 'rest'] }],
    })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_identity_disagreement');
});

test('§3.5a::8: a type:"both" tool whose dispatchMechanisms disagrees with its actual per-surface presence is REJECTED at admission', () => {
  const env = envelope(
    [toolAdapter('p', {
      type: 'both',
      rest: { toolNames: ['a'] },
      mcp: { toolNames: ['a'] },
      // 'a' is on BOTH surfaces but claims only 'mcp' — mechanism disagreement.
      tools: [{ name: 'a', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] }],
    })],
    validManifest(),
  );
  const r = admit(env);
  assert.equal(r.admitted, false);
  assert.equal(r.code, 'dispatch_identity_disagreement');
});

test('§3.5a::8: a type:"both" adapter with an internally-consistent union/mechanism map is ADMITTED (positive control)', () => {
  const env = envelope(
    [toolAdapter('p', {
      type: 'both',
      rest: { toolNames: ['a', 'b'] },
      mcp: { toolNames: ['a'] },
      tools: [
        { name: 'a', description: 'd', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp', 'rest'] },
        { name: 'b', description: 'd2', inputSchema: { type: 'object' }, dispatchMechanisms: ['rest'] },
      ],
    })],
    validManifest({ recordCount: 2, tool_record_count: 2, capability_record_count: 0, recordCountPreOverlay: 2 }),
  );
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
});

test('§3.5a::8: a type:"mcp" (single-surface) adapter is UNAFFECTED by the type:"both" disagreement check', () => {
  // No `rest`/`mcp` sub-objects at all — the disagreement check must not fire
  // for anything other than type:"both" (AS §1.4a governs "both" only).
  const env = envelope([toolAdapter('p', { type: 'mcp' })], validManifest());
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
});

// ── Positive control — a fully compliant Ready tool record admits cleanly ──────

test('positive control: a fully §3.5a-compliant single-surface tool record is ADMITTED', () => {
  const env = envelope([toolAdapter()], validManifest());
  const r = admit(env);
  assert.equal(r.admitted, true, r.reason);
  assert.equal(r.code, 'admitted');
});
