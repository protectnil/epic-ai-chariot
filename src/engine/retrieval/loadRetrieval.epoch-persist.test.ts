/**
 * Adversarial eval: epoch-persist ordering (Finding 1, commit 2f61fe9)
 *
 * The fix moved opts.persist() from the admit-path to the full-hybrid path only.
 * The old ordering advanced the epoch high-water mark even when native/artifacts
 * were absent, so the NEXT restart saw epoch <= persisted.epoch and threw
 * epoch_replay_rejected — a permanent boot failure (§5.6).
 *
 * These evals exercise wireHybridRetrieval with a REAL persisted-epoch object
 * (simulating a file-backed store). No mocks — all assertions are on real return
 * values and the real persist side-effect.
 *
 * Run (after tsc):
 *   node --test dist/engine/retrieval/loadRetrieval.epoch-persist.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { wireHybridRetrieval } from './loadRetrieval.js';
import {
  DEFAULT_RETRIEVAL_CONTRACT,
  COMPILED_SERIALIZER_HASH,
} from './VectorIndexVerifier.js';
import type { CatalogEpochState } from '../federation/AdapterCatalog.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function validManifest() {
  const c = DEFAULT_RETRIEVAL_CONTRACT;
  return {
    version: c.version,
    encoder: {
      denseModelId: c.denseModelId,
      denseModelVersion: c.denseModelVersion,
      denseDims: c.denseDims,
      sparseModelId: c.sparseModelId,
      bm25Method: c.bm25Method,
      idfPolicy: c.idfPolicy,
    },
    // CH-22: recordCount must equal the tool-granular record count carried by
    // the signed catalog itself (validCatalog() below carries exactly 1 tool).
    recordCount: 1,
    tool_record_count: 1,
    capability_record_count: 0,
    recordCountPreOverlay: 1,
    serializer_hash: COMPILED_SERIALIZER_HASH,
  };
}

function validCatalog() {
  return [
    {
      id: 'pagerduty',
      descriptionForRetrieval: 'incident management and on-call alerting',
      searchQueries: ['page on-call', 'create incident'],
      industries: ['software'],
      departments: ['sre'],
      tools: [{ name: 'create_incident', description: 'Create a new incident', inputSchema: { type: 'object' }, dispatchMechanisms: ['mcp'] }],
    },
  ];
}

/** Build a signed envelope at the given epoch. */
function envelope(epoch: number, catalogVersion: number = 2) {
  return {
    catalog: validCatalog(),
    registry: [],
    manifest: validManifest(),
    epoch,
    catalogVersion,
  };
}

/** Minimal real native binding stub — only frozenSerializerHash() is called by wireHybridRetrieval. */
import type { NativeEdgeBinding } from './nativeEdge.js';
const fakeNative = { frozenSerializerHash: () => COMPILED_SERIALIZER_HASH } as unknown as NativeEdgeBinding;

/** Minimal real artifacts — real object, deterministic returns. */
function fakeArtifacts() {
  const fakeShard = {
    upsert() {},
    flush() {},
    pointsCount() { return 1; },
    snapshotManifestJson() { return '{}'; },
    query() { return []; },
  };
  return {
    loadShard: () => fakeShard,
    loadDenseEncoder: () => ({ embed: (xs: string[]) => xs.map(() => [1, 2, 3]) }),
    loadSparseEncoder: () => null,
    loadRerankScorer: () => null,
    querySerializer: () => (q: string) => q,
  };
}

// ── eval 1a: encoder-missing-at-startup fails CLOSED, does NOT advance epoch ──
// AMENDED 2026-07-16b (§4.4 row 2 / §4.1): a manifest that IS admitted but
// whose native module / dense encoder is missing or fails to load at STARTUP
// is a fail-closed load error — there is NO BM25 fallback for this case. Only
// the RUNTIME select()-throws-on-an-already-loaded-bundle path (§4.4 row 3,
// HybridRetriever's try/catch) degrades to BM25.

test('epoch-persist: native/artifacts absent at startup → fail-closed, persist() NOT called', () => {
  // Simulated persistent store — starts empty (fresh install).
  let store: CatalogEpochState | null = null;
  const persist = (s: CatalogEpochState) => { store = s; };

  const result = wireHybridRetrieval({
    envelope: envelope(10),
    signatureVerified: true,
    persisted: null,
    persist,
    native: null,       // absent
    artifacts: null,    // absent
  });

  assert.equal(result.mode, 'fail-closed',
    'must fail closed (never bm25-only) when native/artifacts are unavailable at startup (§4.4 row 2, amended 2026-07-16b)');
  assert.equal(
    (result as { mode: 'fail-closed'; code: string }).code,
    'encoder_load_failed',
    'failure code must be encoder_load_failed',
  );
  assert.equal(store, null,
    'persist() MUST NOT be called on the fail-closed path — epoch must not advance');
});

// ── eval 1b: second boot after a startup fail-closed is still fail-closed ────
// (there is no bm25-only fallback state to "not brick" into — the bundle
// must be fixed or replaced before startup can proceed at all).

test('epoch-persist: second boot with the same unfixed bundle is still fail-closed (not bricked into hybrid, not silently bm25)', () => {
  // Simulated store — empty after first boot (persist was not called).
  let store: CatalogEpochState | null = null;
  const persist = (s: CatalogEpochState) => { store = s; };

  // First boot: valid bundle epoch=10, no native/artifacts → fail-closed.
  const first = wireHybridRetrieval({
    envelope: envelope(10),
    signatureVerified: true,
    persisted: null,
    persist,
    native: null,
    artifacts: null,
  });
  assert.equal(first.mode, 'fail-closed');
  assert.equal(store, null, 'persist not called on first boot (fail-closed path)');

  // Second boot: same bundle (epoch=10), persisted=null (unchanged — persist
  // was never called on the fail-closed path). Confirms the epoch mark was
  // never advanced by the fail-closed path, so a SUBSEQUENT successful boot
  // (once the encoder artifact is fixed) is not spuriously epoch_replay_rejected.
  const second = wireHybridRetrieval({
    envelope: envelope(10),
    signatureVerified: true,
    persisted: store,   // null — unchanged
    persist,
    native: null,
    artifacts: null,
  });

  assert.equal(second.mode, 'fail-closed',
    'second boot with the still-unfixed bundle must remain fail-closed — never bm25-only');
  assert.equal(
    (second as { mode: 'fail-closed'; code: string }).code,
    'encoder_load_failed',
  );
});

// ── eval 1c: full-admission path DOES advance epoch ──────────────────────────

test('epoch-persist: full-admission (native + artifacts) DOES call persist()', () => {
  let store: CatalogEpochState | null = null;
  const persist = (s: CatalogEpochState) => { store = s; };

  const result = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    persisted: { epoch: 9, catalogVersion: 2 }, // prior epoch
    persist,
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });

  assert.equal(result.mode, 'hybrid',
    'valid bundle + native + artifacts must return hybrid');
  assert.deepEqual(store, { epoch: 10, catalogVersion: 2 },
    'persist() MUST be called with the admitted epoch on the full-hybrid path');
});

// ── eval 1d: old-code simulation — show the ordering mattered ────────────────
// Demonstrate that advancing the epoch without the hybrid stack running
// would brick the next boot. This confirms why the fix was necessary.

test('epoch-persist: epoch advanced without hybrid running → next boot fails (regression spec)', () => {
  // Simulate what the OLD code did: manually advance epoch even though
  // native/artifacts were absent (BM25-only path).
  const oldCodePersistedEpoch: CatalogEpochState = { epoch: 10, catalogVersion: 2 };

  // Next boot: same bundle (epoch=10), persisted epoch=10 from old behavior.
  const result = wireHybridRetrieval({
    envelope: envelope(10),
    signatureVerified: true,
    persisted: oldCodePersistedEpoch, // epoch already "advanced" by old code
    persist: () => {},
    native: null,
    artifacts: null,
  });

  // The verifier sees epoch(10) == persisted.epoch(10) with NO bundle
  // identity supplied → epoch_replay_rejected (fail closed: an equal-epoch
  // bundle that cannot prove it is the identical accepted artifact is a replay).
  assert.equal(result.mode, 'fail-closed',
    'boot must fail when epoch was advanced without hybrid running (regression: the old-code brick)');
  assert.equal(
    (result as { mode: 'fail-closed'; code: string }).code,
    'epoch_replay_rejected',
    'failure code must be epoch_replay_rejected — proving why the old ordering bricked boot',
  );
});

// ── eval 1e: restart after a successful hybrid boot must NOT brick ───────────
// Boot 1 full-hybrid persists the mark; boot 2 re-reads the IDENTICAL signed
// bundle. With epoch-only strict '>' admission this deterministically bricked
// every restart after the first hybrid boot; identity binding (bundleSha256)
// makes the same-bundle re-admit an idempotent no-op.

test('epoch-persist: restart with the SAME admitted bundle re-admits as hybrid (no brick)', () => {
  const bundleSha256 = 'a'.repeat(64); // stands in for sha256(verified envelope bytes)
  let store: CatalogEpochState | null = null;
  let persistCalls = 0;
  const persist = (s: CatalogEpochState) => { store = s; persistCalls++; };

  // Boot 1: full hybrid admission — persists the identity-bound mark.
  const first = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    bundleSha256,
    persisted: null,
    persist,
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(first.mode, 'hybrid');
  assert.equal(persistCalls, 1, 'boot 1 persists the mark');
  assert.deepEqual(store, { epoch: 10, catalogVersion: 2, bundleSha256 },
    'persisted mark must be identity-bound to the bundle hash');

  // Boot 2: SAME envelope, SAME bytes, persisted mark from boot 1.
  const second = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    bundleSha256,
    persisted: store,
    persist,
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(second.mode, 'hybrid',
    'restart with the identical admitted bundle must return hybrid, not fail-closed');
  assert.equal(persistCalls, 1,
    'idempotent re-admit must not rewrite the epoch file on every boot');
});

// ── eval 1f: a DIFFERENT bundle at the same epoch is still a replay ──────────

test('epoch-persist: different bundle bytes at the persisted epoch stay rejected', () => {
  const result = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    bundleSha256: 'b'.repeat(64), // different artifact
    persisted: { epoch: 10, catalogVersion: 2, bundleSha256: 'a'.repeat(64) },
    persist: () => {},
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(result.mode, 'fail-closed',
    'a non-identical bundle at the persisted epoch must stay rejected (§5.6 replay defense)');
  assert.equal(
    (result as { mode: 'fail-closed'; code: string }).code,
    'epoch_replay_rejected',
  );
});

// ── eval 1g: a hash-less persisted mark is identity_unproven, NOT a wildcard ──
//
// INVERTED 2026-07-28. This test previously asserted that a same-epoch bundle
// against a legacy hash-unknown mark ADMITS as a "one-time migration". That
// assertion contradicts the governing clause, which CHARIOT-SPEC.md:434 states
// verbatim:
//
//   "A persisted record carrying no `bundleSha256` — written before identity
//    binding — SHALL NOT be treated as matching an arbitrary bundle; it is
//    `identity_unproven` and fails closed with operator-actionable guidance
//    ... Treating an absent hash as a wildcard would convert the equal-epoch
//    branch into an arbitrary-bundle admission for anyone able to delete one
//    field from a local file, which is strictly weaker than the epoch check it
//    stands in for."
//
// The old test was self-consistent with the old implementation and passed
// green while proving the wrong thing: both sides shared the same wrong
// premise. It is derived from the clause now.

test('epoch-persist: hash-less persisted mark is identity_unproven and fails CLOSED (not a wildcard)', () => {
  let store: CatalogEpochState | null = { epoch: 10, catalogVersion: 2 }; // legacy, no hash
  const persist = (s: CatalogEpochState) => { store = s; };

  const result = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    bundleSha256: 'c'.repeat(64),
    persisted: store,
    persist,
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(result.mode, 'fail-closed',
    'an absent persisted bundleSha256 cannot match an arbitrary bundle (§5.6:434)');
  assert.equal(
    (result as { mode: 'fail-closed'; code: string }).code,
    'epoch_replay_rejected',
  );
  assert.deepEqual(store, { epoch: 10, catalogVersion: 2 },
    'the unproven mark must NOT be upgraded with the incoming bundle hash');
});

// ── eval 1h: attacker strips the hash from the local epoch file ──────────────
// The concrete exploit CHARIOT-SPEC.md:434 names: deleting ONE field from a
// local file must not convert the equal-epoch branch into arbitrary-bundle
// admission. Same epoch, same catalogVersion, ATTACKER bundle bytes.

test('epoch-persist: stripping bundleSha256 from the mark does not admit an attacker bundle', () => {
  const result = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    bundleSha256: 'f'.repeat(64), // attacker artifact, never accepted at this mark
    persisted: { epoch: 10, catalogVersion: 2 }, // hash field deleted from disk
    persist: () => {},
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(result.mode, 'fail-closed',
    'hash-stripping must not weaken the equal-epoch branch below the epoch check (§5.6:434)');
});

// ── eval 1i: incoming bundle with no computed hash is identity_unproven ──────
// CHARIOT-SPEC.md:434 — "An incoming bundle whose `bundleSha256` is not
// supplied is likewise `identity_unproven`." Both sides must be proven.

test('epoch-persist: incoming bundle without a supplied bundleSha256 fails closed at an equal epoch', () => {
  const result = wireHybridRetrieval({
    envelope: envelope(10, 2),
    signatureVerified: true,
    // bundleSha256 deliberately omitted — caller could not establish identity
    persisted: { epoch: 10, catalogVersion: 2, bundleSha256: 'a'.repeat(64) },
    persist: () => {},
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(result.mode, 'fail-closed',
    'an unsupplied incoming hash is identity_unproven at an equal epoch (§5.6:434)');
});

// ── eval 1j: re-admission cannot move catalogVersion ─────────────────────────
// CHARIOT-SPEC.md:431 requires catalogVersion EQUALITY for a re-admission: a
// re-admission is not a publication, so the version cannot move under a fixed
// epoch. A byte-identical bundle claiming a HIGHER version is still rejected.

test('epoch-persist: byte-identical bundle at an equal epoch with a different catalogVersion is rejected', () => {
  const bundleSha256 = 'a'.repeat(64);
  const result = wireHybridRetrieval({
    envelope: envelope(10, 3), // version moved under a fixed epoch
    signatureVerified: true,
    bundleSha256,
    persisted: { epoch: 10, catalogVersion: 2, bundleSha256 },
    persist: () => {},
    native: fakeNative,
    artifacts: fakeArtifacts(),
  });
  assert.equal(result.mode, 'fail-closed',
    'a re-admission SHALL NOT change catalogVersion (§5.6:431)');
});
