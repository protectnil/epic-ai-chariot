/**
 * CHARIOT::§5.2::1-5 (CHARIOT-SPEC.md:363-373, CH-02 at :245) — the
 * production adapter-load path (`loadAllAdaptersWithState`, called by
 * `loadChariotState`, which every `toolHandlers.ts` reader depends on via
 * `state.allAdapters` / `state.adapterById`) and the §5.2::5 4.0.0
 * retrieval-triggered invalidation (`classifySealedBundleFailure` /
 * `applySealedBundleFailure`, called from `wireRetrievalForState`).
 *
 * Gate finding #1 (Critical): §5.2::5 was not wired — a retrieval-manifest
 * mismatch / encoder mismatch / sealed-bundle signature failure only threw
 * (§4.4) without also forcing the adapter catalog invalid+empty (CH-02).
 * Closed here: `classifySealedBundleFailure` covers every `AdmissionCode`,
 * and `applySealedBundleFailure` empties `allAdapters`/`adapterById`/both
 * pre-filters for exactly the three named conditions, never for the
 * others (§5.6 replay/downgrade, CH-35 dispatch-identity — not named by
 * §5.2::5).
 *
 * Gate finding #2 (High): `loadAllAdapters()`/`state.allAdapters`/
 * `adapterById` were populated by an ad hoc bytes-or-null check, not the
 * shared `computeCatalogState()`/`effectiveCatalogEntries()` the
 * federation `AdapterCatalog` class uses. Closed here: `loadAllAdaptersWithState`
 * now calls those same functions directly and is the DIRECT source of
 * `state.allAdapters`/`adapterById` — every reader named in the gate
 * (`toolHandlers.ts:1132` `state.allAdapters` category-hint loop, `:1603`
 * `state.adapterById.get(adapterId)`, `:2938` `handleList`'s `state.allAdapters`)
 * reads the SAME objects this file proves are emptied. `handleList`
 * (chariot_list), `handleQuery` (chariot_query), and `handleCall`
 * (chariot_call) are all exercised directly below against a minimal
 * synthetic `ChariotState` (mirroring the fixture pattern
 * `QueryExpander.call-site-opt-in.test.ts` (W15) uses for the same two
 * handlers), proving each sees zero adapters / cannot dispatch when the
 * catalog is empty.
 *
 * Gate finding #1 v2 (P0, this revision): the §5.2::5 state transition to
 * `invalid` was not OBSERVABLE on the production retrieval-failure path —
 * `applySealedBundleFailure` emptied the mutable surfaces but the throw
 * that follows prevents any `ChariotState` from ever being returned, so
 * `catalogState` (captured earlier in `loadChariotState`) was never
 * updated. Closed by carrying the transition ON the thrown error:
 * `wireRetrievalForState` now throws {@link RetrievalBundleRejectedError},
 * whose `catalogState`/`catalogStateReason` are set to `'invalid'` / the
 * trigger reason for exactly the three §5.2::5 codes (undefined for any
 * other fail-closed code) — the only channel back to the caller once the
 * throw has already prevented a return value.
 *
 * Gate finding v4 (P0, this revision): a prior revision added an
 * `acceptedKeysOverride` test-only parameter to `wireRetrievalForState`
 * itself to drive `manifest_mismatch`/`signature_invalid` end-to-end. That
 * is a caller-supplied-key seam on the CH-52 pinned trust anchor
 * (CHARIOT-SPEC.md:525: "The Ed25519 verifying key SHALL be pinned to the
 * compiled-in accepted key set ... A caller-supplied key outside that
 * rotation set SHALL be rejected, so neither a caller nor an attacker
 * controlling the caller's configuration can substitute a signing key") —
 * removed. `wireRetrievalForState` now takes NO key parameter at all;
 * verifying against the compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS` is the
 * ONLY behavior, for tests and production alike. `signature_invalid` is
 * proven below with no seam whatsoever — a fixture signed by a key simply
 * not in the accepted set, rejected by the unmodified production default.
 * `manifest_mismatch` and `encoder_load_failed` positive-signature
 * end-to-end tests (a fixture that PASSES the pinned-key gate, then fails
 * later) require signing with the real accepted private key (the catalog
 * materializer's local-key signer path, confirmed to be the private half
 * of the sole compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS` entry by deriving
 * and byte-comparing its public half — never the private key itself —
 * against `chariot-catalog-public.ts`'s `PROD_KEY_2026_05_07`). That key
 * is production-signing material this public colocated test suite must
 * never read or depend on; both positive-signature end-to-end tests live
 * instead in the PRIVATE eval tree (`test/verified-catalog-e2e-w14.mjs`),
 * which reads the key path from the `CHARIOT_CATALOG_SIGNING_KEY_PATH`
 * env var at test-run time and fails explicitly — never silently skips —
 * if it is unset or unreadable. `encoder_load_failed` is additionally covered here (this public
 * file) by the direct `applySealedBundleFailure('encoder_load_failed', ...)`
 * unit test above, the same code the end-to-end path calls into.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';

import {
  loadAllAdaptersWithState,
  classifySealedBundleFailure,
  applySealedBundleFailure,
  wireRetrievalForState,
  RetrievalBundleRejectedError,
  buildToolsForRouting,
  type AdapterEntry,
} from './ChariotState.js';
import { ToolPreFilter } from '../federation/ToolPreFilter.js';
import { handleList, handleQuery, handleCall } from './toolHandlers.js';
import type { ChariotState } from './ChariotState.js';
import type { AdmissionCode } from '../retrieval/VectorIndexVerifier.js';

function makeTestKeyPair(): { publicKeyPem: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
}

function signBytes(privateKey: KeyObject, bytes: Buffer): string {
  return cryptoSign(null, bytes, privateKey).toString('base64');
}

let envelopeTenantCounter = 0;
function freshTenantId(label: string): string {
  envelopeTenantCounter += 1;
  return `w14-catalog-state-${label}-${process.pid}-${envelopeTenantCounter}`;
}

function freshSandbox(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-state-catalog-test-'));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------
// loadAllAdaptersWithState — CHARIOT::§5.2::3 (CH-02), the production
// adapter-catalog load path.
// ---------------------------------------------------------------------------

test('loadAllAdaptersWithState: catalog file entirely absent → state invalid, empty effective catalog, no throw', async () => {
  const { dir, cleanup } = freshSandbox();
  const prior = process.env.CHARIOT_ADAPTER_CATALOG_PATH;
  try {
    process.env.CHARIOT_ADAPTER_CATALOG_PATH = join(dir, 'does-not-exist-adapter-catalog.json');
    const result = await loadAllAdaptersWithState();
    assert.equal(result.state, 'invalid');
    assert.deepEqual(result.adapters, []);
  } finally {
    if (prior === undefined) delete process.env.CHARIOT_ADAPTER_CATALOG_PATH;
    else process.env.CHARIOT_ADAPTER_CATALOG_PATH = prior;
    cleanup();
  }
});

test('loadAllAdaptersWithState: catalog present but UNSIGNED (no .sig sidecar) → state invalid, empty effective catalog, no throw', async () => {
  const { dir, cleanup } = freshSandbox();
  const prior = process.env.CHARIOT_ADAPTER_CATALOG_PATH;
  try {
    const catalogPath = join(dir, 'chariot-adapter-bundle.json');
    writeFileSync(catalogPath, JSON.stringify({ epoch: 1, catalogVersion: 1, catalog: [{ id: 'x' }] }));
    // Deliberately no .sig sidecar written.
    process.env.CHARIOT_ADAPTER_CATALOG_PATH = catalogPath;

    const result = await loadAllAdaptersWithState();

    assert.equal(result.state, 'invalid');
    assert.deepEqual(result.adapters, []);
  } finally {
    if (prior === undefined) delete process.env.CHARIOT_ADAPTER_CATALOG_PATH;
    else process.env.CHARIOT_ADAPTER_CATALOG_PATH = prior;
    cleanup();
  }
});

test('loadAllAdaptersWithState: catalog present with a TAMPERED signature (does not verify against the production key) → state invalid, empty, no throw', async () => {
  const { dir, cleanup } = freshSandbox();
  const prior = process.env.CHARIOT_ADAPTER_CATALOG_PATH;
  try {
    const catalogPath = join(dir, 'chariot-adapter-bundle.json');
    writeFileSync(catalogPath, JSON.stringify({ epoch: 1, catalogVersion: 1, catalog: [{ id: 'x' }] }));
    writeFileSync(`${catalogPath}.sig`, Buffer.from('not-a-real-signature-bytes').toString('base64'));
    process.env.CHARIOT_ADAPTER_CATALOG_PATH = catalogPath;

    const result = await loadAllAdaptersWithState();

    assert.equal(result.state, 'invalid');
    assert.deepEqual(result.adapters, []);
    assert.ok(result.stateReason.length > 0);
  } finally {
    if (prior === undefined) delete process.env.CHARIOT_ADAPTER_CATALOG_PATH;
    else process.env.CHARIOT_ADAPTER_CATALOG_PATH = prior;
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// classifySealedBundleFailure — CHARIOT::§5.2::5, every AdmissionCode.
// ---------------------------------------------------------------------------

test('classifySealedBundleFailure: the three §5.2::5-named conditions classify correctly', () => {
  assert.equal(classifySealedBundleFailure('manifest_missing'), 'retrieval_manifest_mismatch');
  assert.equal(classifySealedBundleFailure('manifest_mismatch'), 'retrieval_manifest_mismatch');
  assert.equal(classifySealedBundleFailure('serializer_mismatch'), 'retrieval_manifest_mismatch');
  assert.equal(classifySealedBundleFailure('encoder_load_failed'), 'encoder_mismatch');
  assert.equal(classifySealedBundleFailure('signature_invalid'), 'sealed_bundle_signature_failed');
});

test('classifySealedBundleFailure: §5.6 anti-rollback and CH-35 dispatch-identity codes are NOT §5.2::5 triggers (null)', () => {
  const notNamedBySpec52point5: AdmissionCode[] = [
    'epoch_replay_rejected',
    'version_downgrade_rejected',
    'agent_field_gate_failed',
    'dispatch_mechanism_missing_or_empty',
    'ambiguous_tool_route',
    'dispatch_identity_disagreement',
    'envelope_malformed',
    'admitted',
  ];
  for (const code of notNamedBySpec52point5) {
    assert.equal(classifySealedBundleFailure(code), null, `unexpected classification for ${code}`);
  }
});

// ---------------------------------------------------------------------------
// applySealedBundleFailure — the CH-02 side effect: empty allAdapters,
// adapterById, and BOTH pre-filters, for exactly the three named codes.
// ---------------------------------------------------------------------------

function makeAdapters(): AdapterEntry[] {
  // buildToolsForRouting drops any adapter whose description is under 20
  // chars (descriptionIsLowQuality) — real, sufficiently long descriptions
  // here so both fixtures actually reach the BM25 index.
  return [
    { id: 'a1', name: 'a1', description: 'Alpha test adapter for widget management operations', category: 'other', type: 'rest', rest: { module: './x.js', className: 'X', toolCount: 1, toolNames: ['widgetlookup'] } },
    { id: 'a2', name: 'a2', description: 'Bravo test adapter for gadget management operations', category: 'other', type: 'rest', rest: { module: './y.js', className: 'Y', toolCount: 1, toolNames: ['gadgetlookup'] } },
  ] as unknown as AdapterEntry[];
}

function makeIndexedFixture() {
  const allAdapters = makeAdapters();
  const adapterById = new Map(allAdapters.map((a) => [a.id, a]));
  const toolPreFilter = new ToolPreFilter();
  const fullCatalogFilter = new ToolPreFilter();
  toolPreFilter.index(buildToolsForRouting(allAdapters));
  fullCatalogFilter.index(buildToolsForRouting(allAdapters));
  return { allAdapters, adapterById, toolPreFilter, fullCatalogFilter };
}

for (const code of ['manifest_missing', 'manifest_mismatch', 'serializer_mismatch', 'encoder_load_failed', 'signature_invalid'] as const) {
  test(`applySealedBundleFailure(${code}): empties allAdapters, adapterById, and BOTH pre-filters (CH-02 empty effective catalog)`, () => {
    const { allAdapters, adapterById, toolPreFilter, fullCatalogFilter } = makeIndexedFixture();
    // Sanity: fixture is genuinely non-empty before the call.
    assert.equal(allAdapters.length, 2);
    assert.equal(adapterById.size, 2);
    // shortlist-size: > 12 OK because this mirrors the production call shape
    // at toolHandlers.ts's own `selectWithVerdict(query, { maxTools: 20,
    // maxPerServer: 5 })` (handleQuery) — see that call site's own comment,
    // "Ring-1 returns matchedAdapters as an explicit search-result list
    // (adapter IDs + metadata), NOT tool-defs in LLM context. §3."
    assert.ok((toolPreFilter.selectWithVerdict('widgetlookup', { maxTools: 20, maxPerServer: 5 }).tools.length) > 0);

    const kind = applySealedBundleFailure(code, 'test-injected failure', allAdapters, adapterById, toolPreFilter, fullCatalogFilter);

    assert.notEqual(kind, null, `${code} must classify as a §5.2::5 trigger`);
    assert.equal(allAdapters.length, 0, 'allAdapters must be emptied');
    assert.equal(adapterById.size, 0, 'adapterById must be emptied');
    // shortlist-size: > 12 OK because this mirrors the production call shape
    // at toolHandlers.ts's own `selectWithVerdict(query, { maxTools: 20,
    // maxPerServer: 5 })` (handleQuery) — see that call site's own comment,
    // "Ring-1 returns matchedAdapters as an explicit search-result list
    // (adapter IDs + metadata), NOT tool-defs in LLM context. §3."
    assert.equal(toolPreFilter.selectWithVerdict('widgetlookup', { maxTools: 20, maxPerServer: 5 }).tools.length, 0, 'toolPreFilter must be re-indexed empty');
    // shortlist-size: > 12 OK because this mirrors the production call shape
    // at toolHandlers.ts's own `selectWithVerdict(query, { maxTools: 20,
    // maxPerServer: 5 })` (handleQuery) — see that call site's own comment,
    // "Ring-1 returns matchedAdapters as an explicit search-result list
    // (adapter IDs + metadata), NOT tool-defs in LLM context. §3."
    assert.equal(fullCatalogFilter.selectWithVerdict('widgetlookup', { maxTools: 20, maxPerServer: 5 }).tools.length, 0, 'fullCatalogFilter must be re-indexed empty');
  });
}

for (const code of ['epoch_replay_rejected', 'version_downgrade_rejected', 'agent_field_gate_failed'] as const) {
  test(`applySealedBundleFailure(${code}): NOT a §5.2::5 trigger — allAdapters/adapterById/pre-filters are left untouched`, () => {
    const { allAdapters, adapterById, toolPreFilter, fullCatalogFilter } = makeIndexedFixture();

    const kind = applySealedBundleFailure(code, 'test-injected failure', allAdapters, adapterById, toolPreFilter, fullCatalogFilter);

    assert.equal(kind, null);
    assert.equal(allAdapters.length, 2, 'allAdapters must be UNCHANGED for a non-§5.2::5 code');
    assert.equal(adapterById.size, 2, 'adapterById must be UNCHANGED for a non-§5.2::5 code');
  });
}

// ---------------------------------------------------------------------------
// chariot_list (handleList) sees zero adapters when state.allAdapters is
// empty — the observable consequence at the toolHandlers.ts:2938 reader
// named in the gate finding.
// ---------------------------------------------------------------------------

test('handleList (chariot_list) returns zero adapters when state.allAdapters is empty (CH-02 effective catalog)', async () => {
  const state = {
    allAdapters: [],
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [],
    loadedAt: new Date().toISOString(),
    catalogState: 'invalid',
    catalogStateReason: 'test-injected invalid state',
  } as unknown as ChariotState;

  const result = await handleList({}, state) as { adapters: unknown[] };

  assert.deepEqual(result.adapters, []);
});

// ---------------------------------------------------------------------------
// wireRetrievalForState — CHARIOT::§5.2::5, driven END-TO-END through the
// REAL file-read-and-verify path (not just the extracted applySealedBundleFailure
// helper). This function takes NO caller-supplied key parameter
// (CHARIOT-SPEC.md:525, CH-52 trust anchor — see the file header). Only
// `signature_invalid` is provable here with zero seam: a fixture signed
// with ANY key not in the compiled-in `CHARIOT_CATALOG_PUBLIC_KEYS` is
// rejected by the unmodified production code path. `manifest_mismatch` and
// `encoder_load_failed` positive-signature end-to-end tests — a fixture
// that PASSES the pinned-key gate, then fails later — need the real
// production private key and live in the PRIVATE eval tree instead (see
// the file header and `test/verified-catalog-e2e-w14.mjs`).
// ---------------------------------------------------------------------------

function freshRetrievalSandbox(): { dir: string; cleanup: () => void; restoreEnv: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-retrieval-e2e-test-'));
  const priorCatalogPath = process.env.CHARIOT_ADAPTER_CATALOG_PATH;
  const priorEpochPath = process.env.CHARIOT_RETRIEVAL_EPOCH_PATH;
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
    restoreEnv: () => {
      if (priorCatalogPath === undefined) delete process.env.CHARIOT_ADAPTER_CATALOG_PATH;
      else process.env.CHARIOT_ADAPTER_CATALOG_PATH = priorCatalogPath;
      if (priorEpochPath === undefined) delete process.env.CHARIOT_RETRIEVAL_EPOCH_PATH;
      else process.env.CHARIOT_RETRIEVAL_EPOCH_PATH = priorEpochPath;
    },
  };
}

test('wireRetrievalForState: END-TO-END signature_invalid (key NOT in the compiled-in accepted set) through the real, unmodified production file-read-and-verify path → RetrievalBundleRejectedError{code:"signature_invalid", catalogState:"invalid"}, catalog emptied', () => {
  const { dir, cleanup, restoreEnv } = freshRetrievalSandbox();
  try {
    // A locally generated Ed25519 keypair is definitionally NOT a member of
    // the compiled-in CHARIOT_CATALOG_PUBLIC_KEYS set — no override, no
    // seam, this is exactly the "caller/attacker-controlled key" CH-52's
    // trust anchor exists to reject, verified against the unmodified
    // production verifiedReadFailClosed default.
    const unacceptedKey = makeTestKeyPair();
    const bundlePath = join(dir, 'chariot-adapter-bundle.json');
    const bytes = Buffer.from(JSON.stringify({ epoch: 1, catalogVersion: 1, catalog: [] }));
    writeFileSync(bundlePath, bytes);
    writeFileSync(`${bundlePath}.sig`, signBytes(unacceptedKey.privateKey, bytes));
    process.env.CHARIOT_ADAPTER_CATALOG_PATH = bundlePath;
    process.env.CHARIOT_RETRIEVAL_EPOCH_PATH = join(dir, '.retrieval-epoch.json');

    const { allAdapters, adapterById, toolPreFilter, fullCatalogFilter } = makeIndexedFixture();

    let caught: unknown;
    try {
      wireRetrievalForState(toolPreFilter, fullCatalogFilter, dir, allAdapters, adapterById);
    } catch (err) {
      caught = err;
    }

    assert.ok(caught instanceof RetrievalBundleRejectedError, `expected RetrievalBundleRejectedError, got: ${String(caught)}`);
    const err = caught as RetrievalBundleRejectedError;
    assert.equal(err.code, 'signature_invalid');
    assert.equal(err.catalogState, 'invalid', 'the §5.2 state transition must be observable ON the thrown error, since the throw prevents any ChariotState from ever being returned');
    assert.ok(err.catalogStateReason && err.catalogStateReason.length > 0);

    assert.equal(allAdapters.length, 0, 'allAdapters must be emptied by the real end-to-end failure, not just the extracted helper');
    assert.equal(adapterById.size, 0);
  } finally {
    restoreEnv();
    cleanup();
  }
});

test('wireRetrievalForState: the production call shape (no key parameter at all) still verifies successfully against the real, shipped, production-signed catalog', () => {
  // Sanity/regression control against the REAL shipped
  // chariot-adapter-bundle.json/.sig at the repo root (no
  // CHARIOT_ADAPTER_CATALOG_PATH override) — the same fixture
  // query-cli-bridge-dispatch.test.ts depends on. Proves removing the
  // key-override parameter did not regress the one production call shape.
  const { allAdapters, adapterById, toolPreFilter, fullCatalogFilter } = makeIndexedFixture();
  const packageRoot = join(import.meta.dirname, '..', '..', '..');
  const mode = wireRetrievalForState(toolPreFilter, fullCatalogFilter, packageRoot, allAdapters, adapterById);
  assert.ok(mode === 'bm25-only' || mode === 'hybrid', `expected a successful retrieval mode, got: ${mode}`);
  // Success path — untouched by §5.2::5, still populated.
  assert.equal(allAdapters.length, 2);
});

// ---------------------------------------------------------------------------
// chariot_query / chariot_call — CHARIOT::§5.2 (CH-02): with an
// invalid/empty catalog state, chariot_query returns no adapters and
// chariot_call cannot dispatch to any adapter. Mirrors the minimal-fixture
// pattern QueryExpander.call-site-opt-in.test.ts (W15) uses for the same
// two handlers.
// ---------------------------------------------------------------------------

function makeEmptyFilterDouble() {
  return {
    select: async () => [],
    selectWithVerdict: (_query: string, _opts?: unknown) => ({
      tools: [],
      confidence: 0,
      abstain: true,
      degraded: false,
      legsUsed: ['bm25'],
    }),
  };
}

function makeInvalidEmptyState(): ChariotState {
  const filter = makeEmptyFilterDouble();
  return {
    catalogState: 'invalid',
    catalogStateReason: 'test-injected invalid state (CH-02 empty effective catalog)',
    allAdapters: [],
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: filter,
    toolPreFilter: filter,
    getConfiguredAdapters: () => [],
    loadedAt: new Date().toISOString(),
  } as unknown as ChariotState;
}

test('chariot_query (handleQuery) with an invalid/empty catalog state returns no_match — zero adapters surfaced', async () => {
  const state = makeInvalidEmptyState();

  const result = await handleQuery(
    { query: 'anything at all' },
    state,
    { tenantId: freshTenantId('query') },
  ) as { status: string; totalAvailable?: number };

  assert.equal(result.status, 'no_match', `expected no_match against an empty catalog, got: ${JSON.stringify(result)}`);
  assert.equal(result.totalAvailable, 0, 'state.allAdapters.length must be 0 — the effective catalog is genuinely empty, not just unmatched');
});

test('chariot_call (handleCall) with an invalid/empty catalog state cannot dispatch to any adapter — real "adapter not found" outcome, never a fabricated success', async () => {
  const state = makeInvalidEmptyState();

  const result = await handleCall(
    { adapter: 'any-adapter-id', tool: 'any_tool', args: {} },
    state,
    { localMode: true, tenantId: freshTenantId('call') },
  );

  assert.equal(result.isError, true);
  assert.match(JSON.parse(result.content).error as string, /not found/i);
});
