/**
 * CHARIOT::§5.2::1-5 (CHARIOT-SPEC.md:363-373, CH-02 at :245) — the
 * catalog-wide `AdapterCatalog.state`/`stateReason` trust state machine.
 *
 * Failure classes enumerated from the clause and closed here:
 *   - signature-valid + fresh → `verified`, full catalog served
 *   - signature-valid + age > 7 days → `stale`, full catalog still served
 *   - signature MISSING (no .sig file) → `invalid`, empty effective
 *     catalog, `load()` resolves WITHOUT throwing (the defect this unit
 *     fixes: pre-fix this threw at startup)
 *   - signature MISMATCHED (tampered bytes) → `invalid`, empty effective
 *     catalog, no throw
 *   - state is recomputed on every `load()` call (not sticky from a prior
 *     load)
 *   - `markInvalidFromSealedBundleFailure` (CHARIOT::§5.2::5, the 4.0.0
 *     retrieval-manifest/encoder/sealed-bundle triggers) forces `invalid`
 *     and empties the effective catalog regardless of the adapter
 *     catalog's own signature having verified
 *
 * Gate finding (this revision, CHARIOT-SPEC.md:383 §5.4 amended / :523
 * §5.7 trust anchor, ruling accepted 2026-09-03): `publicKeyPem` is now an
 * ADDITIONAL candidate key, intersected against the compiled-in
 * `CHARIOT_CATALOG_PUBLIC_KEYS` rotation set (`intersectWithRotationSet`,
 * `verifyCatalogSignature.ts`) — never a substitute for it. A test-only
 * generated keypair passed as `publicKeyPem` therefore no longer produces
 * a signature that can ever verify (it intersects to zero rotation-set
 * members), so it is no longer a valid way to drive the `verified`/`stale`
 * states hermetically. Every `verified`/`stale` case below is rewritten to
 * use the documented dev/test opt-out, `verifySignature: false`
 * (`CatalogSourceConfig.verifySignature`, CHARIOT-SPEC.md §5.5) — state is
 * then computed from freshness (`materializedAt`) alone, with no
 * signature check attempted at all, which is exactly what that opt-out is
 * for. `invalid`-via-signature-mismatch is still driven by a real
 * mismatch: a fixture signed with a synthetic key, verified against the
 * DEFAULT (unmodified) `CHARIOT_CATALOG_PUBLIC_KEYS` — no test can
 * possess the real production private key, so no test can produce a
 * fixture that verifies `true`; the mismatch path needs no such fixture,
 * only one that is GUARANTEED not to match. One new test (§5.4) proves a
 * caller-supplied key outside the rotation set — not merely unsigned or
 * mismatched — lands in `invalid` with the dedicated
 * `accepted-keys-outside-rotation-set` reason, distinct from a generic
 * signature mismatch.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { AdapterCatalog } from './AdapterCatalog.js';

function makeTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
}

function signBytes(privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'], bytes: Buffer): string {
  return cryptoSign(null, bytes, privateKey).toString('base64');
}

function writeCatalogFixture(
  dir: string,
  envelope: Record<string, unknown>,
  opts: { sign?: ReturnType<typeof generateKeyPairSync>['privateKey']; sigOverride?: string; omitSig?: boolean } = {},
): string {
  const catalogPath = join(dir, 'adapter-catalog.json');
  const bytes = Buffer.from(JSON.stringify(envelope));
  writeFileSync(catalogPath, bytes);
  if (!opts.omitSig) {
    const sigB64 = opts.sigOverride ?? (opts.sign ? signBytes(opts.sign, bytes) : '');
    writeFileSync(`${catalogPath}.sig`, sigB64);
  }
  return catalogPath;
}

function freshSandbox(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-adaptercatalog-test-'));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::1 — signature valid + fresh → verified, full catalog
// Driven via the documented `verifySignature: false` dev/test opt-out
// (CHARIOT-SPEC.md §5.5) — state computed from freshness ALONE, no
// signature attempted, no key of any kind needed.
// ---------------------------------------------------------------------------

test('AdapterCatalog: verifySignature:false + fresh materializedAt → state verified, full catalog effective', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: Date.now(),
      catalog: [{ name: 'demo-adapter', toolNames: ['t1'], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      verifySignature: false,
      epochPath: join(dir, '.epoch.json'),
    });

    await catalog.load();

    assert.equal(catalog.state, 'verified');
    assert.equal(catalog.entries().length, 1);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::2 — signature valid + age > 7 days → stale, full catalog
// ---------------------------------------------------------------------------

test('AdapterCatalog: verifySignature:false + age > 7 days → state stale, catalog STILL fully effective', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: eightDaysAgo,
      catalog: [{ name: 'demo-adapter', toolNames: ['t1'], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      verifySignature: false,
      epochPath: join(dir, '.epoch.json'),
    });

    await catalog.load();

    assert.equal(catalog.state, 'stale');
    // §5.2 table: stale still serves the FULL catalog, not a truncated one.
    assert.equal(catalog.entries().length, 1);
  } finally {
    cleanup();
  }
});

test('AdapterCatalog: exactly 7 days old (boundary, injected clock) → verified, NOT stale', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const FIXED_NOW = 1_800_000_000_000; // arbitrary fixed instant, not real wall-clock time
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: FIXED_NOW - SEVEN_DAYS_MS,
      catalog: [{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      verifySignature: false,
      epochPath: join(dir, '.epoch.json'),
      now: () => FIXED_NOW,
    });

    await catalog.load();

    assert.equal(catalog.state, 'verified');
    assert.equal(catalog.entries().length, 1);
  } finally {
    cleanup();
  }
});

test('AdapterCatalog: 7 days + 1ms old (boundary, injected clock) → stale, NOT verified', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const FIXED_NOW = 1_800_000_000_000; // same fixed instant as the companion boundary test above
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: FIXED_NOW - (SEVEN_DAYS_MS + 1),
      catalog: [{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      verifySignature: false,
      epochPath: join(dir, '.epoch.json'),
      now: () => FIXED_NOW,
    });

    await catalog.load();

    assert.equal(catalog.state, 'stale');
    // §5.2 table: stale still serves the FULL catalog.
    assert.equal(catalog.entries().length, 1);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::3 (CH-02) — signature MISSING or MISMATCHED → invalid,
// empty effective catalog, NO THROW at load (the defect this unit fixes).
// Verification is ENABLED (default) here — these two need a real
// signature-verification ATTEMPT, unlike the verified/stale cases above.
// ---------------------------------------------------------------------------

test('AdapterCatalog: MISSING .sig file → state invalid, empty catalog, load() does NOT throw', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: Date.now(),
      catalog: [{ name: 'demo-adapter', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    // Default verification (no publicKeyPem override, no verifySignature
    // override) — this test only needs the .sig-missing code path, which
    // is independent of which keys are accepted.
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      epochPath: join(dir, '.epoch.json'),
    });

    // Pre-4.0.0 behavior: this threw and crashed startup. Fixed behavior:
    // resolves normally with an empty, invalid-state catalog.
    await assert.doesNotReject(() => catalog.load());

    assert.equal(catalog.state, 'invalid');
    assert.equal(catalog.entries().length, 0);
  } finally {
    cleanup();
  }
});

test('AdapterCatalog: MISMATCHED signature (real mismatch against the DEFAULT compiled-in key set) → state invalid, empty catalog, load() does NOT throw', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const attackerKeys = makeTestKeyPair();
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: Date.now(),
      catalog: [{ name: 'demo-adapter', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    // Signed with a synthetic key that is definitionally NOT a member of
    // CHARIOT_CATALOG_PUBLIC_KEYS — no publicKeyPem override, so the
    // DEFAULT (unmodified) compiled-in set is what this is verified
    // against. Guaranteed not to match; no real production key needed to
    // prove a mismatch, only to prove a match.
    const catalogPath = writeCatalogFixture(dir, envelope, { sign: attackerKeys.privateKey });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      epochPath: join(dir, '.epoch.json'),
    });

    await assert.doesNotReject(() => catalog.load());

    assert.equal(catalog.state, 'invalid');
    assert.equal(catalog.entries().length, 0);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// CHARIOT-SPEC.md:383 (§5.4, amended) / :523 (§5.7 trust anchor) — a
// caller-supplied publicKeyPem that is NOT a member of the compiled-in
// rotation set lands in `invalid` with the DEDICATED
// `accepted-keys-outside-rotation-set` reason — distinct from (and
// diagnosed before ever attempting) the generic signature-mismatch path
// above.
// ---------------------------------------------------------------------------

test('AdapterCatalog: publicKeyPem outside the compiled-in CHARIOT_CATALOG_PUBLIC_KEYS rotation set → state invalid, reason accepted-keys-outside-rotation-set (never a generic signature mismatch)', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const outsideKeys = makeTestKeyPair();
    const envelope = {
      epoch: 1,
      catalogVersion: 1,
      materializedAt: Date.now(),
      catalog: [{ name: 'demo-adapter', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }],
    };
    // Even a genuinely self-signed, untampered fixture must be rejected:
    // the trust-anchor gate runs before any signature bytes are compared.
    const catalogPath = writeCatalogFixture(dir, envelope, { sign: outsideKeys.privateKey });
    const catalog = new AdapterCatalog({
      source: 'bundle',
      catalogPath,
      publicKeyPem: outsideKeys.publicKeyPem,
      epochPath: join(dir, '.epoch.json'),
    });

    await assert.doesNotReject(() => catalog.load());

    assert.equal(catalog.state, 'invalid');
    assert.equal(catalog.stateReason, 'accepted-keys-outside-rotation-set');
    assert.equal(catalog.entries().length, 0);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::4 — state recomputed on every load, not sticky. Proven
// here via `markInvalidFromSealedBundleFailure` (a direct, hermetic state
// mutation requiring no key at all) forcing `invalid`, followed by a
// verifySignature:false load — which must overwrite that forced `invalid`
// with `verified`, proving `load()` recomputes rather than reading a
// sticky prior value.
// ---------------------------------------------------------------------------

test('AdapterCatalog: state is recomputed on every load() — a later load clears a prior (forced) invalid state', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const catalogPath = join(dir, 'adapter-catalog.json');
    const epochPath = join(dir, '.epoch.json');
    const catalog = new AdapterCatalog({ source: 'bundle', catalogPath, verifySignature: false, epochPath });

    // First: force invalid directly — no load(), no key, no signature.
    catalog.markInvalidFromSealedBundleFailure('encoder_mismatch', 'test-injected failure');
    assert.equal(catalog.state, 'invalid');

    // Second: a normal verifySignature:false load with a fresh
    // materializedAt. If `load()` read a sticky prior state instead of
    // recomputing, this would still read `invalid`.
    const envelope2 = { epoch: 2, catalogVersion: 1, materializedAt: Date.now(), catalog: [{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }] };
    writeCatalogFixture(dir, envelope2, { omitSig: true });
    await catalog.load();

    assert.equal(catalog.state, 'verified');
    assert.equal(catalog.entries().length, 1);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::5 — 4.0.0: retrieval-manifest mismatch / encoder
// mismatch / sealed-bundle signature failure ALSO produce invalid.
// ---------------------------------------------------------------------------

test('AdapterCatalog.markInvalidFromSealedBundleFailure: sealed-bundle signature failure forces invalid + empty catalog', async () => {
  const { dir, cleanup } = freshSandbox();
  try {
    const envelope = { epoch: 1, catalogVersion: 1, materializedAt: Date.now(), catalog: [{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' }] };
    const catalogPath = writeCatalogFixture(dir, envelope, { omitSig: true });
    const catalog = new AdapterCatalog({ source: 'bundle', catalogPath, verifySignature: false, epochPath: join(dir, '.epoch.json') });
    await catalog.load();
    assert.equal(catalog.state, 'verified');
    assert.equal(catalog.entries().length, 1);

    catalog.markInvalidFromSealedBundleFailure('sealed_bundle_signature_failed', 'test-injected failure');

    assert.equal(catalog.state, 'invalid');
    assert.equal(catalog.entries().length, 0);
  } finally {
    cleanup();
  }
});

test('AdapterCatalog.markInvalidFromSealedBundleFailure: retrieval-manifest mismatch and encoder mismatch both force invalid', () => {
  const catalogA = new AdapterCatalog({ source: 'bundle', verifySignature: false });
  catalogA.setEntries([{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' } as never]);
  catalogA.markInvalidFromSealedBundleFailure('retrieval_manifest_mismatch', 'manifest mismatch');
  assert.equal(catalogA.state, 'invalid');
  assert.equal(catalogA.entries().length, 0);

  const catalogB = new AdapterCatalog({ source: 'bundle', verifySignature: false });
  catalogB.setEntries([{ name: 'a', toolNames: [], keywords: [], category: 'other', author: 'x', version: '1.0.0' } as never]);
  catalogB.markInvalidFromSealedBundleFailure('encoder_mismatch', 'encoder mismatch');
  assert.equal(catalogB.state, 'invalid');
  assert.equal(catalogB.entries().length, 0);
});
