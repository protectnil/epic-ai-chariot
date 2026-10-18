/**
 * FPS §7.2.6 consumer lockstep — `verifyAndReadArtifact`'s single
 * version-selected branch for `chariot-adapter-bundle.json`.
 *
 * Governing clause (FPS §7.2.6, FABRIQUE-PRODUCT-SPEC-MAY-2026.md:712,
 * verbatim): "Adopting §7.2.3 changes the signed object from the prior
 * full-bundle-bytes model; the manifest MUST carry `signingPayloadVersion`,
 * and the consumer selects its verify path by that version (old full-bytes
 * vs new compact-payload), gated on the monotonic `epoch` anti-rollback ...
 * a single version-selected branch in the one Chariot artifact — NOT a
 * per-backend or per-cloud fork."
 *
 * Governing clause (FPS §7.2.2, :701-704) and (FPS §7.2.3, :706) — see
 * `merkle.ts` / `canonicalize.ts` / `verifyCatalogSignature.ts` module
 * docstrings for the exact quoted bytes this recomputation implements.
 *
 * TEST-COVERAGE LIMITATION (stated, not hidden — same pattern as
 * `verifyCatalogSignature.tamper-rejection.test.ts`'s own documented
 * limitation): every REJECTION path below is exercised through the real
 * exported `verifyAndReadArtifact`/`resolveCompactSigningPayload` API and
 * needs no real signing key, because each one fails BEFORE any
 * `cryptoVerify` attempt. The ONE property this file does NOT exercise
 * end-to-end is "a genuinely valid compact-payload signature is ACCEPTED"
 * — that requires signing with a key in the compiled-in
 * `CHARIOT_CATALOG_PUBLIC_KEYS` rotation set (currently the KMS-custodied
 * production key only; `chariot-catalog-public.ts`'s own doc comment: "the
 * production key ... is the only accepted key"), which this test suite
 * must never possess. Passing a throwaway key as `acceptedKeys` to make
 * `cryptoVerify` exercisable is EXACTLY the caller-supplied-key
 * substitution `verifyAndReadArtifact`'s trust-anchor gate exists to
 * forbid (CHARIOT-SPEC.md:525) — see the tamper-rejection test file's own
 * "Gate finding" note for the precedent. That positive case needs the real
 * production private key or the separately-gated `AdapterCatalog`
 * `publicKeyPem` override pipeline and belongs in the private eval tree,
 * per the same precedent.
 *
 * Run (after tsc): node --test dist/engine/keys/verifyCatalogSignature.compact-payload.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  verifyAndReadArtifact,
  resolveCompactSigningPayload,
  checkCompactPayloadByteCap,
  computeManifestHash,
} from './verifyCatalogSignature.js';
import { CHARIOT_CATALOG_PUBLIC_KEYS, type ChariotCatalogPublicKey } from './chariot-catalog-public.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
// Hand-derived FPS §7.2.2 root for the 2-leaf set
// [{catalog,adapter-a,HASH_A}, {catalog,adapter-b,HASH_B}] — derivation:
// dA = canonicalize({array:"catalog",id:"adapter-a",publishHash:HASH_A})
// dB = canonicalize({array:"catalog",id:"adapter-b",publishHash:HASH_B})
// (sorted order is already catalog/adapter-a < catalog/adapter-b, byte-wise)
// leafA = SHA256(0x00 || dA), leafB = SHA256(0x00 || dB)
// root  = SHA256(0x01 || leafA || leafB)  (n=2, k=1, no last-node dup)
// computed independently with node:crypto and cross-checked against
// computeMerkleRoot() itself producing the identical value.
const TWO_LEAF_ROOT = 'b745cffaca41260dda3f7c992e9ce58175d20e1330233d3f8e6580811d266cb2';

function twoLeafBundle(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    epoch: 1700000000000,
    catalogVersion: 3,
    manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 1 },
    catalog: [
      { id: 'adapter-a', name: 'adapter-a', metadata: { publishHash: HASH_A } },
      { id: 'adapter-b', name: 'adapter-b', metadata: { publishHash: HASH_B } },
    ],
    registry: [],
    ...overrides,
  };
}

/* ---------------------------------------------------------------------- *
 * resolveCompactSigningPayload — direct unit coverage, no file I/O.
 * ---------------------------------------------------------------------- */

test('§7.2.6: manifest.signingPayloadVersion absent -> legacy (no manifest object at all)', () => {
  const bytes = Buffer.from(JSON.stringify({ catalog: [], registry: [] }), 'utf-8');
  const outcome = resolveCompactSigningPayload(bytes);
  assert.equal(outcome.kind, 'legacy');
});

test('§7.2.6: manifest.signingPayloadVersion absent -> legacy (manifest object present, field just missing)', () => {
  const bundle = twoLeafBundle({ manifest: { merkleRoot: TWO_LEAF_ROOT } });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'legacy');
});

test('§7.2.6: unparseable JSON -> legacy (falls through to full-bytes verify, not a distinct failure)', () => {
  const outcome = resolveCompactSigningPayload(Buffer.from('{not json', 'utf-8'));
  assert.equal(outcome.kind, 'legacy');
});

test('§7.2.6: non-object JSON root (array) -> legacy', () => {
  const outcome = resolveCompactSigningPayload(Buffer.from('[1,2,3]', 'utf-8'));
  assert.equal(outcome.kind, 'legacy');
});

for (const badVersion of [0, 2, '1', 1.5, null, true, [1]]) {
  test(`§7.2.6: manifest.signingPayloadVersion=${JSON.stringify(badVersion)} -> invalid-version (distinct from absent)`, () => {
    const bundle = twoLeafBundle({ manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: badVersion } });
    const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
    assert.equal(outcome.kind, 'invalid-version');
  });
}

test('§7.2.6: signingPayloadVersion=1, well-formed 2-leaf bundle -> compact-ready with the exact FPS §7.2.3 payload', () => {
  const bundle = twoLeafBundle();
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'compact-ready');
  if (outcome.kind === 'compact-ready') {
    const parsed = JSON.parse(outcome.payloadBytes.toString('utf-8')) as Record<string, unknown>;
    assert.equal(parsed.merkleRoot, TWO_LEAF_ROOT);
    assert.equal(parsed.epoch, 1700000000000);
    assert.equal(parsed.catalogVersion, 3);
    assert.match(parsed.manifestHash as string, /^[0-9a-f]{64}$/);
    // manifestHash = sha256(canonicalize(manifest)) per FPS §7.2.3 — the
    // FULL shipped manifest object as parsed, {merkleRoot,
    // signingPayloadVersion} here since that is the whole manifest this
    // fixture carries. Cross-check independently with node:crypto.
    const expected = createHash('sha256')
      .update(`{"merkleRoot":"${TWO_LEAF_ROOT}","signingPayloadVersion":1}`, 'utf-8')
      .digest('hex');
    assert.equal(parsed.manifestHash, expected);
  }
});

test('§7.2.3: manifest carries an EXTRA field (tamperAllowlistVersion) -> manifestHash CHANGES, proving the full manifest object is covered', () => {
  // FPS §7.2.3 verbatim: "manifestHash = sha256(canonicalize(manifest))" —
  // `manifest` is the shipped bundle's manifest object AS SERIALIZED, every
  // field it carries. Hashing only a {merkleRoot, signingPayloadVersion}
  // subset (a prior producer divergence, being fixed in the paired
  // producer change) would let an attacker or a corrupt release change
  // `tamperAllowlistVersion` without invalidating the signature — this
  // test proves that field IS covered.
  const bundleNoExtra = twoLeafBundle();
  const bundleWithExtra = twoLeafBundle({
    manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 1, tamperAllowlistVersion: 7 },
  });
  const outcomeNoExtra = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundleNoExtra), 'utf-8'));
  const outcomeWithExtra = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundleWithExtra), 'utf-8'));
  assert.equal(outcomeNoExtra.kind, 'compact-ready');
  assert.equal(outcomeWithExtra.kind, 'compact-ready');
  if (outcomeNoExtra.kind === 'compact-ready' && outcomeWithExtra.kind === 'compact-ready') {
    const parsedNoExtra = JSON.parse(outcomeNoExtra.payloadBytes.toString('utf-8')) as Record<string, unknown>;
    const parsedWithExtra = JSON.parse(outcomeWithExtra.payloadBytes.toString('utf-8')) as Record<string, unknown>;
    assert.notEqual(
      parsedNoExtra.manifestHash,
      parsedWithExtra.manifestHash,
      'an extra manifest field MUST change manifestHash — canonicalize(manifest) covers the full object',
    );
    // Hand-derived (see the module docstring's derivation): sha256 of
    // canonicalize({merkleRoot, signingPayloadVersion, tamperAllowlistVersion})
    // with keys sorted lexicographically (merkleRoot < signingPayloadVersion
    // < tamperAllowlistVersion), independently cross-checked with
    // node:crypto here.
    const expectedWithExtra = createHash('sha256')
      .update(
        `{"merkleRoot":"${TWO_LEAF_ROOT}","signingPayloadVersion":1,"tamperAllowlistVersion":7}`,
        'utf-8',
      )
      .digest('hex');
    assert.equal(parsedWithExtra.manifestHash, expectedWithExtra);
  }
});

test('§7.2.3: literal manifestHash pin for a fixed 3-field manifest (regression guard on the exact hashed shape)', () => {
  // Hand-derived, independent of the implementation: canonicalize sorts
  // keys, so canonicalize({merkleRoot, signingPayloadVersion,
  // tamperAllowlistVersion}) = the literal string below regardless of
  // source object key order; sha256 of that literal string is pinned here.
  const bundle = twoLeafBundle({
    manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 1, tamperAllowlistVersion: 7 },
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'compact-ready');
  if (outcome.kind === 'compact-ready') {
    const parsed = JSON.parse(outcome.payloadBytes.toString('utf-8')) as Record<string, unknown>;
    assert.equal(
      parsed.manifestHash,
      '3925207ba07e53c7a872590e2f5a7ce47c100df203295a11f0fe9abdb6f583c4',
    );
  }
});

test('§7.2.3: computeManifestHash literal pin, isolated fixture manifest { merkleRoot: "a".repeat(64), signingPayloadVersion: 1, tamperAllowlistVersion: 7 }', () => {
  // Hand-derived independently of resolveCompactSigningPayload (this
  // fixture's merkleRoot is NOT a real recomputed root of any leaf set,
  // so it could never reach 'compact-ready' through the full pipeline —
  // computeManifestHash is tested directly, in isolation, exactly for
  // this reason). Derivation: canonicalize sorts keys, so
  // canonicalize({merkleRoot:"aaaa...64", signingPayloadVersion:1,
  // tamperAllowlistVersion:7}) =
  //   {"merkleRoot":"aaaa...64","signingPayloadVersion":1,"tamperAllowlistVersion":7}
  // sha256 of that literal string, computed independently with a
  // standalone node:crypto one-liner before being pasted here.
  const fixtureManifest = {
    merkleRoot: 'a'.repeat(64),
    signingPayloadVersion: 1,
    tamperAllowlistVersion: 7,
  };
  const expectedCanonical =
    `{"merkleRoot":"${'a'.repeat(64)}","signingPayloadVersion":1,"tamperAllowlistVersion":7}`;
  const expectedHash = createHash('sha256').update(expectedCanonical, 'utf-8').digest('hex');
  // Pin the LITERAL hex too, not just the cross-check against createHash
  // above — this is the exact value an independent gate computation
  // reproduced from the same clause bytes.
  assert.equal(expectedHash, 'bdad773c171c7fa3b0cc959c746964736f110a238cbbcd8d1f47de651d52e250');
  assert.equal(computeManifestHash(fixtureManifest), expectedHash);
  assert.equal(
    computeManifestHash(fixtureManifest),
    'bdad773c171c7fa3b0cc959c746964736f110a238cbbcd8d1f47de651d52e250',
  );
});

test('§7.2.3: the signed object is fully pinned — exact compact-payload bytes for a fixed fixture, hand-derived (proves what WOULD be signed, even though the signature itself cannot be produced/verified without the production key)', () => {
  const bundle = twoLeafBundle({
    manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 1, tamperAllowlistVersion: 7 },
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'compact-ready');
  if (outcome.kind === 'compact-ready') {
    // Hand-derived literal expected payload string (key-sorted:
    // catalogVersion, epoch, manifestHash, merkleRoot).
    const expectedPayload =
      '{"catalogVersion":3,"epoch":1700000000000,' +
      '"manifestHash":"3925207ba07e53c7a872590e2f5a7ce47c100df203295a11f0fe9abdb6f583c4",' +
      `"merkleRoot":"${TWO_LEAF_ROOT}"}`;
    assert.equal(outcome.payloadBytes.toString('utf-8'), expectedPayload);
  }
});

test('§7.2.2: recomputed merkleRoot != manifest.merkleRoot -> merkle-mismatch (forged/stale root)', () => {
  const bundle = twoLeafBundle({ manifest: { merkleRoot: 'f'.repeat(64), signingPayloadVersion: 1 } });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'merkle-mismatch');
});

test('§7.2.2: a single record byte changed (publishHash tampered) -> merkle-mismatch, root claimed for the ORIGINAL records', () => {
  const bundle = twoLeafBundle({
    catalog: [
      { id: 'adapter-a', name: 'adapter-a', metadata: { publishHash: 'c'.repeat(64) } }, // tampered
      { id: 'adapter-b', name: 'adapter-b', metadata: { publishHash: HASH_B } },
    ],
  }); // manifest.merkleRoot still claims TWO_LEAF_ROOT (computed over the ORIGINAL HASH_A)
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'merkle-mismatch');
});

test('§7.2.1: a catalog[] entry missing metadata.publishHash -> compact-payload-malformed (not silently skipped)', () => {
  const bundle = twoLeafBundle({
    catalog: [
      { id: 'adapter-a', name: 'adapter-a' }, // no metadata at all
      { id: 'adapter-b', name: 'adapter-b', metadata: { publishHash: HASH_B } },
    ],
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'malformed');
});

test('§7.2.1: a catalog[] entry with an empty-string id -> compact-payload-malformed', () => {
  const bundle = twoLeafBundle({
    catalog: [
      { id: '', name: 'adapter-a', metadata: { publishHash: HASH_A } },
      { id: 'adapter-b', name: 'adapter-b', metadata: { publishHash: HASH_B } },
    ],
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'malformed');
});

test('§7.2.2: manifest.merkleRoot not a 64-hex string -> compact-payload-malformed', () => {
  for (const badRoot of ['not-hex', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 12345]) {
    const bundle = twoLeafBundle({ manifest: { merkleRoot: badRoot, signingPayloadVersion: 1 } });
    const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
    assert.equal(outcome.kind, 'malformed', `merkleRoot=${JSON.stringify(badRoot)} must be malformed`);
  }
});

test('§7.2.3: non-integer epoch or catalogVersion -> compact-payload-malformed', () => {
  const badEpoch = resolveCompactSigningPayload(Buffer.from(JSON.stringify(twoLeafBundle({ epoch: 1.5 })), 'utf-8'));
  assert.equal(badEpoch.kind, 'malformed');
  const badCatalogVersion = resolveCompactSigningPayload(
    Buffer.from(JSON.stringify(twoLeafBundle({ catalogVersion: 'v3' })), 'utf-8'),
  );
  assert.equal(badCatalogVersion.kind, 'malformed');
});

test('§7.2.2: empty catalog[] and registry[] -> empty-leaf-set, rejected regardless of merkleRoot/version', () => {
  // H("") is a fixed, computable value — even if an attacker set
  // manifest.merkleRoot to exactly that value, the bundle is still
  // rejected: a zero-record bundle is a fail-closed release error, not
  // merely a root-mismatch.
  const emptyRoot = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
  const bundle = twoLeafBundle({ catalog: [], registry: [], manifest: { merkleRoot: emptyRoot, signingPayloadVersion: 1 } });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'empty-leaf-set');
});

test('§5.6: bundle.registry absent (not even an empty array) -> compact-payload-malformed, not silently treated as empty', () => {
  const bundle = twoLeafBundle();
  delete bundle.registry;
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'malformed');
});

test('§7.2.3: registry[] leaves participate in the same leaf set as catalog[] (3-leaf cross-array root)', () => {
  // Hand-derived (see derivation script referenced in the PR): sorted order
  // is [catalog/adapter-a, catalog/adapter-b, registry/adapter-a] (array
  // name sorts "catalog" < "registry" byte-wise); n=3, k=2, so the tree is
  // interior(interior(leafA,leafB), leafRegistryA).
  const HASH_C = 'c'.repeat(64);
  const THREE_LEAF_ROOT = 'f41700df905486dc925b6acdaa47b19141a403da189a90e80d335a9459462163';
  const bundle = twoLeafBundle({
    registry: [{ id: 'adapter-a', name: 'adapter-a', metadata: { publishHash: HASH_C } }],
    manifest: { merkleRoot: THREE_LEAF_ROOT, signingPayloadVersion: 1 },
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'compact-ready');
});

test('§7.2.3: the id "adapter-a" appearing in BOTH catalog[] and registry[] is TWO distinct leaves, not deduplicated', () => {
  // Same fixture as the cross-array test above proves this structurally:
  // catalog/adapter-a and registry/adapter-a are different (array, id)
  // tuples and both contribute a leaf — the 3-leaf root above already
  // depends on this (a dedup would produce a 2-leaf tree and a different
  // root that would NOT match the 2-leaf TWO_LEAF_ROOT below).
  const HASH_C = 'c'.repeat(64);
  const dedupedTwoLeafBundle = twoLeafBundle({
    registry: [{ id: 'adapter-a', name: 'adapter-a', metadata: { publishHash: HASH_C } }],
    // Deliberately claims the 2-leaf root — WRONG for this 3-leaf set,
    // which is exactly the point: if (array,id) dedup collapsed this back
    // to 2 leaves, this root would incorrectly match.
    manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 1 },
  });
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(dedupedTwoLeafBundle), 'utf-8'));
  assert.equal(outcome.kind, 'merkle-mismatch', 'the 3-leaf root must not equal the 2-leaf root — no dedup by id alone');
});

/* ---------------------------------------------------------------------- *
 * MAX_COMPACT_SIGNING_PAYLOAD_BYTES — through the validated bundle field
 * surface (manifestHash/merkleRoot always exactly 64 hex chars,
 * epoch/catalogVersion JS integers whose JSON form never exceeds a few
 * dozen characters) a real FPS §7.2.3 payload is bounded under ~250 bytes
 * by construction (CH-52: "which is ≤4096B by construction ... so there
 * is NO size-based fallback") — `resolveCompactSigningPayload` itself
 * cannot be driven to 'oversize' through a realistic bundle. The cap
 * check is extracted into `checkCompactPayloadByteCap` (a pure function
 * over the already-serialized string) specifically so the REJECTION
 * itself is directly testable with a synthetic string, independent of
 * what a bundle can produce.
 * ---------------------------------------------------------------------- */
test('§7.2.3: checkCompactPayloadByteCap rejects a payload of EXACTLY 4096 bytes ("< 4096", strict)', () => {
  const oversizePayload = 'x'.repeat(4096);
  assert.equal(Buffer.byteLength(oversizePayload, 'utf-8'), 4096, 'fixture precondition: exactly 4096 bytes');
  const result = checkCompactPayloadByteCap(oversizePayload);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'compact-payload-oversize');
    assert.equal(result.detail, '4096/4096');
  }
});

test('§7.2.3: checkCompactPayloadByteCap rejects a payload LARGER than 4096 bytes', () => {
  const oversizePayload = 'x'.repeat(5000);
  assert.equal(Buffer.byteLength(oversizePayload, 'utf-8'), 5000);
  const result = checkCompactPayloadByteCap(oversizePayload);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'compact-payload-oversize');
    assert.equal(result.detail, '5000/4096');
  }
});

test('§7.2.3: checkCompactPayloadByteCap accepts a payload of exactly 4095 bytes (one under the cap)', () => {
  const underCapPayload = 'x'.repeat(4095);
  assert.equal(Buffer.byteLength(underCapPayload, 'utf-8'), 4095, 'fixture precondition: exactly 4095 bytes');
  const result = checkCompactPayloadByteCap(underCapPayload);
  assert.equal(result.ok, true);
});

test('§7.2.3: the compact-payload byte cap constant matches the clause ("< 4096 bytes") end-to-end through resolveCompactSigningPayload', () => {
  // End-to-end sanity check that a realistic well-formed payload sits far
  // under the cap (confirms the cap is not accidentally mis-set to
  // something the normal path would trip) — the REJECTION itself is
  // covered by the three checkCompactPayloadByteCap tests above, since no
  // bundle field combination can drive resolveCompactSigningPayload's
  // serialized payload to 4096+ bytes (see this block's docstring).
  const bundle = twoLeafBundle();
  const outcome = resolveCompactSigningPayload(Buffer.from(JSON.stringify(bundle), 'utf-8'));
  assert.equal(outcome.kind, 'compact-ready');
  if (outcome.kind === 'compact-ready') {
    assert.ok(outcome.payloadBytes.length < 4096);
    assert.ok(outcome.payloadBytes.length < 300, 'a realistic compact payload is under ~250 bytes, not near the cap');
  }
});

/* ---------------------------------------------------------------------- *
 * verifyAndReadArtifact — end-to-end wiring through the real file-read +
 * trust-anchor pipeline. None of these need a valid production signature:
 * each fails before (or at) the same gates a legacy artifact would.
 * ---------------------------------------------------------------------- */

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-compact-payload-test-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function makeThrowawayKey(): ChariotCatalogPublicKey {
  const { publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { id: 'throwaway-test-key', pem };
}

test('§7.2.6 wiring: chariot-adapter-bundle.json with signingPayloadVersion=2 is rejected BEFORE the trust-anchor key check even runs (fails on its own merits)', () => {
  withTempDir((dir) => {
    const bundlePath = join(dir, 'chariot-adapter-bundle.json');
    const bundle = twoLeafBundle({ manifest: { merkleRoot: TWO_LEAF_ROOT, signingPayloadVersion: 2 } });
    writeFileSync(bundlePath, JSON.stringify(bundle));
    writeFileSync(`${bundlePath}.sig`, 'garbage-not-a-real-signature==');
    // Even the REAL production key set is used here — the point is that
    // the version check fails FIRST, before any key is even consulted.
    const result = verifyAndReadArtifact(bundlePath, CHARIOT_CATALOG_PUBLIC_KEYS);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'signing-payload-version-invalid');
  });
});

test('§7.2.6 wiring: chariot-adapter-bundle.json with a malformed compact envelope (signingPayloadVersion=1) does NOT fall back to legacy full-bytes verify', () => {
  withTempDir((dir) => {
    const bundlePath = join(dir, 'chariot-adapter-bundle.json');
    const bundle = twoLeafBundle({ manifest: { merkleRoot: 'not-a-valid-root', signingPayloadVersion: 1 } });
    writeFileSync(bundlePath, JSON.stringify(bundle));
    writeFileSync(`${bundlePath}.sig`, 'garbage-not-a-real-signature==');
    const result = verifyAndReadArtifact(bundlePath, CHARIOT_CATALOG_PUBLIC_KEYS);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'compact-payload-malformed');
  });
});

test('§7.2.6 wiring: chariot-adapter-bundle.json with signingPayloadVersion ABSENT still reaches the legacy full-bytes gate (proven via the trust-anchor reason, not a compact-payload reason)', () => {
  withTempDir((dir) => {
    const bundlePath = join(dir, 'chariot-adapter-bundle.json');
    // Deliberately ALSO malformed in a way that would be
    // 'compact-payload-malformed' under the compact path (missing
    // publishHash) — proves the version-absent bundle never enters that
    // branch at all.
    const bundle = { epoch: 1, catalogVersion: 1, catalog: [{ id: 'x' }], registry: [] };
    writeFileSync(bundlePath, JSON.stringify(bundle));
    writeFileSync(`${bundlePath}.sig`, 'garbage-not-a-real-signature==');
    const throwaway = makeThrowawayKey();
    const result = verifyAndReadArtifact(bundlePath, [throwaway]);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(
        result.reason,
        'accepted-keys-outside-rotation-set',
        'a version-absent bundle must reach the SAME trust-anchor gate a legacy artifact would, never a compact-payload-* reason',
      );
    }
  });
});

test('catalog artifact ignores signingPayloadVersion and uses its digest/full-bytes verification paths', () => {
  withTempDir((dir) => {
    const catalogPath = join(dir, 'chariot-adapter-catalog.json');
    // Same shape as a well-formed compact-ready bundle, but this artifact
    // is explicitly OUTSIDE the Merkle leaf set. It uses the catalog
    // SHA-512-digest path (with a legacy full-bytes fallback), regardless
    // of what its JSON happens to contain.
    const bundle = twoLeafBundle();
    writeFileSync(catalogPath, JSON.stringify(bundle));
    writeFileSync(`${catalogPath}.sig`, 'garbage-not-a-real-signature==');
    const throwaway = makeThrowawayKey();
    const result = verifyAndReadArtifact(catalogPath, [throwaway]);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(
        result.reason,
        'accepted-keys-outside-rotation-set',
        'chariot-adapter-catalog.json must never take a compact-payload-* reason',
      );
    }
  });
});

test('§5.1/CHARIOT-SPEC.md:525: the trust-anchor rotation-set gate still applies on the compact-payload path — a well-formed compact envelope with a non-rotation-set key is rejected, never silently accepted', () => {
  withTempDir((dir) => {
    const bundlePath = join(dir, 'chariot-adapter-bundle.json');
    const bundle = twoLeafBundle();
    writeFileSync(bundlePath, JSON.stringify(bundle));
    writeFileSync(`${bundlePath}.sig`, 'garbage-not-a-real-signature==');
    const throwaway = makeThrowawayKey();
    const result = verifyAndReadArtifact(bundlePath, [throwaway]);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.reason, 'accepted-keys-outside-rotation-set');
  });
});
