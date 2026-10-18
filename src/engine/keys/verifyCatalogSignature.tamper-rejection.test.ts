/**
 * AS::§3.1.1::2 — ADAPTER-STANDARD-MAY-2026.md:491 (§3.1.1 "Per-adapter
 * integrity seal"): "**Seal contract:** changing any single shipped
 * record's bytes changes its `publishHash` → changes the root → breaks
 * the signature, so any post-factory modification of any adapter fails
 * verification."
 *
 * CHARIOT-SPEC.md:525 ("Trust anchor", §5.7, CH-52), verbatim: "The Ed25519
 * verifying key SHALL be pinned to the compiled-in accepted key set
 * (`native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM`). A caller-supplied
 * key outside that rotation set SHALL be rejected, so neither a caller nor
 * an attacker controlling the caller's configuration can substitute a
 * signing key." Applied (see `verifyCatalogSignature.ts`'s module
 * docstring) to this module's own pinned key, `CHARIOT_CATALOG_PUBLIC_KEYS`:
 * `verifyAndReadArtifact` now intersects any caller-supplied `acceptedKeys`
 * against that compiled-in set BEFORE ever attempting a signature check —
 * a key outside the set is never tried, and an intersection of zero fails
 * closed with the dedicated `accepted-keys-outside-rotation-set` reason.
 *
 * Gate finding (this revision): a prior revision of this file signed a
 * synthetic fixture bundle with a freshly generated THROWAWAY Ed25519 key
 * and asserted `verifyAndReadArtifact(artifactPath, [throwawayKey])`
 * returned `ok: true` — passing that throwaway key directly as
 * `acceptedKeys` to make the offline-verifier's own signature math
 * (`cryptoVerify`) exercisable without needing the real production private
 * key. That is now EXACTLY the caller-supplied-key substitution the trust
 * anchor above exists to forbid, so it is rejected at the intersection gate
 * before signature math ever runs — no test may pass a key that is not in
 * the compiled-in rotation set and expect a `ok: true` result. The two
 * tests that relied on that pattern to SUCCEED are rewritten below to
 * assert REJECTION instead (the clause's failure enumeration: outside key
 * → rejected), and now serve as the trust-anchor regression tests. One
 * consequence, stated rather than hidden: because a synthetic throwaway
 * key can no longer reach `cryptoVerify` through this exported function at
 * all, the ORIGINAL untampered-vs-tampered signature-math distinction
 * these two tests drew is no longer observable through
 * `verifyAndReadArtifact` with a synthetic key — both now reject for the
 * SAME reason (`accepted-keys-outside-rotation-set`), before either
 * artifact's bytes are ever compared against a signature. The
 * AS::§3.1.1::2 "tamper changes the signature check outcome" property
 * still needs END-TO-END coverage against a REAL accepted key; that
 * requires either the private production signing key (out of scope here —
 * see `test/verified-catalog-e2e-w14.mjs` in the private eval tree for the
 * pattern) or `AdapterCatalog`'s separately spec-sanctioned
 * `CatalogSourceConfig.publicKeyPem` override (CHARIOT-SPEC.md:383-395
 * §5.4: "publicKeyPem?: string, // optional override of the embedded
 * key"), which is a DIFFERENT verification pipeline (`AdapterCatalog.ts`'s
 * own `cryptoVerify` call, not this module) untouched by this fix. Flagged
 * here as a coverage decision for the graph owner, not implemented as a
 * guess.
 *
 * Run (after tsc): node --test dist/engine/keys/verifyCatalogSignature.tamper-rejection.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { verifyAndReadArtifact, intersectWithRotationSet } from './verifyCatalogSignature.js';
import { CHARIOT_CATALOG_PUBLIC_KEYS, type ChariotCatalogPublicKey } from './chariot-catalog-public.js';

/** Build a minimal fixture bundle: one shipped record per AS §2.1's
 *  shape, each carrying its own `metadata.publishHash` (the field the
 *  seal contract's Merkle leaf keys on upstream; here we exercise only
 *  the offline-verifier signature check that sits over the whole
 *  artifact's bytes, per verifyAndReadArtifact's actual implementation:
 *  `cryptoVerify(null, artifact.bytes, keyObject, sigBytes)`). */
function buildFixtureBundleBytes(): Buffer {
  const bundle = {
    catalog: [
      {
        id: 'fixture-adapter-one',
        name: 'fixture-adapter-one',
        metadata: { publishHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
      },
      {
        id: 'fixture-adapter-two',
        name: 'fixture-adapter-two',
        metadata: { publishHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
      },
    ],
    registry: [],
    manifest: { merkleRoot: 'fixture-root-not-recomputed-here' },
  };
  return Buffer.from(JSON.stringify(bundle), 'utf-8');
}

function makeThrowawayKey(): { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']; key: ChariotCatalogPublicKey } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { privateKey, key: { id: 'test-throwaway-key', pem } };
}

// ── CHARIOT-SPEC.md:525 trust anchor — the three-case failure enumeration ──

test('CHARIOT-SPEC.md:525 trust anchor — a key outside the compiled-in rotation set is REJECTED, never tried, even for an untampered, validly self-signed artifact', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  // Fresh, single-use Ed25519 key pair — NEVER a real signing key, and by
  // construction NOT a member of CHARIOT_CATALOG_PUBLIC_KEYS.
  const { privateKey, key: throwawayKey } = makeThrowawayKey();

  const artifactPath = join(dir, 'chariot-adapter-bundle.json');
  const bytes = buildFixtureBundleBytes();
  writeFileSync(artifactPath, bytes);
  // Ed25519 signs the raw message directly — no digest algorithm, matching
  // verifyAndReadArtifact's own `cryptoVerify(null, artifact.bytes, ...)`.
  const signature = cryptoSign(null, bytes, privateKey);
  writeFileSync(`${artifactPath}.sig`, signature.toString('base64'));

  const result = verifyAndReadArtifact(artifactPath, [throwawayKey]);
  assert.equal(result.ok, false, 'a key outside the rotation set must be rejected even though the artifact is genuinely self-signed and untampered');
  if (!result.ok) {
    assert.equal(result.reason, 'accepted-keys-outside-rotation-set');
  }
});

test('CHARIOT-SPEC.md:525 trust anchor — a key outside the rotation set is rejected identically whether or not the artifact is later tampered (the gate runs before signature math)', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const { privateKey, key: throwawayKey } = makeThrowawayKey();

  const artifactPath = join(dir, 'chariot-adapter-bundle.json');
  const originalBytes = buildFixtureBundleBytes();
  const signature = cryptoSign(null, originalBytes, privateKey);
  writeFileSync(`${artifactPath}.sig`, signature.toString('base64'));

  // Post-factory tamper: flip a single byte inside the FIRST shipped
  // record's publishHash value (change one 'a' to 'z'), leave the
  // signature sidecar untouched — the exact "post-factory modification"
  // the seal contract describes. Irrelevant to the outcome here: the
  // trust-anchor gate rejects the key before these bytes are ever compared
  // against the signature, so tampered and untampered bytes produce the
  // identical rejection reason through this path.
  const tamperedBytes = Buffer.from(originalBytes);
  const idx = tamperedBytes.indexOf('a'.charCodeAt(0));
  assert.ok(idx >= 0, 'fixture must contain the byte under test');
  tamperedBytes[idx] = 'z'.charCodeAt(0);
  assert.notDeepEqual(tamperedBytes, originalBytes, 'sanity: the tamper actually changed the bytes');
  writeFileSync(artifactPath, tamperedBytes);

  const result = verifyAndReadArtifact(artifactPath, [throwawayKey]);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'accepted-keys-outside-rotation-set', 'rejected at the key gate, not at signature-verification-failed — the tamper is never reached');
  }
});

test('CHARIOT-SPEC.md:525 trust anchor — a throwaway-signed artifact does not verify against the real, unmodified CHARIOT_CATALOG_PUBLIC_KEYS defaults (no accidental cross-acceptance)', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const { privateKey } = generateKeyPairSync('ed25519');
  const artifactPath = join(dir, 'chariot-adapter-bundle.json');
  const bytes = buildFixtureBundleBytes();
  writeFileSync(artifactPath, bytes);
  const signature = cryptoSign(null, bytes, privateKey);
  writeFileSync(`${artifactPath}.sig`, signature.toString('base64'));

  // No acceptedKeys argument — defaults to the real CHARIOT_CATALOG_PUBLIC_KEYS,
  // which is trivially its own full intersection (every entry is pinned),
  // so this exercises the ORIGINAL signature-verification-failed path,
  // unchanged by the trust-anchor fix.
  const result = verifyAndReadArtifact(artifactPath);
  assert.equal(result.ok, false, 'a fixture signed by a throwaway key must not verify against the production key set');
  if (!result.ok) {
    assert.equal(result.reason, 'signature-verification-failed', 'the production defaults are all pinned, so this fails on signature math, not the rotation-set gate');
  }
});

test('CHARIOT-SPEC.md:525 trust anchor — an EMPTY caller-supplied acceptedKeys array fails closed with the same explicit reason, not signature-verification-failed', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-seal-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const { privateKey } = generateKeyPairSync('ed25519');
  const artifactPath = join(dir, 'chariot-adapter-bundle.json');
  const bytes = buildFixtureBundleBytes();
  writeFileSync(artifactPath, bytes);
  const signature = cryptoSign(null, bytes, privateKey);
  writeFileSync(`${artifactPath}.sig`, signature.toString('base64'));

  const result = verifyAndReadArtifact(artifactPath, []);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, 'accepted-keys-outside-rotation-set');
    assert.match(result.detail ?? '', /contained none in the/);
  }
});

test('CHARIOT-SPEC.md:525 trust anchor — a caller-supplied set that is a SUBSET of (i.e. includes a member of) the compiled-in rotation set is accepted, verified against the real shipped production bundle', async () => {
  const bundlePath = join(import.meta.dirname, '..', '..', '..', 'chariot-adapter-bundle.json');
  if (!existsSync(bundlePath) || !existsSync(`${bundlePath}.sig`)) {
    assert.fail(`expected the real shipped bundle at ${bundlePath} (and its .sig) to exist — this test needs the production-signed fixture other suites already depend on`);
  }
  const { key: throwawayKey } = makeThrowawayKey();
  // The rotation set carries more than one pinned production key during a
  // dual-sign cycle; discover which pinned entry signed the shipped fixture
  // (default set, no caller keys) rather than assuming it is entry [0].
  const withDefaultSet = verifyAndReadArtifact(bundlePath);
  assert.equal(withDefaultSet.ok, true, `the shipped bundle must verify against the default rotation set, got: ${JSON.stringify(withDefaultSet)}`);
  const signingEntry = withDefaultSet.ok
    ? CHARIOT_CATALOG_PUBLIC_KEYS.find((k) => k.id === withDefaultSet.keyId)
    : undefined;
  assert.ok(signingEntry, 'the matched keyId must name a pinned rotation-set entry');
  // Deliberately includes ONE accepted key (the pinned production key that
  // signed the fixture) ALONGSIDE one outside key — proves the outside key
  // is dropped (never tried) while the accepted key still verifies, i.e. a
  // caller cannot widen the trust anchor by mixing in extra keys, but a
  // legitimate subset still works.
  const mixedKeys: ChariotCatalogPublicKey[] = [signingEntry, throwawayKey];

  const result = verifyAndReadArtifact(bundlePath, mixedKeys);
  assert.equal(result.ok, true, 'a caller-supplied set that includes a real pinned key must still verify against the real shipped bundle');
  if (result.ok) {
    assert.equal(result.keyId, signingEntry.id, 'the matched key must be the pinned production key, never the outside key that happened to be mixed in');
  }
});

// ── intersectWithRotationSet — direct unit coverage of the choke point ──────

test('intersectWithRotationSet: drops every key not present (by exact pem) in CHARIOT_CATALOG_PUBLIC_KEYS, keeps every key that is', () => {
  const { key: throwawayKey } = makeThrowawayKey();
  const pinned = CHARIOT_CATALOG_PUBLIC_KEYS[0];

  assert.deepEqual(intersectWithRotationSet([throwawayKey]), []);
  assert.deepEqual(intersectWithRotationSet([]), []);
  assert.deepEqual(intersectWithRotationSet([pinned]), [pinned]);
  assert.deepEqual(intersectWithRotationSet([pinned, throwawayKey]), [pinned]);
  assert.deepEqual(intersectWithRotationSet([throwawayKey, pinned]), [pinned]);
  // A caller-relabeled copy of the pinned key's PEM (different `id`, same
  // `pem` bytes) is still recognized — identity is the PEM, not the label.
  assert.deepEqual(intersectWithRotationSet([{ id: 'renamed', pem: pinned.pem }]), [{ id: 'renamed', pem: pinned.pem }]);
});
