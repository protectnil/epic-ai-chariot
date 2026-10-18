/**
 * CHARIOT::§5.2::1-5 (CHARIOT-SPEC.md:363-373, CH-02 at :245) —
 * `computeCatalogState` / `effectiveCatalogEntries`, the catalog-wide
 * Ed25519-gated trust state machine.
 *
 * Failure classes enumerated from the clause and closed here:
 *   - value: signatureValid true/false, each of the three 4.0.0 flags
 *     true/false, independently and combined
 *   - position/precedence: a 4.0.0 invalid trigger MUST win even when
 *     signatureValid is true (the adapter catalog's own Ed25519 check can
 *     pass while a different 4.0.0 gate on the same envelope fails)
 *   - boundary: age exactly at the 7-day threshold (not stale) vs one ms
 *     past it (stale) vs one ms under it (verified)
 *   - empty/None: materializedAtMs absent, NaN, and Infinity
 *   - effective-catalog: invalid empties the list, verified/stale do not
 *     (and do not mutate the input array)
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCatalogState, effectiveCatalogEntries, CATALOG_STATE_MAX_AGE_MS } from './VerifiedCatalog.js';

const NOW = 1_800_000_000_000; // fixed reference instant

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::1 — signature valid + fresh → verified
// ---------------------------------------------------------------------------

test('computeCatalogState: signature valid + fresh (age 0) → verified', () => {
  const result = computeCatalogState({ signatureValid: true, materializedAtMs: NOW, now: NOW });
  assert.equal(result.state, 'verified');
});

test('computeCatalogState: signature valid + FUTURE materializedAt (negative age) → verified, not a crash', () => {
  const result = computeCatalogState({ signatureValid: true, materializedAtMs: NOW + 60_000, now: NOW });
  assert.equal(result.state, 'verified');
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::2 — signature valid + age > 7 days → stale
// ---------------------------------------------------------------------------

test('computeCatalogState: signature valid + age one ms PAST 7 days → stale', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW - (CATALOG_STATE_MAX_AGE_MS + 1),
    now: NOW,
  });
  assert.equal(result.state, 'stale');
});

test('computeCatalogState: signature valid + age exactly 7 days (boundary) → verified, NOT stale', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW - CATALOG_STATE_MAX_AGE_MS,
    now: NOW,
  });
  assert.equal(result.state, 'verified');
});

test('computeCatalogState: signature valid + age one ms UNDER 7 days → verified', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW - (CATALOG_STATE_MAX_AGE_MS - 1),
    now: NOW,
  });
  assert.equal(result.state, 'verified');
});

test('computeCatalogState: custom maxAgeMs is honored (not hardcoded to 7 days)', () => {
  const oneHour = 60 * 60 * 1000;
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW - (oneHour + 1),
    now: NOW,
    maxAgeMs: oneHour,
  });
  assert.equal(result.state, 'stale');
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::3 (CH-02) — signature mismatch/missing → invalid
// ---------------------------------------------------------------------------

test('computeCatalogState: signature invalid → invalid, regardless of age', () => {
  const fresh = computeCatalogState({ signatureValid: false, materializedAtMs: NOW, now: NOW });
  assert.equal(fresh.state, 'invalid');
  const old = computeCatalogState({ signatureValid: false, materializedAtMs: NOW - 999_999_999, now: NOW });
  assert.equal(old.state, 'invalid');
  const noTimestamp = computeCatalogState({ signatureValid: false, now: NOW });
  assert.equal(noTimestamp.state, 'invalid');
});

// ---------------------------------------------------------------------------
// Empty/None: absent or unparseable materializedAt is NOT an invalid
// trigger (§5.2's invalid triggers are a closed enumeration that does not
// include "no timestamp" — mirrors the codebase's existing precedent for
// the same field in AdapterCatalog.ts's isCatalogStaleFromMaterializedAt).
// ---------------------------------------------------------------------------

test('computeCatalogState: signature valid + ABSENT materializedAt → verified (not invalid, not stale)', () => {
  const result = computeCatalogState({ signatureValid: true, now: NOW });
  assert.equal(result.state, 'verified');
});

test('computeCatalogState: signature valid + NaN materializedAt → verified (treated as absent)', () => {
  const result = computeCatalogState({ signatureValid: true, materializedAtMs: Number.NaN, now: NOW });
  assert.equal(result.state, 'verified');
});

test('computeCatalogState: signature valid + Infinity materializedAt → verified (treated as absent)', () => {
  const result = computeCatalogState({ signatureValid: true, materializedAtMs: Number.POSITIVE_INFINITY, now: NOW });
  assert.equal(result.state, 'verified');
});

// ---------------------------------------------------------------------------
// CHARIOT::§5.2::5 — 4.0.0 additions: retrieval-manifest mismatch,
// encoder mismatch, sealed-bundle signature failure → invalid, and take
// PRECEDENCE over a valid adapter-catalog signature.
// ---------------------------------------------------------------------------

test('computeCatalogState: retrievalManifestMismatch forces invalid even when signatureValid is true and fresh', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW,
    now: NOW,
    retrievalManifestMismatch: true,
  });
  assert.equal(result.state, 'invalid');
});

test('computeCatalogState: encoderMismatch forces invalid even when signatureValid is true and fresh', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW,
    now: NOW,
    encoderMismatch: true,
  });
  assert.equal(result.state, 'invalid');
});

test('computeCatalogState: sealedBundleSignatureFailed forces invalid even when signatureValid is true and fresh', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW,
    now: NOW,
    sealedBundleSignatureFailed: true,
  });
  assert.equal(result.state, 'invalid');
});

test('computeCatalogState: multiple 4.0.0 flags set simultaneously → still exactly one invalid result, no throw', () => {
  const result = computeCatalogState({
    signatureValid: true,
    materializedAtMs: NOW,
    now: NOW,
    retrievalManifestMismatch: true,
    encoderMismatch: true,
    sealedBundleSignatureFailed: true,
  });
  assert.equal(result.state, 'invalid');
});

// ---------------------------------------------------------------------------
// Reason text — never blank, always populated (used for logs).
// ---------------------------------------------------------------------------

test('computeCatalogState: reason is always a non-empty string for every branch', () => {
  const inputs = [
    { signatureValid: true, materializedAtMs: NOW, now: NOW },
    { signatureValid: true, materializedAtMs: NOW - (CATALOG_STATE_MAX_AGE_MS + 1), now: NOW },
    { signatureValid: false, now: NOW },
    { signatureValid: true, now: NOW, retrievalManifestMismatch: true },
    { signatureValid: true, now: NOW, encoderMismatch: true },
    { signatureValid: true, now: NOW, sealedBundleSignatureFailed: true },
  ];
  for (const input of inputs) {
    const result = computeCatalogState(input);
    assert.ok(result.reason.length > 0, `blank reason for ${JSON.stringify(input)}`);
  }
});

// ---------------------------------------------------------------------------
// effectiveCatalogEntries — CH-02: invalid → empty, never partial;
// verified/stale → full, unmutated.
// ---------------------------------------------------------------------------

test('effectiveCatalogEntries: invalid → empty array regardless of input size', () => {
  assert.deepEqual(effectiveCatalogEntries('invalid', [1, 2, 3]), []);
  assert.deepEqual(effectiveCatalogEntries('invalid', []), []);
});

test('effectiveCatalogEntries: verified → full list, same values, not the same array reference (no accidental aliasing)', () => {
  const input = [1, 2, 3];
  const result = effectiveCatalogEntries('verified', input);
  assert.deepEqual(result, [1, 2, 3]);
  assert.notEqual(result, input);
});

test('effectiveCatalogEntries: stale → FULL list, not truncated (the stale row differs only by a WARN log, not by content)', () => {
  const input = ['a', 'b', 'c'];
  const result = effectiveCatalogEntries('stale', input);
  assert.deepEqual(result, ['a', 'b', 'c']);
});

test('effectiveCatalogEntries: empty input stays empty for every state (boundary)', () => {
  assert.deepEqual(effectiveCatalogEntries('verified', []), []);
  assert.deepEqual(effectiveCatalogEntries('stale', []), []);
  assert.deepEqual(effectiveCatalogEntries('invalid', []), []);
});
