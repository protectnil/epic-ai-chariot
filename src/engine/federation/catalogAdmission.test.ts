/**
 * Unit evals for the §5.6 shared admission classifier.
 *
 * Every case here is derived from the CLAUSE's own failure enumeration
 * (CHARIOT-SPEC.md:423-424, :428-434), not from the implementation. The
 * classifier is the SINGLE implementation the clause mandates at :436, so a
 * hole here is a hole in both the adapter-catalog and retrieval admission
 * paths at once.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyCatalogAdmission,
  type PersistedCatalogMark,
} from './catalogAdmission.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

const mark = (over: Partial<PersistedCatalogMark> = {}): PersistedCatalogMark => ({
  epoch: 100,
  catalogVersion: 5,
  bundleSha256: HASH_A,
  ...over,
});

// ── :430 advance ─────────────────────────────────────────────────────────────

test('first run (no persisted mark) is an advance', () => {
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, bundleSha256: HASH_A, persisted: null,
  });
  assert.equal(r.kind, 'advance');
});

test('epoch 0 on first run is an advance (0 is a valid integer epoch, not falsy-rejected)', () => {
  const r = classifyCatalogAdmission({
    epoch: 0, catalogVersion: 0, bundleSha256: HASH_A, persisted: null,
  });
  assert.equal(r.kind, 'advance');
});

test('a strictly greater epoch with an equal catalogVersion is an advance', () => {
  const r = classifyCatalogAdmission({
    epoch: 101, catalogVersion: 5, bundleSha256: HASH_B, persisted: mark(),
  });
  assert.equal(r.kind, 'advance');
});

test('a strictly greater epoch with a HIGHER catalogVersion is an advance', () => {
  const r = classifyCatalogAdmission({
    epoch: 101, catalogVersion: 6, bundleSha256: HASH_B, persisted: mark(),
  });
  assert.equal(r.kind, 'advance');
});

test('an advance without a supplied hash is still an advance (identity is only required at an EQUAL epoch)', () => {
  const r = classifyCatalogAdmission({
    epoch: 101, catalogVersion: 5, persisted: mark(),
  });
  assert.equal(r.kind, 'advance');
});

// ── :424 / :430 downgrade defense ─────────────────────────────────────────

test('a greater epoch carrying a LOWER catalogVersion is rejected as a downgrade', () => {
  const r = classifyCatalogAdmission({
    epoch: 101, catalogVersion: 4, bundleSha256: HASH_B, persisted: mark(),
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'catalog_version_downgrade');
});

// ── :456 replay ─────────────────────────────────────────────────────────────

test('an epoch below the persisted mark is rejected as a replay', () => {
  const r = classifyCatalogAdmission({
    epoch: 99, catalogVersion: 5, bundleSha256: HASH_A, persisted: mark(),
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'epoch_below_persisted');
});

// ── :431 re-admission, the ONLY equal-epoch acceptance ──────────────────────

test('equal epoch + identical hash + equal catalogVersion is a re-admission', () => {
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, bundleSha256: HASH_A, persisted: mark(),
  });
  assert.equal(r.kind, 're-admission');
});

test('equal epoch with a DIFFERENT hash is rejected (identity_mismatch)', () => {
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, bundleSha256: HASH_B, persisted: mark(),
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'identity_mismatch');
});

test('equal epoch with a byte-identical bundle but a MOVED catalogVersion is rejected', () => {
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 6, bundleSha256: HASH_A, persisted: mark(),
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'catalog_version_mismatch');
});

// ── :434 identity is PROVEN, never assumed ──────────────────────────────────

test('equal epoch with NO persisted hash is identity_unproven, not a wildcard', () => {
  const persisted: PersistedCatalogMark = { epoch: 100, catalogVersion: 5 };
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, bundleSha256: HASH_A, persisted,
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'identity_unproven_persisted');
  assert.match(r.message, /remove the epoch file|publish at a higher epoch/,
    ':434 requires operator-actionable guidance on the identity-unproven path');
});

test('equal epoch with NO incoming hash is identity_unproven', () => {
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, persisted: mark(),
  });
  assert.equal(r.kind, 'rejection');
  assert.equal(r.reason, 'identity_unproven_incoming');
});

test('equal epoch with NEITHER hash present is still rejected', () => {
  const persisted: PersistedCatalogMark = { epoch: 100, catalogVersion: 5 };
  const r = classifyCatalogAdmission({
    epoch: 100, catalogVersion: 5, persisted,
  });
  assert.equal(r.kind, 'rejection');
});

// ── :423-424 typed envelope fields ──────────────────────────────────────────
// A NaN epoch compares false against <, > and === alike, so without an
// explicit guard it would fall THROUGH every branch and reach the
// re-admission return. That is the failure class this guard closes.

test('a NaN epoch throws rather than falling through to re-admission', () => {
  assert.throws(
    () => classifyCatalogAdmission({
      epoch: Number.NaN, catalogVersion: 5, bundleSha256: HASH_A, persisted: mark(),
    }),
    /epoch must be an integer/,
  );
});

test('a non-integer epoch throws', () => {
  assert.throws(
    () => classifyCatalogAdmission({
      epoch: 100.5, catalogVersion: 5, bundleSha256: HASH_A, persisted: mark(),
    }),
    /epoch must be an integer/,
  );
});

test('a negative catalogVersion throws', () => {
  assert.throws(
    () => classifyCatalogAdmission({
      epoch: 101, catalogVersion: -1, bundleSha256: HASH_A, persisted: mark(),
    }),
    /catalogVersion must be a non-negative integer/,
  );
});

test('a malformed persisted mark throws rather than being compared against', () => {
  assert.throws(
    () => classifyCatalogAdmission({
      epoch: 101,
      catalogVersion: 5,
      bundleSha256: HASH_A,
      persisted: { epoch: Number.NaN, catalogVersion: 5 },
    }),
    /persisted mark carries a non-integer/,
  );
});

test('a NEGATIVE persisted catalogVersion throws rather than letting version 0 advance past it', () => {
  assert.throws(
    () => classifyCatalogAdmission({
      epoch: 101,
      catalogVersion: 0,
      bundleSha256: HASH_A,
      persisted: { epoch: 100, catalogVersion: -1, bundleSha256: HASH_A },
    }),
    /non-negative integer/,
  );
});

// ── totality: every input lands in exactly one class ────────────────────────

test('the classifier is total over the epoch/version/identity space', () => {
  const hashes: (string | undefined)[] = [undefined, HASH_A, HASH_B];
  const persistedHashes: (string | undefined)[] = [undefined, HASH_A];
  let seen = 0;
  for (const epoch of [99, 100, 101]) {
    for (const catalogVersion of [4, 5, 6]) {
      for (const bundleSha256 of hashes) {
        for (const ph of persistedHashes) {
          const r = classifyCatalogAdmission({
            epoch,
            catalogVersion,
            ...(bundleSha256 !== undefined ? { bundleSha256 } : {}),
            persisted: mark(ph === undefined ? { bundleSha256: undefined } : { bundleSha256: ph }),
          });
          assert.ok(
            r.kind === 'advance' || r.kind === 're-admission' || r.kind === 'rejection',
            'every input must classify',
          );
          if (r.kind === 'rejection') {
            assert.ok(r.reason, 'every rejection must name its failing condition (§5.6:432, :456)');
          }
          seen++;
        }
      }
    }
  }
  assert.equal(seen, 54, 'all combinations exercised');
});
