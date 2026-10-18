/**
 * CHARIOT::§20::4 — "ENTERPRISE_JWT_SECRET values shorter than 32 characters
 * SHALL be rejected at startup." (CHARIOT-SPEC.md:1535, :988)
 *
 * Proves the bootstrap.ts integration seam (enforceJwtSecretLengthFloor,
 * called from bootstrapEnterprise() right after requireEnv('ENTERPRISE_JWT_
 * SECRET', ...)) actually enforces the 32-char floor, closing the gap where
 * requireEnv()'s own generic floor (16 chars — shared with
 * ENTERPRISE_MASTER_KEY/MONGODB_URI/REDIS_URL, none of which carry this
 * clause) let a 16-31 char JWT secret through.
 *
 * bootstrapEnterprise() as a whole cannot be exercised end-to-end in this
 * sandbox: it fails-fast on the native-binary integrity check (item 1)
 * before ever reaching secret validation, regardless of ENTERPRISE_JWT_
 * SECRET's value — reproduced independently of this change via
 * `loadNativeBinding()` returning null here. enforceJwtSecretLengthFloor()
 * is exported specifically so this seam is testable without that
 * dependency.
 *
 * Failure enumeration: (a) unset, (b) 31 chars — the boundary one short of
 * the floor, (c) exactly 32 chars (non-insecure) — must NOT throw for
 * length, (d) 20 chars — inside requireEnv()'s old 16-char floor but still
 * below the 32-char clause floor, proving the specific gap the mapper found
 * is closed and not just the already-tested 31/32 boundary in session.ts.
 *
 * Run (after tsc): node --test dist/iam/bootstrap.jwt-secret-floor.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { enforceJwtSecretLengthFloor } from './bootstrap.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

async function withSecret(value: string | undefined, run: () => void | Promise<void>): Promise<void> {
  const orig = process.env.ENTERPRISE_JWT_SECRET;
  try {
    if (value === undefined) delete process.env.ENTERPRISE_JWT_SECRET;
    else process.env.ENTERPRISE_JWT_SECRET = value;
    await run();
  } finally {
    if (orig !== undefined) process.env.ENTERPRISE_JWT_SECRET = orig;
    else delete process.env.ENTERPRISE_JWT_SECRET;
  }
}

test('CHARIOT::§20::4 (a): unset ENTERPRISE_JWT_SECRET throws via the bootstrap seam', async () => {
  await withSecret(undefined, () => {
    assert.throws(
      () => enforceJwtSecretLengthFloor(),
      /not set or is an insecure default/,
    );
  });
});

test('CHARIOT::§20::4 (b): a 31-char secret (one short of the 32-char floor — boundary) throws "too short" via the bootstrap seam', async () => {
  const thirtyOne = 'b'.repeat(31);
  assert.equal(thirtyOne.length, 31);
  await withSecret(thirtyOne, () => {
    assert.throws(
      () => enforceJwtSecretLengthFloor(),
      /too short \(31 chars, minimum 32\)/,
    );
  });
});

test('CHARIOT::§20::4 (c): an exactly-32-char, non-insecure secret passes length validation via the bootstrap seam (does not throw)', async () => {
  const thirtyTwo = 'Qx7!k9Lp2mZ8vR3nT6wB1yC4dF5gH0j1';
  assert.equal(thirtyTwo.length, 32);
  await withSecret(thirtyTwo, () => {
    assert.doesNotThrow(() => enforceJwtSecretLengthFloor());
  });
});

test('CHARIOT::§20::4 (d): a 20-char secret — inside requireEnv()\'s old 16-char floor but below the 32-char clause floor — still throws "too short" (closes the exact gap the mapper found)', async () => {
  const twenty = 'c'.repeat(20);
  assert.equal(twenty.length, 20);
  await withSecret(twenty, () => {
    assert.throws(
      () => enforceJwtSecretLengthFloor(),
      /too short \(20 chars, minimum 32\)/,
    );
  });
});
