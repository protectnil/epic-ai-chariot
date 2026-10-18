/**
 * Prove-on-revert for the enterprise JWT secret guard — it must be required and
 * strong.
 *
 * session.ts:89-106 (getJwtSecret, module-private, reached through the
 * exported validateEnterpriseJwtSecret()): rejects an unset secret, the
 * insecure defaults 'change-me' / 'changeme' / 'secret', and any secret
 * shorter than 32 characters; accepts a real >=32-char secret.
 *
 * Failure enumeration this locks in: (a) unset, (b) 'change-me',
 * (c) 'changeme', (d) 'secret', (e) 31 chars (one short of the 32-char
 * floor — boundary case), (f) 64-char random-looking value must NOT throw.
 *
 * Run (after tsc): node --test dist/iam/services/session.insecure-jwt-secret.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateEnterpriseJwtSecret, issueToken, verifyToken } from './session.js';

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

test('jwt-secret (a): unset ENTERPRISE_JWT_SECRET throws', async () => {
  await withSecret(undefined, () => {
    assert.throws(
      () => validateEnterpriseJwtSecret(),
      /not set or is an insecure default/,
    );
  });
});

test("jwt-secret (b): 'change-me' throws", async () => {
  await withSecret('change-me', () => {
    assert.throws(
      () => validateEnterpriseJwtSecret(),
      /not set or is an insecure default/,
    );
  });
});

test("jwt-secret (c): 'changeme' throws", async () => {
  await withSecret('changeme', () => {
    assert.throws(
      () => validateEnterpriseJwtSecret(),
      /not set or is an insecure default/,
    );
  });
});

test("jwt-secret (d): 'secret' throws", async () => {
  await withSecret('secret', () => {
    assert.throws(
      () => validateEnterpriseJwtSecret(),
      /not set or is an insecure default/,
    );
  });
});

test('jwt-secret (e): a 31-char value (one short of the 32-char floor) throws "too short"', async () => {
  const thirtyOne = 'a'.repeat(31);
  assert.equal(thirtyOne.length, 31);
  await withSecret(thirtyOne, () => {
    assert.throws(
      () => validateEnterpriseJwtSecret(),
      /too short/,
    );
  });
});

test('jwt-secret (f): a 64-char random-looking secret does NOT throw', async () => {
  const strong = 'Qx7!k9Lp2mZ8vR3nT6wB1yC4dF5gH0jK'.repeat(2);
  assert.equal(strong.length, 64);
  await withSecret(strong, () => {
    assert.doesNotThrow(() => validateEnterpriseJwtSecret());
  });
});

// The guard must be REQUIRED on the actual sign/verify path, not only via the
// standalone validator. getJwtSecret() is called at the top of issueToken()
// (session.ts:211) and verifyToken() (session.ts:338), before any DB/Redis
// work, so an insecure secret makes those operations reject — proving a revert
// that restored a fallback inside issueToken/verifyToken would fail here.
test('jwt-secret (g): issueToken() rejects on the sign path when the secret is an insecure default', async () => {
  await withSecret('change-me', async () => {
    await assert.rejects(
      () => issueToken({} as never, {} as never),
      /not set or is an insecure default/,
    );
  });
});

test('jwt-secret (h): verifyToken() rejects on the verify path when the secret is an insecure default', async () => {
  await withSecret('change-me', async () => {
    await assert.rejects(
      () => verifyToken('a.b.c'),
      /not set or is an insecure default/,
    );
  });
});
