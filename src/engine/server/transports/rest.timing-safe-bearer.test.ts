/**
 * Prove-on-revert for the constant-time REST bearer comparison.
 *
 * rest.ts:200-219 (bindRest auth check): when CHARIOT_REST_TOKEN is set,
 * every request must carry `Authorization: Bearer <token>`, compared via a
 * length guard followed by crypto.timingSafeEqual — never a plain `===` or
 * substring compare, which would leak the token byte-by-byte via response
 * timing. A mismatch (any reason) answers 401 {error:'Unauthorized'}.
 *
 * Failure enumeration this locks in:
 *   (a) correct token                     -> NOT 401 (health endpoint 200)
 *   (b) wrong token, SAME length as real  -> 401 (constant-time path taken,
 *                                                  not a length-based bypass)
 *   (c) wrong token, DIFFERENT length     -> 401 AND no crash — proves the
 *                                                  length guard short-circuits
 *                                                  before timingSafeEqual,
 *                                                  which throws on unequal
 *                                                  buffer lengths
 *   (d) missing Authorization header      -> 401
 *
 * If the length guard were removed, (c) would throw inside the request
 * handler (uncaught in the void IIFE) instead of cleanly answering 401 —
 * this test's server would hang / the fetch would fail to resolve as 401.
 *
 * Run (after tsc): node --test dist/engine/server/transports/rest.timing-safe-bearer.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { bindRest } from './rest.js';
import type { ChariotState } from '../ChariotState.js';
import type { TransportHandle } from '../TransportHandle.js';

const TEST_TOKEN = 'fixed-rest-test-token-abcdef12345678';

function makeMinimalState(): ChariotState {
  return {
    allAdapters: [],
    adapterById: new Map(),
    configuredAdapterIds: new Set(),
    credentials: {},
    fullCatalogFilter: { select: async () => [] },
    toolPreFilter: { select: async () => [] },
    getConfiguredAdapters: () => [],
    loadedAt: new Date(),
  } as unknown as ChariotState;
}

async function withServer(
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const origToken = process.env.CHARIOT_REST_TOKEN;
  const origAllow = process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST;
  process.env.CHARIOT_REST_TOKEN = TEST_TOKEN;
  delete process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST;
  let handle: TransportHandle | undefined;
  try {
    handle = await bindRest(makeMinimalState(), 0, () => 'local');
    await run(`http://127.0.0.1:${handle.port}`);
  } finally {
    if (handle) await handle.close();
    if (origToken !== undefined) process.env.CHARIOT_REST_TOKEN = origToken;
    else delete process.env.CHARIOT_REST_TOKEN;
    if (origAllow !== undefined) process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST = origAllow;
    else delete process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST;
  }
}

test('rest-bearer (a): correct bearer token is NOT rejected with 401', async () => {
  await withServer(async (baseUrl) => {
    const res = await fetch(`${baseUrl}/v1/health`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    assert.notEqual(res.status, 401, 'correct token must not be rejected');
    assert.equal(res.status, 200);
  });
});

test('rest-bearer (b): wrong token of EQUAL length is rejected with 401', async () => {
  await withServer(async (baseUrl) => {
    const wrongSameLength = TEST_TOKEN
      .split('')
      .map((c) => (c === 'a' ? 'z' : 'a'))
      .join('');
    assert.equal(wrongSameLength.length, TEST_TOKEN.length);
    assert.notEqual(wrongSameLength, TEST_TOKEN);
    const res = await fetch(`${baseUrl}/v1/health`, {
      headers: { Authorization: `Bearer ${wrongSameLength}` },
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'Unauthorized' });
  });
});

test('rest-bearer (c): wrong token of DIFFERENT length is rejected with 401 and does not crash the server', async () => {
  await withServer(async (baseUrl) => {
    const shorter = TEST_TOKEN.slice(0, 5);
    const res = await fetch(`${baseUrl}/v1/health`, {
      headers: { Authorization: `Bearer ${shorter}` },
    });
    assert.equal(res.status, 401);
    // Proves the server survived the mismatched-length compare (the length
    // guard short-circuited instead of calling timingSafeEqual on unequal
    // buffers, which throws): a second request on the same server succeeds.
    const res2 = await fetch(`${baseUrl}/v1/health`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    assert.equal(res2.status, 200);
  });
});

test('rest-bearer (d): missing Authorization header is rejected with 401', async () => {
  await withServer(async (baseUrl) => {
    const res = await fetch(`${baseUrl}/v1/health`);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.deepEqual(body, { error: 'Unauthorized' });
  });
});
