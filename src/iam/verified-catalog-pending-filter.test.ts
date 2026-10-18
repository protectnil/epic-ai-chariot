/**
 * @epicai/chariot — REST verified-catalog pending/stale filter eval (feed #7)
 *
 * Commit 185c123 gated 'pending'/'stale'/unverified adapters at the
 * FederationManager dispatch layer, but `verifiedCatalogEnforcementMiddleware`
 * (the REST half of the same gate, src/iam/middleware.ts) only ever stripped
 * `status: 'failed'` adapters out of `req.allowedAdapterIds`. An adapter that
 * had simply never been reviewed (no markVerified/markFailed call — the
 * catalog synthesizes 'pending' for those) sailed straight through, so a
 * brand-new/unvetted adapter's tools were reachable via REST pre-review.
 *
 * This proves the fix: a 'pending' adapter (and a 'stale' one) is now
 * excluded from `allowedAdapterIds` the same way a 'failed' one already was,
 * while a genuinely 'verified' adapter is left untouched.
 *
 * Run after `tsc`: node --test dist/iam/verified-catalog-pending-filter.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import { VerifiedCatalog } from '../catalog/VerifiedCatalog.js';
import { verifiedCatalogEnforcementMiddleware } from './middleware.js';

/** Minimal fake req/res — only the fields the middleware reads/writes. */
function fakeReq(allowedAdapterIds: string[]): Request {
  return { allowedAdapterIds } as unknown as Request;
}

function fakeRes(): Response & { statusCode?: number; jsonBody?: unknown } {
  const res = {
    statusCode: undefined as number | undefined,
    jsonBody: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.jsonBody = body;
      return res;
    },
  };
  return res as unknown as Response & { statusCode?: number; jsonBody?: unknown };
}

test('pending adapter (never verified) is excluded from allowedAdapterIds', () => {
  const catalog = new VerifiedCatalog();
  catalog.markVerified('good-adapter');
  // 'shady-adapter' is never marked verified or failed — getVerification()
  // synthesizes a 'pending' record for it. This is the never-reviewed case.
  const middleware = verifiedCatalogEnforcementMiddleware(catalog);

  const req = fakeReq(['good-adapter', 'shady-adapter']);
  const res = fakeRes();
  let nextCalled = false;
  const next: NextFunction = () => { nextCalled = true; };
  middleware(req, res, next);

  assert.equal(nextCalled, true, 'expected next() to be called (not a hard 403)');
  assert.deepEqual(req.allowedAdapterIds, ['good-adapter'], 'pending adapter must be stripped, verified adapter must remain');
});

test('stale adapter (verification expired) is excluded from allowedAdapterIds', () => {
  const catalog = new VerifiedCatalog({ staleDetection: { maxAgeMs: 1000 } });
  catalog.markVerified('good-adapter');
  // Verified long enough ago to exceed maxAgeMs — getVerification() will
  // report this as 'stale', not 'verified'.
  catalog.markVerified('old-adapter', new Date(Date.now() - 60_000).toISOString());
  const middleware = verifiedCatalogEnforcementMiddleware(catalog);

  const req = fakeReq(['good-adapter', 'old-adapter']);
  const res = fakeRes();
  const next: NextFunction = () => {};
  middleware(req, res, next);

  assert.deepEqual(req.allowedAdapterIds, ['good-adapter'], 'stale adapter must be stripped, fresh adapter must remain');
});

test('all-pending session yields 403 All adapters unavailable', () => {
  const catalog = new VerifiedCatalog();
  const middleware = verifiedCatalogEnforcementMiddleware(catalog);

  const req = fakeReq(['never-reviewed']);
  const res = fakeRes();
  let nextCalled = false;
  const next: NextFunction = () => { nextCalled = true; };
  middleware(req, res, next);

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test('verified-only session is untouched (no false positives)', () => {
  const catalog = new VerifiedCatalog();
  catalog.markVerified('adapter-a');
  catalog.markVerified('adapter-b');
  const middleware = verifiedCatalogEnforcementMiddleware(catalog);

  const req = fakeReq(['adapter-a', 'adapter-b']);
  const res = fakeRes();
  let nextCalled = false;
  const next: NextFunction = () => { nextCalled = true; };
  middleware(req, res, next);

  assert.equal(nextCalled, true);
  assert.deepEqual(req.allowedAdapterIds, ['adapter-a', 'adapter-b']);
});
