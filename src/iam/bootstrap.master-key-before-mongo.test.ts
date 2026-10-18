/**
 * CHARIOT::§18.3::1 — "Master key missing in enterprise mode | Fail-fast at
 * startup (CH-19)." (CHARIOT-SPEC.md:1476)
 *
 * Wave-3a gate finding (P1-2): bootstrapEnterprise() (src/iam/bootstrap.ts)
 * connected to MongoDB (`new MongoClient(...)` / `mongoClient.connect()`)
 * BEFORE fully validating the master key (validateMasterKey() previously
 * ran at "step 5", after Mongo/Redis) — requireEnv('ENTERPRISE_MASTER_KEY',
 * ...) alone (which ran earlier) only catches unset/insecure-default/
 * too-short (its shared 16-char floor), not "does not decode to exactly 32
 * bytes" (crypto.ts's getMasterKeyB64), so a key that passed the generic
 * floor but failed the 32-byte check would only surface AFTER a live Mongo
 * dial. Fixed by moving validateMasterKey() to run immediately after
 * requireEnv('ENTERPRISE_MASTER_KEY', ...), before the MongoDB import/
 * connect.
 *
 * This node's own end-to-end behavior (an actual `MONGODB_URI` pointing at
 * a listener that must never be contacted) cannot be exercised by directly
 * invoking bootstrapEnterprise() in this sandbox: step 1 of that function
 * (loadNativeBinding()) always throws first here, because no native binary
 * is present — bootstrap.jwt-secret-floor.test.ts documents the same,
 * pre-existing limitation for the same reason. There is no
 * --experimental-test-module-mocks flag available to this shared
 * `node --test <file>` runner (scripts/run-all-tests.mjs hardcodes
 * `['--test', file]`) to stub loadNativeBinding() and reach further into
 * the function, so this is a durable SOURCE-ORDER regression test instead:
 * it reads the live .ts source and asserts the byte offset of the
 * validateMasterKey() call is strictly before the byte offset of the first
 * MongoDB dial (`new MongoClient(`) within bootstrapEnterprise()'s body.
 * Given that ordering (proven live here) plus validateMasterKey() being
 * synchronous and free of any Mongo/Redis import (proven separately in
 * bootstrap.enterprise-gate.test.ts's requireMasterKeyForEnterpriseStartup
 * tests, which call the exact same underlying crypto.ts function and
 * complete in low-single-digit ms with no network dependency), a missing/
 * malformed master key throws before any Mongo dial is reachable by
 * construction — this test fails LOUDLY (not silently passes) if a future
 * edit reintroduces the Mongo-before-master-key ordering.
 *
 * Run (after tsc, but this test reads the .ts SOURCE, not dist — path is
 * resolved relative to the compiled test's own location back to the repo's
 * src/ tree): node --test dist/iam/bootstrap.master-key-before-mongo.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

function findBootstrapSource(): string {
  // dist/iam/<this>.test.js -> repo root is three levels up (dist/iam -> dist -> repo).
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, '../../src/iam/bootstrap.ts'), // dist/iam -> repo/src/iam
    join(here, 'bootstrap.ts'), // running directly from src/iam (ts-node style)
  ];
  for (const c of candidates) {
    try {
      return readFileSync(c, 'utf8');
    } catch {
      // try next candidate
    }
  }
  throw new Error(`bootstrap.ts source not found from any of: ${candidates.join(', ')}`);
}

test('CHARIOT::§18.3::1: bootstrapEnterprise() validates the master key before dialing MongoDB (source-order regression)', () => {
  const src = findBootstrapSource();

  const fnStart = src.indexOf('export async function bootstrapEnterprise(');
  assert.ok(fnStart >= 0, 'bootstrapEnterprise() not found in source');
  // Body ends at the next top-level `export function` after it (the next
  // exported symbol, isEnterpriseModeRequested in the current source) —
  // good enough to bound the search to this function's body without a
  // full parser.
  const nextExportIdx = src.indexOf('\nexport function', fnStart + 1);
  const fnEnd = nextExportIdx >= 0 ? nextExportIdx : src.length;
  const body = src.slice(fnStart, fnEnd);

  const masterKeyIdx = body.indexOf('validateMasterKey()');
  const mongoConnectIdx = body.indexOf('new MongoClient(');

  assert.ok(masterKeyIdx >= 0, 'validateMasterKey() call not found in bootstrapEnterprise() body');
  assert.ok(mongoConnectIdx >= 0, 'new MongoClient( call not found in bootstrapEnterprise() body');
  assert.ok(
    masterKeyIdx < mongoConnectIdx,
    `validateMasterKey() (offset ${masterKeyIdx}) must precede new MongoClient( (offset ${mongoConnectIdx}) within bootstrapEnterprise()`,
  );
});
