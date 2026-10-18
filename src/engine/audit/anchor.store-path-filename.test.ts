/**
 * Prove-on-revert for CHARIOT::§9.8.2::5 and CHARIOT::§9.8.2::6.
 *
 * Spec, CHARIOT-SPEC.md §9.8.2:
 *   "The TSA returns a signed timestamp token (`.tsr` file). The client
 *   stores the `.tsr` alongside the chain head hash in a configured anchor
 *   store path (`CHARIOT_ANCHOR_STORE_PATH`, defaults to
 *   `~/.epic-ai/audit/anchors/`). Each anchor file is named
 *   `anchor-{ISO8601-timestamp}-{shortHash}.tsr`."
 *
 * Defect this catches: `persistTsr` ignored `CHARIOT_ANCHOR_STORE_PATH`
 * entirely (always wrote under `<packageRoot>/audit/anchors/`) and named
 * files `<chainId>-<epoch>.tsr` — no `anchor-` prefix, a raw millisecond
 * epoch instead of an ISO-8601 timestamp, and the chain id instead of a
 * short hash of the anchored head.
 *
 * Run (after tsc): node --test dist/engine/audit/anchor.store-path-filename.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { anchorChainHead } from './anchor.js';

const HEAD_HASH_HEX = 'bc143833225b051df90ca516417d2efdbac2255c68f5501109743cc574700d58';

function stubFetch(): typeof fetch {
  return (async () =>
    new Response(Buffer.from('fake-tsr-bytes'), { status: 200 })) as unknown as typeof fetch;
}

test('CHARIOT::§9.8.2::5 — CHARIOT_ANCHOR_STORE_PATH is honored over <packageRoot>/audit/anchors/', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-anchor-pkgroot-'));
  const overrideDir = mkdtempSync(join(tmpdir(), 'chariot-anchor-override-'));
  const prevOverride = process.env.CHARIOT_ANCHOR_STORE_PATH;
  process.env.CHARIOT_ANCHOR_STORE_PATH = overrideDir;
  try {
    const result = await anchorChainHead({
      chainId: 'test-chain',
      headHash: Buffer.from(HEAD_HASH_HEX, 'hex'),
      packageRoot,
      tsaUrl: 'https://tsa.example.invalid/',
      fetchImpl: stubFetch(),
      nowMs: () => Date.parse('2026-06-01T12:34:56.789Z'),
    });
    assert.ok(
      result.tsrPath.startsWith(overrideDir),
      `expected tsrPath ${result.tsrPath} to be written under CHARIOT_ANCHOR_STORE_PATH=${overrideDir}`,
    );
    // The default <packageRoot>/audit/anchors/ dir must NOT have been used.
    assert.ok(
      !result.tsrPath.startsWith(join(packageRoot, 'audit', 'anchors')),
      'CHARIOT_ANCHOR_STORE_PATH must override the packageRoot-derived default, not merely supplement it',
    );
  } finally {
    if (prevOverride === undefined) delete process.env.CHARIOT_ANCHOR_STORE_PATH;
    else process.env.CHARIOT_ANCHOR_STORE_PATH = prevOverride;
    rmSync(packageRoot, { recursive: true, force: true });
    rmSync(overrideDir, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.2::5 — unset CHARIOT_ANCHOR_STORE_PATH defaults to <packageRoot>/audit/anchors/', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-anchor-pkgroot-'));
  const prevOverride = process.env.CHARIOT_ANCHOR_STORE_PATH;
  delete process.env.CHARIOT_ANCHOR_STORE_PATH;
  try {
    const result = await anchorChainHead({
      chainId: 'test-chain',
      headHash: Buffer.from(HEAD_HASH_HEX, 'hex'),
      packageRoot,
      tsaUrl: 'https://tsa.example.invalid/',
      fetchImpl: stubFetch(),
      nowMs: () => Date.parse('2026-06-01T12:34:56.789Z'),
    });
    assert.ok(result.tsrPath.startsWith(join(packageRoot, 'audit', 'anchors')));
  } finally {
    if (prevOverride === undefined) delete process.env.CHARIOT_ANCHOR_STORE_PATH;
    else process.env.CHARIOT_ANCHOR_STORE_PATH = prevOverride;
    rmSync(packageRoot, { recursive: true, force: true });
  }
});

test('CHARIOT::§9.8.2::6 — anchor filename matches anchor-{ISO8601}-{shortHash}.tsr', async () => {
  const packageRoot = mkdtempSync(join(tmpdir(), 'chariot-anchor-pkgroot-'));
  const prevOverride = process.env.CHARIOT_ANCHOR_STORE_PATH;
  delete process.env.CHARIOT_ANCHOR_STORE_PATH;
  try {
    const result = await anchorChainHead({
      chainId: 'test-chain',
      headHash: Buffer.from(HEAD_HASH_HEX, 'hex'),
      packageRoot,
      tsaUrl: 'https://tsa.example.invalid/',
      fetchImpl: stubFetch(),
      nowMs: () => Date.parse('2026-06-01T12:34:56.789Z'),
    });
    const filename = result.tsrPath.split('/').pop() ?? '';
    const pattern = /^anchor-\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z-[0-9a-f]{12}\.tsr$/;
    assert.match(filename, pattern, `filename "${filename}" must match anchor-{ISO8601}-{shortHash}.tsr`);
    // shortHash must actually derive from the anchored head hash, not be arbitrary.
    assert.ok(
      filename.includes(HEAD_HASH_HEX.slice(0, 12)),
      'the shortHash component must be derived from the anchored head hash',
    );
    const listed = readdirSync(join(packageRoot, 'audit', 'anchors'));
    assert.deepEqual(listed, [filename]);
  } finally {
    if (prevOverride === undefined) delete process.env.CHARIOT_ANCHOR_STORE_PATH;
    else process.env.CHARIOT_ANCHOR_STORE_PATH = prevOverride;
    rmSync(packageRoot, { recursive: true, force: true });
  }
});
