/**
 * @epicai/chariot — unit tests for the shared stdio-adapter dependency
 * installer (`installStdioDependency`), used by both `chariot add
 * <adapter>` (src/bin/chariot.ts) and the setup wizard's step 4
 * (src/engine/bin/setup.ts).
 *
 * W42-FIX (2026-09-04, rulings item 100 — row 1.42 proof, gap 1 of 3):
 * the pre-fix version installed the bare, UNPINNED package name (no
 * version suffix) and never verified the result, so `chariot add`
 * installed the registry's `latest` dist-tag rather than the catalog's
 * pinned `mcp.version` — confirmed empirically
 * (/tmp/scratch/wave3/w42/run/VERDICT.md: `chariot add 4fetch` installed
 * 1.4.0 while the catalog pinned 1.2.0). These tests derive directly from
 * AS §1.1 sub-clauses 1-2 (ADAPTER-STANDARD-MAY-2026.md:111-114): the
 * install spec passed to npm MUST be exactly `<packageName>@<version>`,
 * and success MUST NOT be reported unless `verifyNpmIntegrity` confirms
 * the SHA-512 of the resulting cached tarball matches `integrityShasum`.
 *
 * Pure unit tests — spawnFn and verifyNpmIntegrity are both injected, no
 * real npm/network calls, no filesystem I/O.
 *
 * Run: node --test dist/cli/installStdioDependency.test.js
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  installStdioDependency,
  type StdioInstallSpawnFn,
  type StdioInstallTarget,
  type VerifyNpmIntegrityFn,
} from './installStdioDependency.js';

const PINNED: StdioInstallTarget = {
  name: '4fetch',
  mcp: {
    transport: 'stdio',
    packageName: '@amcharts/amcharts5-mcp',
    version: '1.2.0',
    integrityShasum: 'a'.repeat(128),
  },
};

function spawnCapture(): { calls: Array<{ bin: string; argv: string[]; timeoutMs: number }>; fn: StdioInstallSpawnFn } {
  const calls: Array<{ bin: string; argv: string[]; timeoutMs: number }> = [];
  const fn: StdioInstallSpawnFn = (bin, argv, timeoutMs) => {
    calls.push({ bin, argv, timeoutMs });
    return { status: 0, signal: null };
  };
  return { calls, fn };
}

const okVerify: VerifyNpmIntegrityFn = () => ({ ok: true });

describe('installStdioDependency', () => {
  test('not-applicable for a non-stdio adapter', () => {
    const { fn } = spawnCapture();
    const r = installStdioDependency({ name: 'x', mcp: { transport: 'streamable-http' } }, fn, okVerify);
    assert.equal(r.status, 'not-applicable');
  });

  test('not-applicable when mcp.packageName is absent', () => {
    const { fn } = spawnCapture();
    const r = installStdioDependency({ name: 'x', mcp: { transport: 'stdio' } }, fn, okVerify);
    assert.equal(r.status, 'not-applicable');
  });

  // AS §1.1 sub-clause 1 — "Every packageName record carries an exact
  // mcp.version and an mcp.integrityShasum hash." An entry missing either
  // must be refused WITHOUT attempting any install (unpinned-install ban).
  test('refuses (reason: unpinned) when version is missing — never spawns', () => {
    const { fn, calls } = spawnCapture();
    const r = installStdioDependency(
      { name: '4fetch', mcp: { transport: 'stdio', packageName: '@amcharts/amcharts5-mcp', integrityShasum: 'a'.repeat(128) } },
      fn,
      okVerify,
    );
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'unpinned');
    assert.equal(calls.length, 0, 'must not spawn npm for an unpinned catalog row');
  });

  test('refuses (reason: unpinned) when integrityShasum is missing — never spawns', () => {
    const { fn, calls } = spawnCapture();
    const r = installStdioDependency(
      { name: '4fetch', mcp: { transport: 'stdio', packageName: '@amcharts/amcharts5-mcp', version: '1.2.0' } },
      fn,
      okVerify,
    );
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'unpinned');
    assert.equal(calls.length, 0);
  });

  // AS §1.1 sub-clause 1 — the install target MUST be the PINNED spec, not
  // a bare package name that npm would resolve against `latest`.
  test('spawns npm install with the exact pinned <packageName>@<version> spec, never a bare name', () => {
    const { fn, calls } = spawnCapture();
    installStdioDependency(PINNED, fn, okVerify);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].argv, ['install', '-g', '--ignore-scripts', '--', '@amcharts/amcharts5-mcp@1.2.0']);
  });

  test('a non-zero exit status reports failed/spawn-failed and never installed', () => {
    const fn: StdioInstallSpawnFn = () => ({ status: 1, signal: null });
    const r = installStdioDependency(PINNED, fn, okVerify);
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'spawn-failed');
  });

  test('a signal-terminated spawn (e.g. SIGKILL on timeout) reports failed/spawn-failed', () => {
    const fn: StdioInstallSpawnFn = () => ({ status: null, signal: 'SIGKILL' });
    const r = installStdioDependency(PINNED, fn, okVerify);
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'spawn-failed');
  });

  test('a spawn error (e.g. ENOENT — npm not on PATH) reports failed/spawn-failed', () => {
    const fn: StdioInstallSpawnFn = () => ({ status: null, signal: null, error: new Error('ENOENT') });
    const r = installStdioDependency(PINNED, fn, okVerify);
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'spawn-failed');
  });

  test('a thrown spawnFn reports failed/spawn-failed rather than propagating', () => {
    const fn: StdioInstallSpawnFn = () => { throw new Error('boom'); };
    const r = installStdioDependency(PINNED, fn, okVerify);
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'spawn-failed');
  });

  // AS §1.1 sub-clause 2 — "No package is acquired on first use" / the
  // installed artifact must be VERIFIED, not merely fetched, before
  // success is reported. A successful `npm install` exit code alone is
  // NOT sufficient (that was the exact shape of the pre-fix defect: a
  // successful install of the WRONG version still exits 0).
  test('verifyNpmIntegrity is called with (packageName, version, integrityShasum) AFTER a successful spawn, and a failure reports failed/integrity-mismatch — never installed', () => {
    const { fn } = spawnCapture();
    const seen: unknown[] = [];
    const verify: VerifyNpmIntegrityFn = (pkg, version, sha) => {
      seen.push([pkg, version, sha]);
      return { ok: false, reason: 'sha mismatch' };
    };
    const r = installStdioDependency(PINNED, fn, verify);
    assert.equal(r.status, 'failed');
    assert.equal((r as { reason: string }).reason, 'integrity-mismatch');
    assert.deepEqual(seen, [['@amcharts/amcharts5-mcp', '1.2.0', 'a'.repeat(128)]]);
  });

  test('installed is reported ONLY when spawn succeeds AND verifyNpmIntegrity confirms ok', () => {
    const { fn } = spawnCapture();
    const r = installStdioDependency(PINNED, fn, okVerify);
    assert.equal(r.status, 'installed');
  });

  // Failure-class: verifyNpmIntegrity must never be reached if the spawn
  // itself never succeeded — a verify call against a package that was
  // never actually installed would be a false-positive risk.
  test('verifyNpmIntegrity is NOT called when the spawn fails', () => {
    let calledVerify = false;
    const fn: StdioInstallSpawnFn = () => ({ status: 1, signal: null });
    const verify: VerifyNpmIntegrityFn = () => { calledVerify = true; return { ok: true }; };
    installStdioDependency(PINNED, fn, verify);
    assert.equal(calledVerify, false);
  });
});
