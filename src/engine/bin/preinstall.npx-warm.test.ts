/**
 * @epicai/chariot — unit tests for `chariot setup --pre-install`'s npx
 * warm path (`warmNpx` → `npmFetch` / `npxInstall`, src/engine/bin/preinstall.ts).
 *
 * W42-FIX (2026-09-04, rulings item 100 — row 1.42 proof, gaps 2 and 3 of 3):
 *
 *   Gap 2: `npm pack --pack-destination <destDir>` does NOT create
 *   `destDir` itself (confirmed empirically against npm 11.19.0 — a fresh,
 *   never-before-used destDir failed ENOENT opening the packed .tgz; see
 *   /tmp/scratch/wave3/w42/run/VERDICT.md). `npmFetch()` now calls
 *   `ensureDir(destDir)` before invoking `npm pack`.
 *
 *   Gap 3: npm keeps TWO separate caches. `npm pack` only populates
 *   `_cacache` (content-addressable download cache); `npx --no-install`
 *   resolves ONLY from the SEPARATE `_npx` execution cache
 *   (`~/.npm/_npx/<hash>/node_modules/`). Confirmed empirically: after
 *   `chariot setup --pre-install` reported WARMED for a pinned npm
 *   adapter, the runtime's own dispatch-time launch
 *   (`npx --no-install <pkg>@<version>`, network off) still failed —
 *   `npm error npx canceled due to missing packages and no YES option` —
 *   because nothing had ever seeded `_npx`. `warmNpx()` now runs a
 *   `npxInstall` post-install step: seed `_npx` via `npm exec --yes
 *   --package=<pkg>@<version> -- true`, re-verify via the injected
 *   `verifyNpmIntegrity`, then dry-probe `npx --no-install --offline
 *   <pkg>@<version>` — WARMED is reported only if all three succeed.
 *
 * Both `spawnInstall` and `verifyNpmIntegrity` are injected (per
 * `PreInstallOptions`) — no real npm registry/network calls, no
 * dependency on host npm cache state. The mock spawnFn's `npm pack`
 * branch writes a small fixture file at the exact filename
 * `npmPackedTarballPath()` expects (`<normalized-pkg>-<version>.tgz`) so
 * the real `sha512OfFile()` verification step in `verifyAndAuditOne()`
 * runs against real bytes rather than being bypassed.
 *
 * Run: node --test dist/engine/bin/preinstall.npx-warm.test.js
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// EPIC_AI_DIR is a module-level const in ../../cli/paths.js, computed from
// EPIC_AI_DIR_OVERRIDE at first import — must be set BEFORE preinstall.ts
// (which transitively imports paths.js) is ever imported in this process.
// node --test runs each matched test file in its own child process, so
// this is isolated from other test files.
const EPIC_AI_TEST_DIR = mkdtempSync(join(tmpdir(), 'chariot-preinstall-test-'));
process.env.EPIC_AI_DIR_OVERRIDE = EPIC_AI_TEST_DIR;

const { runPreInstallWithAdapters } = await import('./preinstall.js');
type PreInstallModule = typeof import('./preinstall.js');
type SpawnInstallFn = PreInstallModule['spawnInstall'];
type AdapterEntryLike = Parameters<PreInstallModule['runPreInstallWithAdapters']>[0][number];

after(() => {
  rmSync(EPIC_AI_TEST_DIR, { recursive: true, force: true });
});

const PKG = '@amcharts/amcharts5-mcp';
const VERSION = '1.2.0';
const NORMALIZED = PKG.replace(/^@/, '').replace('/', '-'); // amcharts-amcharts5-mcp
const TARBALL_NAME = `${NORMALIZED}-${VERSION}.tgz`;
const FIXTURE_BYTES = Buffer.from('chariot-w42-fix-preinstall-test-fixture-tarball-bytes');
const SHA = createHash('sha512').update(FIXTURE_BYTES).digest('hex');

function pinnedAdapter() {
  return {
    id: '4fetch',
    name: '4fetch',
    mcp: { transport: 'stdio', command: 'npx', packageName: PKG, version: VERSION, integrityShasum: SHA },
  } as AdapterEntryLike;
}

/**
 * The mock `npm pack` branch every test below shares: assert the
 * `--pack-destination` dir already exists (gap 2 assertion, made by the
 * caller inspecting `destDirExisted`), then write the fixture tarball at
 * the exact name `npmPackedTarballPath()` looks for so the real SHA-512
 * verification step downstream has real bytes to hash.
 */
function packBranch(argv: string[]): { exitCode: number; stderr: string } {
  const idx = argv.indexOf('--pack-destination');
  const destDir = argv[idx + 1];
  if (!existsSync(destDir)) {
    // Mirrors real npm 11.19.0: `npm pack` itself fails ENOENT if
    // --pack-destination does not already exist.
    return { exitCode: 1, stderr: 'npm error ENOENT: no such file or directory' };
  }
  writeFileSync(join(destDir, TARBALL_NAME), FIXTURE_BYTES);
  return { exitCode: 0, stderr: '' };
}

describe('warmNpx — npmFetch destDir creation (gap 2)', () => {
  test('npm pack is invoked against a --pack-destination dir that ALREADY EXISTS at call time', async () => {
    let destDirAtCallTime: string | undefined;
    let destDirExisted: boolean | undefined;
    const spawnFn: SpawnInstallFn = async (bin, argv) => {
      if (bin === 'npm' && argv[0] === 'pack') {
        const idx = argv.indexOf('--pack-destination');
        destDirAtCallTime = argv[idx + 1];
        destDirExisted = existsSync(destDirAtCallTime);
        return packBranch(argv as string[]);
      }
      return { exitCode: 0, stderr: '' };
    };
    const manifest = await runPreInstallWithAdapters([pinnedAdapter()], {
      only: 'npx',
      spawnInstall: spawnFn,
      verifyNpmIntegrity: () => ({ ok: true }),
    });
    assert.ok(destDirAtCallTime, 'npm pack --pack-destination must have been invoked');
    assert.equal(destDirExisted, true, 'destDir must exist BEFORE npm pack runs (ensureDir fix) — a regression here would reproduce the empirically-confirmed ENOENT');
    assert.equal(manifest.npxPackages[PKG]?.status, 'WARMED');
  });
});

describe('warmNpx — npxInstall _npx cache seeding (gap 3)', () => {
  test('reports WARMED only after npm pack, npm exec (_npx seed), verify, AND npx --no-install --offline probe all succeed, in that order', async () => {
    const calls: string[] = [];
    const spawnFn: SpawnInstallFn = async (bin, argv) => {
      calls.push(`${bin} ${(argv as string[]).join(' ')}`);
      if (bin === 'npm' && argv[0] === 'pack') return packBranch(argv as string[]);
      return { exitCode: 0, stderr: '' };
    };
    let verifyCalledWith: unknown;
    const manifest = await runPreInstallWithAdapters([pinnedAdapter()], {
      only: 'npx',
      spawnInstall: spawnFn,
      verifyNpmIntegrity: (pkg, version, sha) => { verifyCalledWith = [pkg, version, sha]; return { ok: true }; },
    });

    assert.equal(manifest.npxPackages[PKG]?.status, 'WARMED');

    const packCall = calls.findIndex((c) => c.startsWith('npm pack'));
    const seedCall = calls.findIndex((c) => c.includes('npm exec') && c.includes(`--package=${PKG}@${VERSION}`) && c.includes('-- true'));
    const probeCall = calls.findIndex((c) => c.startsWith('npx --no-install --offline') && c.includes(`${PKG}@${VERSION}`));

    assert.notEqual(packCall, -1, 'npm pack must be called');
    assert.notEqual(seedCall, -1, 'npm exec --yes --package=<pkg>@<version> -- true must be called to seed the _npx cache');
    assert.notEqual(probeCall, -1, 'npx --no-install --offline <pkg>@<version> dry probe must be called');
    assert.ok(packCall < seedCall, 'npm pack (fetch+verify) must run before the _npx seed step');
    assert.ok(seedCall < probeCall, '_npx seed must run before the offline dry probe');
    assert.deepEqual(verifyCalledWith, [PKG, VERSION, SHA], 'post-seed re-verify must check the SAME (pkg, version, integrityShasum) triple');
  });

  test('a seed (npm exec) failure reports FAILED and never reaches the offline probe', async () => {
    const calls: string[] = [];
    const spawnFn: SpawnInstallFn = async (bin, argv) => {
      calls.push(`${bin} ${(argv as string[]).join(' ')}`);
      if (bin === 'npm' && argv[0] === 'pack') return packBranch(argv as string[]);
      if (bin === 'npm' && argv[0] === 'exec') return { exitCode: 1, stderr: 'npm error could not resolve package' };
      return { exitCode: 0, stderr: '' };
    };
    const manifest = await runPreInstallWithAdapters([pinnedAdapter()], {
      only: 'npx',
      spawnInstall: spawnFn,
      verifyNpmIntegrity: () => ({ ok: true }),
    });
    assert.equal(manifest.npxPackages[PKG]?.status, 'FAILED');
    assert.ok(!calls.some((c) => c.startsWith('npx --no-install')), 'must not reach the dry probe after a failed _npx seed');
  });

  // The exact failure signature this fix targets — confirmed empirically
  // in VERDICT.md: a tarball can be fully verified in _cacache (npm pack +
  // SHA match) while `npx --no-install` still cannot launch it, because
  // _npx was never seeded. Simulating "seed reports success but the
  // offline probe still can't resolve it" proves the probe is a REAL
  // independent gate, not a rubber stamp.
  test('an offline-probe failure with the VERDICT.md-confirmed npx error text reports FAILED, not WARMED', async () => {
    const spawnFn: SpawnInstallFn = async (bin, argv) => {
      if (bin === 'npm' && argv[0] === 'pack') return packBranch(argv as string[]);
      if (bin === 'npx' && argv[0] === '--no-install') {
        return { exitCode: 1, stderr: 'npm error npx canceled due to missing packages and no YES option' };
      }
      return { exitCode: 0, stderr: '' };
    };
    const manifest = await runPreInstallWithAdapters([pinnedAdapter()], {
      only: 'npx',
      spawnInstall: spawnFn,
      verifyNpmIntegrity: () => ({ ok: true }),
    });
    assert.equal(manifest.npxPackages[PKG]?.status, 'FAILED');
  });

  test('a post-seed integrity re-verify mismatch reports INTEGRITY_MISMATCH, not WARMED', async () => {
    const spawnFn: SpawnInstallFn = async (bin, argv) => {
      if (bin === 'npm' && argv[0] === 'pack') return packBranch(argv as string[]);
      return { exitCode: 0, stderr: '' };
    };
    const manifest = await runPreInstallWithAdapters([pinnedAdapter()], {
      only: 'npx',
      spawnInstall: spawnFn,
      verifyNpmIntegrity: () => ({ ok: false, reason: 'sha512 mismatch' }),
    });
    assert.equal(manifest.npxPackages[PKG]?.status, 'INTEGRITY_MISMATCH');
  });
});
