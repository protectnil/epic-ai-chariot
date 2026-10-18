/**
 * CHARIOT::§3.1::5-8 — the four on-disk directories in the customer's home
 * directory (CHARIOT-SPEC.md:188-191):
 *   §3.1::5  ~/.epic-ai/models/  — locally-staged retrieval artifacts
 *   §3.1::6  ~/.epic-ai/qdrant/  — bundled local Qdrant data directory
 *   §3.1::7  ~/.epic-ai/cache/   — catalog / tool-schema cache
 *   §3.1::8  ~/.epic-ai/logs/    — wizard / health-check logs
 *
 * `paths.ts` resolves EPIC_AI_DIR (and every path derived from it) ONCE, at
 * module load, from `EPIC_AI_DIR_OVERRIDE`. A same-process re-import would
 * hit Node's ES module cache and silently reuse whatever value was set on
 * the FIRST import — so "with and without the override" is tested by
 * spawning a fresh subprocess per case, the same pattern this repo already
 * uses for module-load-time env resolution (see
 * src/cli/query-cli-bridge-dispatch.test.ts). paths.ts is a leaf module
 * (only node:fs/os/path), so importing the compiled sibling directly in a
 * `node --input-type=module -e` subprocess is fast and has no other
 * dependencies to satisfy.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { homedir } from 'node:os';

interface ResolvedDirs {
  EPIC_AI_DIR: string;
  MODELS_DIR: string;
  QDRANT_DATA_DIR: string;
  CACHE_DIR: string;
  LOGS_DIR: string;
}

function resolveDirsIn(overrideDir: string | undefined): ResolvedDirs {
  const pathsJsUrl = new URL('./paths.js', import.meta.url).href;
  const script = [
    `import * as paths from ${JSON.stringify(pathsJsUrl)};`,
    'process.stdout.write(JSON.stringify({',
    '  EPIC_AI_DIR: paths.EPIC_AI_DIR,',
    '  MODELS_DIR: paths.MODELS_DIR,',
    '  QDRANT_DATA_DIR: paths.QDRANT_DATA_DIR,',
    '  CACHE_DIR: paths.CACHE_DIR,',
    '  LOGS_DIR: paths.LOGS_DIR,',
    '}));',
  ].join('\n');

  const env = { ...process.env };
  if (overrideDir === undefined) {
    delete env.EPIC_AI_DIR_OVERRIDE;
  } else {
    env.EPIC_AI_DIR_OVERRIDE = overrideDir;
  }

  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env,
    encoding: 'utf-8',
  });
  assert.equal(result.status, 0, `subprocess failed: ${result.stderr}`);
  return JSON.parse(result.stdout) as ResolvedDirs;
}

test('without EPIC_AI_DIR_OVERRIDE, all four dirs nest under the real home directory', () => {
  const dirs = resolveDirsIn(undefined);
  const expectedBase = join(homedir(), '.epic-ai');
  assert.equal(dirs.EPIC_AI_DIR, expectedBase);
  assert.equal(dirs.MODELS_DIR, join(expectedBase, 'models'));
  assert.equal(dirs.QDRANT_DATA_DIR, join(expectedBase, 'qdrant'));
  assert.equal(dirs.CACHE_DIR, join(expectedBase, 'cache'));
  assert.equal(dirs.LOGS_DIR, join(expectedBase, 'logs'));
});

test('with EPIC_AI_DIR_OVERRIDE, all four dirs nest under the override, not the real home directory', () => {
  const override = '/tmp/chariot-paths-override-test';
  const dirs = resolveDirsIn(override);
  assert.equal(dirs.EPIC_AI_DIR, override);
  assert.equal(dirs.MODELS_DIR, join(override, 'models'));
  assert.equal(dirs.QDRANT_DATA_DIR, join(override, 'qdrant'));
  assert.equal(dirs.CACHE_DIR, join(override, 'cache'));
  assert.equal(dirs.LOGS_DIR, join(override, 'logs'));
  assert.notEqual(dirs.MODELS_DIR, join(homedir(), '.epic-ai', 'models'));
});

test('the four directories are distinct from each other and from the pre-existing files', () => {
  const dirs = resolveDirsIn('/tmp/chariot-paths-distinct-test');
  const values = [dirs.MODELS_DIR, dirs.QDRANT_DATA_DIR, dirs.CACHE_DIR, dirs.LOGS_DIR];
  assert.equal(new Set(values).size, values.length, 'all four directories must be distinct paths');
});
