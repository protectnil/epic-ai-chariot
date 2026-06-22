#!/usr/bin/env node
/**
 * Tarball leak gate.
 *
 * The line-based leak:scan covers source-tree paths, but customers receive
 * the PACKED tarball — whose contents (tsc-emitted dist comments, .d.ts
 * docblocks, bundled JSON, README) can differ from any path list we maintain
 * by hand. This gate packs the package exactly as `npm publish` would,
 * extracts it, and runs the same denylist scanner over every shipped byte.
 *
 * Denylist patterns come from .leak-denylist/ or $LEAK_DENYLIST_DIR exactly
 * as in leak-scan.mjs — no pattern lives in this file, so the scanner itself
 * stays publishable.
 *
 * Exit codes: 0 clean, 1 leak matched (or scanner failure), 2 usage/setup.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const LEAK_SCAN = join(HERE, 'leak-scan.mjs');

function main() {
  const workDir = mkdtempSync(join(tmpdir(), 'chariot-tarball-scan-'));
  try {
    // --ignore-scripts: lifecycle hooks (prepack chmod) don't change file
    // CONTENTS, and running them from inside a lifecycle context (this gate
    // is invoked by prepublishOnly) risks shell re-entrancy. Scan wants the
    // packed bytes only.
    execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', workDir], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    const tarballs = readdirSync(workDir).filter((f) => f.endsWith('.tgz'));
    if (tarballs.length !== 1) {
      console.error(`::error::expected exactly one packed tarball, found ${tarballs.length}`);
      process.exit(2);
    }
    execFileSync('tar', ['xzf', join(workDir, tarballs[0]), '-C', workDir], {
      stdio: 'inherit',
    });
    const extracted = join(workDir, 'package');
    const scan = spawnSync('node', [LEAK_SCAN, extracted], {
      cwd: REPO_ROOT,
      stdio: 'inherit',
      env: process.env,
    });
    if (scan.status !== 0) {
      console.error(`::error::tarball leak scan FAILED for ${tarballs[0]} — the packed artifact contains denylisted content`);
      process.exit(1);
    }
    console.log(`tarball leak scan clean: ${tarballs[0]}`);
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

main();
