#!/usr/bin/env node
/**
 * Chariot rollback driver.
 *
 * Deprecates @epicai/chariot@<X.Y.Z> and all four native sibling
 * packages in lockstep, then resets the npm `latest` dist-tag on
 * @epicai/chariot to a known-good prior version. Idempotent — re-running
 * against an already-deprecated version is a verified no-op, and resetting
 * the dist-tag to its current value is a no-op.
 *
 * See docs/RUNBOOK-ROLLBACK.md for the surrounding procedure.
 *
 *   NPM_TOKEN=<automation-token> node scripts/rollback.mjs \
 *     --version <X.Y.Z> \
 *     --reason "<short message; surfaced to npm consumers>" \
 *     --reset-latest-to <X.Y.Z-good>
 *
 * Without --reset-latest-to, deprecation alone leaves `latest` pointed at
 * the deprecated broken version and `npm install @epicai/chariot` still
 * installs the deprecated tarball with only a non-fatal warning.
 * The flag is required for any rollback of the package currently on
 * `latest`; pass --no-reset-latest to skip when rolling back a non-latest
 * version (e.g. a deprecation of an old line that does not own `latest`).
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PACKAGES = [
  '@epicai/chariot-bin-linux-x64-gnu',
  '@epicai/chariot-bin-darwin-arm64',
  '@epicai/chariot-bin-darwin-x64',
  '@epicai/chariot-bin-win32-x64-msvc',
  '@epicai/chariot',
];

function usage(code = 1) {
  console.error('Usage: node scripts/rollback.mjs --version <X.Y.Z> --reason "<message>" --reset-latest-to <X.Y.Z-good>');
  console.error('       node scripts/rollback.mjs --version <X.Y.Z> --reason "<message>" --no-reset-latest');
  console.error('Environment: NPM_TOKEN must be set to an automation token with publish/deprecate scope.');
  process.exit(code);
}

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

const args = process.argv.slice(2);
let version = '';
let reason = '';
let resetLatestTo = '';
let noResetLatest = false;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--version') version = args[++i] || '';
  else if (a === '--reason') reason = args[++i] || '';
  else if (a === '--reset-latest-to') resetLatestTo = args[++i] || '';
  else if (a === '--no-reset-latest') noResetLatest = true;
  else if (a === '--help' || a === '-h') usage(0);
  else {
    console.error(`Unknown argument: ${a}`);
    usage(1);
  }
}

if (!SEMVER_RE.test(version)) {
  console.error(`Invalid --version: ${JSON.stringify(version)}`);
  usage(1);
}
if (!reason || reason.length < 12) {
  console.error('--reason is required and must be at least 12 characters (surfaced to npm consumers).');
  usage(1);
}
if (!noResetLatest && !resetLatestTo) {
  console.error('Either --reset-latest-to <X.Y.Z-good> or --no-reset-latest is required.');
  console.error('Pass --reset-latest-to when the rollback target is the current `latest` (otherwise npm install still resolves to the deprecated version).');
  console.error('Pass --no-reset-latest only when rolling back a version that does not own the `latest` dist-tag.');
  usage(1);
}
if (resetLatestTo && !SEMVER_RE.test(resetLatestTo)) {
  console.error(`Invalid --reset-latest-to: ${JSON.stringify(resetLatestTo)}`);
  usage(1);
}
if (resetLatestTo && resetLatestTo === version) {
  console.error('--reset-latest-to cannot equal --version (would point `latest` at the deprecated tarball).');
  process.exit(1);
}
if (!process.env.NPM_TOKEN) {
  console.error('NPM_TOKEN env var is required (automation token with deprecate scope).');
  process.exit(1);
}

const npmrcDir = mkdtempSync(join(tmpdir(), 'chariot-rollback-'));
const npmrcPath = join(npmrcDir, '.npmrc');
writeFileSync(
  npmrcPath,
  `//registry.npmjs.org/:_authToken=${process.env.NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n`,
  { mode: 0o600 },
);

let exitCode = 0;
try {
  const missing = [];
  for (const pkg of PACKAGES) {
    const res = spawnSync('npm', ['view', `${pkg}@${version}`, 'version', `--userconfig=${npmrcPath}`], {
      encoding: 'utf8',
    });
    const ok = res.status === 0 && res.stdout.trim() === version;
    if (!ok) missing.push(pkg);
    console.log(`  view ${pkg}@${version}: ${ok ? 'present' : 'MISSING'}`);
  }
  if (missing.length > 0) {
    console.error(`\nCannot proceed — these packages are not at ${version} on the registry:`);
    for (const m of missing) console.error(`  - ${m}`);
    process.exit(2);
  }

  for (const pkg of PACKAGES) {
    const current = spawnSync('npm', ['view', `${pkg}@${version}`, 'deprecated', `--userconfig=${npmrcPath}`], {
      encoding: 'utf8',
    });
    const existing = (current.stdout || '').trim();
    if (existing === reason) {
      console.log(`  ${pkg}@${version}: already deprecated with this reason — no-op`);
      continue;
    }

    const dep = spawnSync('npm', ['deprecate', `${pkg}@${version}`, reason, `--userconfig=${npmrcPath}`], {
      stdio: 'inherit',
    });
    if (dep.status !== 0) {
      console.error(`  ${pkg}@${version}: deprecate FAILED (exit ${dep.status})`);
      exitCode = 3;
      continue;
    }

    const verify = spawnSync('npm', ['view', `${pkg}@${version}`, 'deprecated', `--userconfig=${npmrcPath}`], {
      encoding: 'utf8',
    });
    const got = (verify.stdout || '').trim();
    if (got !== reason) {
      console.error(`  ${pkg}@${version}: deprecate verify mismatch (expected ${JSON.stringify(reason)}, got ${JSON.stringify(got)})`);
      exitCode = 4;
      continue;
    }
    console.log(`  ${pkg}@${version}: DEPRECATED`);
  }

  if (exitCode === 0 && resetLatestTo) {
    // Reset latest dist-tag on @epicai/chariot so new installs resolve
    // to the known-good version. Sibling packages do not carry
    // their own `latest` semantics for end users (they're resolved via
    // optionalDependencies on the main package), so only the main
    // package's dist-tag is touched here.
    const goodPresent = spawnSync('npm', ['view', `@epicai/chariot@${resetLatestTo}`, 'version', `--userconfig=${npmrcPath}`], {
      encoding: 'utf8',
    });
    if (goodPresent.status !== 0 || goodPresent.stdout.trim() !== resetLatestTo) {
      console.error(`\nCannot reset latest: @epicai/chariot@${resetLatestTo} is not on the registry. Skipping dist-tag reset; latest still points at the deprecated version.`);
      exitCode = 5;
    } else {
      const currentLatest = spawnSync('npm', ['view', '@epicai/chariot', 'dist-tags.latest', `--userconfig=${npmrcPath}`], {
        encoding: 'utf8',
      });
      const currentLatestVal = (currentLatest.stdout || '').trim();
      if (currentLatestVal === resetLatestTo) {
        console.log(`  @epicai/chariot dist-tag latest: already ${resetLatestTo} — no-op`);
      } else {
        const tag = spawnSync('npm', ['dist-tag', 'add', `@epicai/chariot@${resetLatestTo}`, 'latest', `--userconfig=${npmrcPath}`], {
          stdio: 'inherit',
        });
        if (tag.status !== 0) {
          console.error(`  @epicai/chariot dist-tag latest -> ${resetLatestTo}: FAILED (exit ${tag.status})`);
          exitCode = 6;
        } else {
          const verifyLatest = spawnSync('npm', ['view', '@epicai/chariot', 'dist-tags.latest', `--userconfig=${npmrcPath}`], {
            encoding: 'utf8',
          });
          const gotLatest = (verifyLatest.stdout || '').trim();
          if (gotLatest !== resetLatestTo) {
            console.error(`  @epicai/chariot dist-tag latest verify mismatch (expected ${resetLatestTo}, got ${JSON.stringify(gotLatest)})`);
            exitCode = 7;
          } else {
            console.log(`  @epicai/chariot dist-tag latest -> ${resetLatestTo}: SET`);
          }
        }
      }
    }
  }
} finally {
  try {
    rmSync(npmrcDir, { recursive: true, force: true });
  } catch {
    // best-effort cleanup; .npmrc had 0600 perms and tmp dir is process-scoped
  }
}

if (exitCode !== 0) {
  console.error(`\nRollback finished with errors (exit ${exitCode}). Re-run after triage.`);
  process.exit(exitCode);
}

if (resetLatestTo) {
  console.log(`\nRollback of ${version} complete. All ${PACKAGES.length} packages deprecated and @epicai/chariot dist-tag latest reset to ${resetLatestTo}.`);
} else {
  console.log(`\nRollback of ${version} complete. All ${PACKAGES.length} packages deprecated (latest dist-tag not touched per --no-reset-latest).`);
}
console.log('Next: file GHSA if class A, then ship corrected version per docs/RUNBOOK-ROLLBACK.md.');
