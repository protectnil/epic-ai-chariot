#!/usr/bin/env node
/**
 * Pre-publish guard: verify the integrity manifest is complete, fresh,
 * and bound to the current release.
 *
 * Checks (all must pass):
 *   1. Manifest exists and is valid JSON
 *   2. Signature is valid (Ed25519 over the signed payload)
 *   3. Manifest version matches package.json version
 *   4. Manifest commit matches HEAD (or is an ancestor of HEAD)
 *   5. All platforms in optionalDependencies have hashes
 *   6. All hashes are valid SHA-256 hex strings
 *
 * Exits 0 if all checks pass, 1 if any fail.
 */

import { readFileSync, existsSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const MANIFEST_PATH = resolve(ROOT, 'native', 'integrity.json');
const PKG_PATH = resolve(ROOT, 'package.json');

const PUBLIC_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEAaAjNCRAxZlceSqsD3HXRK5HaxYlAtDEIyhebMycQUa8=\n' +
  '-----END PUBLIC KEY-----';

const PACKAGE_TO_PLATFORM = {
  '@epicai/chariot-bin-linux-x64-gnu': 'linux-x64',
  '@epicai/chariot-bin-darwin-arm64': 'darwin-arm64',
  '@epicai/chariot-bin-darwin-x64': 'darwin-x64',
  '@epicai/chariot-bin-win32-x64-msvc': 'win32-x64',
};

let exitCode = 0;
function fail(msg) { console.error(`  FAIL: ${msg}`); exitCode = 1; }
function ok(msg) { console.log(`  OK:   ${msg}`); }

function getGitCommit() {
  try {
    return execSync('git rev-parse HEAD', { cwd: ROOT, encoding: 'utf-8' }).trim();
  } catch {
    return null;
  }
}

function isAncestor(commitA, commitB) {
  try {
    execSync(`git merge-base --is-ancestor ${commitA} ${commitB}`, { cwd: ROOT, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

console.log('\n  Integrity Manifest — Pre-publish Verification\n');

// ── 1. Manifest exists ────────────────────────────────────────────────────

if (!existsSync(MANIFEST_PATH)) {
  fail(`Manifest not found at ${MANIFEST_PATH}`);
  console.error('  Run: npm run integrity:sign -- --key <pem> --platform <os-arch>=<path>');
  process.exit(1);
}

// ── 2. Parse manifest ─────────────────────────────────────────────────────

let manifest;
try {
  manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8'));
} catch (e) {
  fail(`Manifest is not valid JSON: ${e.message}`);
  process.exit(1);
}

if (!manifest.hashes || typeof manifest.hashes !== 'object' || !manifest.signature) {
  fail('Manifest has invalid structure (missing hashes or signature).');
  process.exit(1);
}

// ── 3. Verify signature ──────────────────────────────────────────────────

try {
  const publicKey = createPublicKey(PUBLIC_KEY_PEM);
  const sig = Buffer.from(manifest.signature, 'base64');

  // v2 format: signature covers { version, commit, timestamp, hashes }
  let valid = false;
  if (manifest.version && manifest.commit && manifest.timestamp) {
    const payload = JSON.stringify({
      version: manifest.version,
      commit: manifest.commit,
      timestamp: manifest.timestamp,
      hashes: manifest.hashes,
    });
    valid = verify(null, Buffer.from(payload), publicKey, sig);
  }

  // Fallback: v1 format (signature over hashes only)
  if (!valid) {
    const v1Payload = JSON.stringify(manifest.hashes);
    valid = verify(null, Buffer.from(v1Payload), publicKey, sig);
    if (valid) {
      fail('Manifest uses v1 format (no version/commit binding). Regenerate with scripts/sign-integrity.mjs.');
    }
  }

  if (!valid) {
    fail('Manifest signature is invalid. Regenerate with scripts/sign-integrity.mjs.');
    process.exit(1);
  } else if (exitCode === 0) {
    ok('Signature is valid');
  }
} catch (e) {
  fail(`Signature verification error: ${e.message}`);
  process.exit(1);
}

// ── 4. Version freshness ──────────────────────────────────────────────────

const pkg = JSON.parse(readFileSync(PKG_PATH, 'utf-8'));

if (!manifest.version) {
  fail('Manifest has no version field. Regenerate with scripts/sign-integrity.mjs.');
} else if (manifest.version !== pkg.version) {
  fail(`Manifest version "${manifest.version}" does not match package.json "${pkg.version}". ` +
    'The manifest is stale. Regenerate after version bump.');
} else {
  ok(`Version matches: ${manifest.version}`);
}

// ── 5. Commit freshness ──────────────────────────────────────────────────

const headCommit = getGitCommit();

if (!manifest.commit) {
  fail('Manifest has no commit field. Regenerate with scripts/sign-integrity.mjs.');
} else if (!headCommit) {
  console.log('  WARN: Cannot read git HEAD — skipping commit check');
} else if (manifest.commit === headCommit) {
  ok(`Commit matches HEAD: ${headCommit.slice(0, 12)}`);
} else if (isAncestor(manifest.commit, headCommit)) {
  // Manifest commit is an ancestor of HEAD — acceptable if only non-native changes happened since
  console.log(`  WARN: Manifest commit ${manifest.commit.slice(0, 12)} is ancestor of HEAD ${headCommit.slice(0, 12)}`);
  console.log('        Acceptable if no native binary changes since that commit.');
} else {
  fail(`Manifest commit ${manifest.commit.slice(0, 12)} is not HEAD and not an ancestor of HEAD. ` +
    'The manifest may be from a different branch or a force-pushed history.');
}

// ── 6. Platform coverage ──────────────────────────────────────────────────

const optionalDeps = Object.keys(pkg.optionalDependencies || {});
const advertisedPlatforms = optionalDeps
  .filter(dep => dep in PACKAGE_TO_PLATFORM)
  .map(dep => PACKAGE_TO_PLATFORM[dep]);

const manifestPlatforms = Object.keys(manifest.hashes);

console.log(`  Advertised: ${advertisedPlatforms.join(', ')}`);
console.log(`  Manifest:   ${manifestPlatforms.join(', ')}`);

const missing = advertisedPlatforms.filter(p => !manifestPlatforms.includes(p));
if (missing.length > 0) {
  fail(`Missing platform hashes: ${missing.join(', ')}`);
  console.error('  Publishing would break installs on these platforms.');
} else {
  ok(`All ${advertisedPlatforms.length} platforms covered`);
}

// ── 7. Hash format ────────────────────────────────────────────────────────

for (const [plat, hash] of Object.entries(manifest.hashes)) {
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    fail(`Invalid hash format for ${plat}: ${hash}`);
  }
}

// ── Result ────────────────────────────────────────────────────────────────

if (exitCode === 0) {
  console.log(`\n  All checks passed. Ready to publish.\n`);
} else {
  console.error(`\n  Publish blocked. Fix the issues above.\n`);
}

process.exit(exitCode);
