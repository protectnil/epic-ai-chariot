#!/usr/bin/env node
/**
 * Generate and sign the native binary integrity manifest (v2).
 *
 * The manifest binds binary hashes to a specific release:
 *   { version, commit, timestamp, hashes: { platform: sha256 }, signature }
 *
 * The signature covers JSON.stringify({ version, commit, timestamp, hashes }),
 * binding the integrity record to the exact package version and git commit.
 *
 * Usage (full release — all platforms at once):
 *   node scripts/sign-integrity.mjs \
 *     --key <path-to-signing-key>.pem \
 *     --platform linux-x64=/path/to/chariot-native.node \
 *     --platform darwin-arm64=/path/to/chariot-native.node \
 *     --platform darwin-x64=/path/to/chariot-native.node \
 *     --platform win32-x64=/path/to/chariot-native.node
 *
 * Usage (CI incremental — one platform per job, merge into existing):
 *   node scripts/sign-integrity.mjs \
 *     --key <path-to-signing-key>.pem \
 *     --merge native/integrity.json \
 *     --platform darwin-arm64=/path/to/chariot-native.node
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const MANIFEST_PATH = resolve(ROOT, 'native', 'integrity.json');

const PUBLIC_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEAaAjNCRAxZlceSqsD3HXRK5HaxYlAtDEIyhebMycQUa8=\n' +
  '-----END PUBLIC KEY-----';

function usage() {
  console.error(`Usage: node scripts/sign-integrity.mjs --key <pem> --platform <os-arch>=<path> [...]`);
  console.error(`  --key          Path to Ed25519 private key PEM`);
  console.error(`  --platform     Platform=BinaryPath (repeatable)`);
  console.error(`  --merge <path> Merge new hashes into an existing signed manifest`);
  console.error(`  --out <path>   Output path (default: native/integrity.json)`);
  process.exit(1);
}

function getPackageVersion() {
  const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf-8'));
  return pkg.version;
}

function getGitCommit() {
  try {
    return execSync('git rev-parse HEAD', { cwd: ROOT, encoding: 'utf-8' }).trim();
  } catch {
    console.error('Error: cannot read git commit. Are you in a git repository?');
    process.exit(1);
  }
}

/**
 * Build the signed payload object (everything except the signature itself).
 */
function buildSignedPayload(version, commit, timestamp, hashes) {
  return { version, commit, timestamp, hashes };
}

// ── Parse args ────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let keyPath = '';
let mergePath = '';
let outPath = MANIFEST_PATH;
const platforms = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--key' && args[i + 1]) {
    keyPath = args[++i];
  } else if (args[i] === '--platform' && args[i + 1]) {
    const eq = args[++i].indexOf('=');
    if (eq === -1) { console.error(`Invalid --platform: ${args[i]} (expected os-arch=/path)`); usage(); }
    platforms.push({ platform: args[i].slice(0, eq), binaryPath: args[i].slice(eq + 1) });
  } else if (args[i] === '--merge' && args[i + 1]) {
    mergePath = args[++i];
  } else if (args[i] === '--out' && args[i + 1]) {
    outPath = args[++i];
  } else {
    console.error(`Unknown argument: ${args[i]}`);
    usage();
  }
}

if (!keyPath) { console.error('Error: --key is required'); usage(); }
if (platforms.length === 0) { console.error('Error: at least one --platform is required'); usage(); }

// ── Read private key ──────────────────────────────────────────────────────

let privateKey;
try {
  const pem = readFileSync(keyPath, 'utf-8');
  privateKey = createPrivateKey(pem);
} catch (e) {
  console.error(`Failed to read private key at ${keyPath}: ${e.message}`);
  process.exit(1);
}

// ── Resolve version and commit ────────────────────────────────────────────

const version = getPackageVersion();
const commit = getGitCommit();
const timestamp = new Date().toISOString();

console.log(`  Version: ${version}`);
console.log(`  Commit:  ${commit.slice(0, 12)}`);

// ── Merge existing manifest if requested ──────────────────────────────────

let hashes = {};

if (mergePath) {
  if (!existsSync(mergePath)) {
    console.error(`Merge target not found: ${mergePath}`);
    process.exit(1);
  }

  let existing;
  try {
    existing = JSON.parse(readFileSync(mergePath, 'utf-8'));
  } catch (e) {
    console.error(`Merge target is not valid JSON: ${mergePath}: ${e.message}`);
    process.exit(1);
  }

  if (!existing.hashes || typeof existing.hashes !== 'object' || !existing.signature) {
    console.error(`Merge target has invalid structure (missing hashes or signature): ${mergePath}`);
    process.exit(1);
  }

  // Verify the existing manifest signature before trusting its hashes
  try {
    const publicKey = createPublicKey(PUBLIC_KEY_PEM);
    // Support both v1 (signature over hashes only) and v2 (signature over full payload)
    const v2Payload = existing.version
      ? JSON.stringify({ version: existing.version, commit: existing.commit, timestamp: existing.timestamp, hashes: existing.hashes })
      : null;
    const v1Payload = JSON.stringify(existing.hashes);
    const sig = Buffer.from(existing.signature, 'base64');

    const v2Valid = v2Payload && verify(null, Buffer.from(v2Payload), publicKey, sig);
    const v1Valid = verify(null, Buffer.from(v1Payload), publicKey, sig);

    if (!v2Valid && !v1Valid) {
      console.error(`Merge target has an INVALID signature. Refusing to merge untrusted hashes.`);
      process.exit(1);
    }
  } catch (e) {
    console.error(`Merge target signature verification failed: ${e.message}`);
    process.exit(1);
  }

  // Version mismatch check: if existing manifest is for a different version, warn
  if (existing.version && existing.version !== version) {
    console.error(
      `Merge target is for version ${existing.version}, but package.json is ${version}. ` +
      `Existing platform hashes will be carried forward — verify they are from the correct build.`
    );
  }

  hashes = { ...existing.hashes };
  console.log(`  Merging ${Object.keys(hashes).length} existing platform(s): ${Object.keys(hashes).join(', ')}`);
}

// ── Hash each platform binary ─────────────────────────────────────────────

for (const { platform: plat, binaryPath } of platforms) {
  if (!existsSync(binaryPath)) {
    console.error(`Binary not found: ${binaryPath}`);
    process.exit(1);
  }
  const content = readFileSync(binaryPath);
  const hash = createHash('sha256').update(content).digest('hex');
  hashes[plat] = hash;
  console.log(`  ${plat}: ${hash}`);
}

// ── Sort keys for deterministic output ────────────────────────────────────

const sortedHashes = {};
for (const key of Object.keys(hashes).sort()) {
  sortedHashes[key] = hashes[key];
}

// ── Sign the full release record ──────────────────────────────────────────

const payload = buildSignedPayload(version, commit, timestamp, sortedHashes);
const payloadJson = JSON.stringify(payload);
const signature = sign(null, Buffer.from(payloadJson), privateKey).toString('base64');

// ── Write the manifest ────────────────────────────────────────────────────

const manifest = { ...payload, signature };
writeFileSync(outPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(`\n  Manifest written to ${outPath}`);
console.log(`  Platforms: ${Object.keys(sortedHashes).join(', ')}`);
console.log(`  Signature: ${signature.slice(0, 24)}...`);
