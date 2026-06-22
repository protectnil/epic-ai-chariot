#!/usr/bin/env node
/**
 * Pre-publish gate: verify every signed catalog artifact in the
 * committed working tree against its .sig file using the same
 * Ed25519 verifier the customer runtime uses.
 *
 * This is the gate that 3.0.6 missed: chariot-adapter-bundle.json
 * was edited without re-signing, the .sig file kept the old
 * signature, CI shipped the broken pair to npm, and every customer
 * install failed with "catalog signature gate failed
 * reason=signature-verification-failed" → "No adapters matched"
 * on every query. This script reads each committed catalog JSON and
 * its sibling .sig and exits non-zero on any verification failure.
 *
 * Invoked from .github/workflows/release.yml (validate job) and from
 * package.json prepublishOnly. Both call paths must succeed before
 * any publish step runs.
 *
 * Hard-coded artifact list: the three signed catalog artifacts that
 * ship in the published tarball. If you add a fourth signed artifact,
 * add it here too.
 *
 * Exit codes:
 *   0  — every artifact verified against its .sig
 *   1  — at least one verification failed
 *   2  — usage / setup error (dist not built, artifact missing, etc.)
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

// Only artifacts that ship their own Ed25519 .sig file. The mcp-registry
// is derivative of the bundle (no own .sig) — see BUNDLE_AUTHORITY.md.
const ARTIFACTS = [
  'chariot-adapter-bundle.json',
  'chariot-adapter-catalog.json',
];

const distVerifier = resolve(ROOT, 'dist/engine/keys/verifyCatalogSignature.js');
if (!existsSync(distVerifier)) {
  console.error('  FAIL: dist/engine/keys/verifyCatalogSignature.js not found.');
  console.error('         Run `npm run build` before invoking this gate.');
  process.exit(2);
}

const { verifyAndReadArtifact } = await import(distVerifier);

let failed = 0;
let passed = 0;
console.log('\n  Pre-publish catalog signature gate\n');

for (const name of ARTIFACTS) {
  const path = resolve(ROOT, name);
  if (!existsSync(path)) {
    console.error(`  FAIL: ${name} missing from repo root`);
    failed += 1;
    continue;
  }
  if (!existsSync(`${path}.sig`)) {
    console.error(`  FAIL: ${name}.sig missing alongside ${name}`);
    failed += 1;
    continue;
  }
  const result = verifyAndReadArtifact(path);
  if (result.ok) {
    console.log(`  OK:   ${name} verified against ${name}.sig (keyId=${result.keyId})`);
    passed += 1;
  } else {
    console.error(`  FAIL: ${name} — reason=${result.reason}${result.detail ? ` detail=${result.detail}` : ''}`);
    console.error(`         Re-run the materializer (see BUNDLE_AUTHORITY.md)`);
    console.error(`         to refresh both the bundle and the .sig together.`);
    failed += 1;
  }
}

console.log('');
console.log(`  Catalog signature gate: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error('');
  console.error('  Refusing publish. A signed-but-tampered artifact reaches');
  console.error('  src/engine/keys/verifyCatalogSignature.ts on the customer');
  console.error('  machine and breaks every adapter query at install time.');
  process.exit(1);
}
process.exit(0);
