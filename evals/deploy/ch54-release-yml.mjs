/**
 * CH-54 adversarial eval — Attack 5
 *
 * release.yml supply-chain hardening assertions from 5ddcb7f:
 *
 *  - All third-party action refs in the sign-image job are pinned to immutable
 *    commit SHAs (no floating @v1 / @v2 / @vN tags in the signing path).
 *  - The sign-image job's `if:` guard requires secrets.AWS_REGION != '' so a
 *    missing region cannot produce a wrong-region OIDC assume.
 *  - A post-sign notation verify step exists immediately after the sign step,
 *    making the job fail-closed: a silent sign failure (zero exit but no
 *    verifiable signature) is caught before the job exits.
 *
 * Reads the REAL file and asserts textual / structural properties.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const YML_PATH = join(__dirname, '..', '..', '.github', 'workflows', 'release.yml');

const yml = readFileSync(YML_PATH, 'utf-8');
const lines = yml.split('\n');

// ── Helper: extract lines in the sign-image job ───────────────────────────────

// Find the sign-image job block (from "sign-image:" to the next top-level job).
let signImageStart = -1;
let signImageEnd   = lines.length;

for (let i = 0; i < lines.length; i++) {
  if (/^\s{2}sign-image:\s*$/.test(lines[i])) {
    signImageStart = i;
  } else if (signImageStart >= 0 && /^\s{2}\S/.test(lines[i]) && i > signImageStart) {
    // Next top-level job (2-space indent, non-blank)
    signImageEnd = i;
    break;
  }
}

assert.ok(signImageStart >= 0, 'sign-image job not found in release.yml');

const signImageBlock = lines.slice(signImageStart, signImageEnd).join('\n');

// ── Attack 5a — SHA-pinned action in the signing path ────────────────────────

test('release.yml — notation-action/setup is pinned to commit SHA (not @v1)', () => {
  // Positive: SHA pin present
  assert.match(
    signImageBlock,
    /notation-action\/setup@[0-9a-f]{40}/,
    'notation-action/setup must be pinned to a 40-hex-char commit SHA in the sign-image job',
  );
  // Negative: no floating @v1/v2 tags allowed on the signing path
  assert.doesNotMatch(
    signImageBlock,
    /notation-action\/setup@v\d+(?!\w)/,
    'notation-action/setup must NOT use a floating @vN tag (supply-chain risk)',
  );
});

test('release.yml — configure-aws-credentials is pinned to commit SHA in sign-image', () => {
  assert.match(
    signImageBlock,
    /configure-aws-credentials@[0-9a-f]{40}/,
    'configure-aws-credentials must be pinned to a 40-hex-char commit SHA',
  );
  assert.doesNotMatch(
    signImageBlock,
    /configure-aws-credentials@v\d+(?!\w)/,
    'configure-aws-credentials must NOT use a floating @vN tag',
  );
});

// ── Attack 5b — AWS_REGION != '' in the if-guard ─────────────────────────────

test('release.yml — sign-image if-guard requires secrets.AWS_REGION != empty string', () => {
  // The CH-54 fix added secrets.AWS_REGION != '' to the job-level `if:`.
  // Without it, a job with no region env can produce a wrong-region OIDC token.
  assert.match(
    signImageBlock,
    /secrets\.AWS_REGION\s*!=\s*''/,
    `sign-image if-guard must contain "secrets.AWS_REGION != ''" to prevent wrong-region OIDC\n` +
    `Found sign-image block:\n${signImageBlock.slice(0, 600)}`,
  );
});

// ── Attack 5c — post-sign verify step exists ─────────────────────────────────

test('release.yml — post-sign notation verify step exists after sign step (fail-closed)', () => {
  // The CH-54 fix adds an explicit "Verify image signature with Notation (post-sign)"
  // step so a silent sign failure (exit 0, no verifiable signature) is caught.
  assert.match(
    signImageBlock,
    /verify.*signature.*notation.*post.sign|post.sign.*verify|notation.*verify/i,
    'sign-image job must contain a post-sign notation verify step',
  );
});

test('release.yml — post-sign step uses --emit-verify-args (shared argv source of truth)', () => {
  // scripts/release.mjs --emit-verify-args ensures the verify step uses the
  // same argv builder as the sign step (image-seal.mjs notationVerifyCommand),
  // preventing a divergence where sign passes but verify never actually runs
  // the real check.
  assert.match(
    signImageBlock,
    /--emit-verify-args/,
    'post-sign verify must use --emit-verify-args (shared source of truth via release.mjs)',
  );
});

// ── Attack 5d — NOTATION_CONFIG exported before verify ───────────────────────

test('release.yml — NOTATION_CONFIG is set in post-sign verify step (CH-54 trust-dir injection)', () => {
  // CH-54 requires NOTATION_CONFIG to be exported so notation resolves
  // trustpolicy.json and the trust store from the shipped notation base dir,
  // not the runner default which has no trust material.
  assert.match(
    signImageBlock,
    /NOTATION_CONFIG/,
    'sign-image block must set NOTATION_CONFIG (CH-54 trust-dir injection)',
  );
  assert.match(
    signImageBlock,
    /export NOTATION_CONFIG/,
    'sign-image block must export NOTATION_CONFIG so the notation subprocess sees it',
  );
});
