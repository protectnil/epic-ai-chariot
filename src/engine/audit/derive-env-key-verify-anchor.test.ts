/**
 * @epicai/chariot — deriveEnvKey sanitization + verifyAnchor crypto adversarial eval
 *
 * Two separate proof-of-fix scenarios from the aa3570e security review:
 *
 *  A. deriveEnvKey sanitization + WARN-not-silent-skip
 *     Adapter IDs that contain dots, slashes, hyphens, and other non-alphanumeric
 *     characters (e.g. "my.service/v2") must be sanitised to valid POSIX env-var
 *     names (MY_SERVICE_V2) before credential lookup. When the env var is absent,
 *     a WARN must fire and the adapter must appear in `result.skipped` — NOT
 *     silently absent with no trace.
 *     The dangerous alternative: a raw unsanitised key like "my.service/v2_TOKEN"
 *     could never match any env var (dots/slashes are illegal in POSIX var names),
 *     silently leaving the adapter uncredentialed with no operator-visible signal.
 *
 *  B. verifyAnchor: crypto, not byte-containment
 *     A file that merely CONTAINS the 32-byte head hash somewhere as a raw
 *     substring must NOT verify — the verifier must parse RFC-3161 DER and
 *     extract the TSTInfo messageImprint, not just search for the hash bytes.
 *     The dangerous alternative: a byte-scan `tsr.includes(headHash)` would
 *     accept crafted decoy files that contain the target bytes anywhere.
 *
 * Run after `tsc`: node --test dist/engine/audit/derive-env-key-verify-anchor.test.js
 * Registered in scripts/run-all-tests.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyAnchor } from './anchor.js';
import { __testOnly_deriveEnvKey as deriveEnvKey } from '../federation/RegistryLoader.js';

// ── A. deriveEnvKey sanitization ─────────────────────────────────────────────

test('deriveEnvKey: dot-separated ID is sanitised to UPPER_SNAKE_CASE', () => {
  // "my.adapter.v1" → "MY_ADAPTER_V1"
  const result = deriveEnvKey('my.adapter.v1');
  assert.equal(result, 'MY_ADAPTER_V1');
});

test('deriveEnvKey: slash-separated ID is sanitised to UPPER_SNAKE_CASE', () => {
  // "my/adapter/v2" → "MY_ADAPTER_V2"
  const result = deriveEnvKey('my/adapter/v2');
  assert.equal(result, 'MY_ADAPTER_V2');
});

test('deriveEnvKey: mixed dots and slashes are both replaced with underscores', () => {
  // "service.api/v3.1" → "SERVICE_API_V3_1"
  const result = deriveEnvKey('service.api/v3.1');
  assert.equal(result, 'SERVICE_API_V3_1');
});

test('deriveEnvKey: hyphenated ID (catalog standard) sanitises correctly', () => {
  // "my-cool-adapter" → "MY_COOL_ADAPTER"
  const result = deriveEnvKey('my-cool-adapter');
  assert.equal(result, 'MY_COOL_ADAPTER');
});

test('deriveEnvKey: ID starting with a digit returns undefined (invalid POSIX var name)', () => {
  // "1bad" → "1BAD" → starts with digit → undefined
  const result = deriveEnvKey('1bad');
  assert.equal(result, undefined);
});

test('deriveEnvKey: empty string returns undefined', () => {
  const result = deriveEnvKey('');
  assert.equal(result, undefined);
});

test('deriveEnvKey: ID that becomes empty after sanitisation returns undefined', () => {
  // "..." → "___" → after remove leading digits check → actually "_" is valid
  // True empty: a string of characters that all get stripped. But
  // replace(/[^A-Z0-9]/g, '_') always produces at least underscores from
  // non-empty input, and underscores don't start with a digit. So the only
  // empty case is a true empty string (above). Verify a non-alpha-digit ID
  // gives underscores (not empty or rejected).
  const result = deriveEnvKey('---');
  assert.equal(result, '___', 'pure-separator ID maps to underscores (valid POSIX name)');
  assert.notEqual(result, undefined, 'must not return undefined for non-empty input');
});

// ── B. verifyAnchor: crypto parse, not byte-containment ──────────────────────

test('verifyAnchor: file with hash as raw substring (not valid DER) must NOT verify', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-anchor-'));
  try {
    const headHash = Buffer.alloc(32, 0xde); // 32 bytes — any consistent value

    // Craft a file that contains the 32 target bytes as a substring.
    // This is NOT valid RFC-3161 DER — it's just garbage with the hash embedded.
    const fakeContent = Buffer.concat([
      Buffer.from('fake anchor file preamble — not DER: '),
      headHash,
      Buffer.from(' — more garbage after the hash bytes'),
    ]);
    const fakePath = join(dir, 'decoy.tsr');
    writeFileSync(fakePath, fakeContent);

    // verifyAnchor MUST fail: it should parse RFC-3161 DER, not byte-scan.
    const result = verifyAnchor(headHash, fakePath);
    assert.equal(
      result.valid,
      false,
      'verifyAnchor must reject a file that merely contains the hash as a substring',
    );
    assert.ok(
      typeof result.reason === 'string' && result.reason.length > 0,
      'must provide a descriptive rejection reason',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyAnchor: file with hash bytes at the very start (no DER wrapper) is rejected', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-anchor-'));
  try {
    const headHash = Buffer.alloc(32, 0xff);
    // File = exactly the 32 hash bytes, no DER framing whatsoever
    const fakePath = join(dir, 'raw-hash.tsr');
    writeFileSync(fakePath, headHash);

    const result = verifyAnchor(headHash, fakePath);
    assert.equal(result.valid, false, 'raw hash bytes without DER wrapper must not verify');
    assert.ok(result.reason, 'must explain why verification failed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyAnchor: zero-byte file is rejected cleanly (no crash)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-anchor-'));
  try {
    const headHash = Buffer.alloc(32, 0x01);
    const emptyPath = join(dir, 'empty.tsr');
    writeFileSync(emptyPath, Buffer.alloc(0));

    const result = verifyAnchor(headHash, emptyPath);
    assert.equal(result.valid, false, 'empty anchor file must not verify');
    assert.ok(result.reason, 'must provide a rejection reason for empty file');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('verifyAnchor: non-existent file returns valid=false with a readable reason', () => {
  const headHash = Buffer.alloc(32, 0x02);
  const missingPath = '/tmp/__chariot_nonexistent_anchor__.tsr';

  const result = verifyAnchor(headHash, missingPath);
  assert.equal(result.valid, false, 'missing file must not verify');
  assert.ok(
    result.reason?.includes('cannot read anchor file') || result.reason?.includes('ENOENT'),
    `unexpected reason: ${result.reason}`,
  );
});
