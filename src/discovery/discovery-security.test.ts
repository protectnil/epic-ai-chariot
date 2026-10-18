// Discovery security regressions — (silent oversize-file drop;
// CH-31, CHARIOT::§23.2::45 "a real failure SHALL NOT present as
// exit-0/✓/isError:false") and (config-file content-disclosure
// oracle; the bug's graph edge is CHARIOT §23.2, whose decomposition carries
// no node governing raw error-text disclosure — the assertion below is the
// binding contract for that half).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  collectOversizeSkippedFiles,
  loadDiscoveryConfigFile,
  MAX_DISCOVERY_FILE_BYTES,
} from './helpers.js';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'discovery-sec-'));
}

// ── oversize candidate files are reported, not silently dropped ──────────────

test('a >cap .ts source file is reported as skipped-with-reason', () => {
  const dir = tmp();
  try {
    const big = join(dir, 'routes.ts');
    writeFileSync(big, Buffer.alloc(MAX_DISCOVERY_FILE_BYTES + 1, 0x61)); // >4 MiB
    const small = join(dir, 'small.ts');
    writeFileSync(small, "app.get('/ok', () => {});\n");

    const skipped = collectOversizeSkippedFiles(dir);
    assert.equal(skipped.length, 1, 'exactly the oversize file is reported');
    assert.equal(skipped[0].filePath, big);
    assert.ok(skipped[0].bytes > MAX_DISCOVERY_FILE_BYTES);
    assert.match(skipped[0].reason, /read cap/i, 'reason states why it was skipped');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a >cap oversize openapi.json spec is reported', () => {
  const dir = tmp();
  try {
    const spec = join(dir, 'openapi.json');
    writeFileSync(spec, Buffer.alloc(MAX_DISCOVERY_FILE_BYTES + 10, 0x7b));
    const skipped = collectOversizeSkippedFiles(dir);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].filePath, spec);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('files under the cap and pruned dirs produce no false skips', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'under.ts'), Buffer.alloc(1024, 0x61));
    // A non-candidate large file (e.g. a big binary asset) must be ignored.
    writeFileSync(join(dir, 'blob.bin'), Buffer.alloc(MAX_DISCOVERY_FILE_BYTES + 1, 0x00));
    // An oversize candidate inside a pruned dir must be ignored (scanner skips it).
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'huge.ts'), Buffer.alloc(MAX_DISCOVERY_FILE_BYTES + 1, 0x61));
    const skipped = collectOversizeSkippedFiles(dir);
    assert.equal(skipped.length, 0, 'no false positives from small/non-candidate/pruned files');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── config loader must never echo file bytes ─────────────────────────────────

test('pointing --config at /etc/passwd-like content leaks zero bytes', () => {
  const dir = tmp();
  try {
    // Reproduce the disclosure vector without touching /etc/passwd: a
    // non-JSON secret-shaped file. A naive JSON.parse SyntaxError would embed
    // its leading bytes ("root:x:0:0") in the thrown message.
    const secret = join(dir, 'passwd');
    const secretBody = 'root:x:0:0:root:/root:/bin/bash\nSUPERSECRETVALUE\n';
    writeFileSync(secret, secretBody);

    assert.throws(
      () => loadDiscoveryConfigFile(secret),
      (err: unknown) => {
        const msg = (err as Error).message;
        // The error must be typed/content-free: none of the file's bytes.
        assert.ok(!msg.includes('root:x'), `must not leak file bytes: ${msg}`);
        assert.ok(!msg.includes('SUPERSECRET'), `must not leak file bytes: ${msg}`);
        assert.ok(!/is not valid JSON/i.test(msg), 'must not surface raw JSON.parse SyntaxError');
        assert.match(msg, /discovery config/i, 'typed discovery-config error');
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a valid-JSON but non-config file is rejected without echoing content', () => {
  const dir = tmp();
  try {
    const f = join(dir, 'other.json');
    writeFileSync(f, JSON.stringify({ someUnrelated: 'PAYLOAD_SHOULD_NOT_LEAK', nested: { a: 1 } }));
    assert.throws(
      () => loadDiscoveryConfigFile(f),
      (err: unknown) => {
        const msg = (err as Error).message;
        assert.ok(!msg.includes('PAYLOAD_SHOULD_NOT_LEAK'), `must not leak content: ${msg}`);
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a well-formed discovery config still loads', () => {
  const dir = tmp();
  try {
    const f = join(dir, 'discovery.config.json');
    writeFileSync(f, JSON.stringify({
      codebasePath: '/tmp/app',
      defaults: { baseUrl: 'https://api.example.com', authType: 'none' },
      services: { 'svc-abc': { include: true } },
    }));
    const cfg = loadDiscoveryConfigFile(f);
    assert.equal(cfg.codebasePath, '/tmp/app');
    assert.equal(cfg.defaults.authType, 'none');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
