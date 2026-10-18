/**
 * Grep-guard for C4AMD::§8::8 and §8::9 (traceability.spec_nodes):
 *
 *   §8::8: "Opted-in operational telemetry for air-gapped deployments
 *   SHALL leave the environment only through a deliberate,
 *   customer-controlled, redacted and signed export."
 *   §8::9: "No automatic egress or fallback transmission SHALL be
 *   permitted for air-gapped operational telemetry."
 * Ruling item 93: "v4.0 telemetry has NO automatic transport in any
 * mode."
 *
 * This is a source-level, not a runtime, proof: no file under this
 * directory imports anything capable of network egress (a fetch/HTTP/
 * WebSocket client). That means the CODE has no capability to transmit
 * telemetry automatically, in any mode, ever — a stronger guarantee than
 * "we didn't call it in this code path," which a future edit could
 * silently violate without this test catching it.
 *
 * `export.ts` is exempt from the "no fs/write" implication of this test
 * (it deliberately writes a LOCAL file — see its module doc) but is NOT
 * exempt from the network-import ban: it must remain incapable of
 * transmitting the file it writes.
 *
 * SCANS COMPILED OUTPUT, NOT .ts SOURCE (round-3 verification finding,
 * rc=1): `dirname(fileURLToPath(import.meta.url))` resolves to wherever
 * THIS test is actually running from — `dist/observability/
 * operational-telemetry/` once built, never the `src/` tree — so a
 * `.ts`-suffix scan here finds nothing but `.d.ts` declaration files
 * (which also happen to satisfy a naive "ends with .ts" filter and gave
 * test 1 a false pass) and reading `export.ts` in that directory throws
 * ENOENT, since dist/ only ever ships `export.js`. This test therefore
 * scans `.js` (the actual shipped, executable artifact — a stronger
 * proof than scanning pre-compile source anyway) and reads `export.js`,
 * matching this repo's own established convention for colocated tests
 * that inspect a sibling module's compiled output (see
 * audit.gap-detection.test.ts's `readFileSync(... './audit.js' ...)`).
 *
 * Run (after tsc): node --test dist/observability/operational-telemetry/egress-guard.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const dir = dirname(fileURLToPath(import.meta.url));

// Network-capable identifiers this directory's source must never import or
// reference as a bare word (covers `import ... from 'node:http'`, a global
// `fetch(`, `axios`, `XMLHttpRequest`, `net.connect`, `WebSocket`, etc.).
const FORBIDDEN_PATTERNS: RegExp[] = [
  /from\s+['"]node:https?['"]/,
  /require\(\s*['"]node:https?['"]\s*\)/,
  /from\s+['"]node:net['"]/,
  /from\s+['"]axios['"]/,
  /from\s+['"]node-fetch['"]/,
  /\bfetch\s*\(/,
  /\bXMLHttpRequest\b/,
  /\bWebSocket\b/,
  /\.connect\(/,
];

function compiledJsFilesIn(directory: string): string[] {
  return readdirSync(directory)
    .filter((f) => f.endsWith('.js') && !f.endsWith('.test.js'))
    .map((f) => join(directory, f));
}

test('§8::8-9: no compiled file under operational-telemetry/ imports or invokes a network-capable API', () => {
  const files = compiledJsFilesIn(dir);
  assert.ok(files.length >= 3, 'expected capture.js, redact.js, export.js to exist under this directory (dist)');

  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    for (const pattern of FORBIDDEN_PATTERNS) {
      assert.ok(
        !pattern.test(src),
        `${file} matches forbidden network pattern ${pattern} — telemetry must have NO automatic transport (§8::8-9)`,
      );
    }
  }
});

test('§8::8-9: export.js writes only to the local filesystem (node:fs), never a network client', () => {
  const src = readFileSync(join(dir, 'export.js'), 'utf8');
  assert.match(src, /from\s+['"]node:fs['"]/, 'export.js must use node:fs for its local write');
  assert.doesNotMatch(src, /\bfetch\s*\(/, 'export.js must never call fetch');
});
