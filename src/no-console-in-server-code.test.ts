/**
 * Production logging goes through the project logger (createLogger), never
 * console.*. This guard covers the server-side trees. The CLI entry points
 * (src/bin, src/engine/bin), the eval harness (src/engine/eval) and the routing
 * harness (src/engine/harness) write their product output to stdout/stderr by
 * design (CH-31/CH-32 machine surface) and are governed separately.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Runs from dist/ (compiled) or src/ — resolve the source tree from the repo root.
const SRC = join(here, '..', 'src');
const EXCLUDE_ENGINE_DIRS = new Set(['bin', 'eval', 'harness']);
const EXCLUDE_SRC_DIRS = new Set(['bin']);

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      if (dir === SRC && EXCLUDE_SRC_DIRS.has(e)) continue;
      if (dir === join(SRC, 'engine') && EXCLUDE_ENGINE_DIRS.has(e)) continue;
      walk(p, out);
    } else if (p.endsWith('.ts') && !p.endsWith('.test.ts') && !p.endsWith('.d.ts') && p !== join(SRC, 'engine', 'logger.ts')) {
      out.push(p);
    }
  }
  return out;
}

test('no console.* logging in server-side production source (use createLogger)', () => {
  const offenders: string[] = [];
  for (const f of walk(SRC)) {
    const text = readFileSync(f, 'utf8');
    text.split('\n').forEach((line, i) => {
      // Ignore operator-advice strings that quote a `node -e "console.log(...)"` one-liner.
      if (/console\.(log|error|warn|info)\(/.test(line) && !/Generate with/.test(line)) offenders.push(`${f}:${i + 1}`);
    });
  }
  assert.deepEqual(offenders, [], 'console.* found in server-side source: ' + offenders.join(', '));
});
