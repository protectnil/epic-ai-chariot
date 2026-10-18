/**
 * CHARIOT::§4.7::1 — "The `DomainClassifier` Tier 0 narrowing described in
 * `BUILD-SPEC-CORE-V2.md` Phase 1 is not present in the current source of
 * this package. Only `ToolPreFilter` (Tier 1) operates today."
 * (CHARIOT-SPEC.md:345)
 *
 * This is a constraint on SOURCE PRESENCE, not merely on routing wiring —
 * the acceptance criterion is "No DomainClassifier/Tier-0 present in
 * source; only ToolPreFilter runs." This guard walks the whole source tree
 * (not just the routing path) so the module cannot be reintroduced anywhere
 * — as a standalone file, as a public re-export, or as an import inside a
 * routing-path file (ToolPreFilter, the orchestrator, federation index) —
 * without this test failing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Runs from dist/ (compiled) or src/ — resolve the source tree from the repo root.
const SRC = join(here, '..');
const SELF = fileURLToPath(import.meta.url);

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      walk(p, out);
    } else if (/\.(ts|js|mjs)$/.test(p) && p !== SELF && !p.endsWith('.test.ts')) {
      out.push(p);
    }
  }
  return out;
}

test('DomainClassifier / Tier-0 narrowing is absent from source (CHARIOT::§4.7::1)', () => {
  const offenders: string[] = [];
  for (const f of walk(SRC)) {
    const text = readFileSync(f, 'utf8');
    if (/DomainClassifier/.test(text)) offenders.push(f);
  }
  assert.deepEqual(
    offenders,
    [],
    'DomainClassifier reference(s) found — CHARIOT::§4.7::1 forbids Tier-0 narrowing in source: ' +
      offenders.join(', '),
  );
});
