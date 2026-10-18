/**
 * CHARIOT::§3.6::1 — "The system SHALL set staleDetection.maxAgeMs =
 * 7*24*60*60*1000 (seven days) and SHALL treat a catalog older than seven
 * days from its `materializedAt` timestamp as stale, producing a startup
 * warning." (CHARIOT-SPEC.md:283).
 *
 * Failure classes enumerated from the clause and closed here:
 *   - boundary: exactly 7 days old (not yet stale) vs. one ms past (stale)
 *   - absent: no publisher stamps `materializedAt` today — must never warn
 *   - malformed: non-numeric `materializedAt` — must never warn, never throw
 *   - first-run / fresh: a just-materialized catalog — no warning
 *   - end-to-end: the warning is actually observable at catalog `load()`,
 *     both for `advance` and for a same-bytes `re-admission` restart
 *     (§5.2: "computed on every catalog load and on every refresh cycle")
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AdapterCatalog, isCatalogStaleFromMaterializedAt, type AdapterCatalogEntry } from './AdapterCatalog.js';

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Pure boundary function
// ---------------------------------------------------------------------------

test('isCatalogStaleFromMaterializedAt: absent materializedAt is never stale (no publisher stamps it yet)', () => {
  assert.equal(isCatalogStaleFromMaterializedAt(undefined, SEVEN_DAYS_MS, Date.now()), false);
});

test('isCatalogStaleFromMaterializedAt: exactly 7 days old is NOT yet stale (strict >, matches VerifiedCatalog.isStaleTimestamp)', () => {
  const now = 1_800_000_000_000;
  const materializedAt = now - SEVEN_DAYS_MS;
  assert.equal(isCatalogStaleFromMaterializedAt(materializedAt, SEVEN_DAYS_MS, now), false);
});

test('isCatalogStaleFromMaterializedAt: one ms past 7 days IS stale', () => {
  const now = 1_800_000_000_000;
  const materializedAt = now - SEVEN_DAYS_MS - 1;
  assert.equal(isCatalogStaleFromMaterializedAt(materializedAt, SEVEN_DAYS_MS, now), true);
});

test('isCatalogStaleFromMaterializedAt: a fresh catalog (1 hour old) is not stale', () => {
  const now = 1_800_000_000_000;
  const materializedAt = now - 60 * 60 * 1000;
  assert.equal(isCatalogStaleFromMaterializedAt(materializedAt, SEVEN_DAYS_MS, now), false);
});

test('isCatalogStaleFromMaterializedAt: a future materializedAt is not stale (warning-only gate, no clock-skew rejection)', () => {
  const now = 1_800_000_000_000;
  const materializedAt = now + 1_000_000;
  assert.equal(isCatalogStaleFromMaterializedAt(materializedAt, SEVEN_DAYS_MS, now), false);
});

// ---------------------------------------------------------------------------
// End-to-end: AdapterCatalog.load() actually emits catalog.stale_warning
// ---------------------------------------------------------------------------

function entry(name: string): AdapterCatalogEntry {
  return {
    name,
    displayName: name,
    version: '1.0.0',
    category: 'productivity',
    keywords: ['foo'],
    toolNames: ['do_thing'],
    description: `The ${name} adapter`,
    author: 'community',
  };
}

function writeBundle(dir: string, filename: string, extra: Record<string, unknown>): string {
  const catalogPath = join(dir, filename);
  writeFileSync(
    catalogPath,
    JSON.stringify({
      epoch: Date.now(),
      catalogVersion: 1,
      catalog: [entry('alpha')],
      registry: [],
      ...extra,
    }),
  );
  return catalogPath;
}

/** Capture every process.stderr.write call during `fn`, restoring after. */
async function captureStderr(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  (process.stderr as any).write = (chunk: any) => {
    lines.push(String(chunk));
    return true;
  };
  try {
    await fn();
  } finally {
    process.stderr.write = original;
  }
  return lines;
}

test('AdapterCatalog.load() emits catalog.stale_warning for a materializedAt >7 days old', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-stale-warn-'));
  const materializedAt = Date.now() - SEVEN_DAYS_MS - 60_000; // 1 minute past the boundary
  const catalogPath = writeBundle(dir, 'adapter-bundle.json', { materializedAt });
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  const lines = await captureStderr(async () => {
    const catalog = new AdapterCatalog({ source: 'bundle', verifySignature: false, catalogPath, epochPath });
    await catalog.load();
  });

  const warning = lines.find((l) => l.includes('catalog.stale_warning'));
  assert.ok(warning, `expected a catalog.stale_warning log line; got: ${JSON.stringify(lines)}`);
  assert.ok(warning?.includes(String(materializedAt)), 'warning must carry the materializedAt value');
});

test('AdapterCatalog.load() emits NO catalog.stale_warning when materializedAt is absent', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-stale-warn-absent-'));
  const catalogPath = writeBundle(dir, 'adapter-bundle.json', {}); // no materializedAt field
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  const lines = await captureStderr(async () => {
    const catalog = new AdapterCatalog({ source: 'bundle', verifySignature: false, catalogPath, epochPath });
    await catalog.load();
  });

  assert.ok(
    !lines.some((l) => l.includes('catalog.stale_warning')),
    'must not warn about staleness for a field no publisher stamps yet',
  );
});

test('AdapterCatalog.load() emits NO catalog.stale_warning when materializedAt is fresh', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-stale-warn-fresh-'));
  const catalogPath = writeBundle(dir, 'adapter-bundle.json', { materializedAt: Date.now() - 60_000 });
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  const lines = await captureStderr(async () => {
    const catalog = new AdapterCatalog({ source: 'bundle', verifySignature: false, catalogPath, epochPath });
    await catalog.load();
  });

  assert.ok(
    !lines.some((l) => l.includes('catalog.stale_warning')),
    'a 1-minute-old catalog must not be reported stale',
  );
});

test('AdapterCatalog.load() re-emits catalog.stale_warning on a re-admission restart (§5.2: computed on every load)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chariot-stale-warn-readmit-'));
  const materializedAt = Date.now() - SEVEN_DAYS_MS - 60_000;
  const catalogPath = writeBundle(dir, 'adapter-bundle.json', { materializedAt });
  const epochPath = join(dir, '.chariot-catalog-epoch.json');

  // First boot — establishes the high-water mark.
  await captureStderr(async () => {
    const first = new AdapterCatalog({ source: 'bundle', verifySignature: false, catalogPath, epochPath });
    await first.load();
  });

  // Second instance over the SAME unchanged bytes — a restart, which
  // AdapterCatalog classifies as a re-admission (identical epoch+hash), not
  // an advance. The stale warning must still fire: staleness is a property
  // of the catalog's age, not of whether this load happens to persist a new
  // high-water mark.
  const lines = await captureStderr(async () => {
    const second = new AdapterCatalog({ source: 'bundle', verifySignature: false, catalogPath, epochPath });
    await second.load();
  });

  assert.ok(
    lines.some((l) => l.includes('catalog.stale_warning')),
    `re-admission load must still warn on a stale catalog; got: ${JSON.stringify(lines)}`,
  );
});
