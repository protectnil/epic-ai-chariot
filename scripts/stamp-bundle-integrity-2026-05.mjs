#!/usr/bin/env node
/**
 *  — One-shot bundle-integrity stamping script.
 *
 * Reads chariot-adapter-bundle.json. For each stdio entry (mcp.transport ===
 * 'stdio' && mcp.command in {npx, uvx}), captures BOTH mcp.version AND
 * mcp.integrityShasum:
 *
 *   npm: `npm view <pkg> dist-tags.latest --json` → version
 *        `npm view <pkg>@<version> dist.integrity --json` → "sha512-<base64>"
 *        Decoded base64 → SHA-512 hex (the same value npm published at
 *        publish time and signs as part of the registry trust chain).
 *
 *   uvx: `uv pip download <pkg> --no-deps --dest <tmp>` produces a wheel
 *        file at <tmp>/<pkg>-<version>-...whl (PEP 427). Parse the version
 *        from the wheel filename. SHA-512 the wheel bytes ourselves.
 *
 * Both fields are written together or not at all (preinstall.ts strict mode
 * rejects half-populated rows).
 *
 * The script is idempotent. When the upstream publication pipeline takes
 * over this stamping responsibility, it will write these fields directly
 * to the published catalog and this script can be deleted.
 *
 * Outputs:
 *   - rewritten chariot-adapter-bundle.json
 *   - report at /tmp/bundle-stamp-report-<UTC-iso>.json listing every
 *     stamped row, every unstampable row (with reason), and a count summary
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync, writeFileSync, createReadStream, mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { runConcurrent, extractStdioPackageName } from '../dist/engine/bin/concurrency.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const BUNDLE_PATH = process.env.CHARIOT_BUNDLE_PATH || join(HERE, '..', 'chariot-adapter-bundle.json');
const CONCURRENCY = Math.max(1, Math.min(16, parseInt(process.env.STAMP_CONCURRENCY || '8', 10)));

const STAMP_TS = new Date().toISOString().replace(/[:.]/g, '-');
const REPORT_PATH = process.env.STAMP_REPORT_PATH || join(tmpdir(), `bundle-stamp-report-${STAMP_TS}.json`);

// ── spawnArgv: argv-only wrapper around child_process.spawn ────────────────

function spawnArgv(binary, argv, timeoutMs, captureStdout = true) {
  return new Promise((resolve) => {
    const child = spawn(binary, argv, {
      shell: false,
      stdio: ['ignore', captureStdout ? 'pipe' : 'ignore', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    child.stdout?.on('data', (c) => {
      if (stdoutBytes >= 1_048_576) return;
      stdoutBytes += c.length;
      stdout += c.toString('utf-8');
    });
    let stderrBytes = 0;
    child.stderr?.on('data', (c) => {
      if (stderrBytes >= 16_384) return;
      stderrBytes += c.length;
      stderr += c.toString('utf-8');
    });
    let settled = false;
    const settle = (exitCode) => { if (!settled) { settled = true; resolve({ exitCode, stdout, stderr }); } };
    const sigterm = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* dead */ }
      const sigkill = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* dead */ } settle(-1); }, 2_000);
      sigkill.unref();
    }, timeoutMs);
    sigterm.unref();
    child.on('error', () => { clearTimeout(sigterm); settle(-2); });
    child.on('close', (c) => { clearTimeout(sigterm); settle(c ?? -1); });
  });
}

// ── npm stamping ────────────────────────────────────────────────────────────

async function stampNpm(pkg) {
  // Single registry round-trip: `npm view <pkg>` without `@<version>` returns
  // the manifest of the version `latest` points at, so dist-tags.latest and
  // dist.integrity can be queried together. With ~hundreds of stdio rows in
  // the bundle this halves stamping wall time vs the two-call form.
  const r = await spawnArgv('npm', ['view', pkg, 'dist-tags.latest', 'dist.integrity', '--json'], 30_000);
  if (r.exitCode !== 0) {
    return { ok: false, reason: `npm view exit ${r.exitCode}: ${r.stderr.slice(0, 200)}` };
  }
  let parsed;
  try { parsed = JSON.parse(r.stdout); }
  catch { return { ok: false, reason: `npm view produced unparseable stdout: ${r.stdout.slice(0, 200)}` }; }
  // `npm view <pkg> field1 field2 --json` returns {field1, field2}; with one
  // field it returns the bare value. We requested two fields, so expect an
  // object with both keys.
  if (typeof parsed !== 'object' || parsed == null) {
    return { ok: false, reason: `npm view returned non-object payload: ${JSON.stringify(parsed).slice(0, 200)}` };
  }
  const version = parsed['dist-tags.latest'];
  const integrity = parsed['dist.integrity'];
  if (typeof version !== 'string' || version.length === 0) {
    return { ok: false, reason: `npm view payload missing dist-tags.latest: ${JSON.stringify(parsed).slice(0, 200)}` };
  }
  if (typeof integrity !== 'string' || !integrity.startsWith('sha512-')) {
    return { ok: false, reason: `npm view payload dist.integrity not sha512: ${JSON.stringify(integrity)}` };
  }
  const hex = Buffer.from(integrity.slice('sha512-'.length), 'base64').toString('hex');
  return { ok: true, version, integrityShasum: hex };
}

// ── uvx stamping ────────────────────────────────────────────────────────────

async function stampUvx(pkg) {
  const dest = mkdtempSync(join(tmpdir(), 'chariot-uvx-stamp-'));
  // Single command produces wheel at <dest>/<pkg>-<version>-...whl
  const d = await spawnArgv('uv', ['pip', 'download', pkg, '--no-deps', '--dest', dest], 120_000);
  if (d.exitCode !== 0) {
    return { ok: false, reason: `uv pip download exit ${d.exitCode}: ${d.stderr.slice(0, 200)}` };
  }
  const files = existsSync(dest) ? readdirSync(dest).filter((f) => f.endsWith('.whl')) : [];
  if (files.length === 0) {
    return { ok: false, reason: `uv pip download succeeded but no .whl in ${dest}` };
  }
  const wheelName = files[0];
  // PEP 427: <distribution>-<version>-<python>-<abi>-<platform>.whl
  const parts = wheelName.slice(0, -'.whl'.length).split('-');
  if (parts.length < 5) {
    return { ok: false, reason: `wheel filename ${wheelName} does not match PEP 427 grammar` };
  }
  const version = parts[1];
  // Streaming hash so concurrent uvx workers do not block the event loop
  // on the full wheel body (Node's readFileSync would serialize them).
  const hex = await new Promise((resolve, reject) => {
    const h = createHash('sha512');
    const s = createReadStream(join(dest, wheelName));
    s.on('error', reject);
    s.on('data', (c) => h.update(c));
    s.on('end', () => resolve(h.digest('hex')));
  });
  return { ok: true, version, integrityShasum: hex };
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log(`[stamp] reading ${BUNDLE_PATH}`);
  const bundle = JSON.parse(readFileSync(BUNDLE_PATH, 'utf-8'));
  const catalog = Array.isArray(bundle.catalog) ? bundle.catalog : [];
  console.log(`[stamp] catalog entries: ${catalog.length}`);

  const npmTargets = [];
  const uvxTargets = [];
  for (const a of catalog) {
    if (a?.mcp?.transport !== 'stdio') continue;
    const pkg = extractStdioPackageName(a);
    if (!pkg) continue;
    if (a.mcp.command === 'npx') npmTargets.push({ adapter: a, pkg });
    else if (a.mcp.command === 'uvx') uvxTargets.push({ adapter: a, pkg });
  }
  console.log(`[stamp] stdio targets: npm=${npmTargets.length} uvx=${uvxTargets.length} concurrency=${CONCURRENCY}`);

  const report = { ranAt: new Date().toISOString(), stamped: [], unstampable: [] };

  function processResult(adapter, pkg, command, r) {
    if (r.ok) {
      adapter.mcp.version = r.version;
      adapter.mcp.integrityShasum = r.integrityShasum;
      report.stamped.push({ id: adapter.id, pkg, command, version: r.version });
    } else {
      report.unstampable.push({ id: adapter.id, pkg, command, reason: r.reason });
    }
  }

  // npm + uvx use different binaries with no shared resource constraint, so
  // their stamping passes run in parallel; halves wall time on bundles with
  // similar npm/uvx target counts.
  await Promise.all([
    runConcurrent(npmTargets, async ({ adapter, pkg }) => processResult(adapter, pkg, 'npx', await stampNpm(pkg)), CONCURRENCY),
    runConcurrent(uvxTargets, async ({ adapter, pkg }) => processResult(adapter, pkg, 'uvx', await stampUvx(pkg)), CONCURRENCY),
  ]);

  report.counts = {
    catalog: catalog.length,
    stamped: report.stamped.length,
    unstampable: report.unstampable.length,
  };

  //  — review pass code review Medium: sort report arrays for
  // deterministic byte output across runs. The bundle's per-row writes are
  // already deterministic (each adapter sets two fixed-string fields), but
  // the report's array order would otherwise reflect worker scheduling.
  // The script's idempotency claim depends on byte-equal artifacts on
  // re-run — both bundle and report — so reviewers can diff with confidence.
  report.stamped.sort((a, b) => a.id.localeCompare(b.id));
  report.unstampable.sort((a, b) => a.id.localeCompare(b.id));

  writeFileSync(BUNDLE_PATH, JSON.stringify(bundle, null, 2) + '\n');
  writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');

  console.log('');
  console.log(`[stamp] wrote bundle to ${BUNDLE_PATH}`);
  console.log(`[stamp] wrote report to ${REPORT_PATH}`);
  console.log(`[stamp] counts: ${JSON.stringify(report.counts)}`);

  if (report.unstampable.length > 0) {
    console.error(`[stamp] WARNING: ${report.unstampable.length} rows could not be stamped — these rows will be refused by preinstall.ts strict mode (INTEGRITY_UNPINNED). Operator must either remove them from the bundle or investigate the unstampable reasons in the report.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('[stamp] FATAL:', err && err.stack ? err.stack : err);
  process.exit(2);
});
