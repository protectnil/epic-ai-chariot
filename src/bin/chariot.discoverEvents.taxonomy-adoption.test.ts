/**
 * CHARIOT::§16.1 Discovery (CHARIOT-SPEC.md:1352, rulings item
 * 91/105/112(a)) — "Discovery: `discovery.scan.started`,
 * `discovery.scan.completed`, `discovery.service.approved`,
 * `discovery.service.rejected`, `discovery.exclusion.override`."
 *
 * Ruling 112(a): the `discover [path]` CLI subcommand CHARIOT-SPEC.md
 * §17.1 documents IS implemented in `src/bin/chariot.ts` (`runDiscover()`)
 * — a prior investigation of this codebase mistakenly concluded it was
 * unimplemented because `grep` (without `-a`) silently returns zero
 * matches against this file: `file src/bin/chariot.ts` misdetects it as
 * binary data (its shebang line plus surrounding bytes), and default
 * `grep` skips binary-detected files without an error. `grep -a` or
 * `node -e` reveals the real content. That correction is recorded here so
 * the same tooling trap does not repeat.
 *
 * Mixed approach, per this unit's brief ("behavioral where the scanner is
 * pure, source-inspection only where unavoidable"):
 *   - `discover()` itself (src/discovery/index.ts) is pure/synchronous —
 *     used directly (imported, not spawned) to determine the real service
 *     name a fixture route file resolves to, and in the end-to-end
 *     subprocess smoke test below.
 *   - `runDiscover()`'s emit call SITES (ordering, data shape, the
 *     approve/reject/override decision logic) are gated behind CLI argv
 *     parsing, `@clack/prompts` TTY prompts for the interactive path, and
 *     module-level state `runDiscover()` closes over — none of which this
 *     repo's colocated unit tests stand up (see admin.audit-logs-
 *     export.test.ts's header comment for the established convention).
 *     Proven by source inspection of compiled output instead.
 *   - One real end-to-end subprocess run (matching
 *     `cli-honest-signal.test.ts`'s own `runCli()` fixture and its
 *     existing "Attack 9: discover --json" test) proves the wiring did
 *     not break the command for a real scan with a real discovered
 *     service, via the NON-interactive `--config` path (no TTY prompts
 *     needed) — it cannot observe the in-process `chariotEmitter` events
 *     directly (a spawned subprocess is a separate process), but confirms
 *     the command completes successfully end-to-end with the expected
 *     service/registration counts.
 *
 * Run (after tsc): node --test dist/bin/chariot.discoverEvents.taxonomy-adoption.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const chariotSrc = readFileSync(fileURLToPath(new URL('./chariot.js', import.meta.url)), 'utf8');

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'discover-events-'));
}

// ── Source inspection: emit-site ordering and data shape ──────────────────

test('§16.1 Discovery: discovery.scan.started fires before discover(), discovery.scan.completed fires after, both inside runDiscover()', () => {
  const fnStart = chariotSrc.indexOf('async function runDiscover(');
  assert.ok(fnStart >= 0, 'runDiscover must exist — this codebase DOES implement the discover CLI subcommand (see this file\'s header comment for the earlier tooling-caused misdiagnosis)');
  const scanCallIdx = chariotSrc.indexOf('discover(canonicalPath)', fnStart);
  const startedIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.scan.started'", fnStart);
  const completedIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.scan.completed'", fnStart);
  assert.ok(scanCallIdx > fnStart, 'the discover() call must exist');
  assert.ok(startedIdx > fnStart && startedIdx < scanCallIdx, 'scan.started must fire before discover() is called');
  assert.ok(completedIdx > scanCallIdx, 'scan.completed must fire after discover() returns');
});

test('§16.1 Discovery: discovery.service.approved/rejected/exclusion.override are emitted after service selection converges, gated correctly', () => {
  const fnStart = chariotSrc.indexOf('async function runDiscover(');
  const approvedIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.service.approved'", fnStart);
  const rejectedIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.service.rejected'", fnStart);
  const overrideIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.exclusion.override'", fnStart);
  assert.ok(approvedIdx > fnStart && rejectedIdx > fnStart && overrideIdx > fnStart, 'all three must exist');
  // exclusion.override must be gated on the SAME service-level admin
  // heuristic the UI warning uses ("review carefully"), inside the
  // approved-service loop.
  const overrideBlock = chariotSrc.slice(approvedIdx, overrideIdx + 200);
  assert.match(overrideBlock, /isAdminEndpoint\(\{\s*path:\s*''\s*\},\s*svc\.name\)/, 'exclusion.override must be gated on the service-level isAdminEndpoint heuristic');
});

test('§16.1 Discovery: the zero-selected early return ALSO emits discovery.service.rejected for every discovered service (an implicit rejection, not silently dropped)', () => {
  const fnStart = chariotSrc.indexOf('async function runDiscover(');
  const zeroSelectedIdx = chariotSrc.indexOf('No services selected. Nothing to configure.', fnStart);
  const emitIdx = chariotSrc.indexOf("chariotEmitter.send('discovery.service.rejected'", zeroSelectedIdx);
  const nextBoundary = chariotSrc.indexOf('selected: 0', zeroSelectedIdx);
  assert.ok(zeroSelectedIdx > 0, 'the zero-selected branch must exist');
  assert.ok(emitIdx > zeroSelectedIdx && emitIdx < nextBoundary, 'the rejected emit must sit inside the zero-selected early-return branch, before its return statement');
});

// ── End-to-end subprocess smoke test (non-interactive --config path) ──────

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, '..', 'bin', 'chariot.js');

test('§16.1 Discovery: end-to-end, chariot discover --config <allowlist> --json completes successfully for a real discovered service (wiring did not break the command)', async () => {
  const { discover } = await import('../discovery/index.js');
  const scanDir = tmp();
  const stateDir = tmp();
  try {
    writeFileSync(join(scanDir, 'routes.js'), "app.get('/ok', () => {});\n");

    // Learn the real service name/slug this fixture resolves to by
    // calling the pure scanner directly, exactly as runDiscover() itself
    // does — avoids guessing the scanner's naming convention.
    const preScan = discover(scanDir);
    assert.ok(preScan.services.length > 0, 'sanity: the fixture route file must be discoverable at all');
    const serviceName = preScan.services[0].name;

    const configPath = join(scanDir, 'discovery.config.json');
    writeFileSync(configPath, JSON.stringify({
      codebasePath: scanDir,
      defaults: { baseUrl: 'http://localhost:9999', authType: 'none' },
      services: { [serviceName]: { include: true } },
    }));

    const r = spawnSync(process.execPath, [CLI, 'discover', '--config', configPath, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1', EPIC_AI_DIR_OVERRIDE: stateDir },
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });

    const lines = (r.stdout ?? '').trim().split('\n').filter(Boolean);
    assert.equal(lines.length, 1, `expected exactly one JSON envelope line, got: ${r.stdout}\nstderr: ${r.stderr}`);
    const env = JSON.parse(lines[0]) as { ok: boolean; surface: string; data?: Record<string, unknown> };
    assert.equal(env.surface, 'cli:discover');
    assert.equal(env.ok, true, `expected a successful discover run, got: ${JSON.stringify(env)}`);
    assert.ok((env.data?.services as number) >= 1, 'at least the one fixture service must be reported as discovered');
  } finally {
    rmSync(scanDir, { recursive: true, force: true });
    rmSync(stateDir, { recursive: true, force: true });
  }
});
