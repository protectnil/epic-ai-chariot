/**
 * cli-bridge dispatch regression — `chariot query "<q>"` cli-bridge dispatch branch
 *
 * cmdQuery (src/engine/bin/setup.ts) routes a natural-language query through
 * the same BM25 engine toolHandlers.ts's `chariot_query` MCP tool uses, then
 * dispatches the matched adapter through its OWN if/else transport chain.
 * Before the fix there was no `adapter.type === 'cli-bridge'` branch at all —
 * every cli-bridge adapter fell straight through to the final `else` and got
 * the transport-fallback refusal:
 *
 *   `No executable transport for adapter "<id>".`  (code DISPATCH_FAILED)
 *
 * even though the SAME adapter dispatches correctly through the MCP-server
 * `chariot_query` tool (toolHandlers.ts), including its AS §1.5
 * operator-approval gate (typed refusal code `CLI_APPROVAL_REQUIRED` when the
 * adapter has not been interactively approved via `chariot approve <id>`).
 *
 * Black-box, implementation-agnostic: spawns the REAL built CLI
 * (dist/bin/chariot.js) as a subprocess — both the `--json` agent path and
 * the human path — against the REAL, signed, shipped catalog's `gh` adapter
 * (type: cli-bridge, no envKeys — no credential required to reach the gate),
 * marked "configured" via a sandboxed EPIC_AI_DIR_OVERRIDE/adapter-state.json
 * (the `isInState` routing-inclusion path in
 * src/engine/federation/configuredAdapterIds.ts). To make the post-approval
 * dispatch outcome (success / non-zero exit / timeout) deterministic and
 * offline, a throwaway executable named `gh` is placed on a directory
 * PREPENDED to PATH for the subprocess — findOnPath resolves it ahead of the
 * real /usr/bin/gh, so the test controls exactly what "the CLI binary" does
 * without touching GitHub or depending on this host's gh auth state. Never
 * imports or asserts on any internal function name the fix introduces.
 *
 * Build first: npm run build
 * Run:         node --test dist/cli/query-cli-bridge-dispatch.test.js
 *
 * NOTE (stdin, per team-lead spec item "adapter whose schema declares stdin
 * gets its stdin payload written"): NOT asserted here — infeasible against
 * the current implementation. `AdapterEntry.cli` / `cli.toolSchemas` (both
 * src/engine/server/ChariotState.ts) carry no `stdin` field of any kind, and
 * the shared spawn primitive both dispatch paths now use,
 * `spawnWithTimeout` (src/engine/server/cliDispatch.ts:75-124), opens the
 * child with `stdio: ['ignore', 'pipe', 'pipe']` — stdin is explicitly
 * /dev/null for every CLI-bridge subprocess, on both the MCP/REST path and
 * this `chariot query` path. There is no stdin-payload contract in this
 * codebase today to test against; flagging rather than fabricating an
 * assertion against a non-existent schema field.
 *
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeAdapterShapeHash, type AdapterShapeInput } from './approval.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/cli/query-cli-bridge-dispatch.test.js → dist/bin/chariot.js
const CLI = resolve(__dirname, '..', 'bin', 'chariot.js');
// dist/cli/ → repo root → chariot-adapter-bundle.json (the same file
// loadAllAdapters() resolves to by default — see
// src/engine/server/ChariotState.ts loadAllAdapters/resolvePublishedArtifactDir).
const CATALOG_PATH = resolve(__dirname, '..', '..', 'chariot-adapter-bundle.json');

// Deliberately shares the exact 3-word phrase "gh repo view" with the
// gh_repo_view tool's OWN indexed description ("gh — gh repo view — GitHub
// CLI — read-only browsing..."; see buildToolsForRouting in
// src/engine/bin/setup.ts), so BM25 (ToolPreFilter's own brand-boost/hoist,
// not cmdQuery's cruder post-hoc pin) ranks that exact tool top —
// deterministic regardless of catalog size or ranking-algorithm tuning.
const QUERY = 'gh repo view for the current repository';
const NO_TRANSPORT_MSG = 'No executable transport for adapter';

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(argv: string[], env: Record<string, string>, timeoutMs = 30000): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...argv], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: timeoutMs,
  });
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Parse the last non-empty JSON line from stdout (agent-mode envelope). */
function parseEnvelope(stdout: string): Record<string, unknown> {
  const lines = stdout.trim().split('\n').filter(Boolean);
  assert.ok(lines.length > 0, 'stdout was empty — no JSON envelope emitted');
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'chariot-bug1001-'));
}

interface CliToolSchema {
  name: string;
  subcommand?: string;
  flags?: Record<string, string>;
  positional?: string[];
}

interface CliBlock {
  binary: string;
  args?: string[];
  toolSchemas: CliToolSchema[];
}

/**
 * Read the REAL shipped `gh` cli-bridge catalog entry's `cli` block from the
 * same signed bundle loadAllAdapters() reads, so the approvedShapeHash
 * fixture below always matches whatever the catalog actually ships — never a
 * hand-invented shape that could silently drift from production and make the
 * approved-dispatch tests pass for the wrong reason.
 */
function readShippedGhCliBlock(): CliBlock {
  const raw = JSON.parse(readFileSync(CATALOG_PATH, 'utf-8')) as {
    registry?: Array<Record<string, unknown>>;
    catalog?: Array<Record<string, unknown>>;
  };
  const pool = raw.registry ?? raw.catalog ?? [];
  const gh = pool.find((a) => a.id === 'gh' && a.type === 'cli-bridge');
  assert.ok(gh, 'fixture precondition: the shipped catalog must carry a "gh" cli-bridge adapter');
  const cli = (gh as { cli?: CliBlock }).cli;
  assert.ok(
    !!cli && typeof cli.binary === 'string' && Array.isArray(cli.toolSchemas),
    'fixture precondition: the "gh" catalog entry must carry a well-formed cli block',
  );
  return cli as CliBlock;
}

/**
 * Write adapter-state.json marking 'gh' configured — the `isInState`
 * routing-inclusion branch of getConfiguredAdapterIds — with the given
 * approval fields (null/null = never approved).
 */
function writeGhState(
  epicAiDir: string,
  approval: { approvedAt: string | null; approvedShapeHash: string | null },
): void {
  mkdirSync(epicAiDir, { recursive: true });
  writeFileSync(
    join(epicAiDir, 'adapter-state.json'),
    JSON.stringify(
      {
        schemaVersion: 1,
        lastHealthCheck: null,
        adapters: {
          gh: {
            type: 'cli-bridge',
            status: 'configured',
            toolCount: 8,
            lastVerified: null,
            approvedAt: approval.approvedAt,
            approvedShapeHash: approval.approvedShapeHash,
          },
        },
      },
      null,
      2,
    ),
  );
}

/**
 * Place a throwaway executable named `gh` in `<root>/fakebin/gh` and return
 * that directory, so prepending it to PATH makes findOnPath('gh') resolve to
 * this script instead of any real gh install on the host. `script` is
 * arbitrary POSIX sh; a literal, already-known marker path can be baked
 * straight into the body (no env-var plumbing needed — CLI_BASE_ENV_ALLOWLIST
 * in src/engine/server/cliDispatch.ts does not pass arbitrary custom env vars
 * into the spawned subprocess, only a fixed allowlist).
 */
function writeFakeGh(root: string, script: string): string {
  const binDir = join(root, 'fakebin');
  mkdirSync(binDir, { recursive: true });
  const ghPath = join(binDir, 'gh');
  writeFileSync(ghPath, `#!/bin/sh\n${script}\n`);
  chmodSync(ghPath, 0o755);
  return binDir;
}

function pathWithFakeBinFirst(binDir: string): string {
  return `${binDir}:${process.env.PATH ?? ''}`;
}

// ── Test 1: --json, adapter configured but UNAPPROVED ───────────────────────
//
// The query matches the cli-bridge adapter and must reach the AS §1.5
// approval gate (typed CLI_APPROVAL_REQUIRED envelope) — never the
// transport-fallback error, and NO subprocess may be spawned (proven by a
// marker-touching fake `gh` that must never fire).

test('cli-bridge query (--json, unapproved): cli-bridge adapter is refused with typed CLI_APPROVAL_REQUIRED, no subprocess spawned, never "No executable transport"', () => {
  const dir = tmp();
  try {
    writeGhState(dir, { approvedAt: null, approvedShapeHash: null });
    const marker = join(dir, 'invoked.marker');
    const binDir = writeFakeGh(dir, `touch '${marker}'\necho '{}'\nexit 0`);

    const r = runCli(['query', QUERY, '--json'], { EPIC_AI_DIR_OVERRIDE: dir, PATH: pathWithFakeBinFirst(binDir) });
    const env = parseEnvelope(r.stdout);

    assert.ok(
      !r.stdout.includes(NO_TRANSPORT_MSG),
      `a configured cli-bridge adapter must never fall through to the transport-fallback error: ${r.stdout}`,
    );
    assert.equal(env.ok, false, `an unapproved cli-bridge adapter must refuse, not succeed: ${JSON.stringify(env)}`);
    assert.notEqual(r.code, 0, 'refusal must exit non-zero (CH-31 honest-signal contract)');
    assert.equal(
      env.code,
      'CLI_APPROVAL_REQUIRED',
      `expected the AS §1.5 typed refusal code CLI_APPROVAL_REQUIRED, got ${JSON.stringify(env)}`,
    );
    assert.ok(
      !existsSync(marker),
      'AS §1.5: the approval gate must refuse BEFORE any subprocess spawn — the fake gh must never have run',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Test 2: human path, adapter configured but UNAPPROVED ───────────────────
//
// Same contract on the human (non --json) path: no crash, no transport-
// fallback text, non-zero exit, no subprocess spawn, and the exact AS §1.5
// operator-facing message (verbatim, shared with toolHandlers.ts's identical
// wording — src/engine/bin/setup.ts cmdQuery cli-bridge branch).

test('cli-bridge query (human, unapproved): cli-bridge adapter prints the AS §1.5 operator message, exits non-zero, no subprocess spawned', () => {
  const dir = tmp();
  try {
    writeGhState(dir, { approvedAt: null, approvedShapeHash: null });
    const marker = join(dir, 'invoked.marker');
    const binDir = writeFakeGh(dir, `touch '${marker}'\necho '{}'\nexit 0`);

    const r = runCli(['query', QUERY], { EPIC_AI_DIR_OVERRIDE: dir, PATH: pathWithFakeBinFirst(binDir) });
    const combined = r.stdout + r.stderr;

    assert.ok(
      !combined.includes(NO_TRANSPORT_MSG),
      `human path must not report the transport-fallback error for a cli-bridge adapter: ${combined}`,
    );
    assert.notEqual(r.code, 0, 'an unapproved CLI adapter must exit non-zero on the human path too');
    assert.match(
      combined,
      /This CLI adapter requires interactive approval before first use/i,
      `human output must carry the exact AS §1.5 operator-facing message: ${combined}`,
    );
    assert.match(combined, /chariot approve/i, `human output must name the remediation command: ${combined}`);
    assert.ok(
      !existsSync(marker),
      'AS §1.5: the approval gate must refuse BEFORE any subprocess spawn — the fake gh must never have run',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Test 3: --json, adapter APPROVED (matching shape hash) → real dispatch ──
//
// Once approved (approvedAt set + the AS §1.5 shape hash over the REAL
// binary/toolSchemas matches), the gate must pass and the fake `gh` must
// actually run — proven both by its marker file AND by its stdout literally
// round-tripping into the envelope's result.

test('cli-bridge query (--json, approved): cli-bridge adapter is actually dispatched — fake gh runs, output flows through, never "No executable transport"', () => {
  const dir = tmp();
  try {
    const cli = readShippedGhCliBlock();
    const shapeHash = computeAdapterShapeHash(cli as unknown as AdapterShapeInput);
    writeGhState(dir, { approvedAt: new Date().toISOString(), approvedShapeHash: shapeHash });

    const marker = join(dir, 'invoked.marker');
    const sentinel = 'chariot-bug1001-fake-gh-output';
    const binDir = writeFakeGh(dir, `touch '${marker}'\necho '${sentinel}'\nexit 0`);

    const r = runCli(['query', QUERY, '--json'], { EPIC_AI_DIR_OVERRIDE: dir, PATH: pathWithFakeBinFirst(binDir) });
    const env = parseEnvelope(r.stdout);

    assert.ok(
      !r.stdout.includes(NO_TRANSPORT_MSG),
      `an approved, dispatchable cli-bridge adapter must never fall back to "No executable transport": ${r.stdout}`,
    );
    assert.notEqual(
      env.code,
      'CLI_APPROVAL_REQUIRED',
      `a correctly-approved adapter (matching AS §1.5 shape hash) must pass the gate: ${JSON.stringify(env)}`,
    );
    assert.ok(existsSync(marker), 'the approved adapter must actually spawn the resolved gh binary');
    assert.equal(env.ok, true, `a clean-exit dispatch must be reported as success: ${JSON.stringify(env)}`);
    const data = env.data as Record<string, unknown> | undefined;
    assert.ok(
      typeof data?.result === 'string' && (data.result as string).includes(sentinel),
      `the subprocess's real stdout must flow through as the result, not a fabricated value: ${JSON.stringify(env)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Test 4: --json, adapter APPROVED, subprocess exits non-zero ─────────────
//
// Required behavior: a non-zero cli-bridge exit must surface as a
// distinctly-typed `CLI_NONZERO_EXIT` envelope — NOT the generic
// DISPATCH_FAILED catch-all cmdQuery uses today for every thrown dispatch
// error (src/engine/bin/setup.ts's outer `catch (err) {...failEnvelope('cli:query','DISPATCH_FAILED',...)}`).
// This assertion is expected to FAIL until that follow-up typing lands —
// it is the regression gate for that specific requirement, not for the dispatch branch's
// original "no cli-bridge branch at all" defect (already covered by Tests 1-3).

test('cli-bridge query (--json, approved, non-zero exit): typed CLI_NONZERO_EXIT envelope, not generic DISPATCH_FAILED', () => {
  const dir = tmp();
  try {
    const cli = readShippedGhCliBlock();
    const shapeHash = computeAdapterShapeHash(cli as unknown as AdapterShapeInput);
    writeGhState(dir, { approvedAt: new Date().toISOString(), approvedShapeHash: shapeHash });

    const binDir = writeFakeGh(dir, `echo 'synthetic failure' >&2\nexit 7`);
    const r = runCli(['query', QUERY, '--json'], { EPIC_AI_DIR_OVERRIDE: dir, PATH: pathWithFakeBinFirst(binDir) });
    const env = parseEnvelope(r.stdout);

    assert.ok(
      !r.stdout.includes(NO_TRANSPORT_MSG),
      `a non-zero cli-bridge exit must never be reported as the transport-fallback error: ${r.stdout}`,
    );
    assert.equal(env.ok, false, `a non-zero exit must be reported as a failure: ${JSON.stringify(env)}`);
    assert.notEqual(r.code, 0, 'a non-zero cli-bridge exit must exit the CLI non-zero too');
    assert.equal(
      env.code,
      'CLI_NONZERO_EXIT',
      `expected the typed code CLI_NONZERO_EXIT (not generic DISPATCH_FAILED), got ${JSON.stringify(env)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Test 5: --json, adapter APPROVED, subprocess hangs past its timeout ─────
//
// Required behavior: a cli-bridge subprocess that outlives its
// timeout must surface as a distinctly-typed `CLI_TIMEOUT` envelope — NOT
// generic DISPATCH_FAILED. spawnWithTimeout (src/engine/server/cliDispatch.ts)
// sends SIGTERM at the adapter's effective timeout (30s default — the
// shipped `gh` catalog row carries no cli.timeoutMs override) then SIGKILL
// after a further 2s grace, so this test genuinely waits ~32s; the harness
// spawnSync timeout is raised accordingly. Same follow-up-gate caveat as
// Test 4 — expected to FAIL until CLI_TIMEOUT typing lands in cmdQuery.

test('cli-bridge query (--json, approved, timeout): typed CLI_TIMEOUT envelope, not generic DISPATCH_FAILED', () => {
  const dir = tmp();
  try {
    const cli = readShippedGhCliBlock();
    const shapeHash = computeAdapterShapeHash(cli as unknown as AdapterShapeInput);
    writeGhState(dir, { approvedAt: new Date().toISOString(), approvedShapeHash: shapeHash });

    // Outlives the 30s default timeoutMs + 2s SIGTERM->SIGKILL grace.
    const binDir = writeFakeGh(dir, `sleep 40`);
    const r = runCli(
      ['query', QUERY, '--json'],
      { EPIC_AI_DIR_OVERRIDE: dir, PATH: pathWithFakeBinFirst(binDir) },
      45000,
    );
    const env = parseEnvelope(r.stdout);

    assert.ok(
      !r.stdout.includes(NO_TRANSPORT_MSG),
      `a timed-out cli-bridge dispatch must never be reported as the transport-fallback error: ${r.stdout}`,
    );
    assert.equal(env.ok, false, `a timeout must be reported as a failure: ${JSON.stringify(env)}`);
    assert.notEqual(r.code, 0, 'a timed-out cli-bridge dispatch must exit the CLI non-zero too');
    assert.equal(
      env.code,
      'CLI_TIMEOUT',
      `expected the typed code CLI_TIMEOUT (not generic DISPATCH_FAILED), got ${JSON.stringify(env)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
