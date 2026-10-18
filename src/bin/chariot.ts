#!/usr/bin/env node

// bug-tracker-ref: DEP0040 punycode deprecation surfaces on Node 21+ when any
// transitive dep resolves `require('punycode')` to Node's internal
// (deprecated) module. Suppress ONLY DEP0040; surface every other
// deprecation/warning normally.
//
// Strip every existing 'warning' listener — Node's default stderr
// printer plus any listener a static ESM import registered during its
// module-init phase. The previous `process.listeners('warning')[0]`
// approach assumed Node's default was always at index 0; a transitive
// `process.prependListener('warning', …)` from a dep's module-init
// shifted the default to index 1 and detached the wrong listener,
// leaving DEP0040 un-suppressed. Trade-off accepted: a deliberate
// transitive warning listener is also removed; at the chariot CLI
// entry-point this is preferable to a silently inoperative filter.
process.removeAllListeners('warning');
process.on('warning', (w) => {
  if (w.name === 'DeprecationWarning' && (w as NodeJS.ErrnoException).code === 'DEP0040') return;
  // Match Node's default format so operators see the same shape they
  // would without the filter — PID + bracketed code + trace hint when
  // available. Losing the code / hint would degrade post-mortem from
  // grep-able to vague-text.
  const code = (w as NodeJS.ErrnoException).code;
  const codeTag = typeof code === 'string' && code.length > 0 ? ` [${code}]` : '';
  process.stderr.write(`(node:${process.pid})${codeTag} ${w.name}: ${w.message}\n`);
  // w.stack always begins with `Name: message` (Node sets it). Strip
  // that header before writing the trace; otherwise the header would
  // print twice on every non-DEP0040 warning.
  if (w.stack) {
    const trace = w.stack.split('\n').slice(1).join('\n');
    if (trace.length > 0) process.stderr.write(`${trace}\n`);
  }
});

/**
 * Epic AI® Chariot CLI
 *
 * Chariot CLI — enterprise entry point over the bundled engine:
 * - `chariot` → setup wizard + Chariot status
 * - `chariot discover` → Internal API Discovery
 * - `chariot serve` → MCP server (delegates to bundled engine)
 * - `chariot add/remove/list/health` → Adapter management (delegates to bundled engine)
 * - `chariot license` → License status
 */

import { spawn, spawnSync } from 'node:child_process';
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { signDiscoveredAdapter, defaultEnvelopePaths, loadVerifiedDiscoveredAdapters } from '../discovery/envelope.js';
import { buildDiscoveredToolName, type DiscoveredEndpoint } from '../discovery/DiscoveredRestAdapter.js';
import {
  cmdHealthCheckAdapter,
  effectiveEnvKeys,
  restEnvKeys,
  restAllEnvKeys,
} from '../engine/types/canonical-credentialed-brands.js';
import { createLogger as _mkLog } from '../engine/logger.js';
// CHARIOT::§16.1 Discovery (rulings item 91/105/112(a)) — direct import,
// matching this repo's established pattern.
import { chariotEmitter } from '../observability/emitter.js';
// R8-1: single module-level logger for the cli.approval channel —
// matches the toolHandlers.ts pattern at src/engine/server/toolHandlers.ts:28
// (`_approvalGateLogger`). cmdApprove + cmdRevoke share this instance.
const _cliApprovalLog = _mkLog('cli.approval');
// R7-1: all three approval-command functions share a single top-level
// static import. approval.js is unconditionally pulled by
// src/engine/server/toolHandlers.ts at startup, so lazy loading buys
// nothing on the `chariot serve` path — consistency wins.
import {
  renderToolArgv,
  recordAdapterApproval,
  revokeAdapterApproval,
  listApprovedAdapters,
  sanitizeDisplayString,
} from '../cli/approval.js';
import { createInterface } from 'node:readline';
import { createInterface as createInterfacePromises } from 'node:readline/promises';
import { constants as osConstants, homedir } from 'node:os';
import { join } from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { loadNativeBinding, getBindingLoadError } from '../license/binding.js';
import { validateLicense, revalidateLicense } from '../license/loader.js';
import { activateLicenseFromPath } from '../license/activate.js';
import { renewNow } from '../license/renew-client.js';
import {
  formatStatusLines,
  daysRemainingFromIso,
  summarizeRenewOutcome,
  formatRenewStatusLine,
  type LastRenewalRecord,
} from '../license/cli-format.js';
import {
  discover,
  type DiscoveredService,
  type DiscoveryScanRecord,
  type DiscoveredServiceRecord,
  type DiscoveryConfigFile,
  isAdminEndpoint,
  serviceSlug,
  codebaseHash,
  canonicalizePath,
  validateDiscoveryConfig,
  filterAllowlist,
  computeRescanDiff,
} from '../discovery/index.js';
import { chariotCatalogEnv, loadChariotMcpRegistryWithNative, bundleToolCount, type ChariotRegistryEntry } from '../catalog/artifacts.js';
import {
  ChariotError,
  EXIT,
  agentMode,
  emit,
  fail,
  helpRequested,
  interactiveInNonTty,
  ok,
  type ChariotEnvelope,
} from '../cli/envelope.js';
import { buildManifest, getCommand, renderCommandHelp } from '../cli/capabilities.js';
import { runTelemetryCommand } from '../cli/telemetry.js';
import { installOfflineKit, defaultPackageRoot, formatOfflineKitSummary } from '../cli/offline-kit.js';
import { installStdioDependency } from '../cli/installStdioDependency.js';
import { verifyNpmIntegrity } from '../engine/federation/adapters/npmIntegrityGuard.js';
import {
  CREDENTIAL_VALUE_CONTROL_CHAR_RE,
  EPIC_AI_DIR,
  detectMcpClients,
  detectSystem,
  ensureDir,
  loadConfig,
  loadCredentials,
  loadCredentialsFrom,
  loadState,
  readJsonFile,
  removeAdapterState,
  removeCredential,
  removeMcpConfig,
  saveConfig,
  saveState,
  upsertAdapterState,
  verifyMcpConfigLoaded,
  withLastHealthCheck,
  writeCredential,
  writeMcpConfig,
} from '../cli/index.js';

import {
  type VaultMigrateCounts,
  emptyVaultMigrateCounts,
  addVaultMigrateCounts,
  migrateTenant,
  discoverAllTenantIds,
  connectVaultRedis,
} from '../iam/vaultMigrate.js';
// rulings item 126 (W-IAM-REDACT) — see that module's own doc comment.
import { redactConnectionString } from '../iam/redactConnectionString.js';

const rawArgs = process.argv.slice(2);
// CH-32 (zero-day fix): global flags are position-independent — `chariot
// --json list` must dispatch `list`, not fall into the unknown-command path
// (agentMode() already scans the whole argv for --json). Stable-partition the
// recognized GLOBAL flags to the END so args[0] is always the command and
// every existing positional index (args[1], args[2], …) keeps working.
// Command-specific flags (--http, --chain-id, --token, --config, …) keep
// their relative order and their value pairing.
const GLOBAL_FLAGS = new Set(['--json', '--yes', '-y', '--non-interactive', '--accept-defaults']);
const args = [
  ...rawArgs.filter((a) => !GLOBAL_FLAGS.has(a)),
  ...rawArgs.filter((a) => GLOBAL_FLAGS.has(a)),
];
// After the partition, args[0] is a global flag ONLY when every arg is a
// global flag — i.e. `chariot --json` has no command (same as bare `chariot`).
const command = args[0] !== undefined && GLOBAL_FLAGS.has(args[0]) ? undefined : args[0];

// Top-level non-interactive mode. Set when the user
// passes --yes / --non-interactive / --accept-defaults OR when stdin is not a
// TTY (piped/redirected). Prompts that read --yes return their initialValue;
// prompts with no safe default exit with code 4 (STDIN_REQUIRED) instead of
// hanging on a closed stdin.
// CH-32: a non-TTY stdin reports `isTTY === undefined` (not `false`), so the
// previous `=== false` check missed piped/agent/CI invocations and let
// interactive prompts run against a closed stdin. `!isTTY` covers both
// undefined and false — agent mode (--json/CHARIOT_AGENT) also forces it.
const NON_INTERACTIVE = args.includes('--yes') ||
  args.includes('-y') ||
  args.includes('--non-interactive') ||
  args.includes('--accept-defaults') ||
  args.includes('--json') ||
  process.env.CHARIOT_NON_INTERACTIVE === '1' ||
  process.env.CHARIOT_AGENT === '1' ||
  (process.stdin && !process.stdin.isTTY);
process.env.CHARIOT_NON_INTERACTIVE = NON_INTERACTIVE ? '1' : '';

// bug-tracker-ref: @clack spinner redraws via raw ANSI cursor escapes; on a
// non-TTY stdout (pipe / agent / CI) that floods the stream with literal
// escape noise. Use the animated spinner only on a TTY; otherwise a plain shim.
interface SpinnerLike { start: (m?: string) => void; stop: (m?: string) => void; message: (m?: string) => void }
function makeSpinner(pp: { spinner: () => SpinnerLike }): SpinnerLike {
  // Agent mode (CH-32): stdout must be pure JSON, so the spinner is silent.
  if (agentMode(args)) {
    return { start: () => { /* silent */ }, stop: () => { /* silent */ }, message: () => { /* silent */ } };
  }
  if (process.stdout.isTTY) return pp.spinner();
  // Non-TTY human/CI: progress goes to STDERR so it never corrupts a piped
  // stdout consumer (and stays out of the JSON channel by construction).
  return {
    start: (m?: string) => { if (m) process.stderr.write(m + '\n'); },
    stop: (m?: string) => { if (m) process.stderr.write(m + '\n'); },
    message: () => { /* no-op off-TTY */ },
  };
}
// bug-tracker-ref: singularize tool counts ('1 tool', not '1 tools').
function toolsLabel(n: number): string { return `${n} ${Number(n) === 1 ? 'tool' : 'tools'}`; }

const DISCOVERED_DIR = join(EPIC_AI_DIR, 'discovered-adapters');
// Scan files are per-codebase: scan-{hash}.json — see getScanFilePath()

// ── Engine bridge ──────────────────────────────────────────────────────────

function getEngineSetupPath(): string {
  // Find the Chariot engine's bin — co-located with this compiled file in dist/
  const thisFile = new URL(import.meta.url).pathname;
  // dist/bin/chariot.js → dist/engine/bin/setup.js
  const candidate = join(thisFile, '..', '..', 'engine', 'bin', 'setup.js');
  if (existsSync(candidate)) return candidate;
  throw new Error('Chariot engine not found. Rebuild with: npm run build');
}

function spawnEngine(engineArgs: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const binPath = getEngineSetupPath();
    const child = spawn(process.execPath, [binPath, ...engineArgs], {
      stdio: 'inherit',
      env: chariotCatalogEnv(),
    });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code !== null) { resolve(code); return; }
      // CLAUSE §23.2::17 — every terminal outcome SHALL be
      // honest): the engine child was terminated by a signal (crash / OOM
      // kill / segfault) rather than exiting normally, so Node reports
      // `code === null`. The previous `code ?? 0` coalesced that into a
      // false "success" exit(0) — a hard dispatch failure reported as
      // clean. Report a non-zero, signal-derived code (128+n, the
      // standard POSIX shell convention) so `chariot query`/`chariot
      // serve` callers and agents can never mistake a crashed dispatch
      // for success.
      const signum = signal ? (osConstants.signals as Record<string, number>)[signal] : undefined;
      resolve(typeof signum === 'number' ? 128 + signum : 1);
    });
  });
}

// ── Chariot curated adapters ───────────────────────────────────────────────
// Single source of truth lives in src/catalog/curated.ts.

import { CHARIOT_CURATED, CHARIOT_CURATED_IDS } from '../catalog/curated.js';
import { buildToolsForRoutingChariot } from '../engine/federation/buildToolsForRouting.js';

// ── chariot help ───────────────────────────────────────────────────────────

async function cmdHelp(): Promise<void> {
  console.log('');
  console.log(`  ${pc.bold('Epic AI® Chariot')} — Intelligent Virtual Assistant (IVA)`);
  console.log('');
  console.log(`  ${pc.bold('Commands:')}`);
  console.log('');
  // Render from the single-source-of-truth capability registry (CH-32) so the
  // shipped `chariot --help` (this local cmdHelp, intercepted in main() before
  // engine delegation) can never drift from the dispatcher. Lists every
  // registered command incl. capabilities/version/status/trace/resume.
  const cmds = buildManifest('').commands;
  const col = Math.min(40, Math.max(...cmds.map((c) => c.usage.length)));
  for (const cmd of cmds) {
    console.log(`    ${pc.cyan(cmd.usage.padEnd(col))}  ${cmd.summary}`);
  }
  console.log('');
  console.log(`  ${pc.white('Docs:')}  https://chariot.epic-ai.io`);
  console.log('');
}

// ── chariot list ───────────────────────────────────────────────────────────

function truncateDesc(desc: string, maxLen: number): string {
  const flat = desc.replace(/\s*\n\s*/g, ' ').trim();
  if (flat.length <= maxLen) return flat;
  const cut = flat.lastIndexOf(' ', maxLen);
  return (cut > maxLen * 0.6 ? flat.slice(0, cut) : flat.slice(0, maxLen)) + '…';
}

async function cmdList(term?: string): Promise<ChariotEnvelope> {
  if (term) { return cmdSearch(term); }

  const all = loadChariotMcpRegistryWithNative();
  const state = loadState();
  const json = agentMode();

  const curatedRows = CHARIOT_CURATED_IDS.map(id => all.find(a => a.id === id)).filter(Boolean) as ChariotRegistryEntry[];
  const customIds = Object.keys(state.adapters).filter(id => !CHARIOT_CURATED_IDS.includes(id));
  const customRows = customIds.map(id => all.find(a => a.id === id) || { id, name: id, type: 'mcp' } as ChariotRegistryEntry);

  if (!json) {
    console.log('');
    console.log(`  ${pc.bold('Curated')}  ${pc.white(`(${curatedRows.length})`)}  ${pc.white('— open data, no credentials required')}`);
    console.log('');
    for (const a of curatedRows) {
      const toolCount = bundleToolCount(a);
      const typeLabel = a.type === 'both' ? pc.white('REST+MCP') : pc.white('MCP');
      console.log(`    ${pc.cyan(a.id.padEnd(35))} ${typeLabel}  ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white(truncateDesc(a.description || '', 60))}`);
    }
    console.log('');
    console.log(`  ${pc.bold('Custom')}   ${pc.white(`(${customRows.length})`)}  ${pc.white('— your APIs and credentials')}`);
    console.log('');
    if (customRows.length === 0) {
      console.log(`    ${pc.white('None yet — run:')} ${pc.cyan('chariot configure')}`);
    } else {
      for (const a of customRows) {
        const toolCount = bundleToolCount(a);
        const typeLabel = a.type === 'both' ? pc.white('REST+MCP') : pc.white('MCP');
        console.log(`    ${pc.cyan(a.id.padEnd(35))} ${typeLabel}  ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white(truncateDesc(a.description || '', 60))}`);
      }
    }
    console.log('');
  }

  const toRow = (a: ChariotRegistryEntry, tier: 'curated' | 'custom') => ({
    id: a.id, name: a.name, type: a.type, tier, toolCount: bundleToolCount(a),
  });
  return ok('cli:list', {
    data: {
      curated: curatedRows.map(a => toRow(a, 'curated')),
      custom: customRows.map(a => toRow(a, 'custom')),
    },
  });
}

// ── chariot search ─────────────────────────────────────────────────────────

async function cmdSearch(term?: string): Promise<ChariotEnvelope> {
  const all = loadChariotMcpRegistryWithNative();
  const state = loadState();
  const json = agentMode();

  if (!term) {
    const curatedRows = CHARIOT_CURATED_IDS.map(id => all.find(a => a.id === id)).filter(Boolean) as ChariotRegistryEntry[];
    if (!json) {
      console.log('');
      console.log(`  ${pc.bold('Curated adapters')}  ${pc.white('— vetted, open data, no credentials required')}`);
      console.log('');
      for (const a of curatedRows) {
        const toolCount = bundleToolCount(a);
        console.log(`    ${pc.cyan(a.id.padEnd(35))} ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white(truncateDesc(a.description || '', 60))}`);
      }
      console.log('');
      console.log(`  ${pc.white(`Search all ${all.length} available adapters:`)}  ${pc.cyan('chariot search <term>')}`);
      console.log('');
    }
    return ok('cli:search', {
      data: { term: null, total: all.length, results: curatedRows.map(a => ({ id: a.id, name: a.name, toolCount: bundleToolCount(a), tier: 'curated' as const })) },
    });
  }

  const t = term.toLowerCase();
  // Primary match: id, name, category. Description is a fallback only when
  // the first 120 chars (the summary sentence) contain the term — prevents
  // false positives from passing mentions of third-party services deep in
  // verbose generated descriptions (e.g. "domain-monitor" matching "stripe"
  // because its description body mentions "Stripe Checkout URLs").
  const results = all.filter(a =>
    a.id.toLowerCase().includes(t) ||
    a.name.toLowerCase().includes(t) ||
    (a.category || '').toLowerCase().includes(t) ||
    (a.description || '').toLowerCase().slice(0, 120).includes(t)
  );

  if (results.length === 0) {
    if (!json) console.log(`\n  No adapters matched "${term}". Try a broader term.\n`);
    return fail('cli:search', 'NO_MATCH', {
      severity: 'info',
      exit_code: EXIT.FAILURE,
      retryable: true,
      human_message: `No adapters matched "${term}".`,
      remediation: ['Try a broader term.'],
      data: { term, total: 0, results: [] },
    });
  }

  const customInState = new Set(Object.keys(state.adapters));
  // bug-tracker-ref: within each tier, rerank by best-name match so an exact id
  // (e.g. "slack") wins over substring siblings ("iaapp", "molt2meet").
  // Score: 0 exact id, 1 exact name, 2 id startsWith term, 3 name startsWith
  // term, 4 id contains term, 5 name contains term, 6 description hit only.
  function nameScore(a: typeof results[number]): number {
    const idLc = a.id.toLowerCase();
    const nmLc = (a.name || '').toLowerCase();
    if (idLc === t) return 0;
    if (nmLc === t) return 1;
    if (idLc.startsWith(t)) return 2;
    if (nmLc.startsWith(t)) return 3;
    if (idLc.includes(t)) return 4;
    if (nmLc.includes(t)) return 5;
    return 6;
  }
  function rankWithin(arr: typeof results): typeof results {
    return [...arr].sort((a, b) => nameScore(a) - nameScore(b) || a.id.localeCompare(b.id));
  }
  const sorted = [
    ...rankWithin(results.filter(a => CHARIOT_CURATED_IDS.includes(a.id))),
    ...rankWithin(results.filter(a => !CHARIOT_CURATED_IDS.includes(a.id) && customInState.has(a.id))),
    ...rankWithin(results.filter(a => !CHARIOT_CURATED_IDS.includes(a.id) && !customInState.has(a.id))),
  ];
  const shown = sorted.slice(0, 20);

  const tierOf = (a: ChariotRegistryEntry): 'curated' | 'configured' | 'available' =>
    CHARIOT_CURATED_IDS.includes(a.id) ? 'curated' : customInState.has(a.id) ? 'configured' : 'available';

  if (!json) {
    console.log('');
    console.log(`  ${pc.bold(`${results.length} ${results.length === 1 ? 'adapter' : 'adapters'}`)} matching "${term}"${results.length > 20 ? pc.white(' (showing top 20)') : ''}`);
    console.log('');

    for (const a of shown) {
      const toolCount = bundleToolCount(a);
      const t2 = tierOf(a);
      const tag = t2 === 'curated' ? pc.green('curated') : t2 === 'configured' ? pc.cyan('configured') : pc.white('available');
      console.log(`    ${pc.cyan(a.id.padEnd(35))} ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}  [${tag}]`);
      if (a.description) console.log(`    ${pc.white((' ').repeat(35))} ${pc.white(truncateDesc(a.description, 70))}`);
      console.log('');
    }

    const unconfigured = shown.filter(a => !CHARIOT_CURATED_IDS.includes(a.id) && !customInState.has(a.id));
    if (unconfigured.length > 0) {
      console.log(`  ${pc.white('Add one:')}  ${pc.cyan(`chariot add ${unconfigured[0].id}`)}`);
      console.log('');
    }
  }

  return ok('cli:search', {
    data: {
      term,
      total: results.length,
      results: shown.map(a => ({ id: a.id, name: a.name, toolCount: bundleToolCount(a), tier: tierOf(a) })),
    },
  });
}

// ── chariot add ────────────────────────────────────────────────────────────

/**
 * Parse `--token KEY=VAL` / `--env KEY=VAL` (repeatable) credential
 * overrides from process.argv after the adapter id. Returns a
 * map of credential name → value that cmdAdd writes to
 * ~/.epic-ai/.env via writeCredential() before the interactive
 * prompt path would have asked for them. Closes the bug-tracker entry.
 */
// CANONICAL_CREDENTIALED_BRANDS + effectiveEnvKeys + firstMissingCredential
// moved to src/engine/types/canonical-credentialed-brands.ts so the engine
// paths (ChariotState.getConfiguredAdapterIds, setup.ts) consume the same
// source of truth. Splitting the table across files would reintroduce
// the bug where `chariot health` required ALL keys but the engine
// still accepted ANY one. Keep all four callers routed through the
// shared module.
//
// Imported at top of file (other static imports section). The local
// re-export name preserves cmdAdd's existing `CANONICAL_CREDENTIALED_BRANDS[
// match.id]` shape with no rename needed.

function parseInlineCredentialFlags(argv: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    let kv: string | undefined;
    if (a === '--token' || a === '--env') {
      kv = argv[i + 1];
      i++;
    } else if (a?.startsWith('--token=') || a?.startsWith('--env=')) {
      kv = a.slice(a.indexOf('=') + 1);
    }
    if (typeof kv !== 'string') continue;
    const eq = kv.indexOf('=');
    if (eq <= 0) {
      console.error(pc.red(`--token: expected KEY=VALUE, got "${kv}"`));
      process.exit(2);
    }
    const k = kv.slice(0, eq);
    const v = kv.slice(eq + 1);
    if (v.length === 0) {
      console.error(pc.red(`--token: value for "${k}" is empty`));
      process.exit(2);
    }
    // reject control characters in the value
    // BEFORE the two-phase write loop reaches writeCredential().
    // writeCredential throws on \r\n\0 — if validation accepts them
    // and the throw lands mid-sequence (after one or more credentials
    // are already persisted), the atomicity guarantee the two-phase
    // split provides is violated. Catch every embedded control char
    // ( -, ) here so validation is fail-fast.
    // reject the FULL C0 + DEL + C1 control range.
    // CREDENTIAL_VALUE_CONTROL_CHAR_RE is the single source of truth
    // shared with writeCredential and setup.ts so the byte set cannot
    // drift across call sites. This layer is defence-in-depth + a
    // CLI-shaped error message.
    if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(v)) {
      console.error(pc.red(`--token: value for "${k}" contains an embedded control character (NUL/CR/LF/TAB/ESC/C1)`));
      console.error(pc.dim('  Credential values must be a single line of printable bytes. Re-encode (e.g. base64) before passing on the command line.'));
      process.exit(2);
    }
    // Credential env-keys are UPPER_SNAKE_CASE by IAM convention
    // (loadCredentials reads process.env / ~/.epic-ai/.env keys in
    // that form). Reject lower-case input loudly so operators don't
    // silently lose credentials they thought they passed.
    if (!/^[A-Z][A-Z0-9_]*$/.test(k)) {
      console.error(pc.red(`--token: key "${k}" must match /^[A-Z][A-Z0-9_]*$/ (try ${k.toUpperCase()})`));
      process.exit(2);
    }
    out[k] = v;
  }
  return out;
}

/**
 * Resolve a customer-typed adapter argument (`chariot add <arg>`) against
 * the full adapter list. An exact `id` match ALWAYS wins over a `name`
 * match, checked across the WHOLE collection first — never picked by
 * array order.
 *
 * FIX (2026-09-30, dogfood mechanism-test-mcp, gate BLOCK
 * verdict.1.json): the prior single linear
 * `all.find(a => a.id === adapterName || a.name.toLowerCase() === ...)`
 * evaluated the OR per-element in array order, so a row that matched only
 * by `name` — earlier in `all` than the row whose `id` matched the typed
 * argument exactly — shadowed it. Reproduced live: `chariot add
 * tavily-mcp` resolved to catalog id `runno` (a malformed duplicate row
 * that also happens to have `name: "tavily-mcp"`) instead of id
 * `tavily-mcp` itself, because `runno` was reached first in array order.
 * `runno`'s bogus `DEFAULT_PARAMETERS` credential and the customer-facing
 * `human_message` naming adapter "runno" instead of "tavily-mcp" both
 * trace to this resolution bug, not to the catalog row.
 *
 * When several rows match only by NAME (no exact `id` match exists) this
 * is now a genuine ambiguity, not a silent array-order pick: the caller
 * reports every matching id and asks the customer to re-run with the
 * exact one.
 */
function resolveAdapterByIdOrName<T extends { id: string; name: string }>(
  all: readonly T[],
  adapterName: string,
): { kind: 'found'; adapter: T } | { kind: 'ambiguous'; ids: readonly string[] } | { kind: 'not-found' } {
  const exactId = all.find(a => a.id === adapterName);
  if (exactId) return { kind: 'found', adapter: exactId };
  const nameMatches = all.filter(a => a.name.toLowerCase() === adapterName.toLowerCase());
  if (nameMatches.length === 1) return { kind: 'found', adapter: nameMatches[0] };
  if (nameMatches.length > 1) return { kind: 'ambiguous', ids: nameMatches.map(a => a.id) };
  return { kind: 'not-found' };
}

async function cmdAdd(adapterName: string): Promise<ChariotEnvelope> {
  // Use the native overlay so curated adapters absent from the bundle
  // (bug-tracker-ref: wikipedia removed by catalog purge) are still addable.
  const all = loadChariotMcpRegistryWithNative();

  const resolved = resolveAdapterByIdOrName(all, adapterName);
  if (resolved.kind === 'ambiguous') {
    if (!agentMode()) {
      console.log(`Adapter "${adapterName}" matches multiple catalog entries by name: ${resolved.ids.join(', ')}. Re-run with the exact id.`);
    }
    return fail('cli:add', 'ADAPTER_NAME_AMBIGUOUS', {
      human_message: `Adapter "${adapterName}" matches multiple catalog entries by name: ${resolved.ids.join(', ')}.`,
      cause: `no exact id match for "${adapterName}"; ${resolved.ids.length} rows share this name`,
      remediation: [`Re-run with the exact id, e.g. \`chariot add ${resolved.ids[0]}\`.`],
      data: { query: adapterName, ids: resolved.ids },
    });
  }
  if (resolved.kind === 'not-found') {
    const fuzzy = all.filter(a => a.id.includes(adapterName) || a.name.toLowerCase().includes(adapterName.toLowerCase()));
    const suggestions = fuzzy.slice(0, 5).map(a => a.id);
    if (!agentMode()) {
      if (fuzzy.length > 0) {
        console.log(`Adapter "${adapterName}" not found. Did you mean:`);
        fuzzy.slice(0, 5).forEach(a => console.log(`  ${pc.cyan(a.id)} — ${a.name}`));
      } else {
        console.log(`Adapter "${adapterName}" not found. Run ${pc.cyan('chariot search <term>')} to find one.`);
      }
    }
    return fail('cli:add', 'ADAPTER_NOT_FOUND', {
      human_message: `Adapter "${adapterName}" not found.`,
      cause: `no catalog entry matches "${adapterName}"`,
      remediation: ['Run `chariot search <term>` to find the adapter id.'],
      data: { query: adapterName, suggestions },
    });
  }
  const match = resolved.adapter;

  const s = makeSpinner(p);

  // Install outcome is tracked so a failed pre-install can NEVER present as a
  // bare "✓ added" (the 3.1.2 false-green). CH-42: EACCES gets a correct,
  // honest remediation — never a false "air-gap / supply_chain_integrity_
  // failure" and never the non-existent `chariot setup --pre-install`.
  //
  // W42-FIX (row 1.42 proof, gap 1 of 3): this used to spawn `npm install
  // -g --ignore-scripts -- <args[1]>` inline — the bare, UNPINNED package
  // name straight from the catalog row's `args` array, installing whatever
  // the registry's CURRENT `latest` dist-tag is rather than the catalog's
  // pinned `mcp.version` (confirmed empirically:
  // `/tmp/scratch/wave3/w42/run/VERDICT.md` — `chariot add 4fetch`
  // installed 1.4.0 while the catalog pinned 1.2.0, so the LATER `npx
  // --no-install <pkg>@1.2.0` the runtime actually launches with found
  // nothing). Now routes through the SAME `installStdioDependency()`
  // helper `setup.ts`'s wizard already used (src/cli/installStdioDependency.js)
  // so both callers install the PINNED `<packageName>@<version>` and
  // verify it against `mcp.integrityShasum` via `verifyNpmIntegrity()`
  // (the same check the dispatch-time guard runs) before ever reporting
  // success — AS §1.1 sub-clauses 1-2.
  let installOutcome: 'ok' | 'eacces' | 'failed' | 'unpinned' | 'skipped' = 'skipped';
  let installPkg: string | undefined;
  // Package-name derivation: a direct read of the REAL signed catalog
  // bundle (chariot-adapter-bundle.json, registry[]) shows `mcp.packageName`
  // is ABSENT on every stdio/npx row inspected (including `4fetch`, which
  // DOES carry `mcp.version`/`mcp.integrityShasum`) — the package spec
  // lives in `mcp.args` instead (e.g. `['-y', '@amcharts/amcharts5-mcp']`).
  // Gating on `packageName` alone would silently no-op on every real
  // catalog row. Mirrors `extractStdioPackageName()`
  // (src/engine/bin/concurrency.ts) and `installStdioDependency()`'s own
  // internal derivation — packageName first, else the first non-flag args
  // entry.
  const derivedPkgName = match.mcp?.packageName
    || match.mcp?.args?.find((x) => typeof x === 'string' && x.length > 0 && !x.startsWith('-'));
  if (match.mcp?.transport === 'stdio' && derivedPkgName) {
    installPkg = match.mcp.version ? `${derivedPkgName}@${match.mcp.version}` : derivedPkgName;
    // Argument-injection guard (zero-day fix, preserved): a catalog
    // package spec beginning with '-' would be parsed by npm as an
    // OPTION, not a package spec. Reject dash-prefixed specs outright
    // (the derivation above already skips dash-prefixed `args` entries,
    // so this only fires for a malformed `packageName` field); the shared
    // helper additionally passes `--` as an end-of-options separator
    // (defense-in-depth, matches RegistryLoader.ts's dash-skipping
    // package-name derivation).
    if (derivedPkgName.startsWith('-')) {
      return fail('cli:add', 'INVALID_PACKAGE_SPEC', {
        human_message: `Catalog entry "${match.id}" has a malformed package argument.`,
        cause: `derived package spec "${derivedPkgName}" begins with '-' and would be parsed by npm as an option`,
        remediation: ['Fix the catalog entry upstream and re-publish the signed adapter bundle.'],
        data: { id: match.id, pkg: derivedPkgName },
      });
    }
    s.start(`Installing ${match.name}`);
    let lastStderr = '';
    const result = installStdioDependency(
      match,
      (bin, argv, timeoutMs) => {
        // spawnSync array form — no shell metacharacter exposure; the
        // shared helper appends `--` before the pinned pkg@version spec.
        const r = spawnSync(bin, argv, { stdio: 'pipe', timeout: timeoutMs });
        lastStderr = (r.stderr ? r.stderr.toString() : '') + (r.error ? String(r.error) : '');
        return { error: r.error, status: r.status, signal: r.signal };
      },
      verifyNpmIntegrity,
    );
    if (result.status === 'failed' && result.reason === 'unpinned') {
      installOutcome = 'unpinned';
      s.stop(`${pc.yellow('!')} ${match.name}: catalog entry has no pinned version/integrityShasum — cannot install air-gap-safe`);
    } else if (result.status === 'failed') {
      const eacces = /EACCES|permission denied|EPERM/i.test(lastStderr);
      installOutcome = eacces ? 'eacces' : 'failed';
      s.stop(eacces
        ? `${pc.yellow('!')} ${match.name}: global install denied (EACCES) — see remediation below`
        : `${pc.yellow('!')} ${match.name}: pre-install failed (will fall back to npx at dispatch)`);
    } else {
      installOutcome = 'ok';
      s.stop(`${pc.green('✓')} ${match.name} installed`);
    }
  }

  // Single source of truth — same predicate consumed by cmdHealth, by
  // ChariotState.getConfiguredAdapterIds, by setup.ts, and by
  // RegistryLoader.buildMCPConnection. Splitting the derivation across
  // files re-introduced the round-1 split-brain.
  //
  // restEnvKeys merges in REST_CREDENTIAL_MAP — REST adapters whose
  // constructor needs MORE than a single rest.envKey -> apiKey (e.g.
  // paypal clientId+clientSecret; acumatica clientId+clientSecret+
  // username+password+instanceUrl), including adapters whose auth is an
  // EITHER/OR of two credential sets (e.g. servicenow bearerToken OR
  // username+password). None of the 6,229 catalog rows carries
  // rest.envKey, so without this merge `chariot add` never prompted for
  // these fields and the adapter landed at status='configured' while
  // dispatch (toolHandlers.ts REST branch) still threw "<field> is
  // required" on every call.
  //
  // Load credentials once, BEFORE declaredEnvKeys, so restEnvKeys can see
  // which alternative (if any) is already satisfied — an operator with
  // SERVICENOW_GRC_USERNAME+PASSWORD already on disk must not also be
  // asked for SERVICENOW_GRC_BEARER_TOKEN. Reused below instead of the
  // prior duplicate dynamic-import read.
  const declaredEnvKeysCreds = loadCredentials();
  const declaredEnvKeys = [...new Set([...effectiveEnvKeys(match), ...restEnvKeys(match, declaredEnvKeysCreds).map(f => f.envVar)])];

  // bug-tracker-ref: parse inline `--token KEY=VAL`
  // BEFORE the declaredEnvKeys gate so an operator who supplies
  // --token against an adapter with zero declared env-keys gets a
  // hard error (exit 2) instead of a silent drop. The previous
  // ordering left this combination — a custom adapter missing from
  // both `adapter.mcp.envKeys` and CANONICAL_CREDENTIALED_BRANDS —
  // accepting --token at the parser level and discarding it.
  const inline = parseInlineCredentialFlags(args.slice(2));
  const inlineKeys = Object.keys(inline);
  if (inlineKeys.length > 0 && declaredEnvKeys.length === 0) {
    console.error(pc.red(`--token: adapter "${match.id}" has no declared env-keys; --token cannot be applied.`));
    console.error(pc.dim(`Declare envKeys in the adapter catalog or add "${match.id}" to CANONICAL_CREDENTIALED_BRANDS in src/engine/types/canonical-credentialed-brands.ts.`));
    process.exit(2);
  }

  if (declaredEnvKeys.length > 0) {
    // note: two-phase write so a misspelt second
    // --token does not leave the first --token's value persisted
    // in ~/.epic-ai/.env. Validate the FULL inline set first; only
    // when every entry is acceptable do we persist any of them.
    // Fail fast on unrecognised keys so an operator catches a typo
    // like --token GITHUB_TOKN=… immediately instead of seeing the
    // yellow warning swallowed by a downstream STDIN_REQUIRED.
    // Exit 2 matches the empty-value / non-UPPER_SNAKE rejection
    // paths in parseInlineCredentialFlags.
    for (const k of Object.keys(inline)) {
      if (!declaredEnvKeys.includes(k)) {
        console.error(pc.red(`--token: "${k}" is not a declared env-key for adapter "${match.id}"; expected one of: ${declaredEnvKeys.join(', ')}`));
        process.exit(2);
      }
    }
    for (const [k, v] of Object.entries(inline)) {
      writeCredential(k, v);
    }

    // bug-tracker-ref: in non-interactive mode, skip credential prompts; expect the
    // values already in env/credentials file. If any required key is missing,
    // emit a clear list and exit STDIN_REQUIRED so callers (CI, scripts) can
    // diagnose without inspecting stdin state.
    if (NON_INTERACTIVE) {
      const existing = (await import('../cli/index.js')).loadCredentials();
      const missing = declaredEnvKeys.filter(k => !existing[k] && !process.env[k]);
      if (missing.length > 0) {
        // CHARIOT §23.2: the previous `console.error(...) +
        // process.exit(4)` bypassed the envelope entirely — `chariot add <id>
        // --json` on the missing-credentials path emitted plain text on stderr
        // and no JSON on stdout. Return a typed STDIN_REQUIRED envelope so agent
        // mode gets a single parseable outcome (exit 4 preserved) and human mode
        // keeps its concise message.
        if (!agentMode()) {
          console.error(pc.red(`STDIN_REQUIRED: chariot add ${match.id} needs credentials: ${missing.join(', ')}`));
          console.error(pc.dim(`Set them in ~/.epic-ai/.env or export as environment variables, then re-run.`));
        }
        return fail('cli:add', 'STDIN_REQUIRED', {
          severity: 'blocked',
          exit_code: EXIT.STDIN_REQUIRED,
          retryable: true,
          human_message: `chariot add ${match.id} needs credential(s): ${missing.join(', ')}`,
          cause: `required env key(s) not present and stdin is not a TTY: ${missing.join(', ')}`,
          noninteractive: { available: true, command: `chariot add ${match.id} --token ${missing[0]}=<value>` },
          remediation: [
            `Supply: chariot add ${match.id} --token ${missing.map(k => `${k}=<value>`).join(' --token ')}`,
            'Or set the key(s) in ~/.epic-ai/.env or the environment, then re-run.',
          ],
          data: { id: match.id, credentialsPresent: false, missing, credentialValidated: false },
        });
      }
    } else {
      // a key already supplied via --token must
      // NOT be re-prompted. The previous loop unconditionally prompted
      // every declaredEnvKey, letting any non-empty user input
      // overwrite the credential the operator had just passed on the
      // command line. Track inline-populated keys and skip them.
      const inlinePopulated = new Set(inlineKeys);
      for (const envKey of declaredEnvKeys) {
        if (inlinePopulated.has(envKey)) continue;
        const key = await p.password({ message: envKey });
        if (!p.isCancel(key) && key) writeCredential(envKey, key);
      }
    }
  }

  // Recompute credential coverage so status is honest: only 'configured'
  // when every declared key is actually present (file or env). lastVerified
  // stays null — `add` does NOT assert a credential is VALID (CH-36); a green
  // "validated" requires a live call. We expose `credentialValidated:false`
  // so an agent knows the credential is present-but-unproven.
  const credsNow = loadCredentials();
  const missingKeys = declaredEnvKeys.filter(k => !credsNow[k] && !process.env[k]);
  // Presence ≠ readiness. `credentialsPresent` must report whether a
  // REQUIRED credential is actually configured — a zero-credential adapter has
  // NONE present, so never fabricate `true`. Readiness ('configured') is a
  // separate axis: an adapter is ready when it needs no creds OR every required
  // key is present.
  const credentialsRequired = declaredEnvKeys.length > 0;
  const credentialsPresent = credentialsRequired && missingKeys.length === 0;
  const status = (!credentialsRequired || missingKeys.length === 0) ? 'configured' : 'credentials-pending';

  const pkgDisplay = match.name !== match.id ? pc.dim(` (${match.name})`) : '';

  // P2: save adapter state ONLY when install succeeded or was skipped (no npm
  // install attempted). An eacces or failed install outcome means the adapter
  // is NOT yet operational — marking it 'configured' at that point would let
  // health checks report green on a non-functional adapter.
  const saveAdapterState = (): void => {
    const adapterState = loadState();
    saveState(upsertAdapterState(adapterState, match.id, {
      type: match.type || 'mcp',
      status,
      toolCount: bundleToolCount(match),
      lastVerified: null,
    }));
    const adapterConfig = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };
    const alreadySelected = adapterConfig.selectedAdapters.includes(match.id);
    if (credentialsPresent && !alreadySelected) adapterConfig.selectedAdapters.push(match.id);
    else if (!credentialsPresent && alreadySelected) adapterConfig.selectedAdapters = adapterConfig.selectedAdapters.filter(id => id !== match.id);
    saveConfig(adapterConfig);
  };

  // CH-42: a denied global install is a typed failure with a CORRECT
  // remediation — never the non-existent `chariot setup --pre-install`, never
  // a false air-gap. State is NOT saved so the adapter is not falsely 'configured'.
  if (installOutcome === 'eacces') {
    if (!agentMode()) {
      console.log(`${pc.yellow('!')} ${match.id} could not be installed globally (EACCES) — not added.${pkgDisplay}`);
    }
    return fail('cli:add', 'INSTALL_PERMISSION_DENIED', {
      severity: 'warning',
      human_message: `${match.id} not added — global install of ${installPkg} was denied (EACCES).`,
      cause: 'npm global prefix is not writable by this user (e.g. prefix=/usr owned by root).',
      remediation: [
        'Use a user-writable npm prefix: `npm config set prefix ~/.npm-global` then re-run `chariot add ' + match.id + '`.',
        'Or rely on the npx dispatch fallback (no global install needed) — `chariot query` will fetch the package at call time.',
      ],
      must_not: ['report this as an air-gap or supply-chain failure', 'suggest `chariot setup --pre-install` (no such command)'],
      data: { id: match.id, installed: false, package: installPkg, credentialsPresent, credentialValidated: false },
    });
  }

  // CH-31/CH-42: non-EACCES install failures (registry down, package not found,
  // network error) must NOT fall through to ok(). Return a typed INSTALL_FAILED
  // so callers get an honest non-zero exit, not a false "added" with installed:false.
  if (installOutcome === 'failed') {
    if (!agentMode()) {
      console.log(`${pc.red('✗')} ${match.id} npm install of ${installPkg} failed — not added.${pkgDisplay}`);
    }
    return fail('cli:add', 'INSTALL_FAILED', {
      severity: 'error',
      human_message: `${match.id} not added — npm install of ${installPkg} failed.`,
      cause: 'npm install exited non-zero — package not found, registry unreachable, or network error.',
      remediation: [
        `Check the package name and npm registry availability, then re-run \`chariot add ${match.id}\`.`,
        'Or rely on the npx dispatch fallback (no global install needed) — `chariot query` will fetch the package at call time.',
      ],
      must_not: ['report this as EACCES or a permission error', 'report this as an air-gap or supply-chain failure'],
      data: { id: match.id, installed: false, package: installPkg, credentialsPresent, credentialValidated: false },
    });
  }

  // W42-FIX (row 1.42 proof, gap 1 of 3): an 'unpinned' catalog row MUST
  // fail closed the same as 'eacces'/'failed' — AS §1.1 sub-clause 1
  // forbids an unpinned npm install outright, so falling through to
  // saveAdapterState() here would be a false "✓ added" for an adapter
  // nothing was actually verified-installed for (worse than the pre-fix
  // unpinned-but-attempted install: a false green with NOTHING done).
  if (installOutcome === 'unpinned') {
    if (!agentMode()) {
      console.log(`${pc.yellow('!')} ${match.id}: catalog entry is unpinned (no mcp.version/integrityShasum) — cannot install air-gap-safe. Not added.${pkgDisplay}`);
    }
    return fail('cli:add', 'ADAPTER_UNPINNED', {
      severity: 'warning',
      human_message: `${match.id} not added — the catalog entry has no pinned version/integrityShasum (AS §1.1 sub-clause 1).`,
      cause: 'mcp.version and/or mcp.integrityShasum are absent on this catalog row; an unpinned npm install is not permitted.',
      remediation: [
        'Wait for the catalog publisher to stamp version + integrityShasum for this adapter and re-run `chariot add ' + match.id + '`.',
        'Or rely on the npx dispatch fallback ONLY once the row is pinned — an unpinned row is refused there too (guardNpmStdioAdapter).',
      ],
      must_not: ['report this as installed or added', 'fall back to an unpinned `npm install -g <bare-name>`'],
      data: { id: match.id, installed: false, package: installPkg, credentialsPresent, credentialValidated: false },
    });
  }

  // Install succeeded (or not required) — persist adapter state now that the
  // executable is available (or not needed). This is the first state write,
  // keeping the state file consistent with the actual install outcome.
  saveAdapterState();

  if (status === 'credentials-pending') {
    if (!agentMode()) {
      console.log(`${pc.yellow('!')} ${match.id} added in credentials-pending state — missing: ${missingKeys.join(', ')}${pkgDisplay}`);
    }
    return fail('cli:add', 'ADAPTER_REQUIRES_CREDENTIAL', {
      severity: 'warning',
      human_message: `${match.id} added, but missing credential(s): ${missingKeys.join(', ')}`,
      cause: `required env key(s) not present: ${missingKeys.join(', ')}`,
      noninteractive: { available: true, command: `chariot add ${match.id} --token ${missingKeys[0] ?? 'KEY'}=<value>` },
      remediation: [`Supply: chariot add ${match.id} --token ${missingKeys.map(k => `${k}=<value>`).join(' --token ')}`],
      data: { id: match.id, credentialsPresent: false, missing: missingKeys, credentialValidated: false },
    });
  }

  // Credential present but UNVALIDATED (CH-36): we do not silently claim it
  // works. Honest success carries credentialValidated:false until a live call.
  if (!agentMode()) {
    console.log(`${pc.green('✓')} ${match.id} added to Chariot.${pkgDisplay}`);
    if (declaredEnvKeys.length > 0) {
      console.log(`${pc.dim('  Credential stored but not yet validated — run `chariot query "<question>"` to verify it works.')}`);
    }
  }
  return ok('cli:add', {
    human_message: `${match.id} added`,
    data: { id: match.id, installed: installOutcome === 'ok' || installOutcome === 'skipped', credentialsPresent, credentialValidated: false },
  });
}

// ── chariot remove ─────────────────────────────────────────────────────────

async function cmdRemove(adapterName: string): Promise<ChariotEnvelope> {
  const state = loadState();
  const config = loadConfig();

  if (!state.adapters[adapterName]) {
    // CHARIOT §23.2: main() emits this envelope with
    // humanAlreadyRendered:true, so emit() prints nothing — the human-mode
    // path must render its own message or the command exits 0-bytes/silent.
    // Emit an honest not-found line so a human never sees empty output.
    if (!agentMode()) {
      console.log(`${pc.yellow('!')} Adapter "${adapterName}" is not configured — nothing to remove.`);
      console.log(pc.dim('  Run `chariot list` to see configured adapters.'));
    }
    return fail('cli:remove', 'NOT_CONFIGURED', {
      severity: 'warning',
      human_message: `Adapter "${adapterName}" is not configured.`,
      cause: `no state entry for "${adapterName}"`,
      remediation: ['Run `chariot list` to see configured adapters.'],
    });
  }

  saveState(removeAdapterState(state, adapterName));

  if (config) {
    config.selectedAdapters = config.selectedAdapters.filter(id => id !== adapterName);
    saveConfig(config);
  }

  // CH-38: purge EVERY artifact `add` wrote — including the adapter's
  // credential in ~/.epic-ai/.env. The 3.1.2 `remove` left the token behind
  // ("clean those manually"), a secret-residue gap. We delete exactly the
  // adapter's declared credential keys (never engine-internal keys, never
  // unrelated adapters' keys), then report what was actually removed.
  const all = loadChariotMcpRegistryWithNative();
  const match = all.find(a => a.id === adapterName);
  let removedCreds: string[] = [];
  if (match) {
    // restAllEnvKeys (not restEnvKeys): purge must catch every field this
    // adapter COULD have received a credential for — every alternatives[]
    // group (not just whichever was prompt-facing) plus optional fields.
    const keys = [...effectiveEnvKeys(match), ...restAllEnvKeys(match).map(f => f.envVar)];
    // Never remove a key still required by another configured adapter.
    const remainingIds = Object.keys(loadState().adapters);
    const stillNeeded = new Set<string>();
    for (const otherId of remainingIds) {
      const other = all.find(a => a.id === otherId);
      if (other) {
        for (const k of effectiveEnvKeys(other)) stillNeeded.add(k);
        for (const { envVar } of restAllEnvKeys(other)) stillNeeded.add(envVar);
      }
    }
    const safeToRemove = keys.filter(k => !stillNeeded.has(k));
    if (safeToRemove.length > 0) {
      try { removedCreds = removeCredential(safeToRemove); } catch { /* best-effort purge */ }
    }
  }

  // CH-38/CH-48: remove the Chariot MCP server entry from every AI-client
  // config that the wizard may have written. Best-effort per client; errors
  // do not abort the removal. detectMcpClients() checks path existence so
  // this is a no-op for clients the user never configured.
  const mcpClients = detectMcpClients();
  const removedMcpClients: string[] = [];
  for (const client of mcpClients) {
    try {
      const r = removeMcpConfig(client);
      if (r.removed) removedMcpClients.push(client.id);
    } catch { /* best-effort */ }
  }

  if (!agentMode()) {
    console.log(`${pc.green('✓')} ${adapterName} removed from Chariot.`);
    if (removedCreds.length > 0) {
      console.log(`${pc.green('✓')} purged credential${removedCreds.length === 1 ? '' : 's'}: ${removedCreds.join(', ')}`);
    } else {
      console.log(`${pc.dim('  No adapter-specific credentials remained in ~/.epic-ai/.env.')}`);
    }
    if (removedMcpClients.length > 0) {
      console.log(`${pc.green('✓')} removed Chariot MCP entry from: ${removedMcpClients.join(', ')}`);
    }
  }

  return ok('cli:remove', {
    human_message: `${adapterName} removed`,
    data: { id: adapterName, removedCredentials: removedCreds, removedMcpClients },
  });
}

// ── chariot health ─────────────────────────────────────────────────────────

/**
 * Per-adapter honest health classification (CH-36). A green ✓ requires BOTH
 * a satisfied credential AND at least one callable tool. The two
 * silent-false-success cases the 3.1.2 dogfood found are demoted out of green:
 *   - 0-tool adapters (wikipedia/dns/salesforce) → `no-tools` (warning), and
 *   - credentialed-but-unvalidated custom adapters (the garbage-token github)
 *     → `unvalidated` (warning), NOT a green "configured".
 * `health` does not dial out to validate every token on every run (that would
 * make a read-only status command slow and side-effecting); presence of a
 * credential that has never passed a live call is reported honestly as
 * `unvalidated` rather than asserted "healthy".
 */
type HealthStatus = 'healthy' | 'no-tools' | 'missing-credential' | 'unvalidated' | 'not-found' | 'rejected-envelope';
interface AdapterHealth {
  id: string;
  status: HealthStatus;
  toolCount: number;
  detail: string;
}

function classifyAdapterHealth(
  id: string,
  adapter: ChariotRegistryEntry | undefined,
  creds: Record<string, string>,
  state: ReturnType<typeof loadState>,
): AdapterHealth {
  if (!adapter) {
    return { id, status: 'not-found', toolCount: 0, detail: 'not found in catalog' };
  }
  const isCurated = CHARIOT_CURATED_IDS.includes(id);
  const toolCount = bundleToolCount(adapter);
  const { healthy: hasKey, missingKey, credentialBasis } = cmdHealthCheckAdapter(adapter, creds, isCurated);
  if (!isCurated && !hasKey) {
    return { id, status: 'missing-credential', toolCount, detail: `missing ${missingKey || 'credentials'}` };
  }
  // Credential satisfied (or curated/keyless) — but a green ✓ also requires
  // callable tools (CH-36 / CH-50): a 0-tool adapter is not "healthy".
  if (toolCount === 0) {
    return { id, status: 'no-tools', toolCount, detail: 'no callable tools in bundle' };
  }
  // Custom adapter with a credential present but never exercised by a live
  // call → unvalidated, not green (the garbage-token gap).
  const stateEntry = state.adapters[id];
  // Only an adapter with an ACTUAL configured credential
  // (credentialBasis 'satisfied') that was never exercised by a live call is
  // 'unvalidated'. A keyless / zero-credential adapter (credentialBasis 'none')
  // has no credential to validate — a tool-bearing one is healthy, not
  // "credential present but never validated".
  if (!isCurated && credentialBasis === 'satisfied' && (!stateEntry || stateEntry.lastVerified == null)) {
    return { id, status: 'unvalidated', toolCount, detail: 'credential present but never validated by a live call' };
  }
  return { id, status: 'healthy', toolCount, detail: isCurated ? 'curated' : (stateEntry?.status ?? 'configured') };
}

async function cmdHealth(): Promise<ChariotEnvelope> {
  const state = loadState();
  const creds = loadCredentials();
  const all = loadChariotMcpRegistryWithNative();
  // FIX (2026-09-30, release-blocking): `loadChariotMcpRegistryWithNative()`
  // is a catalog-bundle-only, SYNC loader with no discovered-adapter
  // overlay, so every one of a customer's discovered adapters (state.adapters
  // keys prefixed `discovered:`, per src/engine/federation/
  // configuredAdapterIds.ts) reported "not found in catalog" here even
  // after it was genuinely signed, verified, and dispatchable via
  // `chariot query`/`chariot serve` — a false negative on the health
  // command the customer sees.
  //
  // `loadAllAdapters()` (ChariotState.ts) is the overlay-aware loader
  // `chariot query`/`chariot serve` already use (bundle + native-curated +
  // verified-discovered) — but SWAPPING it in wholesale as the catalog
  // source here regressed curated-adapter health (confirmed by direct
  // reproduction: wikipedia/dns dropped from healthy to "no-tools" —
  // `bundleToolCount()`'s top-level toolCount/toolNames read does not find
  // a match on ChariotState.ts's AdapterEntry shape for those two the way
  // it does on `ChariotRegistryEntry` from loadChariotMcpRegistryWithNative()).
  // So `all` stays the PROVEN-correct catalog source for every already-
  // working adapter, and ONLY the discovered-adapter entries (absent from
  // it entirely) are merged in from the SAME overlay loader chariot
  // query/serve use — additive, not a wholesale replacement. Dynamic
  // import matches this file's existing convention (see the cmdQuery-
  // adjacent call site above) rather than adding a new static import.
  const { loadAllAdapters: loadAllAdaptersForHealth } = await import('../engine/server/ChariotState.js');
  const overlayAdapters = await loadAllAdaptersForHealth();
  const discoveredOverlay = overlayAdapters.filter(a => a.id.startsWith('discovered:'));
  if (discoveredOverlay.length > 0) {
    all.push(...(discoveredOverlay as unknown as ChariotRegistryEntry[]));
  }

  // bug-tracker-ref: `chariot health` must report on the SAME adapter set
  // `chariot list` shows — curated (always-on) PLUS custom (user-added).
  const customIds = Object.keys(state.adapters).filter(id => !CHARIOT_CURATED_IDS.includes(id));
  const configured = [...CHARIOT_CURATED_IDS, ...customIds];
  if (configured.length === 0) {
    if (!agentMode()) console.log(`No adapters configured. Run ${pc.cyan('chariot')} to set up.`);
    // CH-31 (zero-day fix): an ok:false envelope MUST carry a non-zero
    // exit_code — the previous exit_code:EXIT.OK split the honest signal
    // (JSON said failure, process said success). An agent running `chariot
    // health` on an unconfigured install must see non-zero.
    return fail('cli:health', 'NOT_CONFIGURED', {
      severity: 'warning',
      exit_code: EXIT.FAILURE,
      human_message: 'No adapters configured.',
      remediation: ['Run `chariot` to set up, or `chariot add <id>`.'],
    });
  }

  const s = makeSpinner(p);
  s.start(`Checking ${configured.length} adapters`);

  const checks = configured.map(id => classifyAdapterHealth(id, all.find(a => a.id === id), creds, state));

  // FIX (2026-09-30, dogfood mechanism-test-routes): a discovered-adapter
  // envelope that fails signature/identity verification (e.g. the
  // writer/filename id-mismatch bug this same change fixes at the source)
  // was previously dropped SILENTLY — loadVerifiedDiscoveredAdapters()
  // already returns a `rejected: {file, reason}[]` array (see
  // src/discovery/envelope.ts), but nothing surfaced it in `chariot
  // health`. Every rejected envelope now shows as its own red issue line
  // naming the file and the exact rejection reason, so a customer sees
  // WHY a discovered service isn't usable instead of it just vanishing.
  let discoveredRejected: Array<{ file: string; reason: string }> = [];
  try {
    discoveredRejected = loadVerifiedDiscoveredAdapters().rejected;
  } catch {
    // best-effort — a health check must never crash on a discovery-layer
    // read failure; the underlying adapters already reflect the catalog
    // state independent of this diagnostic.
  }
  const rejectedChecks: AdapterHealth[] = discoveredRejected.map(r => ({
    id: r.file,
    status: 'rejected-envelope',
    toolCount: 0,
    detail: r.reason,
  }));
  const allChecks = [...checks, ...rejectedChecks];
  const healthy = allChecks.filter(c => c.status === 'healthy').length;
  const issues = allChecks.length - healthy;

  const icon: Record<HealthStatus, string> = {
    'healthy': pc.green('✓'),
    'no-tools': pc.yellow('!'),
    'missing-credential': pc.yellow('!'),
    'unvalidated': pc.yellow('!'),
    'not-found': pc.red('✗'),
    'rejected-envelope': pc.red('✗'),
  };
  const results = allChecks.map(c =>
    c.status === 'healthy'
      ? `${icon[c.status]} ${c.id}  ${toolsLabel(c.toolCount)}  ${c.detail}`
      : `${icon[c.status]} ${c.id}  ${c.detail}${c.toolCount ? `  (${toolsLabel(c.toolCount)})` : ''}`,
  );

  s.stop('Health check complete');

  if (!agentMode()) {
    p.note(results.join('\n'), `${healthy} healthy, ${issues} need attention`);
  }

  saveState(withLastHealthCheck(state, new Date().toISOString()));

  const data = {
    healthy,
    issues,
    adapters: allChecks.map(c => ({ id: c.id, status: c.status, toolCount: c.toolCount, detail: c.detail })),
  };
  // CH-31: a non-healthy fleet MUST NOT present as exit-0 ✓. Any adapter that
  // is not genuinely healthy makes `health` a typed non-zero outcome an agent
  // can branch on.
  if (issues > 0) {
    return fail('cli:health', 'UNHEALTHY', {
      severity: 'warning',
      human_message: `${healthy} healthy, ${issues} need attention`,
      cause: `${issues} adapter(s) are not callable (0-tool, missing-credential, or unvalidated).`,
      remediation: ['Add credentials with `chariot add <id> --token KEY=VAL`, or run `chariot query` to validate dispatch.'],
      data,
    });
  }
  return ok('cli:health', { human_message: `${healthy} healthy, 0 need attention`, data });
}

// ── chariot configure ──────────────────────────────────────────────────────

async function cmdConfigure(): Promise<ChariotEnvelope> {
  // CH-32: configure is fully interactive — no --config alternative exists
  // yet. In a non-TTY emit a typed INTERACTIVE_PROMPT_IN_NON_TTY with the
  // exact non-interactive command, instead of a bare exit-4 message.
  if (NON_INTERACTIVE) {
    throw new ChariotError(interactiveInNonTty(
      'cli:configure',
      'chariot add <id> --token KEY=VAL',
      'chariot configure opens interactive credential prompts and stdin is not a TTY.',
    ));
  }
  console.log('');
  p.intro(pc.bgCyan(pc.black(' Chariot Configure — Connect Your APIs ')));

  const all = loadChariotMcpRegistryWithNative();

  const scanTargets = await p.multiselect({
    message: 'Where should Chariot look for existing credentials?',
    options: [
      { value: 'epic-ai', label: '~/.epic-ai/.env', hint: 'Chariot\'s credential store' },
      { value: 'home', label: '~/.env', hint: 'home directory env file' },
      { value: 'cwd', label: '.env in current directory', hint: `${process.cwd()}/.env` },
    ],
    initialValues: ['epic-ai'],
    required: true,
  });
  if (p.isCancel(scanTargets)) { p.cancel('Cancelled.'); process.exit(0); }

  const s = makeSpinner(p);
  s.start('Scanning for credentials');

  const foundCreds: Record<string, string> = {};

  if ((scanTargets as string[]).includes('epic-ai')) Object.assign(foundCreds, loadCredentials());
  if ((scanTargets as string[]).includes('home')) Object.assign(foundCreds, loadCredentialsFrom(join(homedir(), '.env')));
  if ((scanTargets as string[]).includes('cwd')) Object.assign(foundCreds, loadCredentialsFrom(join(process.cwd(), '.env')));

  s.stop('Scan complete');

  const matched: Array<{ adapter: ChariotRegistryEntry; key: string }> = [];
  for (const adapter of all) {
    if (CHARIOT_CURATED_IDS.includes(adapter.id)) continue;
    if (adapter.mcp?.envKeys) {
      for (const k of adapter.mcp.envKeys) {
        if (foundCreds[k]) { matched.push({ adapter, key: k }); break; }
      }
    }
  }

  if (matched.length === 0) {
    p.log.info('No matching credentials found in scanned locations.');
  } else {
    p.note(
      matched.map(m => `  ${pc.green(m.key.padEnd(30))} → ${pc.cyan(m.adapter.name)}`).join('\n'),
      `Found ${matched.length} credential${matched.length !== 1 ? 's' : ''}`
    );

    const toWire = await p.multiselect({
      message: 'Wire these adapters?',
      options: matched.map(m => ({
        value: m.adapter.id,
        label: m.adapter.name,
        hint: `${m.key} → ${m.adapter.description?.slice(0, 50) || m.adapter.id}`,
      })),
      initialValues: matched.map(m => m.adapter.id),
      required: false,
    });
    if (p.isCancel(toWire)) { p.cancel('Cancelled.'); process.exit(0); }

    let nextState = loadState();
    const config = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };

    for (const id of (toWire as string[])) {
      const m = matched.find(x => x.adapter.id === id);
      if (!m) continue;
      writeCredential(m.key, foundCreds[m.key]);
      nextState = upsertAdapterState(nextState, id, {
        type: m.adapter.type || 'mcp',
        status: 'configured',
        toolCount: bundleToolCount(m.adapter),
        lastVerified: null,
      });
      if (!config.selectedAdapters.includes(id)) config.selectedAdapters.push(id);
    }
    saveState(nextState);
    saveConfig(config);

    if ((toWire as string[]).length > 0) {
      p.log.success(`${(toWire as string[]).length} adapter${(toWire as string[]).length !== 1 ? 's' : ''} configured.`);
    }
  }

  const addMore = await p.confirm({ message: 'Add adapters manually?', initialValue: false });
  if (!p.isCancel(addMore) && addMore) {
    const name = await p.text({ message: 'Adapter ID (run "chariot search <term>" to find one):' });
    if (!p.isCancel(name) && name) await cmdAdd(name);
  }

  p.outro(`${pc.green('Done.')} Run ${pc.cyan('chariot list')} to see your configured adapters.`);
  return ok('cli:configure', { human_message: 'configure complete' });
}

// ── chariot audit ──────────────────────────────────────────────────────────
//
// Reads the persisted JSONL chain at <packageRoot>/audit/<chainId>.jsonl to
// obtain the current head hash and chain length without a running engine.
// Operator supplies --chain-id; packageRoot defaults to EPIC_AI_DIR.

async function readChainState(chainFile: string): Promise<{ length: number; headHash: string }> {
  if (!existsSync(chainFile)) {
    return { length: 0, headHash: '' };
  }
  const records: Array<{ sequenceNumber: number; hash: string }> = [];
  await new Promise<void>((resolve, reject) => {
    const rl = createInterface({
      input: createReadStream(chainFile, { encoding: 'utf-8' }),
      crlfDelay: Infinity,
    });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const r = JSON.parse(trimmed) as { sequenceNumber?: number; hash?: string };
        if (typeof r.sequenceNumber === 'number' && typeof r.hash === 'string') {
          records.push({ sequenceNumber: r.sequenceNumber, hash: r.hash });
        }
      } catch {
        // skip unparseable lines
      }
    });
    rl.on('close', resolve);
    rl.on('error', reject);
  });
  if (records.length === 0) return { length: 0, headHash: '' };
  records.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  const last = records[records.length - 1];
  return { length: records.length, headHash: last.hash };
}

/**
 * Load the FULL parsed records of a JSONL chain (every field), for per-record
 * hash-chain integrity verification. Unlike readChainState — which projects
 * each line down to {sequenceNumber, hash} for a length/head-hash view — this
 * preserves the complete record so HashChain.verifyChain can recompute each
 * SHA-256 and re-check the previousHash links. Status-update supplement lines
 * (no sequenceNumber/hash) are retained here and filtered inside verifyChain
 * via HashChain.isChainRecord, keeping a single source of truth for that
 * predicate. Unparseable lines are skipped, matching readChainState.
 */
async function readChainRecords(chainFile: string): Promise<import('../engine/types/index.js').ActionRecord[]> {
  if (!existsSync(chainFile)) return [];
  const records: import('../engine/types/index.js').ActionRecord[] = [];
  await new Promise<void>((resolve, reject) => {
    const rl = createInterface({
      input: createReadStream(chainFile, { encoding: 'utf-8' }),
      crlfDelay: Infinity,
    });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        records.push(JSON.parse(trimmed) as import('../engine/types/index.js').ActionRecord);
      } catch {
        // skip unparseable lines (same policy as readChainState)
      }
    });
    rl.on('close', resolve);
    rl.on('error', reject);
  });
  return records;
}

/**
 * Step-by-step trace breakdown + optional LLM-driven attribution scorer.
 *
 * Reads the JSONL audit chain at the standard location (or a supplied path),
 * filters records where `traceId === <id>`, sorts by sequenceNumber, prints a
 * human-readable per-step summary, and — when at least one judge API key is
 * present — invokes `scripts/attribute-trace.mjs` to attribute the failure to
 * a specific stepId via the ensemble panel.
 */
async function cmdTraceExplain(traceId: string | undefined, auditFileArg: string | undefined): Promise<ChariotEnvelope> {
  if (!traceId) {
    if (!agentMode()) {
      console.error(pc.red('Usage: chariot trace explain <traceId> [audit.jsonl]'));
      console.error(pc.dim('  traceId    UUID v4 to filter on'));
      console.error(pc.dim('  audit.jsonl (optional) explicit audit-chain file; defaults to .chariot/audit/chain.jsonl'));
    }
    return fail('cli:trace', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: 'Usage: chariot trace explain <traceId> [audit.jsonl]',
    });
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const auditFile = auditFileArg ?? path.resolve(process.cwd(), '.chariot/audit/chain.jsonl');
  if (!fs.existsSync(auditFile)) {
    if (!agentMode()) {
      console.error(pc.red(`Audit file not found: ${auditFile}`));
      console.error(pc.dim('  Export with: chariot audit export --format jsonl'));
    }
    return fail('cli:trace', 'AUDIT_FILE_NOT_FOUND', {
      exit_code: EXIT.FAILURE,
      human_message: `Audit file not found: ${auditFile}`,
      remediation: ['Export with: chariot audit export --format jsonl'],
      data: { auditFile, traceId },
    });
  }
  const raw = fs.readFileSync(auditFile, 'utf-8').trim();
  // Coalesce status-update lines into their original record by id, so the
  // resolved status/output/durationMs (and any post-record metadata like
  // failureMode) is visible alongside traceId/stepKind. JSONLAdapter is
  // append-only — the original record line carries traceId/stepKind; later
  // status-update lines reuse the id but omit those fields.
  const byId = new Map<string, Record<string, unknown>>();
  const orderById: string[] = [];
  const recordsNoId: Array<Record<string, unknown>> = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(trimmed) as Record<string, unknown>;
    } catch (err) {
      if (!agentMode()) console.error(pc.red(`JSONL parse error: ${(err as Error).message}`));
      return fail('cli:trace', 'AUDIT_PARSE_ERROR', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `JSONL parse error in audit file: ${(err as Error).message}`,
        data: { auditFile, traceId },
      });
    }
    const id = typeof obj.id === 'string' ? obj.id : null;
    if (id === null) {
      recordsNoId.push(obj);
      continue;
    }
    if (byId.has(id)) {
      byId.set(id, { ...byId.get(id)!, ...obj });
    } else {
      byId.set(id, obj);
      orderById.push(id);
    }
  }
  const records: Array<Record<string, unknown>> = [
    ...orderById.map((id) => byId.get(id)!),
    ...recordsNoId,
  ];
  const steps = records
    .filter((r) => (r as { traceId?: string }).traceId === traceId)
    .sort((a, b) => ((a as { sequenceNumber?: number }).sequenceNumber ?? 0) - ((b as { sequenceNumber?: number }).sequenceNumber ?? 0));
  if (steps.length === 0) {
    if (!agentMode()) console.error(pc.red(`No records found for traceId=${traceId}`));
    return fail('cli:trace', 'NOT_FOUND', {
      exit_code: EXIT.FAILURE,
      human_message: `No records found for traceId=${traceId}`,
      data: { traceId, auditFile },
    });
  }

  if (!agentMode()) {
    console.log(pc.bold(`Trace: ${traceId}`));
    for (const s of steps) {
      const r = s as { id?: string; sequenceNumber?: number; stepKind?: string; action?: string; status?: string; output?: unknown; durationMs?: number; confidence?: number };
      const seq = String(r.sequenceNumber ?? 0).padStart(4, '0');
      const kind = r.stepKind ?? r.action ?? 'unknown';
      const status = r.status ?? 'unknown';
      const dur = typeof r.durationMs === 'number' ? `${r.durationMs}ms` : '';
      const conf = typeof r.confidence === 'number' ? ` (confidence: ${r.confidence.toFixed(2)})` : '';
      console.log(`  [${seq}] ${pc.cyan(kind)} → ${status}${dur ? ' (' + dur + ')' : ''}${conf}`);
      if (r.output) {
        const out = typeof r.output === 'string' ? r.output : JSON.stringify(r.output);
        const trimmedOut = out.length > 160 ? out.slice(0, 160) + '…' : out;
        console.log(pc.dim(`         output: ${trimmedOut}`));
      }
    }
  }

  // ── Optional LLM-driven attribution scorer ─────────────────────────────
  const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;
  const hasOpenAI = !!process.env.OPENAI_API_KEY;
  if (!hasAnthropic && !hasOpenAI) {
    if (!agentMode()) {
      console.log('');
      console.log(pc.dim('Attribution scorer skipped — no ANTHROPIC_API_KEY or OPENAI_API_KEY in env.'));
      console.log(pc.dim('  Set one to enable the ensemble panel attribution step.'));
    }
    return ok('cli:trace', {
      human_message: `Trace ${traceId}: ${steps.length} steps (attribution scorer skipped — no API key)`,
      data: { traceId, stepCount: steps.length, steps, attribution: null },
    });
  }

  if (!agentMode()) {
    console.log('');
    console.log(pc.dim('Running ensemble attribution scorer…'));
  }
  const child = await import('node:child_process');
  const url = await import('node:url');
  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const scorerPath = path.resolve(here, '..', '..', 'scripts', 'attribute-trace.mjs');
  if (!fs.existsSync(scorerPath)) {
    if (!agentMode()) console.error(pc.red(`Attribution scorer not found at ${scorerPath}`));
    return fail('cli:trace', 'SCORER_NOT_FOUND', {
      exit_code: EXIT.FAILURE,
      human_message: `Attribution scorer not found at ${scorerPath}`,
      data: { traceId, scorerPath },
    });
  }
  const scorerResult = child.spawnSync('node', [scorerPath, auditFile, traceId], {
    stdio: ['ignore', 'pipe', 'inherit'],
    env: process.env,
  });
  if (scorerResult.status !== 0) {
    return fail('cli:trace', 'SCORER_FAILED', {
      exit_code: scorerResult.status ?? EXIT.FAILURE,
      human_message: `Attribution scorer exited with code ${scorerResult.status ?? 1}`,
      data: { traceId, exitCode: scorerResult.status },
    });
  }
  const scorerOut = scorerResult.stdout?.toString() ?? '';
  let parsed: { attributedStepId?: string | null; errorKind?: string; confidence?: number; agreeingJudges?: number; totalJudges?: number } = {};
  try {
    parsed = JSON.parse(scorerOut);
  } catch (err) {
    if (!agentMode()) {
      console.error(pc.red(`Failed to parse scorer output: ${(err as Error).message}`));
      console.error(scorerOut);
    }
    return fail('cli:trace', 'SCORER_OUTPUT_PARSE_ERROR', {
      exit_code: EXIT.FAILURE,
      cause: (err as Error).message,
      human_message: `Failed to parse attribution scorer output: ${(err as Error).message}`,
      data: { traceId },
    });
  }
  if (!agentMode()) {
    console.log('');
    console.log(pc.bold('Attribution scorer output:'));
    console.log(`  Attributed step: ${parsed.attributedStepId ?? pc.yellow('(no clear winner)')}`);
    console.log(`  Error kind:      ${parsed.errorKind ?? 'unknown'}`);
    if (typeof parsed.confidence === 'number') {
      console.log(`  Confidence:      ${parsed.confidence.toFixed(2)} (${parsed.agreeingJudges}/${parsed.totalJudges} judges agreed)`);
    }
  }
  return ok('cli:trace', {
    human_message: `Trace ${traceId}: ${steps.length} steps, attributed to ${parsed.attributedStepId ?? '(none)'}`,
    data: { traceId, stepCount: steps.length, steps, attribution: parsed },
  });
}

/**
 * `chariot resume <traceId>` subcommand. Reads the most
 * recent checkpoint for the given traceId from the SQLite checkpoint
 * store and prints it. Resume execution (replaying the orchestrator
 * loop from the checkpoint) is a separate ticket; this command ships
 * the read surface for forensic + recovery use.
 *
 * Database path resolution: CHARIOT_SQLITE_PATH env override, else
 * `${EPIC_AI_DIR}/chariot.db`. traceId is validated (non-empty,
 * length-capped) before being passed through parameterized SQL.
 */
// ── chariot approve <id>  +  chariot approvals ───────────────────────────────
// AS §1.5 first-use approval gate for CLI-bridge adapters. The dispatcher
// at engine/server/toolHandlers.ts refuses CLI tool calls until the
// operator has interactively approved the adapter here. No `--yes` /
// env-var bypass — approval is a human-operator decision per spec.

async function cmdApprove(adapterId: string): Promise<ChariotEnvelope> {
  if (NON_INTERACTIVE) {
    // --json implies NON_INTERACTIVE, so this branch emits a typed envelope
    // in both agent and human modes instead of a bare process.exit(4).
    if (!agentMode()) {
      console.error(pc.red('STDIN_REQUIRED: `chariot approve` requires an interactive operator.'));
      console.error(pc.dim('Approval is a human-operator decision per Adapter Standard §1.5; --yes / env-var bypass is not permitted.'));
    }
    return fail('cli:approve', 'INTERACTIVE_PROMPT_IN_NON_TTY', {
      severity: 'blocked',
      exit_code: EXIT.STDIN_REQUIRED,
      retryable: false,
      cause: 'Approval is a human-operator decision per Adapter Standard §1.5; --yes/env-var bypass is not permitted.',
      agent_message: 'chariot approve requires an interactive operator; it cannot be automated via --yes or CHARIOT_AGENT.',
      must_not: ['automate this approval', 'treat the refusal as a transient error'],
    });
  }
  // Note: NON_INTERACTIVE is already set when !process.stdin.isTTY (line ~148),
  // so the previous second TTY check was dead code. The NON_INTERACTIVE guard
  // above is the single gate; this belt-and-suspenders check is removed.

  // Resolve the adapter against the loaded bundle catalog. Imports are
  // dynamic so the bundle-load path (which pulls in heavy engine modules)
  // does not run for every chariot invocation.
  const { loadAllAdapters } = await import('../engine/server/ChariotState.js');
  const adapters = await loadAllAdapters();
  const adapter = adapters.find((a) => a.id === adapterId);
  if (!adapter) {
    console.error(pc.red(`Unknown adapter: ${adapterId}`));
    console.error(pc.dim('Run `chariot list` to see installed adapters.'));
    return fail('cli:approve', 'ADAPTER_NOT_FOUND', {
      exit_code: EXIT.USAGE,
      human_message: `Unknown adapter: ${adapterId}`,
      remediation: ['Run `chariot list` to see installed adapters.'],
      data: { id: adapterId },
    });
  }
  if (adapter.type !== 'cli-bridge' || !adapter.cli?.binary) {
    console.error(pc.red(`Adapter ${adapterId} is not a CLI-bridge adapter (type=${adapter.type}).`));
    console.error(pc.dim('`chariot approve` applies only to cli-bridge adapters per AS §1.5.'));
    return fail('cli:approve', 'ADAPTER_TYPE_MISMATCH', {
      exit_code: EXIT.USAGE,
      human_message: `Adapter ${adapterId} is not a CLI-bridge adapter (type=${adapter.type}).`,
      cause: '`chariot approve` applies only to cli-bridge adapters per AS §1.5.',
      must_not: ['attempt to approve non-cli-bridge adapters'],
      data: { id: adapterId, type: adapter.type },
    });
  }

  // Display the binary + argv template per AS §1.5 first-use display.
  console.log('');
  console.log(`  ${pc.bold('CLI adapter approval')} — Adapter Standard §1.5`);
  console.log('');
  // note: every catalog-sourced string that prints
  // to the operator terminal during approval MUST be control-stripped
  // first. A malicious or malformed catalog with ANSI escapes / NUL /
  // BACKSPACE in cli.binary or cli.args could otherwise repaint the
  // approval display, hide bytes, or fake cursor motion. The
  // dispatcher recomputes the argv from the live catalog at spawn
  // time and never uses these sanitised strings, so there's no
  // execution-semantics impact.
  const safeId = sanitizeDisplayString(adapterId);
  const safeBinary = sanitizeDisplayString(adapter.cli.binary);
  const defaultArgs = Array.isArray(adapter.cli.args) ? adapter.cli.args : [];
  // note: blocker B: a raw `.join(' ')` collapses
  // token boundaries, so args `['a b', 'c']` display the same as
  // `['a', 'b', 'c']`. For a human approval gate that's a security
  // bug — the operator can't see what they're approving. Wrap each
  // arg in single quotes after sanitisation; embedded single quotes
  // are escaped as `'\''` (POSIX-style) so the display is unambiguous
  // even when the arg literally contains the quote character.
  const safeArgs = defaultArgs.map((a) => {
    const s = sanitizeDisplayString(a);
    return `'${s.replace(/'/g, "'\\''")}'`;
  });
  console.log(`    ${pc.cyan('id')}        ${safeId}`);
  console.log(`    ${pc.cyan('binary')}    ${safeBinary}`);
  console.log(`    ${pc.cyan('args')}      ${safeArgs.length > 0 ? safeArgs.join(' ') : pc.dim('(none)')}`);

  const schemas = Array.isArray(adapter.cli.toolSchemas) ? adapter.cli.toolSchemas : [];
  if (schemas.length > 0) {
    console.log('');
    console.log(`  ${pc.bold('Tools the operator is approving:')}`);
    for (const s of schemas) {
      // Use the shared renderToolArgv so the operator-facing display
      // EXACTLY matches the dispatcher's spawn semantics. Pass undefined
      // for baseArgs since base args were displayed on their own line above.
      const parts = renderToolArgv(undefined, s);
      const argDisplay = parts.length > 0 ? parts.join(' ') : pc.dim('(no args)');
      const safeToolName = sanitizeDisplayString(s.name);
      const safeToolDesc = sanitizeDisplayString(s.description ?? '');
      console.log(`    ${pc.cyan(safeToolName)}  ${pc.dim(safeToolDesc)}`);
      console.log(`      ${pc.dim('argv:')} ${safeBinary} ${argDisplay}`);
    }
  }

  console.log('');
  console.log(pc.yellow('  WARNING: Approving this adapter authorises Chariot to spawn the binary above'));
  console.log(pc.yellow('  with the argv shown on every tool call from any AI client. Approve only if you'));
  console.log(pc.yellow('  trust the binary, its argv template, and the AI client that will drive it.'));
  console.log('');

  const rl = createInterfacePromises({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question(`  Approve this CLI adapter for use? [y/N] `)).trim().toLowerCase();
  rl.close();

  if (answer !== 'y' && answer !== 'yes') {
    console.log('');
    console.log(pc.dim('  Approval refused — adapter remains unapproved. No state change.'));
    console.log('');
    // CH-31 (zero-day fix): a refused approval means the approve command did
    // NOT accomplish an approval — ok:false must pair with a non-zero exit
    // code so a script/agent can never read the refusal as success.
    return fail('cli:approve', 'APPROVAL_REFUSED', {
      severity: 'info',
      exit_code: EXIT.FAILURE,
      retryable: true,
      human_message: `Approval refused for ${adapterId} — no state change.`,
      data: { id: adapterId, approved: false },
    });
  }

  const result = recordAdapterApproval(adapterId, {
    binary: adapter.cli.binary,
    args: adapter.cli.args,
    toolSchemas: (adapter.cli.toolSchemas ?? []) as Array<{ name: string; subcommand?: string; flags?: Record<string, string>; positional?: readonly string[] }>,
  });
  // Q-2.2: structured log line so operators have a forensic trail of
  // who approved what + when, in addition to the state-file record.
  // Mirrors the dispatcher's cli_approval_required log shape.
  _cliApprovalLog.info('cli_approval_recorded', {
    adapter_id: adapterId,
    binary: adapter.cli.binary,
    base_args: (adapter.cli.args ?? []) as unknown[],
    tool_count: schemas.length,
    approved_at: result.approvedAt,
    approved_shape_hash: result.approvedShapeHash,
  });
  console.log('');
  console.log(pc.green(`  ✓ Approved at ${result.approvedAt}`));
  console.log(pc.dim(`    shape hash: ${result.approvedShapeHash}`));
  console.log(pc.dim('    A subsequent change to this binary or argv will revoke approval on next dispatch.'));
  console.log('');
  return ok('cli:approve', {
    human_message: `Approved at ${result.approvedAt}`,
    data: { id: adapterId, approved: true, approvedAt: result.approvedAt, approvedShapeHash: result.approvedShapeHash },
  });
}

async function cmdRevoke(adapterId: string): Promise<ChariotEnvelope> {
  // Use `revoked` to avoid shadowing the imported `ok` envelope builder.
  const revoked = revokeAdapterApproval(adapterId);
  if (revoked) {
    _cliApprovalLog.info('cli_approval_revoked', {
      adapter_id: adapterId,
      revoked_at: new Date().toISOString(),
    });
  }
  if (!agentMode()) {
    console.log('');
    if (revoked) {
      console.log(pc.green(`  ✓ Revoked approval for ${adapterId}`));
      console.log(pc.dim('    Subsequent CLI tool calls for this adapter will return CLI_APPROVAL_REQUIRED.'));
    } else {
      console.log(pc.dim(`  No active approval for ${adapterId} (nothing to revoke).`));
    }
    console.log('');
  }
  if (!revoked) {
    // CH-31: not-found must be distinguishable from success — non-zero exit.
    return fail('cli:revoke', 'NOT_FOUND', {
      severity: 'warning',
      exit_code: EXIT.FAILURE,
      human_message: `No active approval for "${adapterId}" — nothing to revoke.`,
      cause: `adapter "${adapterId}" has no recorded approval`,
      remediation: ['Run `chariot approvals` to see currently approved adapters.'],
      data: { id: adapterId, revoked: false },
    });
  }
  return ok('cli:revoke', {
    human_message: `Revoked approval for ${adapterId}`,
    data: { id: adapterId, revoked: true },
  });
}

async function cmdApprovals(): Promise<ChariotEnvelope> {
  const approvals = listApprovedAdapters();
  if (!agentMode()) {
    console.log('');
    if (approvals.length === 0) {
      console.log(pc.dim('  No CLI adapters approved. Run `chariot approve <adapter-id>` to approve one.'));
    } else {
      console.log(`  ${pc.bold('Approved CLI adapters:')}`);
      console.log('');
      for (const a of approvals) {
        console.log(`    ${pc.cyan(a.id.padEnd(30))} ${pc.dim(a.type.padEnd(12))} ${a.approvedAt}`);
      }
    }
    console.log('');
  }
  return ok('cli:approvals', {
    human_message: `${approvals.length} approved CLI adapter${approvals.length !== 1 ? 's' : ''}`,
    data: { count: approvals.length, approvals },
  });
}

async function cmdResume(traceId: string | undefined): Promise<ChariotEnvelope> {
  if (!traceId || traceId.length === 0) {
    if (!agentMode()) {
      console.error(pc.red('Usage: chariot resume <traceId>'));
      console.error(pc.dim('  traceId    UUID or arbitrary trace identifier to look up'));
    }
    return fail('cli:resume', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: 'Usage: chariot resume <traceId>',
    });
  }
  if (traceId.length > 256) {
    if (!agentMode()) console.error(pc.red(`traceId too long: ${traceId.length} chars (max 256)`));
    return fail('cli:resume', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: `traceId too long: ${traceId.length} chars (max 256)`,
    });
  }
  const dbPath = process.env.CHARIOT_SQLITE_PATH ?? join(EPIC_AI_DIR, 'chariot.db');
  // No existence check: SqliteCheckpointStore creates the database
  // and schema on construct. If the DB is missing or empty (fresh
  // install, rotated path, deleted file), the latest() call below
  // returns undefined and prints the "no checkpoints found" path —
  // same outcome as a known-but-empty trace.
  const { SqliteCheckpointStore } = await import('../engine/recovery/SqliteCheckpointStore.js');
  const tenantId = process.env.CHARIOT_TENANT_ID ?? 'local';
    // CHARIOT §23.2: the SqliteCheckpointStore constructor opens (and
  // schema-creates) the SQLite DB eagerly. When the parent directory is absent
  // (fresh install, rotated CHARIOT_SQLITE_PATH, deleted file) libsql throws
  // ERR_SQLITE_ERROR ("unable to open database file") from the constructor —
  // OUTSIDE the previous try — so it propagated to main()'s top-level handler
  // and printed a raw Node/SQLite stack trace instead of an honest envelope.
  // Wrap BOTH construction and the latest() read so every terminal outcome is
  // a typed envelope (ok:false, real code, remediation), never a raw stack.
  let store: InstanceType<typeof SqliteCheckpointStore> | undefined;
  try {
    store = new SqliteCheckpointStore(dbPath);
    const latest = await store.latest(tenantId, traceId);
    if (!latest) {
      if (!agentMode()) console.log(pc.yellow(`No checkpoints found for traceId: ${traceId}`));
      return fail('cli:resume', 'NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `No checkpoints found for traceId: ${traceId}`,
        data: { traceId },
      });
    }
    if (!agentMode()) {
      console.log(pc.bold(`Latest checkpoint for ${traceId}:`));
      console.log(`  stepId:        ${latest.stepId}`);
      console.log(`  parentStepId:  ${latest.parentStepId ?? pc.dim('(root)')}`);
      console.log(`  iteration:     ${latest.iteration}`);
      console.log(`  toolName:      ${latest.toolName ?? pc.dim('(none)')}`);
      console.log(`  serverName:    ${latest.serverName ?? pc.dim('(none)')}`);
      console.log(`  timestamp:     ${latest.timestamp.toISOString()}`);
      console.log(`  input:         ${JSON.stringify(latest.input)}`);
      console.log(`  output:        ${JSON.stringify(latest.output)}`);
    }
    return ok('cli:resume', {
      human_message: `Latest checkpoint for ${traceId}`,
      data: {
        traceId,
        stepId: latest.stepId,
        parentStepId: latest.parentStepId ?? null,
        iteration: latest.iteration,
        toolName: latest.toolName ?? null,
        serverName: latest.serverName ?? null,
        timestamp: latest.timestamp.toISOString(),
        input: latest.input,
        output: latest.output,
      },
    });
  } catch (err) {
    // An unopenable / unreadable checkpoint store (missing parent
    // directory, permission denied, corrupt DB) becomes a typed failure with
    // a real code and remediation — never a raw SQLite stack trace.
    const msg = err instanceof Error ? err.message : String(err);
    if (!agentMode()) {
      console.error(pc.red(`Cannot read checkpoint store: ${msg}`));
      console.error(pc.dim(`  Path: ${dbPath}`));
      console.error(pc.dim('  Ensure the directory exists and is writable, or set CHARIOT_SQLITE_PATH to a valid location.'));
    }
    return fail('cli:resume', 'CHECKPOINT_STORE_UNAVAILABLE', {
      exit_code: EXIT.FAILURE,
      retryable: true,
      human_message: `Cannot read checkpoint store at ${dbPath}: ${msg}`,
      cause: msg,
      remediation: [
        'Ensure the checkpoint store directory exists and is writable.',
        'Set CHARIOT_SQLITE_PATH to a valid database location, or run `chariot query` first to initialize it.',
      ],
      data: { traceId, dbPath },
    });
  } finally {
    store?.close();
  }
}

async function cmdAudit(): Promise<ChariotEnvelope> {
  const { CHARIOT_ERROR_CODES } = await import('../engine/types/index.js');
  const sub = args[1];

  // ── Resolve packageRoot and chainId ─────────────────────────────────────

  const chainIdFlag = args.indexOf('--chain-id');
  const rawChainId: string =
    chainIdFlag !== -1 && args[chainIdFlag + 1]
      ? args[chainIdFlag + 1]
      : (process.env.CHARIOT_CHAIN_ID ?? 'default');

  // P2 path-traversal: reject `..` components and directory separators so
  // an attacker cannot escape the audit/ directory via `--chain-id ../../etc/passwd`.
  if (/[/\\]|\.\./.test(rawChainId)) {
    if (!agentMode()) console.error(pc.red(`--chain-id contains path separators or ".." — rejected: ${rawChainId}`));
    return fail('cli:audit', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: `--chain-id must not contain "/" "\\" or ".." (got: ${rawChainId})`,
      remediation: ['Use a plain identifier such as "default" or "prod-2026".'],
    });
  }
  const chainId = rawChainId;

  const packageRoot = EPIC_AI_DIR;
  const chainFile = join(packageRoot, 'audit', `${chainId}.jsonl`);

  // ── chariot audit anchor ─────────────────────────────────────────────────

  if (sub === 'anchor') {
    const { anchorChainHead } = await import('../engine/audit/anchor.js');

    const tsaUrl = process.env.CHARIOT_TSA_URL;
    if (!tsaUrl) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.TSA_NOT_CONFIGURED} CHARIOT_TSA_URL is not set`);
      return fail('cli:audit', 'TSA_NOT_CONFIGURED', {
        exit_code: EXIT.FAILURE,
        human_message: 'CHARIOT_TSA_URL is not set — cannot anchor chain head.',
        remediation: ['Set CHARIOT_TSA_URL to a valid RFC-3161 TSA endpoint.'],
        data: { chainId },
      });
    }

    const { headHash: headHex } = await readChainState(chainFile);
    if (!headHex || headHex.length !== 64) {
      if (!agentMode()) console.error(`error chain file not found or empty: ${chainFile}`);
      return fail('cli:audit', 'CHAIN_FILE_NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `Chain file not found or empty: ${chainFile}`,
        data: { chainId, chainFile },
      });
    }
    const headBuf = Buffer.from(headHex, 'hex');

    let anchorResult;
    try {
      anchorResult = await anchorChainHead({
        chainId,
        headHash: headBuf,
        packageRoot,
        tsaUrl,
      });
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'ANCHOR_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Failed to anchor chain head: ${(err as Error).message}`,
        data: { chainId },
      });
    }

    const tsaHost = new URL(tsaUrl).host;
    const shortHash = headHex.slice(0, 8);
    if (!agentMode()) console.log(`anchored chain=${chainId} head=${shortHash} tsa=${tsaHost} tsr=${anchorResult.tsrPath}`);
    return ok('cli:audit', {
      human_message: `anchored chain=${chainId} head=${shortHash} tsa=${tsaHost} tsr=${anchorResult.tsrPath}`,
      data: { sub: 'anchor', chainId, headHash: shortHash, tsaHost, tsrPath: anchorResult.tsrPath },
    });
  }

  // ── chariot audit attest ─────────────────────────────────────────────────

  if (sub === 'attest') {
    const { persistAttestation, canonicalAttestationPayload } = await import(
      '../engine/audit/length-attestation.js'
    );
    // CHARIOT::§9.8.1::1 — the signing key is obtained through the
    // ChainSigner custody abstraction (kms/vault-transit/sealed-store).
    // There is NO plaintext env backend, in any mode (gate finding
    // F1) — the default backend (CHARIOT_AUDIT_SIGNER_BACKEND unset) is
    // sealed-store, which requires a key to have been provisioned first
    // via `chariot audit custody import-key` (an existing PEM) or a
    // rotation (a freshly minted key).
    const { createChainSigner } = await import('../engine/audit/chainSigner.js');

    let signer;
    try {
      signer = await createChainSigner({ packageRoot });
    } catch (err) {
      const message = (err as Error).message;
      if (!agentMode()) console.error(`error ${message}`);
      return fail('cli:audit', 'SIGNING_KEY_NOT_CONFIGURED', {
        exit_code: EXIT.FAILURE,
        cause: message,
        human_message: message,
        remediation: [
          "Run 'chariot audit custody import-key' to seal an existing Ed25519 PEM into the sealed-store backend " +
            '(the default), or set CHARIOT_AUDIT_SIGNER_BACKEND to kms or vault-transit and its required env vars. ' +
            'See docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md.',
        ],
        data: { chainId },
      });
    }

    const { length, headHash: headHex } = await readChainState(chainFile);
    if (length === 0 && !headHex) {
      if (!agentMode()) console.error(`error chain file not found or empty: ${chainFile}`);
      return fail('cli:audit', 'CHAIN_FILE_NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `Chain file not found or empty: ${chainFile}`,
        data: { chainId, chainFile },
      });
    }

    const attestedAt = new Date().toISOString();
    let attestation;
    try {
      // Mirrors signLengthAttestation's own construction exactly (canonical
      // payload -> Ed25519 sign -> base64url), sourcing the key from the
      // ChainSigner custody abstraction instead of a raw PEM string.
      const payload = {
        schemaVersion: 1 as const,
        chainId,
        length,
        headHash: headHex,
        attestedAt,
      };
      const signature = await signer.sign(canonicalAttestationPayload(payload));
      attestation = { ...payload, signature: signature.toString('base64url') };
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'ATTEST_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Failed to sign length attestation: ${(err as Error).message}`,
        data: { chainId },
      });
    }

    let attPath;
    try {
      attPath = persistAttestation(packageRoot, attestation);
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'ATTEST_PERSIST_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Failed to persist attestation: ${(err as Error).message}`,
        data: { chainId },
      });
    }

    const shortHash = headHex ? headHex.slice(0, 8) : '(empty)';
    if (!agentMode()) console.log(`attested chain=${chainId} length=${length} head=${shortHash} path=${attPath}`);
    return ok('cli:audit', {
      human_message: `attested chain=${chainId} length=${length} head=${shortHash} path=${attPath}`,
      data: { sub: 'attest', chainId, length, headHash: shortHash, attestationPath: attPath },
    });
  }

  // ── chariot audit custody import-key ──────────────────────────────────────
  //
  // CHARIOT::§9.8.1::1 (gate finding F1) — the one-time path for an
  // operator who already has an Ed25519 PEM on disk/in a secrets manager:
  // seal it into the sealed-store custody backend, then tell the operator
  // to delete the plaintext source THEMSELVES. This command never deletes
  // a file it did not create.

  if (sub === 'custody' && args[2] === 'import-key') {
    const fileFlag = args.indexOf('--file');
    const filePath = fileFlag !== -1 ? args[fileFlag + 1] : undefined;

    let pem: string;
    try {
      if (filePath) {
        pem = readFileSync(filePath, 'utf-8');
      } else if (!process.stdin.isTTY) {
        pem = readFileSync(0, 'utf-8');
      } else {
        if (!agentMode()) console.error('Usage: chariot audit custody import-key --file <path>  (or pipe a PEM via stdin)');
        return fail('cli:audit', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'chariot audit custody import-key requires --file <path> or a PEM piped via stdin.',
          data: { sub: 'custody-import-key' },
        });
      }
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'CUSTODY_IMPORT_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Could not read the PEM to import: ${(err as Error).message}`,
        data: { sub: 'custody-import-key' },
      });
    }

    const { sealSigningKey } = await import('../engine/audit/chainSigner.js');
    let sealed;
    try {
      sealed = sealSigningKey(packageRoot, pem);
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'CUSTODY_IMPORT_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Failed to seal the imported key: ${(err as Error).message}`,
        data: { sub: 'custody-import-key' },
      });
    }

    const message =
      `Sealed the imported key into the sealed-store custody backend (kid=${sealed.kid}, path=${sealed.path}). ` +
      'DELETE THE PLAINTEXT PEM SOURCE YOURSELF NOW — this command never deletes files it did not create, and ' +
      'plaintext key material MUST NOT remain on the application host filesystem (CHARIOT §9.8.1::1).';
    if (!agentMode()) console.log(message);
    return ok('cli:audit', {
      human_message: message,
      data: { sub: 'custody-import-key', kid: sealed.kid, path: sealed.path },
    });
  }

  // ── chariot audit custody-check ─────────────────────────────────────────
  //
  // CHARIOT::§9.8.1::2 (gate finding F4) — standalone diagnostic:
  // runs the same custody check `createChainSigner()` runs before
  // constructing a signer in enterprise mode, but callable in ANY mode so
  // an operator can verify the gate BEFORE flipping CHARIOT_ENTERPRISE=1.

  if (sub === 'custody-check') {
    const backendArg = (args[2] ?? process.env.CHARIOT_AUDIT_SIGNER_BACKEND ?? 'sealed-store') as
      | 'kms'
      | 'vault-transit'
      | 'sealed-store';
    const { checkKmsCustody, checkVaultCustody, checkSealedStoreCustody } = await import(
      '../engine/audit/custodyCheck.js'
    );

    let result;
    if (backendArg === 'kms') {
      const keyId = process.env.CHARIOT_AUDIT_KMS_KEY_ID;
      if (!keyId) {
        return fail('cli:audit', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'CHARIOT_AUDIT_KMS_KEY_ID must be set to custody-check the kms backend.',
          data: { sub: 'custody-check', backend: 'kms' },
        });
      }
      result = await checkKmsCustody(keyId, process.env.CHARIOT_AUDIT_KMS_REGION);
    } else if (backendArg === 'vault-transit') {
      const addr = process.env.CHARIOT_AUDIT_VAULT_ADDR;
      const token = process.env.CHARIOT_AUDIT_VAULT_TOKEN;
      const keyName = process.env.CHARIOT_AUDIT_VAULT_KEY_NAME;
      if (!addr || !token || !keyName) {
        return fail('cli:audit', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message:
            'CHARIOT_AUDIT_VAULT_ADDR, CHARIOT_AUDIT_VAULT_TOKEN, and CHARIOT_AUDIT_VAULT_KEY_NAME must all be set ' +
            'to custody-check the vault-transit backend.',
          data: { sub: 'custody-check', backend: 'vault-transit' },
        });
      }
      result = await checkVaultCustody(addr, token, keyName);
    } else if (backendArg === 'sealed-store') {
      result = checkSealedStoreCustody();
    } else {
      return fail('cli:audit', 'USAGE_ERROR', {
        exit_code: EXIT.USAGE,
        human_message: `Unknown custody-check backend '${String(backendArg)}'. Must be one of: kms, vault-transit, sealed-store.`,
        data: { sub: 'custody-check' },
      });
    }

    const message = `custody check (${result.backend}): passed=${result.passed} checkable=${result.checkable} — ${result.reason}`;
    if (!agentMode()) (result.passed ? console.log : console.error)(message);
    if (result.passed) {
      return ok('cli:audit', { human_message: message, data: { sub: 'custody-check', ...result } });
    }
    return fail('cli:audit', 'CUSTODY_CHECK_FAILED', {
      exit_code: EXIT.FAILURE,
      human_message: message,
      data: { sub: 'custody-check', ...result },
    });
  }

  // ── chariot audit rotate-key ─────────────────────────────────────────────
  //
  // CHARIOT::§9.8.1::3 — forward-only rotation, backend-specific
  // (keyRotation.ts, gate finding F3): never prints or returns private
  // material for any backend. Publishes the new public key to the
  // persistent verify-key store (verifyKeyStore.ts, gate finding F2) and
  // records a chained `audit.signing_key.rotated` event, in the SAME call.

  if (sub === 'rotate-key') {
    const backendFlag = args.indexOf('--backend');
    const backendArg = backendFlag !== -1 ? args[backendFlag + 1] : (process.env.CHARIOT_AUDIT_SIGNER_BACKEND ?? 'sealed-store');
    if (backendArg !== 'sealed-store' && backendArg !== 'kms' && backendArg !== 'vault-transit') {
      return fail('cli:audit', 'USAGE_ERROR', {
        exit_code: EXIT.USAGE,
        human_message: `Unknown --backend '${backendArg}'. Must be one of: sealed-store, kms, vault-transit.`,
        data: { sub: 'rotate-key' },
      });
    }
    const backend = backendArg;

    const { rotateSigningKey } = await import('../engine/audit/keyRotation.js');
    const { createChainSigner, fetchKmsPublicKey, fetchVaultPublicKey } = await import('../engine/audit/chainSigner.js');
    const { AuditTrail } = await import('../engine/audit/AuditTrail.js');

    const kmsKeyIdFlag = args.indexOf('--kms-key-id');
    const newKmsKeyId = kmsKeyIdFlag !== -1 ? args[kmsKeyIdFlag + 1] : undefined;
    const vaultKeyFlag = args.indexOf('--vault-key');
    const vaultKeyName = vaultKeyFlag !== -1 ? args[vaultKeyFlag + 1] : process.env.CHARIOT_AUDIT_VAULT_KEY_NAME;
    const vaultAddr = process.env.CHARIOT_AUDIT_VAULT_ADDR;
    const vaultToken = process.env.CHARIOT_AUDIT_VAULT_TOKEN;
    const kmsRegion = process.env.CHARIOT_AUDIT_KMS_REGION;

    // Best-effort: fetch the CURRENT key's public half (before rotating) so
    // the chain record's oldKid is populated. Never fatal — a first-ever
    // rotation has no prior key to fetch.
    let oldPublicKeyPem: string | undefined;

    if (backend === 'sealed-store') {
      try {
        const current = await createChainSigner({ backend: 'sealed-store', packageRoot });
        oldPublicKeyPem = (await current.getKeyInfo()).publicKeyPem;
      } catch {
        // no prior sealed-store key — fine, first rotation.
      }
    } else if (backend === 'kms') {
      const currentKmsKeyId = process.env.CHARIOT_AUDIT_KMS_KEY_ID;
      if (currentKmsKeyId) {
        try {
          oldPublicKeyPem = (await fetchKmsPublicKey(currentKmsKeyId, kmsRegion)).publicKeyPem;
        } catch {
          // ignore — proceed without an old key
        }
      }
      if (!newKmsKeyId) {
        return fail('cli:audit', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message:
            '--kms-key-id is required for --backend kms (the NEW key id/ARN, created out-of-band with ' +
            'KeySpec=ECC_NIST_EDWARDS25519 — KMS has no in-place rotate for asymmetric keys).',
          data: { sub: 'rotate-key' },
        });
      }
    } else {
      // vault-transit
      if (!vaultAddr || !vaultToken || !vaultKeyName) {
        return fail('cli:audit', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message:
            'CHARIOT_AUDIT_VAULT_ADDR, CHARIOT_AUDIT_VAULT_TOKEN, and --vault-key (or CHARIOT_AUDIT_VAULT_KEY_NAME) ' +
            'are all required for --backend vault-transit.',
          data: { sub: 'rotate-key' },
        });
      }
      try {
        oldPublicKeyPem = (await fetchVaultPublicKey(vaultAddr, vaultToken, vaultKeyName)).publicKeyPem;
      } catch {
        // ignore — first rotation of this key name
      }
    }

    const trail = new AuditTrail({ store: 'append-only-log', path: chainFile, integrity: 'sha256-chain' });
    await trail.init();

    let result;
    try {
      result = await rotateSigningKey(trail, {
        backend,
        epicAiDir: packageRoot,
        packageRoot,
        oldPublicKeyPem,
        newKmsKeyId,
        kmsRegion,
        vaultAddr,
        vaultToken,
        vaultKeyName,
      });
    } catch (err) {
      if (!agentMode()) console.error(`error ${(err as Error).message}`);
      return fail('cli:audit', 'ROTATE_KEY_FAILED', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Key rotation failed: ${(err as Error).message}`,
        data: { sub: 'rotate-key', backend },
      });
    }

    const message =
      `Rotated the audit signing key (backend=${backend}): new kid=${result.kid}` +
      `${result.oldKid ? ` (old kid=${result.oldKid})` : ' (no prior key — first rotation)'}, ` +
      `chain record id=${result.record.id}. The new public key is already in the persistent verify-key store ` +
      `(${packageRoot}/audit/verify-keys.json) — publish it via your existing distribution path too, and never ` +
      'remove the old key from either.';
    if (!agentMode()) console.log(message);
    return ok('cli:audit', {
      human_message: message,
      data: {
        sub: 'rotate-key',
        backend,
        kid: result.kid,
        oldKid: result.oldKid,
        publicKeyPem: result.publicKeyPem,
        chainRecordId: result.record.id,
      },
    });
  }

  // ── chariot audit verify-anchor ──────────────────────────────────────────

  if (sub === 'verify-anchor') {
    const { verifyAnchor } = await import('../engine/audit/anchor.js');

    const tsrPath = args[2];
    if (!tsrPath) {
      if (!agentMode()) console.error('Usage: chariot audit verify-anchor <tsrPath> [--cert <pem>]');
      return fail('cli:audit', 'USAGE_ERROR', {
        exit_code: EXIT.USAGE,
        human_message: 'Usage: chariot audit verify-anchor <tsrPath> [--cert <pem>]',
      });
    }

    const certFlag = args.indexOf('--cert');
    const certPath = certFlag !== -1 ? args[certFlag + 1] : undefined;
    const certPem = certPath ? readFileSync(certPath, 'utf-8') : undefined;

    const { headHash: headHex } = await readChainState(chainFile);
    if (!headHex || headHex.length !== 64) {
      if (!agentMode()) console.error(`error chain file not found or empty: ${chainFile}`);
      return fail('cli:audit', 'CHAIN_FILE_NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `Chain file not found or empty: ${chainFile}`,
        data: { chainId, chainFile },
      });
    }
    const headBuf = Buffer.from(headHex, 'hex');

    const verifyResult = verifyAnchor(headBuf, tsrPath, certPem);
    if (!agentMode()) console.log(`valid=${verifyResult.valid} reason=${verifyResult.reason ?? 'ok'}${verifyResult.code ? ` code=${verifyResult.code}` : ''}`);
    if (!verifyResult.valid) {
      return fail('cli:audit', 'VERIFY_ANCHOR_FAILED', {
        exit_code: EXIT.FAILURE,
        human_message: `Anchor verification failed: ${verifyResult.reason ?? 'unknown'}`,
        data: { sub: 'verify-anchor', chainId, valid: false, reason: verifyResult.reason, code: verifyResult.code },
      });
    }
    return ok('cli:audit', {
      human_message: `Anchor verified: valid=true`,
      data: { sub: 'verify-anchor', chainId, valid: true, reason: verifyResult.reason ?? 'ok' },
    });
  }

  // ── chariot audit verify-length ──────────────────────────────────────────

  if (sub === 'verify-length') {
    const { loadAttestations, detectTruncation, verifyLengthAttestation } = await import(
      '../engine/audit/length-attestation.js'
    );

    const { length } = await readChainState(chainFile);
    const attestations = loadAttestations(packageRoot, chainId);

    // FAIL-CLOSED (zero-day fix): an empty attestation set for a NON-EMPTY
    // chain must never read as "chain intact". detectTruncation over [] yields
    // lastAttestedLength=0 → truncated=false, so an attacker who truncates the
    // chain and deletes <packageRoot>/audit/length-attestations/ would get a
    // clean exit-0 — defeating the exact threat (write access to the
    // attestation dir) the module's own doc-comment defends against.
    if (attestations.length === 0) {
      if (length === 0) {
        // Fresh install: no chain records AND no attestations. There is no
        // evidence either way — report that honestly instead of "intact".
        if (!agentMode()) console.log(`truncated=false length=0 attestations=0 (nothing to verify)`);
        return ok('cli:audit', {
          human_message: `No chain records and no attestations for chain "${chainId}" — nothing to verify.`,
          data: { sub: 'verify-length', chainId, truncated: false, length: 0, attestationCount: 0, verified: false },
        });
      }
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.NO_LENGTH_ATTESTATIONS} chain has ${length} records but zero attestations`);
      return fail('cli:audit', 'NO_LENGTH_ATTESTATIONS', {
        exit_code: EXIT.FAILURE,
        human_message: `Chain "${chainId}" has ${length} records but no length attestations were found — cannot rule out truncation (missing or deleted attestation evidence).`,
        remediation: [
          'Run `chariot audit attest` to establish a signed length attestation.',
          'If attestations previously existed, treat their absence as tamper evidence and investigate before trusting this chain.',
        ],
        data: { sub: 'verify-length', chainId, length, attestationCount: 0 },
      });
    }

    // Signature verification (zero-day fix): loadAttestations accepts any
    // schemaVersion-1 JSON — without Ed25519 verification a forged unsigned
    // file is trusted verbatim (permanent false-truncation DoS, or a
    // fresh-but-short forgery attempting to mask truncation). Verify every
    // attestation against the operator's public key and hard-fail on any
    // invalid signature — a bad signature in the append-only dir is itself
    // tamper evidence, so it is NEVER silently skipped. No key → fail closed.
    //
    // CHARIOT::§9.8.1::3 (gate round-3 finding) — the candidate verify-key
    // set is sourced from `resolveVerifyKeys(epicAiDir)` alone (chainSigner.ts)
    // — the SAME function admin.ts's export route calls — rather than a
    // second, hand-rolled copy of the CHARIOT_AUDIT_VERIFY_KEY /
    // CHARIOT_AUDIT_VERIFY_KEYS parsing logic. `packageRoot` here IS the
    // same epic-ai directory as admin.ts's `resolveEpicAiDir()`: both
    // ultimately read `process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(),
    // '.epic-ai')` — `packageRoot = EPIC_AI_DIR` (src/cli/paths.ts) and
    // `resolveEpicAiDir()` (src/engine/audit/serveAuditSink.ts) are
    // independent re-implementations of the identical expression, so a
    // record published by `rotateSigningKey()` (which also writes under
    // this same directory) is visible to both the CLI and the admin route
    // with zero extra wiring. `resolveVerifyKeys()` itself owns the
    // persistent verify-key store, `CHARIOT_AUDIT_VERIFY_KEYS`, and the
    // legacy single `CHARIOT_AUDIT_VERIFY_KEY`/`CHARIOT_AUDIT_SIGNING_KEY`
    // fallback (including its file-path-or-inline-PEM convenience) — this
    // command must not reimplement any of that locally.
    const { resolveVerifyKeys } = await import('../engine/audit/chainSigner.js');
    let verifyKeys: Map<string, import('node:crypto').KeyObject>;
    try {
      verifyKeys = resolveVerifyKeys(packageRoot);
    } catch (err) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.AUDIT_VERIFY_KEY_INVALID} ${(err as Error).message}`);
      return fail('cli:audit', 'AUDIT_VERIFY_KEY_INVALID', {
        exit_code: EXIT.FAILURE,
        cause: (err as Error).message,
        human_message: `Could not resolve the attestation verify-key set: ${(err as Error).message}`,
        data: { sub: 'verify-length', chainId },
      });
    }
    const verifyKeyPems = Array.from(verifyKeys.values(), (k) => k.export({ type: 'spki', format: 'pem' }) as string);
    if (verifyKeyPems.length === 0) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.AUDIT_VERIFY_KEY_NOT_CONFIGURED} CHARIOT_AUDIT_VERIFY_KEY is not set — refusing to trust unverified attestations`);
      return fail('cli:audit', 'AUDIT_VERIFY_KEY_NOT_CONFIGURED', {
        exit_code: EXIT.FAILURE,
        human_message: 'CHARIOT_AUDIT_VERIFY_KEY is not set — attestation signatures cannot be verified, refusing to verify-length fail-open.',
        remediation: [
          'Set CHARIOT_AUDIT_VERIFY_KEY to the Ed25519 public key PEM matching the CHARIOT_AUDIT_SIGNING_KEY used by `chariot audit attest`.',
          'Alternatively set CHARIOT_AUDIT_SIGNING_KEY (the public half is derived from it), CHARIOT_AUDIT_VERIFY_KEYS ' +
            'for a multi-key set, or rotate a key (which publishes to the persistent verify-key store automatically).',
        ],
        data: { sub: 'verify-length', chainId, attestationCount: attestations.length },
      });
    }
    let invalidCount = 0;
    for (const a of attestations) {
      // CHARIOT::§9.8.1::3 — valid if it verifies under ANY retained key.
      let validUnderAnyKey = false;
      for (const pem of verifyKeyPems) {
        // CHARIOT::§9.8.3::3 — verifyLengthAttestation(att: LengthAttestation, publicKeyPem: string): Promise<AttestationVerifyResult>
        const r = await verifyLengthAttestation(a, pem);
        if (r.valid) {
          validUnderAnyKey = true;
          break;
        }
      }
      if (!validUnderAnyKey) invalidCount += 1;
    }
    if (invalidCount > 0) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.ATTESTATION_SIGNATURE_INVALID} ${invalidCount}/${attestations.length} attestation(s) failed Ed25519 verification`);
      return fail('cli:audit', 'ATTESTATION_SIGNATURE_INVALID', {
        exit_code: EXIT.FAILURE,
        human_message: `${invalidCount} of ${attestations.length} length attestation(s) for chain "${chainId}" failed Ed25519 signature verification — treat as tamper evidence.`,
        remediation: [
          'Inspect <packageRoot>/audit/length-attestations/ for forged or corrupted files.',
          'Confirm CHARIOT_AUDIT_VERIFY_KEY matches the key used by `chariot audit attest`.',
        ],
        data: { sub: 'verify-length', chainId, attestationCount: attestations.length, invalidCount },
      });
    }

    const { truncated, lastAttestedLength } = detectTruncation(length, attestations);

    if (truncated) {
      if (!agentMode()) {
        console.log(`truncated=true lastAttestedLength=${lastAttestedLength}`);
        console.error(`code=${CHARIOT_ERROR_CODES.CHAIN_TRUNCATION_DETECTED}`);
      }
      return fail('cli:audit', 'CHAIN_TRUNCATION_DETECTED', {
        exit_code: EXIT.FAILURE,
        human_message: `Chain truncation detected — last attested length: ${lastAttestedLength}, current: ${length}`,
        data: { sub: 'verify-length', chainId, truncated: true, length, lastAttestedLength },
      });
    }

    // Attestation-downgrade defense (§9.8.3): an
    // attacker with write access to the append-only attestation dir cannot
    // forge a signature, but CAN DELETE the newest (longest) attestation to
    // downgrade the verifier to an older, shorter one — then rewrite every
    // record beyond that shorter length and recompute the chain forward. The
    // per-attestation head binding below only certifies each SURVIVING
    // attestation's prefix, so records in the deleted attestation's range would
    // otherwise read as an ordinary "un-attested growth window" (§9.8.3 l.887)
    // and pass. Close it: a clean "intact" verdict requires the chain to be
    // FULLY attestation-covered — length === lastAttestedLength. Any record
    // beyond the highest surviving attestation (length > lastAttestedLength) is
    // that un-attested window: it cannot be certified and may conceal a
    // deletion-downgrade tamper. Fail closed; the operator must `audit attest`
    // at the current head and re-verify (and `audit verify-anchor` covers the
    // TSA re-stitch defense, §9.8.2). verify-length has no automated caller —
    // it is a deliberate CLI check — so requiring attest-at-head is the natural
    // audit workflow, not an operational regression.
    if (length > lastAttestedLength) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.CHAIN_UNATTESTED_SUFFIX} ${length - lastAttestedLength} record(s) beyond the highest attestation (length=${lastAttestedLength})`);
      return fail('cli:audit', 'CHAIN_UNATTESTED_SUFFIX', {
        exit_code: EXIT.FAILURE,
        human_message: `Audit chain "${chainId}" has ${length - lastAttestedLength} record(s) beyond the highest signed attestation (attested length ${lastAttestedLength}, current length ${length}). An un-attested suffix cannot be certified intact and could conceal a deletion-downgrade tamper. Run \`chariot audit attest\` at the current head, then re-verify.`,
        remediation: [
          'Run `chariot audit attest` to sign the current chain head, then re-run `chariot audit verify-length`.',
          'If you did NOT grow the chain since the last attestation, treat the missing coverage as tamper evidence — a newer attestation may have been deleted (deletion-downgrade).',
          'For post-compromise re-stitch defense, cross-check with `chariot audit verify-anchor` (TSA-anchored head hashes).',
        ],
        data: { sub: 'verify-length', chainId, length, lastAttestedLength, unattestedSuffix: length - lastAttestedLength },
      });
    }

    // CHARIOT §19 tamper-evidence: the attestation/length signals
    // above only prove the chain has not been TRUNCATED — they say nothing
    // about per-record integrity. An attacker with write access to the JSONL
    // can rewrite any record's fields (tool/output/status/...) and zero every
    // hash/previousHash while keeping the line count unchanged; that passes
    // every check above and used to read as "Chain intact" / exit 0, gutting
    // the provable-sovereignty guarantee. Load the full chain and recompute
    // each SHA-256 + re-check the previousHash links via HashChain.verifyChain
    // (which excludes status-update supplement lines through its documented
    // isChainRecord predicate). FAIL CLOSED on any broken record.
    const { HashChain } = await import('../engine/audit/HashChain.js');
    const chainRecords = await readChainRecords(chainFile);
    const integrity = HashChain.verifyChain(chainRecords);
    if (!integrity.valid) {
      if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.CHAIN_INTEGRITY_VIOLATION} record sequence=${integrity.brokenAt ?? '(unknown)'} failed hash/previousHash verification`);
      return fail('cli:audit', 'CHAIN_INTEGRITY_VIOLATION', {
        exit_code: EXIT.FAILURE,
        human_message: `Audit chain "${chainId}" failed per-record integrity verification at sequenceNumber=${integrity.brokenAt ?? '(unknown)'} — a record's hash or previousHash link does not match its contents (tamper evidence).`,
        remediation: [
          'Do NOT trust this chain: at least one record was altered after it was written.',
          'Investigate the record at the reported sequenceNumber and any records after it.',
          'Restore the chain from a signed/anchored backup and re-verify.',
        ],
        data: { sub: 'verify-length', chainId, truncated: false, length, attestationCount: attestations.length, integrityValid: false, brokenAt: integrity.brokenAt ?? null },
      });
    }

    // Attestation head binding (CHARIOT §19): verifyChain above only proves
    // the chain is INTERNALLY consistent (each record's hash recomputes and the
    // previousHash links form an unbroken run). It does NOT bind that run to the
    // SIGNED head. An attacker with write access to the JSONL can mutate a
    // record's content and then RECOMPUTE THE CHAIN FORWARD — re-hash the
    // mutated record, fix the next record's previousHash, re-hash it, and on to
    // the head — producing a chain verifyChain accepts, at the SAME length
    // (detectTruncation clean). What they cannot do is re-sign: the length
    // attestation is Ed25519-signed over {length, headHash} and its headHash
    // still commits to the PRE-tamper head. Bind every signature-verified
    // attestation to the live chain: the record at the attested length
    // (orderedChain[length-1], using the same isChainRecord filter + sequence
    // sort verifyChain used) MUST hash-match the attested headHash. Any
    // divergence — or a length the live chain cannot produce — is tamper
    // evidence. Fail closed.
    const orderedChain = chainRecords
      .filter((r) => HashChain.isChainRecord(r))
      .sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    for (const att of attestations) {
      if (!Number.isInteger(att.length) || att.length <= 0) continue;
      const headAtAttested = orderedChain[att.length - 1];
      if (!headAtAttested || headAtAttested.hash !== att.headHash) {
        if (!agentMode()) console.error(`error code=${CHARIOT_ERROR_CODES.CHAIN_INTEGRITY_VIOLATION} attested headHash for length=${att.length} does not match the live chain head (recompute-forward tamper)`);
        return fail('cli:audit', 'CHAIN_INTEGRITY_VIOLATION', {
          exit_code: EXIT.FAILURE,
          human_message: `Audit chain "${chainId}" failed head-hash attestation binding: the signed attestation for length ${att.length} commits to head ${att.headHash.slice(0, 12)}…, but the live chain head at that length is ${headAtAttested ? headAtAttested.hash.slice(0, 12) + '…' : '(absent)'} — the chain was rewritten after it was attested (recompute-forward tamper).`,
          remediation: [
            'Do NOT trust this chain: its content was altered and the hash chain re-stitched after a signed attestation was issued.',
            'The signed length attestation is ground truth for the attested prefix — restore the chain from a signed/anchored backup and re-verify.',
          ],
          data: { sub: 'verify-length', chainId, integrityValid: false, attestedLength: att.length, expectedHeadHash: att.headHash, liveHeadHash: headAtAttested ? headAtAttested.hash : null },
        });
      }
    }

    if (!agentMode()) console.log(`truncated=false length=${length} attestations=${attestations.length} integrity=ok (signatures + head-hash binding verified)`);
    return ok('cli:audit', {
      human_message: `Chain intact — length: ${length}, per-record integrity + attested head-hash binding verified (${attestations.length} signature-verified attestation${attestations.length === 1 ? '' : 's'})`,
      data: { sub: 'verify-length', chainId, truncated: false, length, attestationCount: attestations.length, verified: true, integrityValid: true },
    });
  }

  // ── Unknown audit subcommand ─────────────────────────────────────────────

  if (!agentMode()) {
    console.error(pc.red(`Unknown subcommand: chariot audit ${sub ?? ''}`));
    console.error(pc.dim('Valid: chariot audit [anchor|attest|verify-anchor <tsr>|verify-length] [--chain-id <id>]'));
  }
  return fail('cli:audit', 'USAGE_ERROR', {
    exit_code: EXIT.USAGE,
    human_message: `Unknown audit subcommand: ${sub ?? '(none)'}`,
    remediation: ['Valid: chariot audit [anchor|attest|verify-anchor <tsr>|verify-length] [--chain-id <id>]'],
  });
}

// ── chariot vault (CHARIOT §12.2, CH-10, rulings item 59) ──────────────────

async function cmdVault(): Promise<ChariotEnvelope> {
  const sub = args[1];
  if (sub !== 'migrate') {
    return fail('cli:vault', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: `Unknown subcommand: chariot vault ${sub ?? '(none)'}`,
      remediation: ['Valid: chariot vault migrate --tenant <id>|--all [--dry-run]'],
    });
  }

  const dryRun = args.includes('--dry-run');
  const allFlag = args.includes('--all');
  const tenantFlagIdx = args.indexOf('--tenant');
  const tenantArg = tenantFlagIdx !== -1 ? args[tenantFlagIdx + 1] : undefined;

  if (!allFlag && !tenantArg) {
    return fail('cli:vault', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: 'chariot vault migrate requires --tenant <id> or --all',
      remediation: ['chariot vault migrate --tenant <id> [--dry-run]', 'chariot vault migrate --all [--dry-run]'],
    });
  }
  if (allFlag && tenantArg) {
    return fail('cli:vault', 'USAGE_ERROR', {
      exit_code: EXIT.USAGE,
      human_message: '--tenant and --all are mutually exclusive',
    });
  }

  // CH-10 (§12.2, rulings item 59): "refuses to run without ENTERPRISE_MASTER_KEY".
  const { validateMasterKey } = await import('../iam/crypto.js');
  try {
    validateMasterKey();
  } catch (err) {
    return fail('cli:vault', 'MASTER_KEY_NOT_CONFIGURED', {
      exit_code: EXIT.FAILURE,
      cause: (err as Error).message,
      human_message: `chariot vault migrate refuses to run: ${(err as Error).message}`,
    });
  }

  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    return fail('cli:vault', 'MONGODB_URI_NOT_SET', {
      exit_code: EXIT.FAILURE,
      human_message: 'MONGODB_URI is not set — chariot vault migrate requires the enterprise IAM database.',
    });
  }
  const mongoDb = process.env.MONGODB_DB || 'chariot';

  const { MongoClient } = await import('mongodb');
  let client: InstanceType<typeof MongoClient>;
  try {
    client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });
    await client.connect();
  } catch (err) {
    return fail('cli:vault', 'MONGODB_UNAVAILABLE', {
      exit_code: EXIT.FAILURE,
      cause: (err as Error).message,
      human_message: `chariot vault migrate: MongoDB unavailable at ${redactConnectionString(mongoUri)}`,
    });
  }

  const redis = await connectVaultRedis();
  const checkpointDbPath = join(EPIC_AI_DIR, 'chariot.db');

  try {
    // resolveLegacyDecryptPolicy's marker lookup (crypto.ts) needs the
    // same injected client any other IAM read uses.
    const { setMongoClient } = await import('../iam/db.js');
    setMongoClient(client, mongoDb);

    const db = client.db(mongoDb);
    const tenantIds = allFlag ? await discoverAllTenantIds(db) : [tenantArg as string];

    const results: Record<string, VaultMigrateCounts & { markerWritten: boolean; markerRefusedReason?: string }> = {};
    for (const tenantId of tenantIds) {
      results[tenantId] = await migrateTenant(db, tenantId, dryRun, redis, checkpointDbPath);
    }

    const totals = Object.values(results).reduce(
      (acc, r) => addVaultMigrateCounts(acc, r),
      emptyVaultMigrateCounts(),
    );

    if (!agentMode()) {
      console.log(`chariot vault migrate ${dryRun ? '(dry-run) ' : ''}— ${tenantIds.length} tenant(s)${redis ? '' : ' [Redis not walked]'}`);
      for (const [tenantId, r] of Object.entries(results)) {
        console.log(
          `  ${tenantId}: legacy=${r.legacy} upgraded=${r.upgraded} failed=${r.failed} alreadyV2=${r.alreadyV2}` +
          (r.markerWritten ? ' [migration marker written]' : ` [marker not written: ${r.markerRefusedReason}]`),
        );
      }
    }

    return ok('cli:vault', {
      human_message: `chariot vault migrate: ${tenantIds.length} tenant(s), ${totals.upgraded} upgraded, ${totals.failed} failed` +
        (dryRun ? ' (dry-run — no writes made)' : '') +
        (redis ? '' : ' (Redis not walked — see per-tenant markerRefusedReason)'),
      data: { sub: 'migrate', dryRun, redisWalked: redis !== null, tenants: results, totals },
    });
  } catch (err) {
    return fail('cli:vault', 'INTERNAL_ERROR', {
      exit_code: EXIT.FAILURE,
      cause: (err as Error).message,
      human_message: `chariot vault migrate failed: ${(err as Error).message}`,
    });
  } finally {
    try {
      await client.close();
    } catch {
      // best-effort close
    }
    if (redis) {
      try {
        await redis.quit();
      } catch {
        // best-effort close
      }
    }
  }
}

// ── chariot setup wizard ───────────────────────────────────────────────────

async function runSetupWizard(): Promise<void> {
  const allAdapters = loadChariotMcpRegistryWithNative();
  const totalTools = allAdapters.reduce((sum, a) => sum + bundleToolCount(a), 0);

  console.log('');
  p.note(
    `${totalTools.toLocaleString()} tools across ${allAdapters.length} adapters. One self-hosted MCP gateway.\nYour context window only loads what the query needs.`,
    pc.bgCyan(pc.black(' Epic AI® Chariot '))
  );

  const s = makeSpinner(p);
  s.start('Detecting your system');
  const system = await detectSystem();
  s.stop('System detected');

  const detectedClients = system.mcpClients.filter(c => c.detected);
  const hasLocalLLM = system.localBackend !== null;

  p.note(
    [
      `${pc.green('✓')} Node.js ${system.nodeVersion}`,
      `${pc.green('✓')} ${system.platform} / ${system.arch}`,
      hasLocalLLM ? `${pc.green('✓')} ${system.localBackend} running on port ${system.localPort}` : `${pc.white('○')} No local LLM detected`,
      `${pc.green('✓')} ${allAdapters.length} adapters available`,
      `${pc.green('✓')} ${detectedClients.length} AI client${detectedClients.length !== 1 ? 's' : ''} detected`,
    ].join('\n'),
    'System'
  );

  const configuredClients: string[] = [];

  if (detectedClients.length === 0 && !hasLocalLLM) {
    p.log.warning('No AI clients or local LLMs detected.');
    p.note(
      [
        'Install an MCP-compatible AI client:',
        '',
        `  ${pc.cyan('Claude Code')}   — npm install -g @anthropic-ai/claude-code`,
        `  ${pc.cyan('Cursor')}        — cursor.com`,
        `  ${pc.cyan('VS Code')}       — code.visualstudio.com + Copilot`,
        `  ${pc.cyan('Windsurf')}      — windsurf.com`,
        '',
        'Or install a local LLM:',
        '',
        `  ${pc.cyan('llama.cpp')}     — brew install llama.cpp`,
        `  ${pc.cyan('Ollama')}        — brew install ollama`,
      ].join('\n'),
      'Getting started'
    );
    const cont = await p.confirm({ message: 'Continue anyway? (you can configure clients later)', initialValue: false });
    if (p.isCancel(cont) || !cont) { p.cancel('Install an AI client and re-run.'); process.exit(0); }
  } else if (detectedClients.length > 0) {
    const clientOptions = detectedClients.map(c => ({
      value: c.id,
      label: c.name,
      hint: c.hint || c.configPath.replace(homedir(), '~'),
    }));

    if (hasLocalLLM) {
      clientOptions.push({
        value: 'local',
        label: `Local SLM (${system.localBackend} on port ${system.localPort})`,
        hint: 'No cloud LLM needed',
      });
    }

    const selectedClients = await p.multiselect({
      // CH-38: explicit opt-in. The 3.1.2 wizard PRE-CHECKED writing into the
      // user's live ~/.claude / ~/.codex / ~/.gemini configs; default to none
      // selected so a confirm never silently mutates real client configs.
      message: 'Select AI clients to register Chariot in (Space to toggle — none selected by default):',
      options: clientOptions,
      initialValues: [],
      required: false,
    });
    if (p.isCancel(selectedClients)) { p.cancel('Setup cancelled.'); process.exit(0); }

    // Supply-chain pin (zero-day fix): the MCP launch entry written into AI
    // client configs must pin the EXACT running release and forbid a registry
    // fetch at client launch. An unpinned `npx @epicai/chariot` re-resolves at
    // every AI-client start — a compromised/newer npm publish would execute on
    // the next launch, and an air-gapped deploy would generate outbound
    // registry traffic. `--no-install` + `@<version>` matches the
    // npmIntegrityGuard fail-closed contract; the wizard itself runs from this
    // package, so the pinned version is guaranteed to be installed locally.
    const chariotMcpEntry = {
      command: 'npx',
      args: ['--no-install', `@epicai/chariot@${readPkgVersion()}`, 'serve'],
    };

    const writeResults: string[] = [];
    for (const clientId of selectedClients as string[]) {
      if (clientId === 'local') continue;
      const client = system.mcpClients.find(c => c.id === clientId);
      if (!client) continue;

      const autoWrite = await p.confirm({
        message: `Write Chariot to ${client.name} config? (${client.configPath.replace(homedir(), '~')})`,
        initialValue: true,
      });
      if (p.isCancel(autoWrite)) continue;

      if (autoWrite) {
        const result = writeMcpConfig(client, chariotMcpEntry);
        if (result.success) {
          // CH-48: VERIFY-LOAD before reporting ✓. A write to a path/format
          // the client never reads is a silent no-op (CH-31). Re-read the
          // file and confirm the entry is present in the right shape; only
          // then claim "configured".
          const verify = verifyMcpConfigLoaded(client);
          if (verify.loaded) {
            writeResults.push(result.error === 'already configured'
              ? `${pc.green('✓')} ${client.name} — already configured (verified at ${client.configPath.replace(homedir(), '~')})`
              : `${pc.green('✓')} ${client.name} — configured + verified (${client.configPath.replace(homedir(), '~')})`);
            configuredClients.push(clientId);
          } else {
            writeResults.push(`${pc.red('✗')} ${client.name} — wrote ${client.configPath.replace(homedir(), '~')} but verify-load failed: ${verify.reason}`);
          }
        } else {
          writeResults.push(`${pc.yellow('!')} ${client.name} — ${result.error}`);
        }
      } else {
        const serverEntry = { chariot: chariotMcpEntry };
        const configStr = JSON.stringify({ [client.configKey]: serverEntry }, null, 2);
        p.note(
          [
            `Add this to ${pc.cyan(client.configPath.replace(homedir(), '~'))}:`,
            '',
            pc.white('─'.repeat(42)),
            configStr,
            pc.white('─'.repeat(42)),
          ].join('\n'),
          `${client.name} — manual config`
        );
        configuredClients.push(clientId);
      }
    }

    if (writeResults.length > 0) p.note(writeResults.join('\n'), 'MCP Clients Configured');

    if ((selectedClients as string[]).includes('local')) {
      p.log.success(`Using ${system.localBackend} on port ${system.localPort}`);
      configuredClients.push('local');
    }

    if (configuredClients.length === 0) {
      p.note(
        [
          `Add adapters later:  ${pc.cyan('chariot add <adapter-id>')}`,
          `Check health:        ${pc.cyan('chariot health')}`,
          `List all adapters:   ${pc.cyan('chariot list')}`,
        ].join('\n'),
        'Quick reference'
      );
      saveConfig({ selectedAdapters: [], secretsProvider: 'manual', aiClient: 'none' });
      p.outro(`${pc.green('Done.')} Configure your AI clients and run this wizard again.\n  Your credentials never leave this machine.`);
      return;
    }
  } else if (hasLocalLLM) {
    p.log.success(`Using ${system.localBackend} on port ${system.localPort}`);
    configuredClients.push('local');
  }

  // Auto-configure curated adapters (vetted zero-credential sources)
  const s2 = makeSpinner(p);
  s2.start('Configuring curated data sources');

  let nextState = loadState();
  const curatedAdapterEntries = CHARIOT_CURATED.map(c => allAdapters.find(a => a.id === c.id)).filter(Boolean) as ChariotRegistryEntry[];
  for (const c of CHARIOT_CURATED) {
    const adapter = allAdapters.find(a => a.id === c.id);
    nextState = upsertAdapterState(nextState, c.id, {
      type: adapter?.type || 'mcp',
      status: 'configured',
      toolCount: c.tools,
      lastVerified: null,
    });
  }
  saveState(nextState);
  saveConfig({
    selectedAdapters: CHARIOT_CURATED.map(c => c.id),
    secretsProvider: 'manual',
    aiClient: configuredClients.join(','),
  });

  s2.stop('Curated data sources configured');

  p.note(
    CHARIOT_CURATED.map(c => `${pc.green('✓')} ${c.name.padEnd(14)} ${String(c.tools).padStart(2)} ${Number(c.tools) === 1 ? 'tool' : 'tools'}   ${pc.white(c.desc)}`).join('\n'),
    `Curated (${CHARIOT_CURATED.length}) — no credentials required`
  );

  // Routing demo — in-process BM25 intelligence preview
  const { ToolPreFilter } = await import('../engine/index.js');
  const demoFilter = new ToolPreFilter();
  demoFilter.index(buildToolsForRoutingChariot(curatedAdapterEntries));

  const routingLines: string[] = [];
  for (const c of CHARIOT_CURATED) {
    const matches = await demoFilter.select(c.demoQuery, { maxTools: 3, maxPerServer: 2 });
    const topId = matches[0]?.server;
    const routed = topId === c.id;
    const arrow = routed ? pc.green('→') : pc.yellow('→');
    const adapterLabel = routed ? pc.green(c.name) : pc.yellow(topId || '?');
    routingLines.push(`  ${pc.white(`"${c.demoQuery.slice(0, 48)}${c.demoQuery.length > 48 ? '…' : ''}"`)}`);
    routingLines.push(`  ${arrow} ${adapterLabel}`);
    routingLines.push('');
  }

  p.note(routingLines.join('\n').trimEnd(), 'Routing intelligence');

  p.note(
    [
      pc.bold('Try these yourself:'),
      '',
      ...CHARIOT_CURATED.map(c => `  ${pc.cyan(`chariot query "${c.demoQuery}"`)}`),
    ].join('\n'),
    'Test it'
  );

  p.note(
    [
      `  ${pc.cyan('chariot configure')}   connect your APIs and credentials`,
      `  ${pc.cyan('chariot help')}        see all commands`,
    ].join('\n'),
    'When you\'re ready to connect your own APIs'
  );

  p.outro(`${pc.green('Chariot is ready.')} Your data never leaves this machine.`);
}

// ── Header ─────────────────────────────────────────────────────────────────

function printHeader(): void {
  console.log();
  console.log(pc.bold('  Epic AI® Chariot'));
  console.log(pc.dim('  Intelligence that acts.™'));
  console.log();

  const license = validateLicense();
  const native = loadNativeBinding();
  const bindingError = getBindingLoadError();

  switch (license.mode) {
    case 'licensed':
      console.log(
        pc.green('  ✓ Licensed') +
        pc.dim(` — ${license.companyName}, ${license.totalSeats} seats, expires ${license.expiresAt}`),
      );
      // Even with a valid license, enterprise mode requires JWT_SECRET and MASTER_KEY.
      if (!process.env.ENTERPRISE_JWT_SECRET) {
        console.log(pc.red('  ✗ Missing ENTERPRISE_JWT_SECRET') + pc.dim(' — session tokens cannot be issued'));
      }
      if (!process.env.ENTERPRISE_MASTER_KEY) {
        console.log(pc.red('  ✗ Missing ENTERPRISE_MASTER_KEY') + pc.dim(' — credential vault unavailable'));
      }
      break;
    case 'grace':
      console.log(
        pc.yellow('  ⚠ Grace period') +
        pc.dim(` — ${license.companyName}, expires ${license.graceEndsAt}. Payment may need attention.`),
      );
      break;
    case 'degraded':
      console.log(
        pc.red('  ✗ License lapsed') +
        pc.dim(' — single-user mode only. Multi-user features blocked.'),
      );
      break;
    default: {
      if (native) {
        // bug-tracker-ref: dropped the second "Buy seats" CTA here; the dedicated
        // unlicensed-mode message branch at the bottom of this file is the
        // canonical site.
        console.log(pc.yellow('  ○ Single-user mode') + pc.dim(' — full features, no license file'));
      } else if (bindingError && bindingError.includes('interface verification')) {
        // Binary present but corrupted/replaced
        console.log(pc.red('  ✗ Binary verification failed'));
        console.log(pc.red(`    ${bindingError}`));
      } else {
        // No binary at all → single-user mode
        console.log(pc.dim('  ○ Single-user mode') + pc.dim(' — enterprise binary not installed'));
      }
    }
  }
  console.log();
}

// ── Discovery scan persistence ─────────────────────────────────────────────

function generateScanId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function getScanFilePath(codePath: string): string {
  return join(DISCOVERED_DIR, `scan-${codebaseHash(codePath)}.json`);
}

// ── chariot discover ───────────────────────────────────────────────────────

function loadDiscoveryConfig(configPath: string): DiscoveryConfigFile {
  const text = readFileSync(configPath, 'utf-8');
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    // A raw JSON.parse SyntaxError embeds bytes of the file being
    // parsed — pointing --config at any readable file (e.g. /etc/passwd) then
    // leaked ~10-30 of its bytes back to the caller (bounded content-disclosure
    // oracle, CHARIOT §23.2). Discard the SyntaxError entirely and throw a
    // content-free typed error naming only the path.
    throw new Error(`Discovery config at ${configPath} is not valid JSON`);
  }
  if (!raw || typeof raw !== 'object') {
    throw new Error(`Discovery config at ${configPath} is not a JSON object`);
  }
  return validateDiscoveryConfig(raw as Record<string, unknown>);
}

function printServiceTable(
  services: Array<{ name: string; framework: string; endpoints: number; excluded: number; baseUrl: string; authType: string }>,
): void {
  const nameWidth = Math.max(12, ...services.map(s => s.name.length)) + 2;
  const fwWidth = Math.max(10, ...services.map(s => s.framework.length)) + 2;

  console.log();
  console.log(
    pc.dim('  ') +
    pc.bold('Service'.padEnd(nameWidth)) +
    pc.bold('Framework'.padEnd(fwWidth)) +
    pc.bold('Endpoints'.padEnd(12)) +
    pc.bold('Excluded'.padEnd(11)) +
    pc.bold('Auth'.padEnd(10)) +
    pc.bold('Base URL'),
  );
  console.log(pc.dim('  ' + '-'.repeat(nameWidth + fwWidth + 12 + 11 + 10 + 30)));

  for (const svc of services) {
    const authLabel = svc.authType === 'none'
      ? pc.dim('none')
      : svc.authType === 'bearer'
        ? pc.green('bearer')
        : pc.cyan('api_key');
    console.log(
      '  ' +
      svc.name.padEnd(nameWidth) +
      pc.dim(svc.framework.padEnd(fwWidth)) +
      pc.green(String(svc.endpoints).padEnd(12)) +
      (svc.excluded > 0 ? pc.yellow(String(svc.excluded).padEnd(11)) : pc.dim('0'.padEnd(11))) +
      authLabel.padEnd(10 + (authLabel.length - svc.authType.length)) +
      pc.dim(svc.baseUrl),
    );
  }
  console.log();
}

async function runDiscover(): Promise<Record<string, unknown>> {
  // CH-32 (zero-day fix): in agent mode stdout must be PURE JSON — one
  // envelope line, emitted by main(). Every human rendering in this function
  // (banner, info lines, rescan diff, service overview, tables, summary) is
  // guarded behind `!json`, and error paths throw ChariotError so the central
  // CH-31 catch emits exactly one typed envelope instead of process.exit(1).
  const json = agentMode();
  if (!json) printHeader();

  const rescan = args.includes('--rescan');
  const configFlag = args.indexOf('--config');
  const configFilePath = configFlag !== -1 ? args[configFlag + 1] : null;
  const pathFlag = args.indexOf('--path');
  const pathFlagValue = pathFlag !== -1 ? args[pathFlag + 1] : null;

  // CHARIOT §23.2: `--path` and `--config` both name the codebase to
  // scan. The previous `if (configFilePath) … else if (pathFlagValue)` ladder
  // silently let --config win and dropped a user-supplied --path with no word.
  // A user-supplied flag must never be silently ignored — when both are given,
  // fail with an explicit, typed conflict instead of quietly honoring one.
  if (configFilePath && pathFlagValue) {
    throw new ChariotError(fail('cli:discover', 'FLAG_CONFLICT', {
      exit_code: EXIT.USAGE,
      human_message: 'Pass either --path <dir> or --config <file>, not both.',
      cause: '--path and --config both specify the codebase to scan; honoring one would silently ignore the other.',
      remediation: [
        'Use --config <file> for a config-driven scan, OR --path <dir> to scan a directory directly — not both.',
      ],
      data: { path: pathFlagValue, config: configFilePath },
    }));
  }

  const nonInteractive = configFilePath != null;

  // ── Step 1: Determine codebase path ─────────────────────────────────────

  let codebasePath: string;

  if (configFilePath) {
    if (!existsSync(configFilePath)) {
      throw new ChariotError(fail('cli:discover', 'CONFIG_NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `Config file not found: ${configFilePath}`,
        remediation: ['Pass an existing discovery config file via --config <file>.'],
        data: { configFilePath },
      }));
    }
    const cfg = loadDiscoveryConfig(configFilePath);
    codebasePath = cfg.codebasePath;
    if (!json) p.log.info(`Using config: ${configFilePath}`);
  } else if (pathFlagValue) {
    if (!existsSync(pathFlagValue)) {
      throw new ChariotError(fail('cli:discover', 'PATH_NOT_FOUND', {
        exit_code: EXIT.FAILURE,
        human_message: `--path directory not found: ${pathFlagValue}`,
        remediation: ['Pass an existing directory via --path <dir>.'],
        data: { path: pathFlagValue },
      }));
    }
    codebasePath = pathFlagValue;
  } else {
    const positional = args.find(a => a !== 'discover' && a !== '--rescan' && a !== '--config' && a !== '--path' && a !== '--json' && !a.startsWith('--'));
    if (positional) {
      codebasePath = positional;
    } else if (NON_INTERACTIVE) {
      // CH-32: positional [path] is documented; in a non-TTY emit a typed
      // INTERACTIVE_PROMPT_IN_NON_TTY with the exact non-interactive command
      // instead of falling through to the stdin prompt.
      throw new ChariotError(interactiveInNonTty(
        'cli:discover',
        'chariot discover --path <dir> --json   (or --config <file>)',
        'discover needs a codebase path and stdin is not a TTY.',
      ));
    } else {
      const result = await p.text({
        message: 'Path to your codebase:',
        placeholder: './src',
        defaultValue: './src',
        validate: (val) => {
          if (!existsSync(val || './src')) return 'Directory does not exist.';
        },
      });
      if (p.isCancel(result)) process.exit(0);
      codebasePath = result as string;
    }
  }

  const canonicalPath = canonicalizePath(codebasePath);

  // ── Step 2: Scan ────────────────────────────────────────────────────────

  const s = makeSpinner(p);
  s.start('Scanning codebase for APIs...');

  // CHARIOT::§16.1 Discovery (CHARIOT-SPEC.md:1352, rulings item
  // 91/105/112(a)) — the scan boundary. `discover()` (src/discovery/
  // index.ts) is synchronous, so started/completed bracket the one call.
  chariotEmitter.send('discovery.scan.started', { data: { codebasePath: canonicalPath } });

  const result = discover(canonicalPath);

  chariotEmitter.send('discovery.scan.completed', {
    data: {
      codebasePath: canonicalPath,
      services: result.services.length,
      totalEndpoints: result.totalEndpoints,
      scanDurationMs: result.scanDurationMs,
    },
  });

  s.stop(
    pc.green(`${result.services.length} services`) +
    pc.dim(' with ') +
    pc.green(`${result.totalEndpoints} endpoints`) +
    pc.dim(` discovered in ${result.scanDurationMs}ms`),
  );

  if (result.services.length === 0) {
    if (!json) {
      console.log();
      p.log.warn('No APIs found.');
      console.log(pc.dim('  Supported: OpenAPI specs (.json/.yaml), Express.js routes.'));
      console.log(pc.dim('  Make sure your codebase path contains API definitions or route files.'));
      console.log();
    }
    return { services: 0, totalEndpoints: 0, scanDurationMs: result.scanDurationMs, registered: 0 };
  }

  // ── Step 3: Rescan diff (if applicable) ─────────────────────────────────

  const scanFilePath = getScanFilePath(canonicalPath);
  if (rescan && existsSync(scanFilePath)) {
    const previousScan = JSON.parse(readFileSync(scanFilePath, 'utf-8')) as DiscoveryScanRecord;
    const diff = computeRescanDiff(previousScan, result, canonicalPath);

    if (!json) {
    console.log();
    p.log.step(pc.bold('Changes since last scan:'));
    if (diff.added.length > 0) {
      for (const svc of diff.added) {
        console.log(pc.green(`  + ${svc.name}`) + pc.dim(` (${svc.framework}) — ${svc.endpoints.length} endpoints`));
      }
    }
    if (diff.removed.length > 0) {
      for (const svc of diff.removed) {
        console.log(pc.red(`  - ${svc.name}`) + pc.dim(' — no longer detected'));
      }
    }
    if (diff.changed.length > 0) {
      for (const ch of diff.changed) {
        const delta = ch.currentEndpoints - ch.previousEndpoints;
        const deltaStr = delta > 0 ? pc.green(`+${delta}`) : delta < 0 ? pc.red(`${delta}`) : pc.dim('±0');
        console.log(pc.cyan(`  ~ ${ch.name}`) + pc.dim(` — ${ch.previousEndpoints} → ${ch.currentEndpoints} endpoints (${deltaStr})`));
        for (const ep of ch.addedEndpoints.slice(0, 3)) {
          console.log(pc.green(`      + ${ep.method.toUpperCase()} ${ep.path}`));
        }
        if (ch.addedEndpoints.length > 3) {
          console.log(pc.dim(`      ... and ${ch.addedEndpoints.length - 3} more added`));
        }
        for (const ep of ch.removedEndpoints.slice(0, 3)) {
          console.log(pc.red(`      - ${ep.method.toUpperCase()} ${ep.path}`));
        }
        if (ch.removedEndpoints.length > 3) {
          console.log(pc.dim(`      ... and ${ch.removedEndpoints.length - 3} more removed`));
        }
      }
    }
    if (diff.unchanged > 0) {
      console.log(pc.dim(`  = ${diff.unchanged} service${diff.unchanged === 1 ? '' : 's'} unchanged`));
    }
    } // end !json rescan-diff rendering
    if (diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0) {
      if (!json) p.log.info('No changes detected. Your adapters are up to date.');
      return {
        services: result.services.length,
        totalEndpoints: result.totalEndpoints,
        scanDurationMs: result.scanDurationMs,
        registered: 0,
        upToDate: true,
      };
    }
    if (!json) console.log();
  }

  // ── Step 4: Service overview ────────────────────────────────────────────

  if (!json) {
  console.log();
  p.log.step(pc.bold('Discovered services:'));
  console.log();

  for (const svc of result.services) {
    const regularEps = svc.endpoints.filter(e => !isAdminEndpoint(e, svc.name));
    const adminEps = svc.endpoints.filter(e => isAdminEndpoint(e, svc.name));
    const isAdmin = isAdminEndpoint({ path: '' }, svc.name);

    console.log(
      (isAdmin ? pc.yellow('  ! ') : '  ') +
      pc.bold(svc.name) +
      pc.dim(` (${svc.framework})`) +
      pc.dim(' — ') +
      pc.green(`${regularEps.length} exposed`) +
      (adminEps.length > 0 ? pc.dim(', ') + pc.yellow(`${adminEps.length} excluded`) : ''),
    );

    // Show top 5 endpoints as a preview
    for (const ep of regularEps.slice(0, 5)) {
      console.log(pc.dim(`    ${pc.green('+')} ${ep.method.toUpperCase().padEnd(7)} ${ep.path}`));
    }
    if (regularEps.length > 5) {
      console.log(pc.dim(`    ... and ${regularEps.length - 5} more`));
    }
    if (adminEps.length > 0) {
      for (const ep of adminEps.slice(0, 3)) {
        console.log(pc.dim(`    ${pc.red('-')} ${ep.method.toUpperCase().padEnd(7)} ${ep.path}`) + pc.dim(' (excluded)'));
      }
      if (adminEps.length > 3) {
        console.log(pc.dim(`    ... and ${adminEps.length - 3} more excluded`));
      }
    }
    console.log();
  }
  } // end !json service-overview rendering

  // ── Step 5: Select services ─────────────────────────────────────────────

  const cfgFile = configFilePath ? loadDiscoveryConfig(configFilePath) : null;

  let selectedServices: DiscoveredService[];

  if (nonInteractive && cfgFile) {
    // Non-interactive: explicit allowlist only — services must have include: true
    selectedServices = filterAllowlist(result.services, cfgFile.services, canonicalPath) as DiscoveredService[];
    if (selectedServices.length === 0) {
      throw new ChariotError(fail('cli:discover', 'NO_SERVICES_MATCHED', {
        exit_code: EXIT.FAILURE,
        human_message: 'No services matched the config allowlist. Nothing to register.',
        remediation: ['Each service in the config must have "include": true to be exposed.'],
        data: { services: result.services.length, selected: 0 },
      }));
    }
    if (!json) p.log.info(`Non-interactive: ${selectedServices.length} services selected from config allowlist.`);
  } else if (!json) {
    const serviceOptions = result.services.map((svc, idx) => {
      const regularEps = svc.endpoints.filter(e => !isAdminEndpoint(e, svc.name));
      const isAdmin = isAdminEndpoint({ path: '' }, svc.name);
      return {
        value: idx,
        label: `${svc.name} (${svc.framework})`,
        hint: `${regularEps.length} endpoints${isAdmin ? pc.yellow(' [admin — review carefully]') : ''}`,
      };
    });

    const selectedIndices = await p.multiselect({
      message: 'Which services should your AI have access to?',
      options: serviceOptions,
      required: false,
    });

    if (p.isCancel(selectedIndices)) process.exit(0);
    if ((selectedIndices as number[]).length === 0) {
      if (!json) p.log.info('No services selected. Nothing to configure.');
      // CHARIOT::§16.1 Discovery (CHARIOT-SPEC.md:1352, rulings item
      // 91/105/112(a)) — the approval decision: nothing was chosen, so
      // every discovered service was implicitly rejected.
      for (const svc of result.services) {
        chariotEmitter.send('discovery.service.rejected', {
          data: { codebasePath: canonicalPath, service: svc.name, framework: svc.framework },
        });
      }
      return {
        services: result.services.length,
        totalEndpoints: result.totalEndpoints,
        scanDurationMs: result.scanDurationMs,
        selected: 0,
        registered: 0,
      };
    }

    selectedServices = (selectedIndices as number[]).map(i => result.services[i]);
  } else {
    throw new ChariotError(fail('cli:discover', 'JSON_MODE_REQUIRES_CONFIG', {
      exit_code: EXIT.FAILURE,
      human_message: 'discover --json requires --config <file> so service selection can be resolved without prompts.',
      remediation: ['Pass a discovery config file with explicit allowlist/defaults, or run without --json for interactive selection.'],
      data: { codebasePath: canonicalPath },
    }));
  }

  // CHARIOT::§16.1 Discovery (CHARIOT-SPEC.md:1352, rulings item
  // 91/105/112(a)) — the approval decision, covering both the
  // non-interactive (config allowlist) and interactive (multiselect)
  // paths converged above. `discovery.exclusion.override` fires for a
  // selected service the scanner itself flagged admin/internal
  // (`isAdminEndpoint({path:''}, svc.name)` — the SAME service-level
  // heuristic that drove the "[admin — review carefully]" UI warning at
  // selection time above): choosing to expose it anyway IS the
  // force-include this event names. There is no separate PER-ENDPOINT
  // override in this codebase — admin-flagged individual endpoints
  // within an otherwise-approved service remain unconditionally excluded
  // (see `adminEndpoints`/`excludedEndpoints` below, Step 7) — only the
  // service-level admin heuristic has an override path today.
  {
    const selectedSet = new Set(selectedServices);
    for (const svc of selectedServices) {
      chariotEmitter.send('discovery.service.approved', {
        data: { codebasePath: canonicalPath, service: svc.name, framework: svc.framework },
      });
      if (isAdminEndpoint({ path: '' }, svc.name)) {
        chariotEmitter.send('discovery.exclusion.override', {
          severity: 'warning',
          data: { codebasePath: canonicalPath, service: svc.name, framework: svc.framework },
        });
      }
    }
    for (const svc of result.services) {
      if (!selectedSet.has(svc)) {
        chariotEmitter.send('discovery.service.rejected', {
          data: { codebasePath: canonicalPath, service: svc.name, framework: svc.framework },
        });
      }
    }
  }

  // ── Step 6: Batch defaults ──────────────────────────────────────────────

  let defaultBaseUrl: string | undefined;
  let defaultAuthType: string | undefined;
  let defaultAuthEnvKey: string | undefined;

  if (cfgFile?.defaults) {
    defaultBaseUrl = cfgFile.defaults.baseUrl;
    defaultAuthType = cfgFile.defaults.authType;
    defaultAuthEnvKey = cfgFile.defaults.authEnvKey;
  } else if (!json && selectedServices.length > 1) {
    const useBatchDefaults = await p.confirm({
      message: `Apply the same connection settings to all ${selectedServices.length} services?`,
      initialValue: true,
    });

    if (p.isCancel(useBatchDefaults)) process.exit(0);

    if (useBatchDefaults) {
      const bUrl = await p.text({
        message: 'Default base URL for all services:',
        placeholder: 'http://localhost:3000',
      });
      if (p.isCancel(bUrl)) process.exit(0);
      defaultBaseUrl = bUrl as string;

      const bAuth = await p.select({
        message: 'Default authentication for all services:',
        options: [
          { value: 'none', label: 'None — public or internal network' },
          { value: 'bearer', label: 'Bearer token' },
          { value: 'api_key', label: 'API key header' },
        ],
      });
      if (p.isCancel(bAuth)) process.exit(0);
      defaultAuthType = bAuth as string;

      if (defaultAuthType !== 'none') {
        const bKey = await p.text({
          message: defaultAuthType === 'bearer' ? 'Token (or $ENV_VAR):' : 'API key (or $ENV_VAR):',
          placeholder: '$MY_SERVICE_TOKEN',
        });
        if (p.isCancel(bKey)) process.exit(0);
        defaultAuthEnvKey = bKey as string;
      }
    }
  }

  // ── Step 7: Per-service config (only for services without defaults) ─────

  interface ServiceConfig {
    service: DiscoveredService;
    regularEndpoints: Array<{ method: string; path: string; handlerName?: string; filePath: string; lineNumber: number }>;
    adminEndpoints: Array<{ method: string; path: string }>;
    baseUrl: string;
    authType: string;
    authEnvKey?: string;
  }

  const configured: ServiceConfig[] = [];

  for (const service of selectedServices) {
    const regularEndpoints = service.endpoints.filter(e => !isAdminEndpoint(e, service.name));
    const adminEndpoints = service.endpoints.filter(e => isAdminEndpoint(e, service.name));

    // Resolve config: per-service override (by serviceId or name) → batch defaults → prompt
    const svcId = serviceSlug(service.name, service.basePath, canonicalPath);
    const cfgOverride = cfgFile?.services?.[svcId] ?? cfgFile?.services?.[service.name];

    let baseUrl = cfgOverride?.baseUrl || defaultBaseUrl;
    let authType = cfgOverride?.authType || defaultAuthType;
    let authEnvKey = cfgOverride?.authEnvKey || defaultAuthEnvKey;

    if (nonInteractive) {
      // In non-interactive mode, all fields must be resolvable without prompts
      const incomplete = (msg: string): ChariotError =>
        new ChariotError(fail('cli:discover', 'CONFIG_INCOMPLETE', {
          exit_code: EXIT.FAILURE,
          human_message: msg,
          remediation: ['Set the missing field in the config file defaults or per-service override.'],
          data: { service: service.name },
        }));
      if (!baseUrl) {
        throw incomplete(`No baseUrl for service "${service.name}" — set it in config defaults or per-service override.`);
      }
      if (!authType) {
        throw incomplete(`No authType for service "${service.name}" — set it in config defaults or per-service override.`);
      }
      if (authType !== 'none' && !authEnvKey) {
        throw incomplete(`Service "${service.name}" requires auth (${authType}) but no authEnvKey is set in config defaults or per-service override.`);
      }
    } else {
      if (!baseUrl) {
        const bUrl = await p.text({
          message: `Base URL for ${pc.bold(service.name)}:`,
          placeholder: 'http://localhost:3000',
        });
        if (p.isCancel(bUrl)) process.exit(0);
        baseUrl = bUrl as string;
      }

      if (!authType) {
        const bAuth = await p.select({
          message: `Authentication for ${pc.bold(service.name)}:`,
          options: [
            { value: 'none', label: 'None — public or internal network' },
            { value: 'bearer', label: 'Bearer token' },
            { value: 'api_key', label: 'API key header' },
          ],
        });
        if (p.isCancel(bAuth)) process.exit(0);
        authType = bAuth as string;
      }

      if (authType !== 'none' && !authEnvKey) {
        const bKey = await p.text({
          message: authType === 'bearer'
            ? `Token for ${pc.bold(service.name)} (or $ENV_VAR):`
            : `API key for ${pc.bold(service.name)} (or $ENV_VAR):`,
          placeholder: '$MY_SERVICE_TOKEN',
        });
        if (p.isCancel(bKey)) process.exit(0);
        authEnvKey = bKey as string;
      }
    }

    configured.push({ service, regularEndpoints, adminEndpoints, baseUrl, authType, authEnvKey });
  }

  // ── Step 8: Review table ────────────────────────────────────────────────

  const totalEndpoints = configured.reduce((sum, c) => sum + c.regularEndpoints.length, 0);
  const totalExcluded = configured.reduce((sum, c) => sum + c.adminEndpoints.length, 0);

  if (!json) {
    printServiceTable(configured.map(c => ({
      name: c.service.name,
      framework: c.service.framework,
      endpoints: c.regularEndpoints.length,
      excluded: c.adminEndpoints.length,
      baseUrl: c.baseUrl,
      authType: c.authType,
    })));

    console.log(
      pc.dim('  Total: ') +
      pc.bold(`${configured.length} services`) +
      pc.dim(', ') +
      pc.green(`${totalEndpoints} endpoints exposed`) +
      (totalExcluded > 0 ? pc.dim(', ') + pc.yellow(`${totalExcluded} excluded`) : ''),
    );
    console.log();
  }

  // ── Step 9: Confirmation ────────────────────────────────────────────────

  if (!nonInteractive) {
    const proceed = await p.confirm({
      message: 'Register these services? Your AI will be able to query them.',
      initialValue: true,
    });
    if (p.isCancel(proceed) || !proceed) {
      if (!json) p.log.info('Discovery cancelled. No changes made.');
      return {
        services: result.services.length,
        totalEndpoints: result.totalEndpoints,
        scanDurationMs: result.scanDurationMs,
        selected: configured.length,
        registered: 0,
        cancelled: true,
      };
    }
  }

  // ── Step 10: Persist ────────────────────────────────────────────────────

  ensureDir(DISCOVERED_DIR);
  const scanId = generateScanId();
  const scanRecord: DiscoveryScanRecord = {
    scanId,
    scannedAt: new Date().toISOString(),
    codebasePath: canonicalPath,
    overallStatus: 'complete',
    services: [],
  };

  const sp = makeSpinner(p);
  sp.start('Registering adapters...');

  for (const c of configured) {
    // Resolve auth credential
    let resolvedAuthEnvKey: string | undefined;
    if (c.authType !== 'none' && c.authEnvKey) {
      if (c.authEnvKey.startsWith('$')) {
        resolvedAuthEnvKey = c.authEnvKey.slice(1);
      } else {
        const credKey = `CHARIOT_DISCOVERED_${c.service.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TOKEN`;
        writeCredential(credKey, c.authEnvKey);
        resolvedAuthEnvKey = credKey;
      }
    }

    const serviceRecord: DiscoveredServiceRecord = {
      serviceId: serviceSlug(c.service.name, c.service.basePath, canonicalPath),
      name: c.service.name,
      framework: c.service.framework,
      basePath: c.service.basePath,
      endpointCount: c.regularEndpoints.length,
      excludedEndpointCount: c.adminEndpoints.length,
      endpoints: c.regularEndpoints.map(ep => ({
        method: ep.method,
        path: ep.path,
        handlerName: ep.handlerName,
        filePath: ep.filePath,
        lineNumber: ep.lineNumber,
      })),
      excludedEndpoints: c.adminEndpoints.map(ep => ({ method: ep.method, path: ep.path })),
      status: 'approved',
      approvedBy: nonInteractive ? 'config-file' : 'cli-admin',
      approvedAt: new Date().toISOString(),
      rejectedBy: null,
      rejectedAt: null,
      baseUrl: c.baseUrl,
      authType: c.authType,
      authEnvKey: resolvedAuthEnvKey,
    };

    scanRecord.services.push(serviceRecord);

    // Register in Chariot adapter state
    const state = loadState();
    // `discovered:` namespaces this adapter id away from the catalog id
    // space (ChariotState.ts's authoritativeIds collision guard rejects a
    // discovered payload that reuses a catalog id, e.g. a customer's
    // internal service literally named "stripe" or "wikipedia" — the
    // prefix is what makes that guard meaningful). This is the OPERATIONAL
    // identity: state.adapters key, config.selectedAdapters entry, and
    // (applied at READ time by ChariotState.ts, not baked into the signed
    // bytes) the routable AdapterEntry.id.
    //
    // FIX (2026-09-30, dogfood mechanism-test-routes): this prefixed id was
    // PREVIOUSLY also used as the SIGNED payload.id/_adapterId, but the
    // envelope file is written at the BARE `${serviceRecord.serviceId}.json`
    // — envelope.ts's loader requires the filename stem to equal the signed
    // _adapterId (docstring lines 6-13: "the loader requires the filename
    // stem to equal _adapterId"; enforced at :227-228 via
    // `expectedAdapterId !== undefined && env._adapterId !== expectedAdapterId`
    // -> "signed for id ... but expected ..."), so EVERY discovered envelope
    // was rejected on the very next load. The signed identity now uses the
    // BARE serviceId (matching the filename); the `discovered:` prefix is
    // applied only when ChariotState.ts reads the verified payload back into
    // an AdapterEntry — never inside the signed bytes.
    const adapterId = `discovered:${serviceRecord.serviceId}`;
    saveState(upsertAdapterState(state, adapterId, {
      type: 'rest',
      status: 'configured',
      toolCount: c.regularEndpoints.length,
      lastVerified: null,
    }));

    // Add to config
    const config = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };
    if (!config.selectedAdapters.includes(adapterId)) {
      config.selectedAdapters.push(adapterId);
    }
    saveConfig(config);

    // Write signed adapter definition. `id` here is the BARE serviceId —
    // it must equal the filename stem (see comment above); the
    // `discovered:` operational prefix is applied at read time, never
    // signed.
    //
    // FIX (2026-09-30, release-blocking): populate `rest.module`/
    // `rest.className` pointing at the ONE generic
    // DiscoveredRestAdapter (src/discovery/DiscoveredRestAdapter.ts) —
    // this is what makes ChariotState.ts's EXISTING isDispatchable()
    // REST branch (`adapter.rest?.module && adapter.rest?.className`)
    // recognise a discovered adapter with NO new special-cased branch
    // needed. `rest.envKey`/`rest.baseUrl` reuse the SAME single-
    // credential mechanism every other REST adapter already goes
    // through (chariot add / chariot health / toolHandlers.ts REST
    // dispatch). The endpoint list — the one piece of data no
    // hand-written adapter class ever needed before, since a
    // discovered service's endpoints are scanned dynamically rather
    // than authored — travels as `rest.discoveredEndpointsJson`.
    // `description` is REQUIRED to be >=20 chars of real text or
    // ChariotState.ts's descriptionIsLowQuality() silently excludes the
    // adapter from the BM25 routing index entirely (buildToolsForRouting).
    const adapterDefPath = join(DISCOVERED_DIR, `${serviceRecord.serviceId}.json`);
    const seenToolNames = new Set<string>();
    const toolNames = c.regularEndpoints.map(ep => buildDiscoveredToolName(ep.method.toUpperCase(), ep.path, seenToolNames));
    const endpointsForDispatch: DiscoveredEndpoint[] = c.regularEndpoints.map(ep => ({
      method: ep.method,
      path: ep.path,
      handlerName: ep.handlerName,
    }));
    const endpointSummary = c.regularEndpoints.slice(0, 5).map(ep => `${ep.method.toUpperCase()} ${ep.path}`).join(', ')
      + (c.regularEndpoints.length > 5 ? ', ...' : '');
    const signed = signDiscoveredAdapter({
      id: serviceRecord.serviceId,
      name: c.service.name,
      description: `Discovered ${c.service.framework} service "${c.service.name}" — ${c.regularEndpoints.length} endpoint(s): ${endpointSummary}.`,
      framework: c.service.framework,
      discoveredAt: serviceRecord.approvedAt,
      // Mirrored at the TOP level (not just under `rest`) matching the
      // signed catalog's own convention (e.g. paypal carries both
      // top-level `toolCount` AND `rest.toolCount`, identical values) —
      // `bundleToolCount()` (src/catalog/artifacts.ts, shared by
      // chariot health/list/search) reads the TOP-level field first and
      // has no `rest.*` fallback, so without this a discovered adapter
      // with real tools would show 0 tools everywhere `bundleToolCount`
      // is used, not just in health.
      type: 'rest',
      toolCount: c.regularEndpoints.length,
      toolNames,
      rest: {
        module: './dist/discovery/DiscoveredRestAdapter.js',
        className: 'DiscoveredRestAdapter',
        baseUrl: c.baseUrl,
        authType: c.authType,
        envKey: resolvedAuthEnvKey,
        toolCount: c.regularEndpoints.length,
        toolNames,
        discoveredEndpointsJson: JSON.stringify(endpointsForDispatch),
      },
    }, defaultEnvelopePaths(EPIC_AI_DIR));
    writeFileSync(adapterDefPath, JSON.stringify(signed, null, 2));
  }

  // Persist scan record
  writeFileSync(getScanFilePath(canonicalPath), JSON.stringify(scanRecord, null, 2));

  sp.stop(pc.green('Done'));

  // ── Step 11: Final summary ──────────────────────────────────────────────

  if (!json) {
    console.log();
    console.log(pc.bold('  Epic AI® Chariot — Discovery Complete'));
    console.log();
    console.log(`  ${pc.green(String(configured.length))} services registered`);
    console.log(`  ${pc.green(String(totalEndpoints))} endpoints exposed to your AI`);
    if (totalExcluded > 0) {
      console.log(`  ${pc.yellow(String(totalExcluded))} admin/internal endpoints excluded`);
    }
    console.log(`  ${pc.dim('Scan ID:')} ${scanId}`);
    console.log();
    console.log(pc.dim('  Adapters saved to ~/.epic-ai/discovered-adapters/'));
    console.log(pc.dim('  Your AI can now query these services via Chariot.'));
    console.log();
    console.log(pc.dim('  Next steps:'));
    console.log(pc.dim('    chariot serve              Start the MCP server'));
    console.log(pc.dim('    chariot discover --rescan   Update after code changes'));
    console.log(pc.dim('    chariot health              Verify adapter connectivity'));
    console.log();
  }

  return {
    services: result.services.length,
    totalEndpoints,
    totalExcluded,
    scanDurationMs: result.scanDurationMs,
    selected: configured.length,
    registered: configured.length,
    scanId,
  };
}

// ── chariot license ────────────────────────────────────────────────────────

const LAST_RENEWAL_PATH = join(EPIC_AI_DIR, 'state', 'last_renewal.json');

function readLastRenewal(): LastRenewalRecord | null {
  // R9-1: read+parse via the shared cli/state.ts helper. Domain
  // validation (ts:number + outcome_kind:string) stays in the caller
  // because the helper is generic over T.
  const j = readJsonFile<LastRenewalRecord>(LAST_RENEWAL_PATH);
  if (j && typeof j.ts === 'number' && typeof j.outcome_kind === 'string') return j;
  return null;
}

function writeLastRenewal(rec: LastRenewalRecord): void {
  try {
    mkdirSync(join(EPIC_AI_DIR, 'state'), { recursive: true });
    const tmp = `${LAST_RENEWAL_PATH}.tmp.${process.pid}`;
    writeFileSync(tmp, JSON.stringify(rec, null, 2) + '\n', {
      encoding: 'utf-8',
      mode: 0o600,
    });
    renameSync(tmp, LAST_RENEWAL_PATH);
  } catch {
    // Best-effort; CLI should still report the renew result even if
    // the state file write fails.
  }
}

function runLicense(): void {
  printHeader();
  const license = validateLicense();
  const lastRenewal = readLastRenewal();
  const lines = formatStatusLines(license, lastRenewal);

  // Color the whole block by mode — keeps a single source of truth for
  // line content (formatStatusLines) while preserving the existing
  // green/yellow/red/dim signal on the terminal.
  const colorize =
    license.mode === 'licensed'
      ? pc.green
      : license.mode === 'grace'
        ? pc.yellow
        : license.mode === 'degraded'
          ? pc.red
          : pc.dim;
  for (const line of lines) {
    console.log(`  ${colorize(line)}`);
  }
  if (license.mode === 'unlicensed') {
    console.log();
    console.log(pc.dim('  Running in single-user mode with full features.'));
    console.log(pc.dim('  Buy seats at https://epic-ai.io'));
  } else if (license.mode === 'grace') {
    console.log();
    console.log(pc.dim('  This usually means a payment didn\'t process.'));
    console.log(pc.dim('  If your payment method is current, the license'));
    console.log(pc.dim('  will renew automatically. No action needed.'));
  } else if (license.mode === 'degraded') {
    console.log();
    console.log('  Single-user mode is active with full features.');
    console.log('  Multi-user access, SSO, shared credentials, and RBAC are paused.');
    console.log();
    console.log('  This will resolve automatically when your payment processes.');
    console.log('  If you need help: support@epic-ai.io');
  }
  console.log();
}

async function runLicenseActivate(sourcePath: string | undefined): Promise<void> {
  if (!sourcePath || sourcePath.length === 0) {
    console.error(pc.red('  Usage: chariot license activate <path>'));
    process.exit(2);
  }
  const result = activateLicenseFromPath(sourcePath);
  if (!result.ok) {
    console.error(pc.red(`  ✗ Activate failed: ${result.reason}`));
    console.error(pc.dim(`    ${result.message}`));
    process.exit(1);
  }
  // Force a fresh validate so the cached state reflects the new file.
  // The runtime loader applies anti-rollback against ~/.epic-ai/state/
  // license_epoch — a signed-but-stale license (older license_epoch than
  // the host has previously accepted) writes successfully but is then
  // rejected on read. Surface that to the user instead of claiming
  // success on a non-functional file.
  const post = revalidateLicense();
  const c = result.claims;
  if (post.mode === 'licensed' || post.mode === 'grace') {
    console.log();
    console.log(pc.green('  ✓ License activated'));
    console.log(pc.dim(`    Written to ${result.writtenPath}`));
    console.log();
    console.log(`  Company:   ${c.companyName ?? c.companyId}`);
    if (c.tier) console.log(`  Tier:      ${c.tier}`);
    if (c.totalSeats !== undefined) console.log(`  Seats:     ${c.totalSeats}`);
    console.log(`  Expires:   ${c.expiresAtIso}`);
    if (c.slaTier) console.log(`  SLA tier:  ${c.slaTier}`);
    console.log();
    return;
  }
  console.error();
  console.error(
    pc.yellow('  ⚠ License written, but the runtime loader rejected it.'),
  );
  console.error(pc.dim(`    Written to ${result.writtenPath}`));
  console.error(pc.dim(`    Reason:     ${post.reason ?? 'unknown'}`));
  console.error(
    pc.dim(
      '    This usually means the file is older than a license already accepted on this host.',
    ),
  );
  console.error();
  process.exit(1);
}

async function runLicenseRenewNow(): Promise<void> {
  console.log();
  console.log(pc.dim('  Calling epic-ai.io/api/license/renew …'));
  const outcome = await renewNow();
  const summary = summarizeRenewOutcome(outcome);
  const tag =
    summary.color === 'g'
      ? pc.green('  ✓')
      : summary.color === 'y'
        ? pc.yellow('  ◦')
        : pc.red('  ✗');
  console.log(`${tag} ${summary.line}`);
  // Spec §10.3: report HTTP status and whether a new license was written.
  console.log(pc.dim(`    ${formatRenewStatusLine(summary)}`));
  writeLastRenewal({
    ts: Math.floor(Date.now() / 1000),
    outcome_kind: outcome.kind,
    message: 'message' in outcome ? outcome.message : undefined,
  });
  console.log();
  if (outcome.kind === 'renewed') {
    process.exit(0);
  }
  if (outcome.kind === 'no_new_billing') {
    // Distinct exit code so scripts can tell "no work to do" from "error".
    process.exit(0);
  }
  process.exit(1);
}

// ── Delegated commands ─────────────────────────────────────────────────────

/**
 * bug-tracker-ref: locate and optionally kill a prior `chariot serve --http`
 * listener so the operator isn't blocked by "Server already initialized".
 *   chariot status            → report listening pid / port
 *   chariot serve --status    → same
 *   chariot serve --stop      → SIGTERM the listener, then report
 */
async function cmdServeStopOrStatus(argv: readonly string[]): Promise<void> {
  const wantStop = argv.includes('--stop');
  // Parse `--http [port]` first; fall back to CHARIOT_HTTP_PORT env
  // (the engine reads that same env at bind time in src/engine/bin/
  // setup.ts) so `chariot serve --stop` finds an engine bound via
  // env-only config; finally default to 3550 to match the engine.
  // Validate against the actual TCP port range (1-65535) to reject
  // out-of-range digit strings like "70000".
  const isValidPort = (s: string | undefined): boolean => {
    if (!s || !/^\d{1,5}$/.test(s)) return false;
    const n = Number(s);
    return n > 0 && n <= 65535;
  };
  let port = 3550;
  const envPort = process.env.CHARIOT_HTTP_PORT;
  if (isValidPort(envPort)) port = Number(envPort);
  const httpIdx = argv.indexOf('--http');
  if (httpIdx >= 0 && isValidPort(argv[httpIdx + 1])) {
    port = Number(argv[httpIdx + 1]);
  } else if (httpIdx < 0) {
    // Accept a bare positional port (`chariot status <port>` /
    // `chariot serve status <port>`) so the probe targets the requested port.
    // Skipped when `--http` is present (handled above); flags like --stop /
    // --status / status never parse as a valid port so they are ignored.
    const barePort = argv.slice(1).find(isValidPort);
    if (isValidPort(barePort)) port = Number(barePort);
  }
  const { execSync } = await import('node:child_process');
  let pids: number[] = [];
  // +#4: PID extraction was previously inside a
  // gawk-only `match($0, /re/, a)` three-argument form that mawk
  // (Alpine, minimal Debian) does not support — awk silently
  // syntax-errors and the function reports "no listener" falsely.
  // The ss filter pattern `:port ` (trailing space) also misses
  // `*:port` / `[::]:port` / `0.0.0.0:port` forms depending on ss
  // version. Move the PID extraction into Node-side regex (portable)
  // and split the lsof + ss invocations so we can distinguish
  // "tool unavailable on this host" from "no listener bound" — the
  // previous code swallowed both into exit-0 "no listener", making
  // monitoring scripts indistinguishable from failure mode.
  let toolFailures = 0;
  // 1) lsof — emits one PID per line via -t.
  try {
    const out = execSync(`lsof -nP -iTCP:${port} -sTCP:LISTEN -t`, {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    pids = out.trim().split(/\s+/).filter(Boolean).map(Number).filter(n => Number.isFinite(n) && n > 0);
  } catch (e: unknown) {
    const errno = (e as { code?: string }).code;
    const status = (e as { status?: number }).status;
    // lsof exit 1 = ran successfully but no match (genuine "no listener");
    // ENOENT / status 127 = lsof not installed on host (tool failure).
    if (errno === 'ENOENT' || status === 127) toolFailures++;
  }
  // 2) ss fallback — only if lsof produced nothing. POSIX awk replaced
  // by Node-side regex so Alpine/mawk hosts work.
  if (pids.length === 0) {
    try {
      const ssOut = execSync(`ss -tlnHp`, {
        encoding: 'utf8',
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      // Match `:<port>` at a word boundary — covers `*:3550`,
      // `0.0.0.0:3550`, `[::]:3550`, `127.0.0.1:3550`. Use a non-digit
      // (or EOL) lookbehind via negative-char-class to avoid matching
      // a port that is a SUFFIX of a larger port number (`:13550`
      // must not match port 3550).
      const portRe = new RegExp(`(?<![0-9]):${port}(?![0-9])`);
      const pidRe = /pid=(\d+)/;
      const matched: number[] = [];
      for (const line of ssOut.split('\n')) {
        if (!portRe.test(line)) continue;
        const m = pidRe.exec(line);
        if (m) {
          const n = Number(m[1]);
          if (Number.isFinite(n) && n > 0) matched.push(n);
        }
      }
      pids = matched;
    } catch (e: unknown) {
      const errno = (e as { code?: string }).code;
      const status = (e as { status?: number }).status;
      if (errno === 'ENOENT' || status === 127) toolFailures++;
    }
  }
  if (pids.length === 0) {
    if (toolFailures === 2) {
      // Both lsof and ss are absent — we cannot determine listener
      // state. Exit 2 so monitoring scripts can distinguish this from
      // the legitimate exit-0 "no listener" case.
      console.error(`${pc.red('chariot status:')} neither lsof nor ss is available on this host; cannot determine listener on port ${port}.`);
      console.error(pc.dim('  Install lsof (`apt-get install lsof` / `brew install lsof`) or iproute2 (provides ss) and retry.'));
      process.exit(2);
    }
    console.log(`${pc.dim('chariot status:')} no listener on port ${port}.`);
    return;
  }
  console.log(`${pc.cyan('chariot status:')} port ${port} held by pid${pids.length > 1 ? 's' : ''} ${pids.join(', ')}`);
  if (wantStop) {
    for (const pid of pids) {
      try { process.kill(pid, 'SIGTERM'); console.log(`  ${pc.green('✓')} SIGTERM → ${pid}`); }
      catch (e) { console.log(`  ${pc.yellow('!')} kill ${pid} failed: ${e instanceof Error ? e.message : e}`); }
    }
  }
}

async function delegateToEngine(engineArgs: string[]): Promise<void> {
  try {
    const code = await spawnEngine(engineArgs);
    if (code !== 0) process.exit(code);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(pc.red(`Failed to start Chariot: ${msg}`));
    process.exit(1);
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

function readPkgVersion(): string {
  try {
    // dist/bin/chariot.js → ../../package.json (package root). readFileSync
    // accepts a file URL directly, so no path/url imports are needed.
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
    return pkg.version;
  } catch { return '0.0.0'; }
}

async function main(): Promise<void> {
  const json = agentMode(args);

  // CH-32 — universal NON-INVASIVE `--help`: `--help`/`-h` anywhere prints
  // help and NEVER executes a side-effecting action (the 3.1.2 `discover
  // --help` ran a scan; `add --help` misrouted). Intercepted before dispatch.
  //
  // CLAUSE §23.2::21 — `--help` SHALL print help text, i.e. the
  // full command list, same as the `help` subcommand): `getCommand()`
  // strips leading dashes off its argument, so a bare `chariot --help`
  // (command === '--help') resolved to the `help` capability record and
  // rendered ITS one-line per-command summary via renderCommandHelp()
  // instead of falling through to cmdHelp()'s full command list — a
  // flag↔subcommand inconsistency (`chariot help` showed everything,
  // `chariot --help` showed one line). Only look up a per-command capability
  // when `command` names some OTHER real command; when `--help`/`-h`/`help`
  // is itself the (sole) token, always render the full list.
  if (helpRequested(args)) {
    const isHelpFlagItself = command === undefined || command === '--help' || command === '-h' || command === 'help';
    const cap = isHelpFlagItself ? undefined : getCommand(command);
    if (cap) {
      if (json) process.stdout.write(JSON.stringify(cap) + '\n');
      else console.log(renderCommandHelp(cap).join('\n'));
    } else {
      await cmdHelp();
    }
    return;
  }

  // CH-32 — machine-readable capability manifest (the "AI UI"): per-command
  // non-interactive invocation + arg schema.
  if (command === 'capabilities') {
    const manifest = buildManifest(readPkgVersion());
    process.stdout.write((json ? JSON.stringify(manifest) : JSON.stringify(manifest, null, 2)) + '\n');
    return;
  }

  try {
  switch (command) {
    case 'discover': {
      // CH-32: the envelope carries the structured discovery result; all
      // human rendering inside runDiscover is suppressed in agent mode so
      // stdout is exactly one JSON.parse-able line.
      const discoverResult = await runDiscover();
      if (json) emit(ok('cli:discover', { data: discoverResult }), { json });
      break;
    }

    case 'license': {
      // CHARIOT §23.2: the capability manifest recommends exactly
      // `chariot license --json`, but reading `args[1]` treated the `--json`
      // flag (moved to the tail by the global-flag partition, or trailing when
      // no subcommand is given) as an unknown subcommand → exit 2. Take the
      // first NON-flag token as the subcommand so `--json` is the agent-mode
      // flag it is, defaulting to `status` when only flags are present.
      const sub = args.slice(1).find(a => !a.startsWith('-'));
      if (!sub || sub === 'status') {
        // CHARIOT §23.2: the capability manifest recommends
        // `chariot license --json`, but runLicense() only renders human
        // prose — an agent parsing stdout got no typed envelope (and a
        // false exit-0 with no machine-readable status). In agent mode emit
        // the same `ok(...)` envelope shape the other commands (list/health/
        // version) use, carrying the structured license status; human mode
        // (no --json / CHARIOT_AGENT) keeps the exact runLicense() output.
        if (json) {
          const license = validateLicense();
          const lastRenewal = readLastRenewal();
          emit(
            ok('cli:license', {
              human_message: `License mode: ${license.mode}`,
              data: {
                sub: 'status',
                mode: license.mode,
                valid: license.valid,
                companyId: license.companyId ?? null,
                companyName: license.companyName ?? null,
                totalSeats: license.totalSeats ?? null,
                issuedAt: license.issuedAt ?? null,
                expiresAt: license.expiresAt ?? null,
                graceEndsAt: license.graceEndsAt ?? null,
                daysRemaining: daysRemainingFromIso(license.expiresAt),
                reason: license.reason ?? null,
                lastRenewal: lastRenewal ?? null,
                statusLines: formatStatusLines(license, lastRenewal),
              },
            }),
            { json },
          );
        } else {
          runLicense();
        }
      } else if (sub === 'activate') {
        await runLicenseActivate(args[2]);
      } else if (sub === 'renew-now') {
        await runLicenseRenewNow();
      } else {
        console.error(
          pc.red(`Unknown subcommand: chariot license ${sub}`),
        );
        console.error(
          pc.dim('Valid: chariot license [status|activate <path>|renew-now]'),
        );
        process.exit(2);
      }
      break;
    }

    case 'telemetry': {
      // C4AMD §8 (amended 2026-10-12): agent-operable telemetry controls.
      // One typed envelope; in human mode a success prints its message.
      const telemetryEnv = await runTelemetryCommand(args.slice(1));
      emit(telemetryEnv, { json });
      if (!json && telemetryEnv.ok && telemetryEnv.human_message) console.log(telemetryEnv.human_message);
      break;
    }

    case 'serve':
    case '--serve':
      // bug-tracker-ref: support `chariot serve --stop` and `chariot status` so
      // operators can recover from a stuck listener without manually
      // grepping ps / lsof. The engine bind layer surfaces EADDRINUSE
      // on conflict; the CLI shell here owns the kill / report path.
      if (args.includes('--stop') || args.includes('--status') || args[1] === 'status') {
        await cmdServeStopOrStatus(args);
        break;
      }
      await delegateToEngine(['serve', ...args.slice(1)]);
      break;

    case 'status':
      // §23.2: pass the real argv (which carries `--http <port>` and
      // a bare `status <port>` positional) instead of a hardcoded
      // `['serve','--status']` that pinned the probe to the 3550 default and
      // falsely reported "no listener" for a live server on any other port.
      await cmdServeStopOrStatus(args);
      break;

    case 'query':
      await delegateToEngine(args);
      break;

    case 'help':
    case '--help':
    case '-h':
      await cmdHelp();
      break;

    case 'version':
    case '--version':
    case '-v': {
      const version = readPkgVersion();
      if (json) emit(ok('cli:version', { data: { version } }), { json });
      else console.log(version);
      break;
    }

    case 'list': {
      // Extract the first non-flag positional so `chariot list --json` does not
      // pass '--json' as the search term (Finding 1).
      const listTerm = args.slice(1).find(a => !a.startsWith('-'));
      emit(await cmdList(listTerm), { json, humanAlreadyRendered: true });
      break;
    }

    case 'search': {
      // Extract the first non-flag positional so `chariot search --json <term>`
      // resolves the term correctly and flags stay flags (Finding 1).
      const searchTerm = args.slice(1).find(a => !a.startsWith('-'));
      emit(await cmdSearch(searchTerm), { json, humanAlreadyRendered: true });
      break;
    }

    case 'add': {
      // First non-flag positional is the adapter id, so `chariot add <id>
      // --json` and `chariot add --json <id>` both resolve the id (flags
      // like --json/--token are not mistaken for the id).
      const addId = args.slice(1).find(a => !a.startsWith('-'));
      if (!addId) {
        throw new ChariotError(fail('cli:add', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'Usage: chariot add <adapter-id> [--token KEY=VAL]',
          remediation: ['Run `chariot search <term>` to find an adapter id.'],
        }));
      }
      emit(await cmdAdd(addId), { json, humanAlreadyRendered: true });
      break;
    }

    case 'remove': {
      const removeId = args.slice(1).find(a => !a.startsWith('-'));
      if (!removeId) {
        throw new ChariotError(fail('cli:remove', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'Usage: chariot remove <adapter-id>',
        }));
      }
      emit(await cmdRemove(removeId), { json, humanAlreadyRendered: true });
      break;
    }

    case 'health':
      emit(await cmdHealth(), { json, humanAlreadyRendered: true });
      break;

    case 'configure':
      emit(await cmdConfigure(), { json, humanAlreadyRendered: true });
      break;

    case 'audit':
      emit(await cmdAudit(), { json, humanAlreadyRendered: true });
      break;

    case 'vault':
      emit(await cmdVault(), { json, humanAlreadyRendered: true });
      break;

    case 'approve': {
      const approveId = args.slice(1).find(a => !a.startsWith('-'));
      if (!approveId) {
        throw new ChariotError(fail('cli:approve', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'Usage: chariot approve <adapter-id>',
        }));
      }
      emit(await cmdApprove(approveId), { json, humanAlreadyRendered: true });
      break;
    }

    case 'approvals':
      emit(await cmdApprovals(), { json, humanAlreadyRendered: true });
      break;

    case 'revoke': {
      const revokeId = args.slice(1).find(a => !a.startsWith('-'));
      if (!revokeId) {
        throw new ChariotError(fail('cli:revoke', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: 'Usage: chariot revoke <adapter-id>',
        }));
      }
      emit(await cmdRevoke(revokeId), { json, humanAlreadyRendered: true });
      break;
    }

    case 'resume':
      // `chariot resume <traceId>` reads the latest
      // checkpoint from the SQLite checkpoint store.
      emit(await cmdResume(args[1]), { json, humanAlreadyRendered: true });
      break;

    case 'trace': {
      const sub = args[1];
      if (sub === 'explain') {
        // CHARIOT §23.2: parse flags OUT before reading positionals so
        // the documented `chariot trace explain <traceId> --json` works. The
        // global-flag partition moves `--json` to the end of argv, where it was
        // then consumed as the audit-file positional (args[3]) — breaking the
        // tool's own example with a bogus "Audit file not found: --json". Take
        // the first two NON-flag tokens after `explain` as traceId + auditFile.
        const traceArgs = args.slice(2).filter(a => !a.startsWith('-'));
        emit(await cmdTraceExplain(traceArgs[0], traceArgs[1]), { json, humanAlreadyRendered: true });
      } else {
        throw new ChariotError(fail('cli:trace', 'USAGE_ERROR', {
          exit_code: EXIT.USAGE,
          human_message: `Unknown subcommand: chariot trace ${sub ?? '(none)'}`,
          remediation: ['Valid: chariot trace explain <traceId> [auditFile.jsonl]'],
        }));
      }
      break;
    }

    case undefined: {
      // Offline kit (recipient-specific tarball only; CHARIOT §17.2a): when
      // <packageRoot>/kit is present, verify every sha256 and install models /
      // sealed shard / ONNX Runtime / licence into the Epic AI dir BEFORE
      // catalog and retrieval loading — interactive or not, with no prompt.
      // Any refusal is a ChariotError. Absent kit → no output, no change.
      // Agent (--json) mode keeps stdout to its single JSON envelope (CH-31).
      const kitSummary = await installOfflineKit(defaultPackageRoot(), EPIC_AI_DIR);
      for (const line of formatOfflineKitSummary(kitSummary)) (json ? console.error : console.log)(line);
      if (NON_INTERACTIVE) {
        throw new ChariotError(interactiveInNonTty(
          'cli:wizard',
          'chariot add <id> --token KEY=VAL   (then `chariot serve`)',
          'the setup wizard is interactive and stdin is not a TTY.',
        ));
      }
      await runSetupWizard();
      if (json) emit(ok('cli:wizard'), { json });
      break;
    }

    default: {
      // CH-31/CH-32 (zero-day fix): agent mode must receive exactly ONE JSON
      // envelope on stdout — never the banner + human usage screen — and the
      // failure must flow through the central ChariotError catch below
      // (single emit, honest non-zero exit) instead of process.exit(1).
      if (!json) {
      printHeader();
      console.log(pc.red(`Unknown command: ${command}`));
      console.log();
      console.log('Usage:');
      console.log('  chariot                       Run setup wizard');
      console.log('  chariot serve                 Start MCP server (stdio)');
      console.log('  chariot serve --http [port]   Start MCP server (HTTP/SSE)');
      console.log('  chariot discover              Scan codebase for internal APIs');
      console.log('  chariot discover --rescan     Rescan and show changes');
      console.log('  chariot discover --config f   Non-interactive from config file');
      console.log('  chariot search <term>         Search all available adapters');
      console.log('  chariot add <adapter-id>      Add an adapter');
      console.log('  chariot remove <adapter-id>   Remove an adapter');
      console.log('  chariot list                  List installed adapters');
      console.log('  chariot list <term>           Search adapters by keyword');
      console.log('  chariot health                Check adapter health');
      console.log('  chariot license               Show license status');
      console.log('  chariot license activate <path>  Install a license file from disk');
      console.log('  chariot license renew-now        Force an immediate renew call');
      console.log('  chariot configure             Configure credentials');
      console.log('  chariot audit anchor          RFC-3161 timestamp the current chain head');
      console.log('  chariot vault migrate --tenant <id>|--all [--dry-run]  CH-10 legacy-ciphertext migration (§12.2)');
      console.log('  chariot audit attest          Sign a length attestation for the chain');
      console.log('  chariot audit verify-anchor <tsr>  Verify a .tsr against chain head');
      console.log('  chariot trace explain <traceId> [audit.jsonl]  Step-by-step trace + attribution');
      console.log('  chariot audit verify-length   Detect chain truncation from attestations');
      console.log('  chariot help                  Show help');
      console.log('  chariot capabilities          Print the machine-readable capability manifest');
      console.log();
      }
      throw new ChariotError(fail('cli:unknown-command', 'USAGE_ERROR', {
        exit_code: EXIT.USAGE,
        human_message: `Unknown command: ${command}`,
        remediation: [
          'Run `chariot help` for usage',
          'Run `chariot capabilities` for the machine-readable command manifest',
        ],
      }));
    }
  }
  } catch (err) {
    // CH-31: every typed failure surfaces as ONE envelope (JSON in agent
    // mode, a concise diagnostic otherwise) with the correct exit code — a
    // real failure can never present as exit-0 / ✓.
    if (err instanceof ChariotError) {
      emit(err.envelope, { json });
      return;
    }
    throw err;
  }
}

main().catch((err) => {
  if (agentMode(args)) {
    emit(fail(`cli:${command ?? 'unknown'}`, 'INTERNAL_ERROR', {
      cause: err instanceof Error ? err.message : String(err),
    }), { json: true });
    return;
  }
  console.error(pc.red('Fatal error:'), err);
  process.exit(1);
});
