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
import { signDiscoveredAdapter, defaultEnvelopePaths } from '../discovery/envelope.js';
import {
  cmdHealthCheckAdapter,
  effectiveEnvKeys,
} from '../engine/types/canonical-credentialed-brands.js';
import { createLogger as _mkLog } from '../engine/logger.js';
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
import { homedir } from 'node:os';
import { join } from 'node:path';
import * as p from '@clack/prompts';
import pc from 'picocolors';
import { loadNativeBinding, getBindingLoadError } from '../license/binding.js';
import { validateLicense, revalidateLicense } from '../license/loader.js';
import { activateLicenseFromPath } from '../license/activate.js';
import { renewNow } from '../license/renew-client.js';
import {
  formatStatusLines,
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
import { chariotCatalogEnv, loadChariotMcpRegistry, loadChariotMcpRegistryWithNative, type ChariotRegistryEntry } from '../catalog/artifacts.js';
import {
  CREDENTIAL_VALUE_CONTROL_CHAR_RE,
  EPIC_AI_DIR,
  detectSystem,
  ensureDir,
  loadConfig,
  loadCredentials,
  loadCredentialsFrom,
  loadState,
  readJsonFile,
  removeAdapterState,
  saveConfig,
  saveState,
  upsertAdapterState,
  withLastHealthCheck,
  writeCredential,
  writeMcpConfig,
} from '../cli/index.js';

const args = process.argv.slice(2);
const command = args[0];

// bug-tracker-ref/bug-tracker-ref/bug-tracker-ref: top-level non-interactive mode. Set when the user
// passes --yes / --non-interactive / --accept-defaults OR when stdin is not a
// TTY (piped/redirected). Prompts that read --yes return their initialValue;
// prompts with no safe default exit with code 4 (STDIN_REQUIRED) instead of
// hanging on a closed stdin.
const NON_INTERACTIVE = args.includes('--yes') ||
  args.includes('-y') ||
  args.includes('--non-interactive') ||
  args.includes('--accept-defaults') ||
  process.env.CHARIOT_NON_INTERACTIVE === '1' ||
  (process.stdin && process.stdin.isTTY === false);
process.env.CHARIOT_NON_INTERACTIVE = NON_INTERACTIVE ? '1' : '';

// bug-tracker-ref: @clack spinner redraws via raw ANSI cursor escapes; on a
// non-TTY stdout (pipe / agent / CI) that floods the stream with literal
// escape noise. Use the animated spinner only on a TTY; otherwise a plain shim.
interface SpinnerLike { start: (m?: string) => void; stop: (m?: string) => void; message: (m?: string) => void }
function makeSpinner(pp: { spinner: () => SpinnerLike }): SpinnerLike {
  if (process.stdout.isTTY) return pp.spinner();
  return {
    start: (m?: string) => { if (m) console.log(m); },
    stop: (m?: string) => { if (m) console.log(m); },
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
    child.on('close', (code) => resolve(code ?? 0));
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
  console.log(`    ${pc.cyan('chariot')}                       run the setup wizard`);
  console.log(`    ${pc.cyan('chariot query "<question>"')}    route a question to your adapters`);
  console.log(`    ${pc.cyan('chariot list')}                  show Curated + Custom adapters`);
  console.log(`    ${pc.cyan('chariot search [term]')}         search all available adapters`);
  console.log(`    ${pc.cyan('chariot add <id>')}              add an adapter and enter credentials`);
  console.log(`    ${pc.dim('chariot add <id> --token KEY=VAL [--token …]   non-interactive credential set')}`);
  console.log(`    ${pc.cyan('chariot remove <id>')}           remove an adapter`);
  console.log(`    ${pc.cyan('chariot configure')}             connect your APIs and credentials`);
  console.log(`    ${pc.cyan('chariot health')}                check adapter status`);
  console.log(`    ${pc.cyan('chariot serve')}                 start MCP server over stdio (default)`);
  console.log(`    ${pc.cyan('chariot serve --http [port]')}   start Streamable-HTTP MCP (default 3550)`);
  console.log(`    ${pc.cyan('chariot discover')}              scan codebase for internal APIs`);
  console.log(`    ${pc.cyan('chariot license')}               show license status`);
  console.log(`    ${pc.cyan('chariot approve <id>')}          interactively approve a CLI-bridge adapter (AS §1.5)`);
  console.log(`    ${pc.cyan('chariot approvals')}             list approved CLI adapters`);
  console.log(`    ${pc.cyan('chariot revoke <id>')}           remove a prior CLI adapter approval`);
  console.log(`    ${pc.cyan('chariot audit anchor')}          RFC-3161 timestamp the current chain head`);
  console.log(`    ${pc.cyan('chariot audit attest')}          sign a length attestation for the chain`);
  console.log(`    ${pc.cyan('chariot audit verify-anchor')}   verify a .tsr file against the chain head`);
  console.log(`    ${pc.cyan('chariot audit verify-length')}   detect chain truncation from attestations`);
  console.log(`    ${pc.cyan('chariot help')}                  show this help`);
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

async function cmdList(term?: string): Promise<void> {
  if (term) { await cmdSearch(term); return; }

  const all = loadChariotMcpRegistryWithNative();
  const state = loadState();

  const curatedRows = CHARIOT_CURATED_IDS.map(id => all.find(a => a.id === id)).filter(Boolean) as ChariotRegistryEntry[];
  const customIds = Object.keys(state.adapters).filter(id => !CHARIOT_CURATED_IDS.includes(id));
  const customRows = customIds.map(id => all.find(a => a.id === id) || { id, name: id, type: 'mcp' } as ChariotRegistryEntry);

  console.log('');
  console.log(`  ${pc.bold('Curated')}  ${pc.white(`(${curatedRows.length})`)}  ${pc.white('— open data, no credentials required')}`);
  console.log('');
  for (const a of curatedRows) {
    const toolCount = a.mcp?.toolCount ?? 0;
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
      const toolCount = a.mcp?.toolCount ?? 0;
      const typeLabel = a.type === 'both' ? pc.white('REST+MCP') : pc.white('MCP');
      console.log(`    ${pc.cyan(a.id.padEnd(35))} ${typeLabel}  ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white(truncateDesc(a.description || '', 60))}`);
    }
  }
  console.log('');
}

// ── chariot search ─────────────────────────────────────────────────────────

async function cmdSearch(term?: string): Promise<void> {
  const all = loadChariotMcpRegistryWithNative();
  const state = loadState();

  if (!term) {
    const curatedRows = CHARIOT_CURATED_IDS.map(id => all.find(a => a.id === id)).filter(Boolean) as ChariotRegistryEntry[];
    console.log('');
    console.log(`  ${pc.bold('Curated adapters')}  ${pc.white('— vetted, open data, no credentials required')}`);
    console.log('');
    for (const a of curatedRows) {
      const toolCount = a.mcp?.toolCount ?? 0;
      console.log(`    ${pc.cyan(a.id.padEnd(35))} ${String(toolCount).padStart(3)} ${Number(toolCount) === 1 ? 'tool' : 'tools'}   ${pc.white(truncateDesc(a.description || '', 60))}`);
    }
    console.log('');
    console.log(`  ${pc.white(`Search all ${all.length} available adapters:`)}  ${pc.cyan('chariot search <term>')}`);
    console.log('');
    return;
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
    console.log(`\n  No adapters matched "${term}". Try a broader term.\n`);
    return;
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

  console.log('');
  console.log(`  ${pc.bold(`${results.length} ${results.length === 1 ? 'adapter' : 'adapters'}`)} matching "${term}"${results.length > 20 ? pc.white(' (showing top 20)') : ''}`);
  console.log('');

  for (const a of shown) {
    const toolCount = a.mcp?.toolCount ?? 0;
    const tag = CHARIOT_CURATED_IDS.includes(a.id)
      ? pc.green('curated')
      : customInState.has(a.id)
        ? pc.cyan('configured')
        : pc.white('available');
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

async function cmdAdd(adapterName: string): Promise<void> {
  // Use the native overlay so curated adapters absent from the bundle
  // (bug-tracker-ref: wikipedia removed by catalog purge) are still addable.
  const all = loadChariotMcpRegistryWithNative();

  const match = all.find(a => a.id === adapterName || a.name.toLowerCase() === adapterName.toLowerCase());
  if (!match) {
    const fuzzy = all.filter(a => a.id.includes(adapterName) || a.name.toLowerCase().includes(adapterName.toLowerCase()));
    if (fuzzy.length > 0) {
      console.log(`Adapter "${adapterName}" not found. Did you mean:`);
      fuzzy.slice(0, 5).forEach(a => console.log(`  ${pc.cyan(a.id)} — ${a.name}`));
    } else {
      console.log(`Adapter "${adapterName}" not found. Run ${pc.cyan('chariot search <term>')} to find one.`);
    }
    process.exit(1);
  }

  const s = makeSpinner(p);

  if (match.mcp?.transport === 'stdio' && match.mcp?.args?.[1]) {
    const pkg = match.mcp.args[1];
    s.start(`Installing ${match.name}`);
    // spawnSync array form — no shell metacharacter exposure on `pkg`.
    const r = spawnSync('npm', ['install', '-g', '--ignore-scripts', pkg], {
      stdio: 'pipe', timeout: 60000,
    });
    if (r.error || (r.status !== null && r.status !== 0) || r.signal) {
      s.stop(`${pc.yellow('!')} Install failed — run manually: npm install -g ${pkg}`);
    } else {
      s.stop(`${pc.green('✓')} ${match.name} installed`);
    }
  }

  // Single source of truth — same predicate consumed by cmdHealth, by
  // ChariotState.getConfiguredAdapterIds, by setup.ts, and by
  // RegistryLoader.buildMCPConnection. Splitting the derivation across
  // files re-introduced the round-1 split-brain.
  const declaredEnvKeys = effectiveEnvKeys(match);

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
        console.error(pc.red(`STDIN_REQUIRED: chariot add ${match.id} needs credentials: ${missing.join(', ')}`));
        console.error(pc.dim(`Set them in ~/.epic-ai/.env or export as environment variables, then re-run.`));
        process.exit(4);
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

  const state = loadState();
  saveState(upsertAdapterState(state, match.id, {
    type: match.type || 'mcp',
    status: 'configured',
    toolCount: match.mcp?.toolCount || 0,
    lastVerified: null,
  }));

  const config = loadConfig() || { selectedAdapters: [], secretsProvider: 'manual', aiClient: 'unknown' };
  if (!config.selectedAdapters.includes(match.id)) config.selectedAdapters.push(match.id);
  saveConfig(config);

  // bug-tracker-ref: print the persisted adapter id (not the npm package name)
  // so the customer sees the same identifier `chariot remove <id>` /
  // `chariot health` will use. Show the package name parenthetically.
  const pkgDisplay = match.name !== match.id ? pc.dim(` (${match.name})`) : '';
  console.log(`${pc.green('✓')} ${match.id} added to Chariot.${pkgDisplay}`);
}

// ── chariot remove ─────────────────────────────────────────────────────────

async function cmdRemove(adapterName: string): Promise<void> {
  const state = loadState();
  const config = loadConfig();

  if (!state.adapters[adapterName]) {
    console.log(`Adapter "${adapterName}" is not configured.`);
    process.exit(1);
  }

  saveState(removeAdapterState(state, adapterName));

  if (config) {
    config.selectedAdapters = config.selectedAdapters.filter(id => id !== adapterName);
    saveConfig(config);
  }

  console.log(`${pc.green('✓')} ${adapterName} removed from Chariot.`);
  console.log(`${pc.white('  Note: credentials in ~/.epic-ai/.env and MCP client configs are not removed.')}`);
  console.log(`${pc.white('  Clean those manually if needed.')}`);
}

// ── chariot health ─────────────────────────────────────────────────────────

async function cmdHealth(): Promise<void> {
  const state = loadState();
  const creds = loadCredentials();
  const all = loadChariotMcpRegistryWithNative();

  // bug-tracker-ref: `chariot health` must report on the SAME adapter set
  // `chariot list` shows — that is, curated (always-on, no creds
  // required) PLUS custom (user-added via `chariot add`). Earlier
  // code iterated only Object.keys(state.adapters), which omits
  // curated rows that aren't explicitly added, producing a misleading
  // "2 healthy" while `chariot list` showed 3 curated + 2 custom = 5.
  const customIds = Object.keys(state.adapters).filter(id => !CHARIOT_CURATED_IDS.includes(id));
  const configured = [...CHARIOT_CURATED_IDS, ...customIds];
  if (configured.length === 0) {
    console.log(`No adapters configured. Run ${pc.cyan('chariot')} to set up.`);
    return;
  }

  const s = makeSpinner(p);
  s.start(`Checking ${configured.length} adapters`);

  const results: string[] = [];
  let healthy = 0;
  let issues = 0;

  for (const id of configured) {
    const adapter = all.find(a => a.id === id);
    if (!adapter) {
      results.push(`${pc.red('✗')} ${id} — not found in catalog`);
      issues++;
      continue;
    }

    // cmdHealthCheckAdapter is the shared
    // health-decision helper. setup.ts cmdHealth uses the same call —
    // the two surfaces cannot diverge on credential resolution.
    const isCurated = CHARIOT_CURATED_IDS.includes(id);
    const { healthy: hasKey, missingKey } = cmdHealthCheckAdapter(adapter, creds, isCurated);

    if (isCurated || hasKey) {
      // bug-tracker-ref: curated rows have no state.adapters entry; fall back
      // to catalog-derived tool count + 'curated' label so the line
      // renders correctly for both curated and custom.
      const stateEntry = state.adapters[id];
      const toolCount = stateEntry?.toolCount ?? adapter.mcp?.toolCount ?? 0;
      const label = isCurated ? 'curated' : (stateEntry?.status ?? 'configured');
      results.push(`${pc.green('✓')} ${adapter.id}  ${toolsLabel(toolCount)}  ${label}`);
      healthy++;
    } else {
      // bug-tracker-ref: render canonical adapter id (what `chariot list`
      // prints) here too, not adapter.name (npm package name); the
      // two surfaces MUST share the same identifier.
      results.push(`${pc.yellow('!')} ${adapter.id}  missing ${missingKey || 'credentials'}`);
      issues++;
    }
  }

  s.stop('Health check complete');

  p.note(results.join('\n'), `${healthy} healthy, ${issues} need attention`);

  saveState(withLastHealthCheck(state, new Date().toISOString()));
}

// ── chariot configure ──────────────────────────────────────────────────────

async function cmdConfigure(): Promise<void> {
  // bug-tracker-ref: configure is fully interactive — no --config alternative exists yet.
  // Fail fast in non-interactive mode rather than hanging on stdin.
  if (NON_INTERACTIVE) {
    console.error(pc.red('STDIN_REQUIRED: chariot configure is interactive.'));
    console.error(pc.dim('Use `chariot add <id>` per adapter with credentials in ~/.epic-ai/.env, or `chariot discover --config <file>`.'));
    process.exit(4);
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
        toolCount: m.adapter.mcp?.toolCount || 0,
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
 * Step-by-step trace breakdown + optional LLM-driven attribution scorer.
 *
 * Reads the JSONL audit chain at the standard location (or a supplied path),
 * filters records where `traceId === <id>`, sorts by sequenceNumber, prints a
 * human-readable per-step summary, and — when at least one judge API key is
 * present — invokes `scripts/attribute-trace.mjs` to attribute the failure to
 * a specific stepId via the ensemble panel.
 */
async function cmdTraceExplain(traceId: string | undefined, auditFileArg: string | undefined): Promise<void> {
  if (!traceId) {
    console.error(pc.red('Usage: chariot trace explain <traceId> [audit.jsonl]'));
    console.error(pc.dim('  traceId    UUID v4 to filter on'));
    console.error(pc.dim('  audit.jsonl (optional) explicit audit-chain file; defaults to .chariot/audit/chain.jsonl'));
    process.exit(2);
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const auditFile = auditFileArg ?? path.resolve(process.cwd(), '.chariot/audit/chain.jsonl');
  if (!fs.existsSync(auditFile)) {
    console.error(pc.red(`Audit file not found: ${auditFile}`));
    console.error(pc.dim('  Export with: chariot audit export --format jsonl'));
    process.exit(1);
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
      console.error(pc.red(`JSONL parse error: ${(err as Error).message}`));
      process.exit(1);
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
    console.error(pc.red(`No records found for traceId=${traceId}`));
    process.exit(1);
  }

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
      const trimmed = out.length > 160 ? out.slice(0, 160) + '…' : out;
      console.log(pc.dim(`         output: ${trimmed}`));
    }
  }

  // ── Optional LLM-driven attribution scorer ─────────────────────────────
  const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;
  const hasOpenAI = !!process.env.OPENAI_API_KEY;
  if (!hasAnthropic && !hasOpenAI) {
    console.log('');
    console.log(pc.dim('Attribution scorer skipped — no ANTHROPIC_API_KEY or OPENAI_API_KEY in env.'));
    console.log(pc.dim('  Set one to enable the ensemble panel attribution step.'));
    process.exit(0);
  }

  console.log('');
  console.log(pc.dim('Running ensemble attribution scorer…'));
  const child = await import('node:child_process');
  const url = await import('node:url');
  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const scorerPath = path.resolve(here, '..', '..', 'scripts', 'attribute-trace.mjs');
  if (!fs.existsSync(scorerPath)) {
    console.error(pc.red(`Attribution scorer not found at ${scorerPath}`));
    process.exit(1);
  }
  const result = child.spawnSync('node', [scorerPath, auditFile, traceId], {
    stdio: ['ignore', 'pipe', 'inherit'],
    env: process.env,
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  const scorerOut = result.stdout?.toString() ?? '';
  let parsed: { attributedStepId?: string | null; errorKind?: string; confidence?: number; agreeingJudges?: number; totalJudges?: number } = {};
  try {
    parsed = JSON.parse(scorerOut);
  } catch (err) {
    console.error(pc.red(`Failed to parse scorer output: ${(err as Error).message}`));
    console.error(scorerOut);
    process.exit(1);
  }
  console.log('');
  console.log(pc.bold('Attribution scorer output:'));
  console.log(`  Attributed step: ${parsed.attributedStepId ?? pc.yellow('(no clear winner)')}`);
  console.log(`  Error kind:      ${parsed.errorKind ?? 'unknown'}`);
  if (typeof parsed.confidence === 'number') {
    console.log(`  Confidence:      ${parsed.confidence.toFixed(2)} (${parsed.agreeingJudges}/${parsed.totalJudges} judges agreed)`);
  }
  process.exit(0);
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

async function cmdApprove(adapterId: string): Promise<void> {
  if (NON_INTERACTIVE) {
    console.error(pc.red('STDIN_REQUIRED: `chariot approve` requires an interactive operator.'));
    console.error(pc.dim('Approval is a human-operator decision per Adapter Standard §1.5; --yes / env-var bypass is not permitted.'));
    process.exit(4);
  }
  if (!process.stdin.isTTY) {
    console.error(pc.red('STDIN_REQUIRED: `chariot approve` requires a TTY for the interactive confirmation prompt.'));
    process.exit(4);
  }

  // Resolve the adapter against the loaded bundle catalog. Imports are
  // dynamic so the bundle-load path (which pulls in heavy engine modules)
  // does not run for every chariot invocation.
  const { loadAllAdapters } = await import('../engine/server/ChariotState.js');
  const adapters = await loadAllAdapters();
  const adapter = adapters.find((a) => a.id === adapterId);
  if (!adapter) {
    console.error(pc.red(`Unknown adapter: ${adapterId}`));
    console.error(pc.dim('Run `chariot list` to see installed adapters.'));
    process.exit(2);
  }
  if (adapter.type !== 'cli-bridge' || !adapter.cli?.binary) {
    console.error(pc.red(`Adapter ${adapterId} is not a CLI-bridge adapter (type=${adapter.type}).`));
    console.error(pc.dim('`chariot approve` applies only to cli-bridge adapters per AS §1.5.'));
    process.exit(2);
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
    return;
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
}

async function cmdRevoke(adapterId: string): Promise<void> {
  const ok = revokeAdapterApproval(adapterId);
  if (ok) {
    _cliApprovalLog.info('cli_approval_revoked', {
      adapter_id: adapterId,
      revoked_at: new Date().toISOString(),
    });
  }
  console.log('');
  if (ok) {
    console.log(pc.green(`  ✓ Revoked approval for ${adapterId}`));
    console.log(pc.dim('    Subsequent CLI tool calls for this adapter will return CLI_APPROVAL_REQUIRED.'));
  } else {
    console.log(pc.dim(`  No active approval for ${adapterId} (nothing to revoke).`));
  }
  console.log('');
}

async function cmdApprovals(): Promise<void> {
  const approvals = listApprovedAdapters();
  console.log('');
  if (approvals.length === 0) {
    console.log(pc.dim('  No CLI adapters approved. Run `chariot approve <adapter-id>` to approve one.'));
    console.log('');
    return;
  }
  console.log(`  ${pc.bold('Approved CLI adapters:')}`);
  console.log('');
  for (const a of approvals) {
    console.log(`    ${pc.cyan(a.id.padEnd(30))} ${pc.dim(a.type.padEnd(12))} ${a.approvedAt}`);
  }
  console.log('');
}

async function cmdResume(traceId: string | undefined): Promise<void> {
  if (!traceId || traceId.length === 0) {
    console.error(pc.red('Usage: chariot resume <traceId>'));
    console.error(pc.dim('  traceId    UUID or arbitrary trace identifier to look up'));
    process.exit(2);
  }
  if (traceId.length > 256) {
    console.error(pc.red(`traceId too long: ${traceId.length} chars (max 256)`));
    process.exit(2);
  }
  const dbPath = process.env.CHARIOT_SQLITE_PATH ?? join(EPIC_AI_DIR, 'chariot.db');
  // No existence check: SqliteCheckpointStore creates the database
  // and schema on construct. If the DB is missing or empty (fresh
  // install, rotated path, deleted file), the latest() call below
  // returns undefined and prints the "no checkpoints found" path —
  // same outcome as a known-but-empty trace.
  const { SqliteCheckpointStore } = await import('../engine/recovery/SqliteCheckpointStore.js');
  const store = new SqliteCheckpointStore(dbPath);
  const tenantId = process.env.CHARIOT_TENANT_ID ?? 'local';
  try {
    const latest = await store.latest(tenantId, traceId);
    if (!latest) {
      console.log(pc.yellow(`No checkpoints found for traceId: ${traceId}`));
      process.exit(1);
    }
    console.log(pc.bold(`Latest checkpoint for ${traceId}:`));
    console.log(`  stepId:        ${latest.stepId}`);
    console.log(`  parentStepId:  ${latest.parentStepId ?? pc.dim('(root)')}`);
    console.log(`  iteration:     ${latest.iteration}`);
    console.log(`  toolName:      ${latest.toolName ?? pc.dim('(none)')}`);
    console.log(`  serverName:    ${latest.serverName ?? pc.dim('(none)')}`);
    console.log(`  timestamp:     ${latest.timestamp.toISOString()}`);
    console.log(`  input:         ${JSON.stringify(latest.input)}`);
    console.log(`  output:        ${JSON.stringify(latest.output)}`);
    process.exit(0);
  } finally {
    store.close();
  }
}

async function cmdAudit(): Promise<void> {
  const { CHARIOT_ERROR_CODES } = await import('../engine/types/index.js');
  const sub = args[1];

  // ── Resolve packageRoot and chainId ─────────────────────────────────────

  const chainIdFlag = args.indexOf('--chain-id');
  const chainId: string =
    chainIdFlag !== -1 && args[chainIdFlag + 1]
      ? args[chainIdFlag + 1]
      : (process.env.CHARIOT_CHAIN_ID ?? 'default');

  const packageRoot = EPIC_AI_DIR;
  const chainFile = join(packageRoot, 'audit', `${chainId}.jsonl`);

  // ── chariot audit anchor ─────────────────────────────────────────────────

  if (sub === 'anchor') {
    const { anchorChainHead } = await import('../engine/audit/anchor.js');
    const { HashChain } = await import('../engine/audit/HashChain.js');

    const tsaUrl = process.env.CHARIOT_TSA_URL;
    if (!tsaUrl) {
      console.error(
        `error code=${CHARIOT_ERROR_CODES.TSA_NOT_CONFIGURED} CHARIOT_TSA_URL is not set`,
      );
      process.exit(1);
    }

    const { headHash: headHex } = await readChainState(chainFile);
    if (!headHex || headHex.length !== 64) {
      console.error(`error chain file not found or empty: ${chainFile}`);
      process.exit(1);
    }
    const headBuf = Buffer.from(headHex, 'hex');

    const result = await anchorChainHead({
      chainId,
      headHash: headBuf,
      packageRoot,
      tsaUrl,
    }).catch((err: Error) => {
      console.error(`error ${err.message}`);
      process.exit(1);
    });

    const chain = new HashChain();
    chain.recordAnchor(headBuf, new Date(result.anchoredAt));

    const tsaHost = new URL(tsaUrl).host;
    const shortHash = headHex.slice(0, 8);
    console.log(
      `anchored chain=${chainId} head=${shortHash} tsa=${tsaHost} tsr=${result.tsrPath}`,
    );
    process.exit(0);
  }

  // ── chariot audit attest ─────────────────────────────────────────────────

  if (sub === 'attest') {
    const { signLengthAttestation, persistAttestation } = await import(
      '../engine/audit/length-attestation.js'
    );
    const { HashChain } = await import('../engine/audit/HashChain.js');

    const privateKeyPem = process.env.CHARIOT_AUDIT_SIGNING_KEY;
    if (!privateKeyPem) {
      console.error(
        'error CHARIOT_AUDIT_SIGNING_KEY is not set — ' +
          'supply the Ed25519 private key PEM for length attestation signing',
      );
      process.exit(1);
    }

    const { length, headHash: headHex } = await readChainState(chainFile);
    if (length === 0 && !headHex) {
      console.error(`error chain file not found or empty: ${chainFile}`);
      process.exit(1);
    }

    const attestedAt = new Date().toISOString();
    let attestation;
    try {
      attestation = signLengthAttestation(
        {
          schemaVersion: 1,
          chainId,
          length,
          headHash: headHex,
          attestedAt,
        },
        privateKeyPem,
      );
    } catch (err) {
      console.error(`error ${(err as Error).message}`);
      process.exit(1); return;
    }

    let attPath;
    try {
      attPath = persistAttestation(packageRoot, attestation);
    } catch (err) {
      console.error(`error ${(err as Error).message}`);
      process.exit(1); return;
    }

    const chain = new HashChain();
    chain.recordLengthAttestation(length);

    const shortHash = headHex ? headHex.slice(0, 8) : '(empty)';
    console.log(
      `attested chain=${chainId} length=${length} head=${shortHash} path=${attPath}`,
    );
    process.exit(0);
  }

  // ── chariot audit verify-anchor ──────────────────────────────────────────

  if (sub === 'verify-anchor') {
    const { verifyAnchor } = await import('../engine/audit/anchor.js');

    const tsrPath = args[2];
    if (!tsrPath) {
      console.error('Usage: chariot audit verify-anchor <tsrPath> [--cert <pem>]');
      process.exit(2);
    }

    const certFlag = args.indexOf('--cert');
    const certPath = certFlag !== -1 ? args[certFlag + 1] : undefined;
    const certPem = certPath ? readFileSync(certPath, 'utf-8') : undefined;

    const { headHash: headHex } = await readChainState(chainFile);
    if (!headHex || headHex.length !== 64) {
      console.error(`error chain file not found or empty: ${chainFile}`);
      process.exit(1);
    }
    const headBuf = Buffer.from(headHex, 'hex');

    const result = verifyAnchor(headBuf, tsrPath, certPem);
    console.log(`valid=${result.valid} reason=${result.reason ?? 'ok'}${result.code ? ` code=${result.code}` : ''}`);
    process.exit(result.valid ? 0 : 1);
  }

  // ── chariot audit verify-length ──────────────────────────────────────────

  if (sub === 'verify-length') {
    const { loadAttestations, detectTruncation } = await import(
      '../engine/audit/length-attestation.js'
    );

    const { length } = await readChainState(chainFile);
    const attestations = loadAttestations(packageRoot, chainId);
    const { truncated, lastAttestedLength } = detectTruncation(length, attestations);

    if (truncated) {
      console.log(`truncated=true lastAttestedLength=${lastAttestedLength}`);
      console.error(`code=${CHARIOT_ERROR_CODES.CHAIN_TRUNCATION_DETECTED}`);
      process.exit(1);
    }

    console.log(`truncated=false length=${length}`);
    process.exit(0);
  }

  // ── Unknown audit subcommand ─────────────────────────────────────────────

  console.error(pc.red(`Unknown subcommand: chariot audit ${sub ?? ''}`));
  console.error(
    pc.dim(
      'Valid: chariot audit [anchor|attest|verify-anchor <tsr>|verify-length] [--chain-id <id>]',
    ),
  );
  process.exit(2);
}

// ── chariot setup wizard ───────────────────────────────────────────────────

async function runSetupWizard(): Promise<void> {
  const allAdapters = loadChariotMcpRegistryWithNative();
  const totalTools = allAdapters.reduce((sum, a) => sum + (a.mcp?.toolCount ?? 0), 0);

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
      message: 'Configure Chariot for these AI clients? (Space to toggle, Enter to confirm)',
      options: clientOptions,
      initialValues: detectedClients.map(c => c.id),
      required: false,
    });
    if (p.isCancel(selectedClients)) { p.cancel('Setup cancelled.'); process.exit(0); }

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
        const result = writeMcpConfig(client, { command: 'npx', args: ['@epicai/chariot', 'serve'] });
        if (result.success) {
          writeResults.push(result.error === 'already configured'
            ? `${pc.green('✓')} ${client.name} — already configured`
            : `${pc.green('✓')} ${client.name} — configured`);
          configuredClients.push(clientId);
        } else {
          writeResults.push(`${pc.yellow('!')} ${client.name} — ${result.error}`);
        }
      } else {
        const serverEntry = { chariot: { command: 'npx', args: ['@epicai/chariot', 'serve'] } };
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
  const raw: unknown = JSON.parse(readFileSync(configPath, 'utf-8'));
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

async function runDiscover(): Promise<void> {
  printHeader();

  const rescan = args.includes('--rescan');
  const configFlag = args.indexOf('--config');
  const configFilePath = configFlag !== -1 ? args[configFlag + 1] : null;
  const nonInteractive = configFilePath != null;

  // ── Step 1: Determine codebase path ─────────────────────────────────────

  let codebasePath: string;

  if (configFilePath) {
    if (!existsSync(configFilePath)) {
      p.log.error(`Config file not found: ${configFilePath}`);
      process.exit(1);
    }
    const cfg = loadDiscoveryConfig(configFilePath);
    codebasePath = cfg.codebasePath;
    p.log.info(`Using config: ${configFilePath}`);
  } else {
    const positional = args.find(a => a !== 'discover' && a !== '--rescan' && a !== '--config');
    if (positional) {
      codebasePath = positional;
    } else if (NON_INTERACTIVE) {
      // bug-tracker-ref: positional [path] is documented; in non-interactive mode we
      // refuse to fall through to the stdin prompt and instead error cleanly.
      console.error(pc.red('STDIN_REQUIRED: chariot discover needs a path or --config <file>.'));
      console.error(pc.dim('Usage: chariot discover ./src   or   chariot discover --config ./chariot-discover.json'));
      process.exit(4);
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

  const result = discover(canonicalPath);

  s.stop(
    pc.green(`${result.services.length} services`) +
    pc.dim(' with ') +
    pc.green(`${result.totalEndpoints} endpoints`) +
    pc.dim(` discovered in ${result.scanDurationMs}ms`),
  );

  if (result.services.length === 0) {
    console.log();
    p.log.warn('No APIs found.');
    console.log(pc.dim('  Supported: OpenAPI specs (.json/.yaml), Express.js routes.'));
    console.log(pc.dim('  Make sure your codebase path contains API definitions or route files.'));
    console.log();
    return;
  }

  // ── Step 3: Rescan diff (if applicable) ─────────────────────────────────

  const scanFilePath = getScanFilePath(canonicalPath);
  if (rescan && existsSync(scanFilePath)) {
    const previousScan = JSON.parse(readFileSync(scanFilePath, 'utf-8')) as DiscoveryScanRecord;
    const diff = computeRescanDiff(previousScan, result, canonicalPath);

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
    if (diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0) {
      p.log.info('No changes detected. Your adapters are up to date.');
      return;
    }
    console.log();
  }

  // ── Step 4: Service overview ────────────────────────────────────────────

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

  // ── Step 5: Select services ─────────────────────────────────────────────

  const cfgFile = configFilePath ? loadDiscoveryConfig(configFilePath) : null;

  let selectedServices: DiscoveredService[];

  if (nonInteractive && cfgFile) {
    // Non-interactive: explicit allowlist only — services must have include: true
    selectedServices = filterAllowlist(result.services, cfgFile.services, canonicalPath) as DiscoveredService[];
    if (selectedServices.length === 0) {
      p.log.error('No services matched the config allowlist. Nothing to register.');
      p.log.info('Each service in the config must have "include": true to be exposed.');
      process.exit(1);
    }
    p.log.info(`Non-interactive: ${selectedServices.length} services selected from config allowlist.`);
  } else {
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
      p.log.info('No services selected. Nothing to configure.');
      return;
    }

    selectedServices = (selectedIndices as number[]).map(i => result.services[i]);
  }

  // ── Step 6: Batch defaults ──────────────────────────────────────────────

  let defaultBaseUrl: string | undefined;
  let defaultAuthType: string | undefined;
  let defaultAuthEnvKey: string | undefined;

  if (cfgFile?.defaults) {
    defaultBaseUrl = cfgFile.defaults.baseUrl;
    defaultAuthType = cfgFile.defaults.authType;
    defaultAuthEnvKey = cfgFile.defaults.authEnvKey;
  } else if (selectedServices.length > 1) {
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
      if (!baseUrl) {
        p.log.error(`No baseUrl for service "${service.name}" — set it in config defaults or per-service override.`);
        process.exit(1);
      }
      if (!authType) {
        p.log.error(`No authType for service "${service.name}" — set it in config defaults or per-service override.`);
        process.exit(1);
      }
      if (authType !== 'none' && !authEnvKey) {
        p.log.error(`Service "${service.name}" requires auth (${authType}) but no authEnvKey is set in config defaults or per-service override.`);
        process.exit(1);
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

  printServiceTable(configured.map(c => ({
    name: c.service.name,
    framework: c.service.framework,
    endpoints: c.regularEndpoints.length,
    excluded: c.adminEndpoints.length,
    baseUrl: c.baseUrl,
    authType: c.authType,
  })));

  const totalEndpoints = configured.reduce((sum, c) => sum + c.regularEndpoints.length, 0);
  const totalExcluded = configured.reduce((sum, c) => sum + c.adminEndpoints.length, 0);

  console.log(
    pc.dim('  Total: ') +
    pc.bold(`${configured.length} services`) +
    pc.dim(', ') +
    pc.green(`${totalEndpoints} endpoints exposed`) +
    (totalExcluded > 0 ? pc.dim(', ') + pc.yellow(`${totalExcluded} excluded`) : ''),
  );
  console.log();

  // ── Step 9: Confirmation ────────────────────────────────────────────────

  if (!nonInteractive) {
    const proceed = await p.confirm({
      message: 'Register these services? Your AI will be able to query them.',
      initialValue: true,
    });
    if (p.isCancel(proceed) || !proceed) {
      p.log.info('Discovery cancelled. No changes made.');
      return;
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

    // Write signed adapter definition.
    const adapterDefPath = join(DISCOVERED_DIR, `${serviceRecord.serviceId}.json`);
    const signed = signDiscoveredAdapter({
      id: adapterId,
      name: c.service.name,
      framework: c.service.framework,
      baseUrl: c.baseUrl,
      authType: c.authType,
      authEnvKey: resolvedAuthEnvKey,
      endpoints: c.regularEndpoints,
      discoveredAt: serviceRecord.approvedAt,
    }, defaultEnvelopePaths(EPIC_AI_DIR));
    writeFileSync(adapterDefPath, JSON.stringify(signed, null, 2));
  }

  // Persist scan record
  writeFileSync(getScanFilePath(canonicalPath), JSON.stringify(scanRecord, null, 2));

  sp.stop(pc.green('Done'));

  // ── Step 11: Final summary ──────────────────────────────────────────────

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
  if (httpIdx >= 0 && isValidPort(argv[httpIdx + 1])) port = Number(argv[httpIdx + 1]);
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

async function main(): Promise<void> {
  switch (command) {
    case 'discover':
      await runDiscover();
      break;

    case 'license': {
      const sub = args[1];
      if (!sub || sub === 'status') {
        runLicense();
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
      await cmdServeStopOrStatus(['serve', '--status']);
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
      // bug-tracker-ref: standard --version / -v / version subcommand.
      // Read package.json synchronously — no network, no child process.
      const { readFileSync } = await import('node:fs');
      const { fileURLToPath } = await import('node:url');
      const { dirname, resolve } = await import('node:path');
      const here = dirname(fileURLToPath(import.meta.url));
      const pkgPath = resolve(here, '..', '..', 'package.json');
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };
      console.log(pkg.version);
      break;
    }

    case 'list':
      await cmdList(args[1]);
      break;

    case 'search':
      await cmdSearch(args[1]);
      break;

    case 'add':
      if (!args[1]) { console.error('Usage: chariot add <adapter-id>  (run "chariot search <term>" to find one)'); process.exit(1); }
      await cmdAdd(args[1]);
      break;

    case 'remove':
      if (!args[1]) { console.error('Usage: chariot remove <adapter-id>'); process.exit(1); }
      await cmdRemove(args[1]);
      break;

    case 'health':
      await cmdHealth();
      break;

    case 'configure':
      await cmdConfigure();
      break;

    case 'audit':
      await cmdAudit();
      break;

    case 'approve':
      if (!args[1]) {
        console.error('Usage: chariot approve <adapter-id>');
        process.exit(1);
      }
      await cmdApprove(args[1]);
      break;

    case 'approvals':
      await cmdApprovals();
      break;

    case 'revoke':
      if (!args[1]) {
        console.error('Usage: chariot revoke <adapter-id>');
        process.exit(1);
      }
      await cmdRevoke(args[1]);
      break;

    case 'resume':
 // `chariot resume <traceId>` reads the latest
      // checkpoint from the SQLite checkpoint store.
      await cmdResume(args[1]);
      break;

    case 'trace': {
      const sub = args[1];
      if (sub === 'explain') {
        await cmdTraceExplain(args[2], args[3]);
      } else {
        console.error(pc.red(`Unknown subcommand: chariot trace ${sub ?? '(none)'}`));
        console.error(pc.dim('Valid: chariot trace explain <traceId> [auditFile.jsonl]'));
        process.exit(2);
      }
      break;
    }

    case undefined:
      if (NON_INTERACTIVE) {
        console.error(pc.red('STDIN_REQUIRED: setup wizard cannot run non-interactively.'));
        console.error(pc.dim('Use specific commands instead: chariot add <id>, chariot configure --config <file>, chariot discover --config <file>.'));
        process.exit(4);
      }
      await runSetupWizard();
      break;

    default:
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
      console.log('  chariot audit attest          Sign a length attestation for the chain');
      console.log('  chariot audit verify-anchor <tsr>  Verify a .tsr against chain head');
      console.log('  chariot trace explain <traceId> [audit.jsonl]  Step-by-step trace + attribution');
      console.log('  chariot audit verify-length   Detect chain truncation from attestations');
      console.log('  chariot help                  Show help');
      console.log();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(pc.red('Fatal error:'), err);
  process.exit(1);
});
