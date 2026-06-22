/**
 * @epicai/chariot — Setup wizard pre-install + pre-warm (Phase R.7)
 *
 * Implements `chariot setup --pre-install` per the review-approved design at
 * docs/setup-wizard-pre-install-design-may-2026.md (repo-relative).
 *
 * Three groups, in order:
 *   1. CLI binaries  — serial within group; per-binary 10min timeout
 *   2. npx warmup    — memory-bounded concurrency (≤8, see warmConcurrency); per-package 60s timeout
 *   3. uvx warmup    — memory-bounded concurrency (≤8, see warmConcurrency); per-package 120s timeout
 *
 * Outputs ~/.epic-ai/setup-manifest.json (mode 0644) for `chariot health`.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { existsSync, readFileSync, writeFileSync, chmodSync, readdirSync, createReadStream } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AdapterEntry } from '../server/ChariotState.js';
import type { AuditTrail } from '../audit/AuditTrail.js';
import { findOnPath, EPIC_AI_DIR, ensureDir } from '../../cli/paths.js';
import { runConcurrent, warmConcurrency, extractStdioPackageName } from './concurrency.js';

export type Host = 'darwin' | 'debian' | 'rhel' | 'arch' | 'win32' | 'unsupported';
type Manager = 'brew' | 'apt' | 'dnf' | 'pacman' | 'winget' | 'manual';

type Status =
  | 'OK' | 'INSTALLED' | 'FAILED'
  | 'SKIP_HOST_UNSUPPORTED' | 'SKIP_UNKNOWN_PACKAGE' | 'SKIP_MANUAL'
  | 'WARMED' | 'NOT_FOUND' | 'SKIP_NO_UVX_TOOL'
  | 'DRY_RUN'
 // supply-chain integrity gates
  | 'INTEGRITY_UNPINNED'  // bundle row missing version or integrityShasum — install refused
  | 'INTEGRITY_MISMATCH'; // tarball/wheel digest does not match bundle-pinned SHA — install refused

interface CliBinaryStatus { status: Status; path?: string; installCommand?: string; detail?: string; }
interface PackageStatus { status: Status; detail?: string; }
interface Manifest {
  version: 1;
  ranAt: string;
  host: { platform: NodeJS.Platform; arch: string; packageManager: Manager | 'none' };
  cliBinaries: Record<string, CliBinaryStatus>;
  npxPackages: Record<string, PackageStatus>;
  uvxPackages: Record<string, PackageStatus>;
  summary: { totals: Record<string, number> };
}

const MANIFEST_PATH = join(EPIC_AI_DIR, 'setup-manifest.json');

// ── Host detection (§4.1) ─────────────────────────────────────────────────

export function detectHost(): Host {
  if (process.platform === 'darwin') return 'darwin';
  if (process.platform === 'win32') return 'win32';
  if (process.platform !== 'linux') return 'unsupported';
  try {
    const os = readFileSync('/etc/os-release', 'utf-8');
    const idMatch = /^ID=("?)([^"\n]+)\1$/m.exec(os);
    const likeMatch = /^ID_LIKE=("?)([^"\n]+)\1$/m.exec(os);
    const id = idMatch?.[2] ?? '';
    const like = likeMatch?.[2] ?? '';
    if (id === 'debian' || id === 'ubuntu' || like.includes('debian')) return 'debian';
    if (id === 'fedora' || id === 'rhel' || id === 'centos' || like.includes('rhel') || like.includes('fedora')) return 'rhel';
    if (id === 'arch' || like.includes('arch')) return 'arch';
  } catch { /* file missing */ }
  return 'unsupported';
}

function hostPackageManager(host: Host): Manager | 'none' {
  switch (host) {
    case 'darwin': return 'brew';
    case 'debian': return 'apt';
    case 'rhel': return 'dnf';
    case 'arch': return 'pacman';
    case 'win32': return 'winget';
    default: return 'none';
  }
}

// ── Per-binary install target (§4.2) ──────────────────────────────────────

type FallbackEntry =
  | { manager: 'brew' | 'apt' | 'dnf' | 'pacman' | 'winget'; package: string }
  | { manager: 'manual'; hint: string }
  | null;

// Tier 2: hardcoded 5-CLI fallback (§4.2 table)
const TIER2_FALLBACK: Record<string, Record<Host, FallbackEntry>> = {
  gh: {
    darwin: { manager: 'brew', package: 'gh' },
    debian: { manager: 'apt', package: 'gh' },
    rhel:   { manager: 'dnf', package: 'gh' },
    arch:   { manager: 'pacman', package: 'github-cli' },
    win32:  { manager: 'winget', package: 'GitHub.cli' },
    unsupported: null,
  },
  aws: {
    darwin: { manager: 'brew', package: 'awscli' },
    debian: { manager: 'apt', package: 'awscli' },
    rhel:   { manager: 'dnf', package: 'awscli' },
    arch:   { manager: 'pacman', package: 'aws-cli' },
    win32:  { manager: 'winget', package: 'Amazon.AWSCLI' },
    unsupported: null,
  },
  gcloud: {
    darwin: { manager: 'brew', package: '--cask google-cloud-sdk' },
    debian: { manager: 'apt', package: 'google-cloud-cli' },
    rhel:   { manager: 'dnf', package: 'google-cloud-cli' },
    arch:   { manager: 'pacman', package: 'google-cloud-sdk' },
    win32:  { manager: 'winget', package: 'Google.CloudSDK' },
    unsupported: null,
  },
  az: {
    darwin: { manager: 'brew', package: 'azure-cli' },
    debian: { manager: 'apt', package: 'azure-cli' },
    rhel:   { manager: 'dnf', package: 'azure-cli' },
    arch:   { manager: 'pacman', package: 'azure-cli' },
    win32:  { manager: 'winget', package: 'Microsoft.AzureCLI' },
    unsupported: null,
  },
  stripe: {
    darwin: { manager: 'brew', package: 'stripe/stripe-cli/stripe' },
    debian: { manager: 'manual', hint: 'See https://stripe.com/docs/stripe-cli for the official install script.' },
    rhel:   { manager: 'manual', hint: 'See https://stripe.com/docs/stripe-cli for the official install script.' },
    arch:   { manager: 'manual', hint: 'AUR: stripe-cli (yay -S stripe-cli) or see https://stripe.com/docs/stripe-cli.' },
    win32:  { manager: 'winget', package: 'Stripe.StripeCLI' },
    unsupported: null,
  },
};

type ResolvedTarget =
  | { kind: 'install'; manager: Manager; package: string }
  | { kind: 'manual'; hint: string }
  | { kind: 'unknown' };

function resolveInstallTarget(adapter: AdapterEntry, binary: string, host: Host): ResolvedTarget {
  if (host === 'unsupported') return { kind: 'unknown' };
  // Tier 1: schema-declared cli.installTargets on the adapter.
  const targets = adapter.cli?.installTargets;
  if (targets) {
    const key = host as Exclude<Host, 'unsupported'>;
    const entry = targets[key];
    if (entry) {
      if (entry.manager === 'manual') return { kind: 'manual', hint: entry.hint };
      return { kind: 'install', manager: entry.manager, package: entry.package };
    }
  }
  // Tier 2: hardcoded fallback for the 5 GT-anchored CLIs.
  const fallback = TIER2_FALLBACK[binary]?.[host];
  if (fallback) {
    if (fallback.manager === 'manual') return { kind: 'manual', hint: fallback.hint };
    return { kind: 'install', manager: fallback.manager, package: fallback.package };
  }
  return { kind: 'unknown' };
}

// ── Install command construction (§4.3) ───────────────────────────────────

function buildInstallArgv(manager: Manager, pkg: string): { binary: string; argv: string[] } {
  switch (manager) {
    case 'brew':
      return { binary: 'brew', argv: ['install', ...pkg.split(/\s+/).filter(Boolean)] };
    case 'apt':
      return { binary: 'sudo', argv: ['apt-get', 'install', '-y', pkg] };
    case 'dnf':
      return { binary: 'sudo', argv: ['dnf', 'install', '-y', pkg] };
    case 'pacman':
      return { binary: 'sudo', argv: ['pacman', '-S', '--noconfirm', pkg] };
    case 'winget':
      return { binary: 'winget', argv: ['install', '--exact', '--id', pkg] };
    case 'manual':
      throw new Error('manual targets do not produce an argv');
  }
}

// ── Spawn helper with timeout + stderr redactor reuse ────────────────────

// Mirror of CLIBridge §6 redactor (kept inline so this module has no
// dependency on toolHandlers.ts — the redactor is short).
function redactStderr(stderr: string): string {
  return stderr
    .replace(/\b(ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{20,}/g, '<REDACTED_GH>')
    .replace(/\bglpat-[A-Za-z0-9_-]{20,}/g, '<REDACTED_GITLAB>')
    .replace(/\bsk_(test|live)_[A-Za-z0-9]{20,}/g, '<REDACTED_STRIPE>')
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '<REDACTED_AWS>')
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '<REDACTED_JWT>')
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/g, '<REDACTED_PEM>')
    .slice(0, 4096);
}

const SUBPROCESS_ENV_ALLOWLIST = ['PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'TEMP', 'TMP'] as const;
function baseSubprocessEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of SUBPROCESS_ENV_ALLOWLIST) {
    const v = process.env[k];
    if (typeof v === 'string') env[k] = v;
  }
  return env;
}

/**
 * SpawnInstall signature (extended with optional `captureStdout`
 * so callers like `npmCachedTarballPath` can read `npm cache ls --json`
 * output without going through stderr). The 5th positional argument is
 * back-compat optional; existing callers that omit it get the original
 * stderr-only contract.
 */
export type SpawnInstallFn = (
  binary: string,
  argv: string[],
  timeoutMs: number,
  inheritStdio?: boolean,
  captureStdout?: boolean,
) => Promise<{ exitCode: number; stderr: string; stdout?: string }>;

// Exported for R.8 tests so timeout/SIGKILL behavior is directly verifiable.
// Production callers go through runPreInstall / runPreInstallWithAdapters.
export const spawnInstall: SpawnInstallFn = (binary, argv, timeoutMs, inheritStdio = true, captureStdout = false) => {
  return new Promise((resolve) => {
    // CLI-install path (inheritStdio=true): inherit stdin/stdout/stderr fully
    // so sudo's password prompt is visible to the user on its native TTY.
    // We lose programmatic stderr capture on this path; the manifest records
    // only the exit code + a generic note (sudo failures rarely emit
    // structured info anyway). npx/uvx warmup (inheritStdio=false) pipes
    // stderr because those paths never invoke sudo and we want the captured
    // 404/install-error text in the manifest. captureStdout=true pipes
    // stdout too, reserved for callers that need to parse a command's
    // structured output (none in the current code path).
    const child = spawn(binary, argv, {
      env: baseSubprocessEnv(),
      shell: false,
      stdio: inheritStdio
        ? 'inherit'
        : ['ignore', captureStdout ? 'pipe' : 'ignore', 'pipe'],
    });
    let stderr = '';
    let stderrBytes = 0;
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderrBytes >= 16_384) return;
      stderrBytes += chunk.length;
      stderr += chunk.toString('utf-8');
    });
    let stdout = '';
    let stdoutBytes = 0;
    child.stdout?.on('data', (chunk: Buffer) => {
      if (stdoutBytes >= 1_048_576) return; // 1 MiB cap for cache-ls JSON
      stdoutBytes += chunk.length;
      stdout += chunk.toString('utf-8');
    });
    let settled = false;
    const settle = (exitCode: number) => { if (!settled) { settled = true; resolve({ exitCode, stderr, stdout: captureStdout ? stdout : undefined }); } };
    const sigterm = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* dead */ }
      const sigkill = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* dead */ }
        settle(-1);
      }, 2_000);
      sigkill.unref();
    }, timeoutMs);
    sigterm.unref();
    child.on('error', () => { clearTimeout(sigterm); settle(-2); });
    child.on('close', (code) => { clearTimeout(sigterm); settle(code ?? -1); });
  });
};

// ── Workload extraction (§3) ──────────────────────────────────────────────

export interface Workload {
  cli: Array<{ binary: string; adapter: AdapterEntry }>;
  npx: AdapterEntry[];
  uvx: AdapterEntry[];
}

export function extractWorkload(adapters: AdapterEntry[]): Workload {
  const cliMap = new Map<string, AdapterEntry>();
  const npxMap = new Map<string, AdapterEntry>(); // dedup by pkg name; first-wins
  const uvxMap = new Map<string, AdapterEntry>();
  for (const a of adapters) {
    if (a.type === 'cli-bridge' && a.cli?.binary) {
      if (!cliMap.has(a.cli.binary)) cliMap.set(a.cli.binary, a);
    }
    if (a.mcp?.transport === 'stdio' && a.mcp.command === 'npx') {
      const pkg = extractStdioPackageName(a);
      if (pkg && !npxMap.has(pkg)) npxMap.set(pkg, a);
    }
    if (a.mcp?.transport === 'stdio' && a.mcp.command === 'uvx') {
      const pkg = extractStdioPackageName(a);
      if (pkg && !uvxMap.has(pkg)) uvxMap.set(pkg, a);
    }
  }
  return {
    cli: Array.from(cliMap.entries()).map(([binary, adapter]) => ({ binary, adapter })),
    npx: Array.from(npxMap.values()),
    uvx: Array.from(uvxMap.values()),
  };
}

// ── Pre-install CLI binaries (serial — §2) ────────────────────────────────

async function preinstallCli(
  cli: Workload['cli'],
  host: Host,
  dryRun: boolean,
): Promise<Record<string, CliBinaryStatus>> {
  const out: Record<string, CliBinaryStatus> = {};
  for (const { binary, adapter } of cli) {
    const onPath = findOnPath(binary);
    if (onPath) {
      out[binary] = { status: 'OK', path: onPath };
      continue;
    }
    if (host === 'unsupported') {
      out[binary] = { status: 'SKIP_HOST_UNSUPPORTED' };
      continue;
    }
    const target = resolveInstallTarget(adapter, binary, host);
    if (target.kind === 'unknown') {
      // provenance is a runtime-stamped extension field on bundle entries
      // (Phase 1.4) — not declared on AdapterEntry. Read defensively.
      const provenance = (adapter as { provenance?: { source_url?: string | null } }).provenance;
      out[binary] = { status: 'SKIP_UNKNOWN_PACKAGE', detail: `no installTargets schema entry and not in 5-CLI fallback (source: ${provenance?.source_url ?? 'unknown'})` };
      continue;
    }
    if (target.kind === 'manual') {
      out[binary] = { status: 'SKIP_MANUAL', detail: target.hint };
      continue;
    }
    const { binary: cmdBin, argv } = buildInstallArgv(target.manager, target.package);
    if (dryRun) {
      out[binary] = { status: 'DRY_RUN', installCommand: `${cmdBin} ${argv.join(' ')}` };
      continue;
    }
    const { exitCode, stderr } = await spawnInstall(cmdBin, argv, 10 * 60 * 1000, true);
    if (exitCode === 0) {
      out[binary] = { status: 'INSTALLED', installCommand: `${cmdBin} ${argv.join(' ')}` };
    } else {
      out[binary] = {
        status: 'FAILED',
        installCommand: `${cmdBin} ${argv.join(' ')}`,
        detail: `exit ${exitCode}: ${redactStderr(stderr)}`.slice(0, 800),
      };
    }
  }
  return out;
}

// ── npx + uvx warmup (concurrent 8) ───────────────────────────────────────

function sha512OfFile(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha512');
    const stream = createReadStream(path);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Locate the packed npm tarball for pkg@version inside a `npm pack
 * --pack-destination` target directory. npm pack normalizes the filename:
 * `@scope/name` → `scope-name-<version>.tgz`; plain `name` → `name-<version>.tgz`.
 * Argv-only, no shell.
 */
function npmPackedTarballPath(destDir: string, pkg: string, version: string): string | null {
  let entries: string[];
  try { entries = readdirSync(destDir); } catch { return null; }
  const normalized = pkg.replace(/^@/, '').replace('/', '-');
  const exact = `${normalized}-${version}.tgz`;
  if (entries.includes(exact)) return join(destDir, exact);
  // Fallback: any single .tgz in the dest dir (in case npm changes its
  // filename normalization rules in a future release).
  const fallback = entries.find((f) => f.endsWith('.tgz'));
  return fallback ? join(destDir, fallback) : null;
}

/**
 * Find the downloaded wheel for pkg==version inside a `uv pip download --dest`
 * target directory. Wheel filename grammar (PEP 427): `<pkg>-<version>-...whl`.
 */
function uvxDownloadedWheelPath(destDir: string, pkg: string, version: string): string | null {
  let entries: string[];
  try { entries = readdirSync(destDir); } catch { return null; }
  const expectedPrefix = `${pkg.replace(/-/g, '_')}-${version}-`; // PEP 503 normalization
  const altPrefix = `${pkg}-${version}-`;
  const match = entries.find((f) => f.endsWith('.whl') && (f.startsWith(expectedPrefix) || f.startsWith(altPrefix)));
  return match ? join(destDir, match) : null;
}

// Pin-classified row: caller has verified version + expectedSha non-null.
// Keeping these as own type lets the unified runner avoid `as string` casts.
interface PinnedAdapter { adapter: AdapterEntry; pkg: string; version: string; expectedSha: string }
interface GitPinnedAdapter { adapter: AdapterEntry; pkg: string; cloneUrl: string; gitRef: string }

function unpinnedDetail(version: string | undefined, expectedSha: string | undefined): string {
  return `bundle row missing version (${version ?? 'absent'}) or integrityShasum (${expectedSha ? 'present' : 'absent'}) — install refused`;
}

const GIT_REF_RE = /^[0-9a-f]{40}$/;

// `github:Owner/repo` → https clone URL. Returns null for malformed specs.
function githubCloneUrl(pkg: string): string | null {
  const m = /^github:([\w.-]+\/[\w.-]+)$/.exec(pkg);
  return m ? `https://github.com/${m[1]}.git` : null;
}

// Partition adapters into pinned (have version + integrityShasum), git-pinned
// (github: source with a 40-hex mcp.gitRef — bug-tracker-ref) and unpinned
// (return INTEGRITY_UNPINNED before any host-tool check, so strict refusal is
// host-independent).
function classifyIntegrity(adapters: AdapterEntry[]): { pinned: PinnedAdapter[]; gitPinned: GitPinnedAdapter[]; unpinned: Record<string, PackageStatus> } {
  const pinned: PinnedAdapter[] = [];
  const gitPinned: GitPinnedAdapter[] = [];
  const unpinned: Record<string, PackageStatus> = {};
  for (const a of adapters) {
    const pkg = extractStdioPackageName(a);
    if (!pkg) continue;
    if (pkg.startsWith('github:')) {
      // npm tarball pins do not exist for github: specs; the git-commit pin
      // (mcp.gitRef) is their integrity contract.
      const gitRef = a.mcp?.gitRef;
      const cloneUrl = githubCloneUrl(pkg);
      if (!gitRef || !GIT_REF_RE.test(gitRef)) {
        unpinned[pkg] = { status: 'INTEGRITY_UNPINNED', detail: `github: source requires mcp.gitRef (40-hex commit SHA); gitRef=${gitRef ?? 'absent'} — install refused` };
        continue;
      }
      if (!cloneUrl) {
        unpinned[pkg] = { status: 'INTEGRITY_UNPINNED', detail: `malformed github: spec "${pkg}" — install refused` };
        continue;
      }
      gitPinned.push({ adapter: a, pkg, cloneUrl, gitRef });
      continue;
    }
    const version = a.mcp?.version;
    const expectedSha = a.mcp?.integrityShasum;
    if (!version || !expectedSha) {
      unpinned[pkg] = { status: 'INTEGRITY_UNPINNED', detail: unpinnedDetail(version, expectedSha) };
      continue;
    }
    pinned.push({ adapter: a, pkg, version, expectedSha });
  }
  return { pinned, gitPinned, unpinned };
}

// Fetch the verifiable artifact (tarball or wheel) and return its path,
// or a terminal PackageStatus on a fetch-level failure that should be
// recorded directly in the manifest.
type FetchResult = { ok: true; tarballPath: string } | { ok: false; status: PackageStatus };

// Post-verify hook (uvx uses this for `uv tool install`; npx leaves it absent).
type PostInstall = () => Promise<{ ok: true } | { ok: false; status: PackageStatus }>;
type PostInstallFactory = (p: PinnedAdapter, ctx: WarmCtx) => PostInstall;

async function verifyAndAuditOne(
  p: PinnedAdapter,
  fetchArtifact: () => Promise<FetchResult>,
  postInstall: PostInstall | undefined,
  audit: AuditTrail | undefined,
): Promise<PackageStatus> {
  const f = await fetchArtifact();
  if (!f.ok) {
    // Registry-level failure (404, network error, malformed tarball
    // location) — the install attempt is over but it is still an attempt
    // and the chain must record it so a chain-reader can distinguish
    // "we never tried" from "we tried and the registry said no".
    await auditFetchFailure(audit, p.pkg, p.version, p.expectedSha, f.status);
    return f.status;
  }
  const actualSha = await sha512OfFile(f.tarballPath);
  if (actualSha !== p.expectedSha) {
    await auditMismatch(audit, p.pkg, p.version, p.expectedSha, actualSha);
    return {
      status: 'INTEGRITY_MISMATCH',
      detail: `expected=${p.expectedSha.slice(0, 16)}… actual=${actualSha.slice(0, 16)}… (full digests in audit trail)`,
    };
  }
  if (postInstall) {
    const r = await postInstall();
    if (!r.ok) {
      // SHA matched but the post-verify install command failed for some
      // other reason (uv tool install resolver error, dependency conflict,
      // venv create failure, etc). The integrity decision is verified, but
      // the install attempt itself did not complete — that is its own
      // audit-visible event class so the chain records every install
      // attempt regardless of where in the pipeline it terminated.
      await auditPostVerifyFailure(audit, p.pkg, p.version, p.expectedSha, r.status);
      return r.status;
    }
  }
  await auditVerified(audit, p.pkg, p.version, p.expectedSha);
  return { status: 'WARMED' };
}

async function auditVerified(audit: AuditTrail | undefined, pkg: string, version: string, sha: string): Promise<void> {
  if (!audit) return;
  await audit.record({
    timestamp: new Date(),
    action: 'supply-chain-install-verified',
    tool: pkg,
    server: 'chariot-setup',
    tier: 'auto',
    status: 'completed',
    input: { pkg, version, expectedSha: sha },
    output: { actualSha: sha, result: 'verified' },
    persona: 'setup-wizard',
    durationMs: 0,
  });
}

async function auditFetchFailure(audit: AuditTrail | undefined, pkg: string, version: string, expectedSha: string, terminalStatus: PackageStatus): Promise<void> {
  if (!audit) return;
  await audit.record({
    timestamp: new Date(),
    action: 'supply-chain-install-fetch-failed',
    tool: pkg,
    server: 'chariot-setup',
    tier: 'auto',
    status: 'failed',
    input: { pkg, version, expectedSha },
    output: { result: 'fetch-failed', terminalStatus: terminalStatus.status, detail: terminalStatus.detail },
    persona: 'setup-wizard',
    durationMs: 0,
  });
}

async function auditPostVerifyFailure(audit: AuditTrail | undefined, pkg: string, version: string, expectedSha: string, terminalStatus: PackageStatus): Promise<void> {
  if (!audit) return;
  await audit.record({
    timestamp: new Date(),
    action: 'supply-chain-install-post-verify-failed',
    tool: pkg,
    server: 'chariot-setup',
    tier: 'auto',
    status: 'failed',
    input: { pkg, version, expectedSha },
    output: { result: 'post-verify-failed', terminalStatus: terminalStatus.status, detail: terminalStatus.detail },
    persona: 'setup-wizard',
    durationMs: 0,
  });
}

async function auditMismatch(audit: AuditTrail | undefined, pkg: string, version: string, expected: string, actual: string): Promise<void> {
  if (!audit) return;
  await audit.record({
    timestamp: new Date(),
    action: 'supply-chain-install-mismatch',
    tool: pkg,
    server: 'chariot-setup',
    tier: 'auto',
    status: 'failed',
    input: { pkg, version, expectedSha: expected },
    output: { actualSha: actual, result: 'fail-closed' },
    persona: 'setup-wizard',
    durationMs: 0,
  });
}

interface WarmCtx { dryRun: boolean; spawnFn: SpawnInstallFn; audit: AuditTrail | undefined }

// Build a fetcher closure for an npm row: `npm pack --pack-destination <tmp>`
// produces the registry-served tarball as a file we own.
function npmFetch(p: PinnedAdapter, ctx: WarmCtx): () => Promise<FetchResult> {
  return async () => {
    const destDir = join(tmpdir(), 'chariot-npm-verify', p.pkg.replace(/^@/, '').replace('/', '-'));
    const { exitCode, stderr } = await ctx.spawnFn('npm', ['pack', `${p.pkg}@${p.version}`, '--pack-destination', destDir], 60_000, false);
    if (exitCode !== 0) {
      const status: PackageStatus = (stderr.includes('404') || stderr.includes('E404'))
        ? { status: 'NOT_FOUND', detail: `npm registry returned 404 for ${p.pkg}@${p.version}` }
        : { status: 'FAILED', detail: `exit ${exitCode}: ${redactStderr(stderr)}`.slice(0, 400) };
      return { ok: false, status };
    }
    const tarball = npmPackedTarballPath(destDir, p.pkg, p.version);
    if (!tarball) {
      return { ok: false, status: { status: 'FAILED', detail: `npm pack succeeded but no .tgz matched ${p.pkg}@${p.version} in ${destDir}` } };
    }
    return { ok: true, tarballPath: tarball };
  };
}

// Build a fetcher closure for a uvx row: `uv pip download --no-deps` is the
// only documented uv form that materializes the wheel archive on disk
// (`uv tool install` extracts and discards it; `uv pip show --files` lists
// installed files, not the original archive bytes).
function uvxFetch(p: PinnedAdapter, ctx: WarmCtx): () => Promise<FetchResult> {
  return async () => {
    const destDir = join(tmpdir(), 'chariot-uvx-verify', p.pkg);
    const dl = await ctx.spawnFn('uv', ['pip', 'download', `${p.pkg}==${p.version}`, '--no-deps', '--dest', destDir], 120_000, false);
    if (dl.exitCode !== 0) {
      return { ok: false, status: { status: 'FAILED', detail: `uv pip download exit ${dl.exitCode}: ${redactStderr(dl.stderr)}`.slice(0, 400) } };
    }
    const wheel = uvxDownloadedWheelPath(destDir, p.pkg, p.version);
    if (!wheel) {
      return { ok: false, status: { status: 'FAILED', detail: `uv pip download succeeded but no .whl matched ${p.pkg}-${p.version}-… in ${destDir}` } };
    }
    return { ok: true, tarballPath: wheel };
  };
}

// uvx-only post-verify step: actually install the verified wheel via the
// documented `uv tool install <pkg>==<version>` form. npx has no analogous
// step because `npm pack` is itself the registry round-trip.
const uvxInstall: PostInstallFactory = (p, ctx) => async () => {
  const r = await ctx.spawnFn('uv', ['tool', 'install', `${p.pkg}==${p.version}`], 120_000, false);
  if (r.exitCode !== 0) {
    return { ok: false, status: { status: 'FAILED', detail: `uv tool install exit ${r.exitCode}: ${redactStderr(r.stderr)}`.slice(0, 400) } };
  }
  return { ok: true };
};

// Clone-and-verify pre-fetch for git-pinned github: stdio adapters (bug-tracker-ref).
// Each repo is fetched at exactly mcp.gitRef into
// ~/.epic-ai/git-adapters/<owner__repo>/<sha> and the checked-out HEAD is
// verified against the pin before reporting WARMED. Fail-closed: fetch
// failures report FAILED; a HEAD that does not match the pin reports
// INTEGRITY_MISMATCH.
async function warmGitPinned(gitPinned: GitPinnedAdapter[], ctx: WarmCtx): Promise<Record<string, PackageStatus>> {
  const out: Record<string, PackageStatus> = {};
  if (gitPinned.length === 0) return out;
  if (!findOnPath('git')) {
    for (const p of gitPinned) out[p.pkg] = { status: 'FAILED', detail: 'git not on PATH — required to pre-fetch github:-pinned adapters' };
    return out;
  }
  await runConcurrent(gitPinned, async (p) => {
    if (ctx.dryRun) {
      out[p.pkg] = { status: 'DRY_RUN', detail: `git fetch ${p.cloneUrl} @ ${p.gitRef} → verify HEAD` };
      return;
    }
    const safeName = p.pkg.replace(/^github:/, '').replace(/[^\w.-]/g, '__');
    const checkoutDir = join(EPIC_AI_DIR, 'git-adapters', safeName, p.gitRef);
    const revParse = async (): Promise<string | null> => {
      const r = await ctx.spawnFn('git', ['-C', checkoutDir, 'rev-parse', 'HEAD'], 30_000, false, true);
      return r.exitCode === 0 ? (r.stdout ?? '').trim() : null;
    };
    // Idempotent: an existing checkout that already verifies is WARMED.
    if (existsSync(join(checkoutDir, '.git')) && (await revParse()) === p.gitRef) {
      out[p.pkg] = { status: 'WARMED' };
      return;
    }
    ensureDir(checkoutDir);
    const steps: Array<[string, string[]]> = [
      ['init', ['-C', checkoutDir, 'init', '--quiet']],
      ['fetch', ['-C', checkoutDir, 'fetch', '--depth', '1', p.cloneUrl, p.gitRef]],
      ['checkout', ['-C', checkoutDir, 'checkout', '--quiet', '--detach', 'FETCH_HEAD']],
    ];
    for (const [label, argv] of steps) {
      const r = await ctx.spawnFn('git', argv, 120_000, false);
      if (r.exitCode !== 0) {
        out[p.pkg] = { status: 'FAILED', detail: `git ${label} exit ${r.exitCode} for ${p.cloneUrl}@${p.gitRef}: ${redactStderr(r.stderr)}`.slice(0, 400) };
        return;
      }
    }
    const head = await revParse();
    if (head !== p.gitRef) {
      out[p.pkg] = { status: 'INTEGRITY_MISMATCH', detail: `pinned=${p.gitRef.slice(0, 16)}… checked-out HEAD=${(head ?? 'unknown').slice(0, 16)}… — refused` };
      return;
    }
    out[p.pkg] = { status: 'WARMED' };
  }, warmConcurrency());
  return out;
}

async function warmStdio(
  adapters: AdapterEntry[],
  toolName: 'npm' | 'uv',
  missingToolStatus: PackageStatus,
  dryRunDetail: (p: PinnedAdapter) => string,
  fetch: (p: PinnedAdapter, ctx: WarmCtx) => () => Promise<FetchResult>,
  postInstall: PostInstallFactory | undefined,
  ctx: WarmCtx,
): Promise<Record<string, PackageStatus>> {
  const { pinned, gitPinned, unpinned: out } = classifyIntegrity(adapters);
  // github:-pinned rows take the git clone-and-verify path (npm has no
  // tarball to verify for a github: spec). Only the npx lane carries them;
  // a github: spec under uvx is a malformed row and is refused.
  if (toolName === 'npm') {
    Object.assign(out, await warmGitPinned(gitPinned, ctx));
  } else {
    for (const p of gitPinned) out[p.pkg] = { status: 'INTEGRITY_UNPINNED', detail: 'github: spec is not valid under uvx — install refused' };
  }
  if (pinned.length === 0) return out;
  if (!findOnPath(toolName)) {
    for (const p of pinned) out[p.pkg] = missingToolStatus;
    return out;
  }
  // Memory-bounded fan-out: each warm op (`npm pack` / `uv pip download`) can
  // drive ~1.6 GB, so a fixed width of 8 OOM-killed a 15 GB host.
  await runConcurrent(pinned, async (p) => {
    if (ctx.dryRun) { out[p.pkg] = { status: 'DRY_RUN', detail: dryRunDetail(p) }; return; }
    out[p.pkg] = await verifyAndAuditOne(p, fetch(p, ctx), postInstall ? postInstall(p, ctx) : undefined, ctx.audit);
  }, warmConcurrency());
  return out;
}

function warmNpx(adapters: AdapterEntry[], ctx: WarmCtx): Promise<Record<string, PackageStatus>> {
  return warmStdio(
    adapters, 'npm',
    { status: 'FAILED', detail: 'npm not on PATH' },
    (p) => `npm pack ${p.pkg}@${p.version}`,
    npmFetch,
    undefined,
    ctx,
  );
}

function warmUvx(adapters: AdapterEntry[], ctx: WarmCtx): Promise<Record<string, PackageStatus>> {
  return warmStdio(
    adapters, 'uv',
    { status: 'SKIP_NO_UVX_TOOL', detail: 'uv not on PATH — install via: brew install uv | pipx install uv | winget install astral-sh.uv' },
    (p) => `uv pip download ${p.pkg}==${p.version} → verify → uv tool install ${p.pkg}==${p.version}`,
    uvxFetch,
    uvxInstall,
    ctx,
  );
}

// ── Entry point ──────────────────────────────────────────────────────────

export interface PreInstallOptions {
  dryRun?: boolean;
  skipPreWarm?: boolean;
  only?: 'cli' | 'npx' | 'uvx' | null;
  /**
 * test-only injection point for the spawn primitive. Production
   * callers omit this and get the real `spawnInstall`. The supply-chain
   * eval (test/supply-chain-eval-may-2026/) injects a mock so the verify
   * code path runs against canned spawn outcomes without touching the
   * real npm registry or uv tool venv.
   */
  spawnInstall?: SpawnInstallFn;
  /**
 * optional AuditTrail. When provided, every supply-chain
   * verification attempt emits a hash-chained audit entry (spec §6).
   * When absent, install verification still runs (manifest records the
   * outcome) but no audit entry is emitted (spec §6.2). Strict
   * environments configure audit at `chariot setup` time.
   */
  auditTrail?: AuditTrail;
}

export async function runPreInstall(opts: PreInstallOptions = {}): Promise<Manifest> {
  const { loadAllAdapters } = await import('../server/ChariotState.js');
  const adapters = await loadAllAdapters();
  return runPreInstallWithAdapters(adapters, opts);
}

// Internal: same as runPreInstall but takes the adapter list directly.
// Exported for tests so they can inject synthetic adapter sets without
// having to produce a signed bundle fixture.
export async function runPreInstallWithAdapters(adapters: AdapterEntry[], opts: PreInstallOptions = {}): Promise<Manifest> {
  const workload = extractWorkload(adapters);
  const host = detectHost();
  const dryRun = !!opts.dryRun;
  const spawnFn: SpawnInstallFn = opts.spawnInstall ?? spawnInstall;
  const audit = opts.auditTrail;

  console.log(`Chariot setup --pre-install (host=${host}, dryRun=${dryRun})`);
  console.log(`  cli-bridge binaries: ${workload.cli.length}`);
  console.log(`  stdio npx packages:  ${workload.npx.length}`);
  console.log(`  stdio uvx packages:  ${workload.uvx.length}`);

  const onlyCli = opts.only === 'cli' || (!opts.only);
  const onlyNpx = (opts.only === 'npx' || (!opts.only)) && !opts.skipPreWarm;
  const onlyUvx = (opts.only === 'uvx' || (!opts.only)) && !opts.skipPreWarm;

  // CLI installs go first and serially because they invoke sudo for the
  // host package manager; interleaving them with npx/uvx would corrupt the
  // password prompt's TTY. Once CLI is done, the npx and uvx warmers
  // dispatch to different binaries and share no resource constraint, so
  // they run in parallel.
  const ctx: WarmCtx = { dryRun, spawnFn, audit };
  const cliResults = onlyCli ? await preinstallCli(workload.cli, host, dryRun) : {};
  const [npxResults, uvxResults] = await Promise.all([
    onlyNpx ? warmNpx(workload.npx, ctx) : Promise.resolve<Record<string, PackageStatus>>({}),
    onlyUvx ? warmUvx(workload.uvx, ctx) : Promise.resolve<Record<string, PackageStatus>>({}),
  ]);

  const totals: Record<string, number> = {};
  for (const set of [cliResults, npxResults, uvxResults]) {
    for (const v of Object.values(set)) {
      totals[v.status] = (totals[v.status] ?? 0) + 1;
    }
  }

  const manifest: Manifest = {
    version: 1,
    ranAt: new Date().toISOString(),
    host: { platform: process.platform, arch: process.arch, packageManager: hostPackageManager(host) },
    cliBinaries: cliResults,
    npxPackages: npxResults,
    uvxPackages: uvxResults,
    summary: { totals },
  };

  ensureDir(EPIC_AI_DIR);
  writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n');
  chmodSync(MANIFEST_PATH, 0o644);
  console.log('');
  console.log(`Manifest: ${MANIFEST_PATH}`);
  console.log('Totals:', JSON.stringify(totals));
  return manifest;
}

export function readManifest(): Manifest | null {
  if (!existsSync(MANIFEST_PATH)) return null;
  try {
    return JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8')) as Manifest;
  } catch {
    return null;
  }
}
